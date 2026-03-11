"""
Kill Chain API — AI-powered campaign timeline analysis.
"""
import hashlib
import json
import re
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..database import get_db
from ..models.kill_chain import KillChain
from ..models.node import Node
from ..services.access_control import (
    get_active_provider_for_user,
    require_kill_chain_access,
    require_project_access,
)
from ..services import llm_service
from ..services.environment_catalog_service import build_environment_catalog_outline_for_context

router = APIRouter(prefix="/kill-chains", tags=["kill_chains"])

MITRE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
]

CKC_PHASES = [
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
    "Installation", "Command & Control", "Actions on Objectives"
]

UNIFIED_PHASES = [
    "Reconnaissance", "Weaponization", "Social Engineering", "Exploitation",
    "Persistence", "Defense Evasion", "Command & Control", "Pivoting",
    "Discovery", "Privilege Escalation", "Execution", "Credential Access",
    "Lateral Movement", "Collection", "Exfiltration", "Impact",
    "Objectives", "Anti-Forensics"
]

ATTACK_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
VALID_DIFFICULTIES = {"trivial", "easy", "moderate", "hard", "very_hard"}
VALID_DEFENSIVE_COVERAGE = {"none", "minimal", "partial", "good", "strong"}
VALID_RISK_RATINGS = {"critical", "high", "medium", "low"}
VALID_ATTACK_COMPLEXITY = {"low", "medium", "high", "very_high"}
MIN_PHASE_DESCRIPTION_LENGTH = 60
MIN_SUMMARY_LENGTH = 220
MIN_RECOMMENDATIONS = 3
KILL_CHAIN_PHASE_CHUNK_LIMIT = 1
KILL_CHAIN_REQUEST_RETRIES = 2


# --- Schemas ---

class KillChainCreate(BaseModel):
    project_id: str
    name: str
    description: str = ""
    framework: str = "mitre_attck"


class KillChainUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    framework: Optional[str] = None
    phases: Optional[list] = None


class AIMapRequest(BaseModel):
    user_guidance: str = ""
    planning_profile: str = "balanced"
    refresh: bool = False


class AIGenerateKillChainRequest(BaseModel):
    framework: str = "mitre_attck"
    user_guidance: str = ""
    planning_profile: str = "balanced"
    refresh: bool = False


def _framework_phases(framework: str) -> list[str]:
    if framework == "mitre_attck":
        return MITRE_TACTICS
    if framework == "unified":
        return UNIFIED_PHASES
    if framework == "cyber_kill_chain":
        return CKC_PHASES
    raise HTTPException(400, f"Unsupported kill chain framework: {framework}")


def _phase_key(value: str) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip().lower().replace("&", " and ")
    return re.sub(r"[^a-z0-9]+", " ", normalized).strip()


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in values:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        if isinstance(item, str):
            cleaned = item.strip()
            if cleaned:
                items.append(cleaned)
    return _dedupe_preserve_order(items)


def _coerce_float(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_confidence(value: Any) -> float:
    score = _coerce_float(value)
    if score is None:
        return 0.0
    return max(0.0, min(1.0, score))


def _normalize_choice(value: Any, valid_values: set[str], fallback: str) -> str:
    if not isinstance(value, str):
        return fallback
    normalized = value.strip().lower().replace(" ", "_")
    return normalized if normalized in valid_values else fallback


def _normalize_technique_id(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    candidate = value.strip().upper()
    return candidate if ATTACK_TECHNIQUE_RE.fullmatch(candidate) else ""


def _pick_preferred_text(*values: Any) -> str:
    candidates = [value.strip() for value in values if isinstance(value, str) and value.strip()]
    return max(candidates, key=len, default="")


def _phase_shell(name: str, phase_index: int) -> dict:
    return {
        "phase": name,
        "phase_index": phase_index,
        "description": "",
        "mapped_nodes": [],
        "tools": [],
        "iocs": [],
        "log_sources": [],
        "detection_window": "",
        "dwell_time": "",
        "break_opportunities": [],
        "difficulty": "moderate",
        "defensive_coverage": "none",
        "coverage_notes": "",
    }


def _normalize_mapped_nodes(raw_phase: dict, node_lookup: dict[str, Node]) -> list[dict]:
    if not node_lookup:
        return []

    normalized: dict[tuple[str, str], dict] = {}
    raw_mapped_nodes = raw_phase.get("mapped_nodes")
    raw_node_ids = raw_phase.get("node_ids")

    if isinstance(raw_mapped_nodes, list):
        source_items = raw_mapped_nodes
    elif isinstance(raw_node_ids, list):
        source_items = [{"node_id": node_id} for node_id in raw_node_ids]
    else:
        source_items = []

    for item in source_items:
        if not isinstance(item, dict):
            continue
        node_id = item.get("node_id")
        if not isinstance(node_id, str) or node_id not in node_lookup:
            continue

        technique_id = _normalize_technique_id(item.get("technique_id"))
        technique_name = item.get("technique_name") if technique_id and isinstance(item.get("technique_name"), str) else ""
        key = (node_id, technique_id)
        current = normalized.get(key)
        candidate = {
            "node_id": node_id,
            "node_title": node_lookup[node_id].title,
            "technique_id": technique_id,
            "technique_name": technique_name.strip(),
            "confidence": _normalize_confidence(item.get("confidence")),
        }
        if current is None:
            normalized[key] = candidate
            continue
        current["confidence"] = max(current["confidence"], candidate["confidence"])
        current["technique_name"] = _pick_preferred_text(current.get("technique_name", ""), candidate["technique_name"])

    return list(normalized.values())


def _merge_phase_entries(existing: dict, incoming: dict) -> dict:
    merged = dict(existing)
    merged["description"] = _pick_preferred_text(existing.get("description", ""), incoming.get("description", ""))
    merged["detection_window"] = _pick_preferred_text(existing.get("detection_window", ""), incoming.get("detection_window", ""))
    merged["dwell_time"] = _pick_preferred_text(existing.get("dwell_time", ""), incoming.get("dwell_time", ""))
    merged["coverage_notes"] = _pick_preferred_text(existing.get("coverage_notes", ""), incoming.get("coverage_notes", ""))
    merged["tools"] = _dedupe_preserve_order(existing.get("tools", []) + incoming.get("tools", []))
    merged["iocs"] = _dedupe_preserve_order(existing.get("iocs", []) + incoming.get("iocs", []))
    merged["log_sources"] = _dedupe_preserve_order(existing.get("log_sources", []) + incoming.get("log_sources", []))
    merged["break_opportunities"] = _dedupe_preserve_order(existing.get("break_opportunities", []) + incoming.get("break_opportunities", []))
    if existing.get("difficulty") == "moderate" and incoming.get("difficulty") != "moderate":
        merged["difficulty"] = incoming["difficulty"]
    if existing.get("defensive_coverage") == "none" and incoming.get("defensive_coverage") != "none":
        merged["defensive_coverage"] = incoming["defensive_coverage"]

    mapped_nodes: dict[tuple[str, str], dict] = {}
    for item in existing.get("mapped_nodes", []) + incoming.get("mapped_nodes", []):
        if not isinstance(item, dict) or not item.get("node_id"):
            continue
        key = (item["node_id"], item.get("technique_id", ""))
        current = mapped_nodes.get(key)
        if current is None:
            mapped_nodes[key] = dict(item)
            continue
        current["confidence"] = max(current.get("confidence", 0), item.get("confidence", 0))
        current["technique_name"] = _pick_preferred_text(current.get("technique_name", ""), item.get("technique_name", ""))
    merged["mapped_nodes"] = list(mapped_nodes.values())
    return merged


def _normalize_phase_entry(raw_phase: dict, expected_name: str, phase_index: int, node_lookup: dict[str, Node]) -> dict:
    phase = _phase_shell(expected_name, phase_index)
    phase["description"] = raw_phase.get("description").strip() if isinstance(raw_phase.get("description"), str) else ""
    phase["mapped_nodes"] = _normalize_mapped_nodes(raw_phase, node_lookup)
    phase["tools"] = _string_list(raw_phase.get("tools"))
    phase["iocs"] = _string_list(raw_phase.get("iocs"))
    phase["log_sources"] = _string_list(raw_phase.get("log_sources"))
    phase["break_opportunities"] = _string_list(raw_phase.get("break_opportunities"))
    phase["detection_window"] = raw_phase.get("detection_window").strip() if isinstance(raw_phase.get("detection_window"), str) else ""
    phase["dwell_time"] = raw_phase.get("dwell_time").strip() if isinstance(raw_phase.get("dwell_time"), str) else ""
    phase["difficulty"] = _normalize_choice(raw_phase.get("difficulty"), VALID_DIFFICULTIES, "moderate")
    phase["defensive_coverage"] = _normalize_choice(raw_phase.get("defensive_coverage"), VALID_DEFENSIVE_COVERAGE, "none")
    phase["coverage_notes"] = raw_phase.get("coverage_notes").strip() if isinstance(raw_phase.get("coverage_notes"), str) else ""
    return phase


def _normalize_recommendations(value: Any, expected_phases: list[str]) -> list[dict]:
    if not isinstance(value, list):
        return []
    expected_by_key = {_phase_key(phase): phase for phase in expected_phases}
    recommendations: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        title = item.get("title").strip() if isinstance(item.get("title"), str) else ""
        description = item.get("description").strip() if isinstance(item.get("description"), str) else ""
        if not title or not description:
            continue
        addresses = []
        for phase_name in _string_list(item.get("addresses_phases")):
            canonical = expected_by_key.get(_phase_key(phase_name))
            if canonical:
                addresses.append(canonical)
        recommendations.append({
            "priority": _normalize_choice(item.get("priority"), VALID_RISK_RATINGS, "medium"),
            "title": title,
            "description": description,
            "addresses_phases": _dedupe_preserve_order(addresses),
            "effort": _normalize_choice(item.get("effort"), {"low", "medium", "high"}, "medium"),
        })
    return recommendations


def _coerce_coverage_score(value: Any, phases: list[dict]) -> float:
    numeric = _coerce_float(value)
    if numeric is not None:
        return max(0.0, min(1.0, numeric))
    if not phases:
        return 0.0
    weights = {"none": 0.0, "minimal": 0.2, "partial": 0.5, "good": 0.75, "strong": 1.0}
    score = sum(weights.get(phase.get("defensive_coverage", "none"), 0.0) for phase in phases) / len(phases)
    return round(score, 2)


def _compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _kill_chain_request_signature(
    *,
    project_name: str,
    objective: str,
    description: str,
    framework: str,
    user_guidance: str,
    planning_profile: str,
    context_preset: str,
    nodes: list[Node],
) -> str:
    payload = {
        "project_name": project_name,
        "objective": objective,
        "description": description,
        "framework": framework,
        "user_guidance": user_guidance,
        "planning_profile": planning_profile,
        "context_preset": context_preset,
        "nodes": [
            {
                "id": node.id,
                "title": node.title,
                "description": (node.description or "")[:160],
                "threat_category": node.threat_category or "",
                "attack_surface": node.attack_surface or "",
                "platform": node.platform or "",
                "required_access": node.required_access or "",
                "mitigations": [mit.title for mit in (node.mitigations or [])[:5]],
                "detections": [det.title for det in (node.detections or [])[:5]],
            }
            for node in nodes[:80]
        ],
    }
    return hashlib.sha256(_compact_json(payload).encode("utf-8")).hexdigest()


async def _request_json_object_with_retries(
    config: dict[str, Any],
    messages: list[dict[str, str]],
    *,
    temperature: float,
    max_tokens: int,
    timeout_override: int,
    required_keys: tuple[str, ...] = (),
) -> tuple[dict[str, Any], str]:
    last_error = "LLM returned malformed or incomplete JSON"
    for attempt in range(KILL_CHAIN_REQUEST_RETRIES + 1):
        attempt_messages = messages
        if attempt:
            attempt_messages = list(messages)
            attempt_messages[-1] = {
                **attempt_messages[-1],
                "content": attempt_messages[-1]["content"] + (
                    "\n\nYour previous response was incomplete, malformed, or missing required fields. "
                    "Return smaller, strictly valid JSON only."
                ),
            }
        response = await llm_service.chat_completion(
            config,
            attempt_messages,
            temperature=max(0.2, temperature - (attempt * 0.1)),
            max_tokens=max_tokens,
            timeout_override=timeout_override,
        )
        if response["status"] != "success":
            last_error = response.get("message", "LLM request failed")
            continue
        parsed = llm_service.parse_json_object_response(response.get("content", ""))
        if not required_keys or any(parsed.get(key) for key in required_keys):
            return parsed, ""
        last_error = "LLM returned malformed or incomplete JSON"
    return {}, last_error


def _normalize_overview_payload(parsed: dict[str, Any], expected_phases: list[str]) -> dict[str, Any]:
    expected_by_key = {_phase_key(phase): phase for phase in expected_phases}
    phase_objective_map: dict[str, str] = {}
    for item in parsed.get("phase_objectives", []):
        if not isinstance(item, dict):
            continue
        phase_name = expected_by_key.get(_phase_key(item.get("phase", "")))
        objective = item.get("objective").strip() if isinstance(item.get("objective"), str) else ""
        if phase_name and objective:
            phase_objective_map[phase_name] = objective

    return {
        "overview_summary": parsed.get("overview_summary").strip() if isinstance(parsed.get("overview_summary"), str) else "",
        "campaign_concept": parsed.get("campaign_concept").strip() if isinstance(parsed.get("campaign_concept"), str) else "",
        "threat_actor_profile": parsed.get("threat_actor_profile").strip() if isinstance(parsed.get("threat_actor_profile"), str) else "",
        "initial_compromise_hypothesis": parsed.get("initial_compromise_hypothesis").strip() if isinstance(parsed.get("initial_compromise_hypothesis"), str) else "",
        "priority_surfaces": _string_list(parsed.get("priority_surfaces")),
        "defensive_posture": parsed.get("defensive_posture").strip() if isinstance(parsed.get("defensive_posture"), str) else "",
        "control_pressures": _string_list(parsed.get("control_pressures")),
        "critical_path_hypothesis": parsed.get("critical_path_hypothesis").strip() if isinstance(parsed.get("critical_path_hypothesis"), str) else "",
        "phase_objectives": [
            {
                "phase": phase_name,
                "objective": phase_objective_map.get(
                    phase_name,
                    f"Describe the most plausible attacker objective, target surface, and defensive pressure points for {phase_name}.",
                ),
            }
            for phase_name in expected_phases
        ],
    }


def _build_fallback_overview(
    *,
    project_name: str,
    objective: str,
    framework: str,
    expected_phases: list[str],
    nodes: list[Node],
) -> dict[str, Any]:
    priority_surfaces = _dedupe_preserve_order([
        *(node.attack_surface.strip() for node in nodes if isinstance(node.attack_surface, str) and node.attack_surface.strip()),
        *(node.platform.strip() for node in nodes if isinstance(node.platform, str) and node.platform.strip()),
    ])[:6]
    root_surface = priority_surfaces[0] if priority_surfaces else "the most exposed identity, remote access, and operational interfaces"
    return {
        "overview_summary": (
            f"Fallback campaign outline for {project_name}: analysts should plan a {framework} intrusion path that advances toward "
            f"{objective or 'the stated project objective'} by prioritizing {root_surface} and adjacent trust boundaries. "
            "Use the generated phase details as the primary artifact and treat this overview as a checkpointed planning baseline."
        ),
        "campaign_concept": f"Multi-stage intrusion focused on {objective or 'the project objective'} through the highest-value reachable surfaces.",
        "threat_actor_profile": "Assume a capable operator with enough tooling and patience to progress across multiple phases while adapting to visible controls.",
        "initial_compromise_hypothesis": f"The most plausible initial foothold will target {root_surface} or a closely related administrative path.",
        "priority_surfaces": priority_surfaces,
        "defensive_posture": "Control coverage is uneven and should be validated phase-by-phase rather than assumed to be consistent across the campaign.",
        "control_pressures": [
            "Prioritize where attacker activity must cross trust boundaries or trigger observable control points.",
            "Use phase-specific detections and hardening actions instead of broad generic advice.",
        ],
        "critical_path_hypothesis": f"Reach the objective by moving from the initial foothold through the least-resisted path across identities, execution, control, and objective actions.",
        "phase_objectives": [
            {
                "phase": phase_name,
                "objective": f"Plan the attacker objective, target surface, and intended outcome for {phase_name} in support of {objective or 'the campaign goal'}.",
            }
            for phase_name in expected_phases
        ],
    }


def _build_phase_chunks(expected_phases: list[str], overview: dict[str, Any]) -> list[dict[str, Any]]:
    objective_lookup = {
        item.get("phase"): item.get("objective")
        for item in overview.get("phase_objectives", [])
        if isinstance(item, dict) and item.get("phase")
    }
    chunks: list[dict[str, Any]] = []
    for index in range(0, len(expected_phases), KILL_CHAIN_PHASE_CHUNK_LIMIT):
        phase_names = expected_phases[index:index + KILL_CHAIN_PHASE_CHUNK_LIMIT]
        chunk_id = f"chunk-{index // KILL_CHAIN_PHASE_CHUNK_LIMIT + 1}"
        chunks.append({
            "id": chunk_id,
            "label": f"{phase_names[0]} to {phase_names[-1]}",
            "phase_names": phase_names,
            "phase_objectives": [
                {"phase": phase_name, "objective": objective_lookup.get(phase_name, "")}
                for phase_name in phase_names
            ],
        })
    return chunks


def _normalize_phase_chunk_plan(stored_chunks: Any, expected_phases: list[str], overview: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(stored_chunks, list):
        return _build_phase_chunks(expected_phases, overview)
    expected_set = set(expected_phases)
    normalized: list[dict[str, Any]] = []
    for index, chunk in enumerate(stored_chunks, start=1):
        if not isinstance(chunk, dict):
            continue
        phase_names = [phase_name for phase_name in _string_list(chunk.get("phase_names")) if phase_name in expected_set]
        if not phase_names:
            continue
        normalized.append({
            "id": chunk.get("id") if isinstance(chunk.get("id"), str) and chunk.get("id").strip() else f"chunk-{index}",
            "label": chunk.get("label") if isinstance(chunk.get("label"), str) and chunk.get("label").strip() else f"{phase_names[0]} to {phase_names[-1]}",
            "phase_names": phase_names,
            "phase_objectives": [
                objective for objective in chunk.get("phase_objectives", [])
                if isinstance(objective, dict) and objective.get("phase") in phase_names
            ],
        })
    return normalized or _build_phase_chunks(expected_phases, overview)


def _split_phase_chunk(chunk: dict[str, Any]) -> list[dict[str, Any]]:
    phase_names = [phase_name for phase_name in chunk.get("phase_names", []) if isinstance(phase_name, str) and phase_name]
    if len(phase_names) <= 1:
        return []
    midpoint = max(1, len(phase_names) // 2)
    partitions = [phase_names[:midpoint], phase_names[midpoint:]]
    objectives = {
        item.get("phase"): item
        for item in chunk.get("phase_objectives", [])
        if isinstance(item, dict) and item.get("phase")
    }
    split_chunks: list[dict[str, Any]] = []
    for index, group in enumerate(partitions, start=1):
        split_chunks.append({
            "id": f"{chunk.get('id', 'chunk')}-split-{index}",
            "label": f"{chunk.get('label', 'Phase chunk')} (Split {index})",
            "phase_names": group,
            "phase_objectives": [objectives[phase_name] for phase_name in group if phase_name in objectives],
        })
    return split_chunks


def _validate_phase_detail_payload(normalized: dict[str, Any], expected_phases: list[str]) -> list[str]:
    errors: list[str] = []
    normalized_phases = normalized.get("phases", [])
    actual_names = [phase.get("phase") for phase in normalized_phases]
    missing = [phase_name for phase_name in expected_phases if phase_name not in actual_names]
    if missing:
        errors.append(f"Missing required phases: {', '.join(missing)}.")

    sparse_descriptions = [
        phase.get("phase", "")
        for phase in normalized_phases
        if len(phase.get("description", "").strip()) < MIN_PHASE_DESCRIPTION_LENGTH
    ]
    if sparse_descriptions:
        errors.append(f"These phases need fuller operational descriptions: {', '.join(sparse_descriptions)}.")

    thin_support = [
        phase.get("phase", "")
        for phase in normalized_phases
        if not (
            phase.get("mapped_nodes")
            or phase.get("tools")
            or phase.get("iocs")
            or phase.get("log_sources")
            or phase.get("break_opportunities")
        )
    ]
    if thin_support:
        errors.append(f"These phases need tools, detections, IOCs, or mapped nodes: {', '.join(thin_support)}.")

    return errors


def _merge_phase_state(existing_phases: list[dict], incoming_phases: list[dict], expected_phases: list[str]) -> list[dict]:
    by_phase: dict[str, dict] = {}
    for phase in existing_phases:
        if isinstance(phase, dict) and phase.get("phase") in expected_phases:
            by_phase[phase["phase"]] = phase
    for phase in incoming_phases:
        if not isinstance(phase, dict) or phase.get("phase") not in expected_phases:
            continue
        if phase["phase"] in by_phase:
            by_phase[phase["phase"]] = _merge_phase_entries(by_phase[phase["phase"]], phase)
        else:
            by_phase[phase["phase"]] = phase
    return [by_phase[phase_name] for phase_name in expected_phases if phase_name in by_phase]


def _normalize_synthesis_payload(parsed: dict[str, Any], expected_phases: list[str], phases: list[dict]) -> dict[str, Any]:
    return {
        "campaign_summary": parsed.get("campaign_summary").strip() if isinstance(parsed.get("campaign_summary"), str) else "",
        "recommendations": _normalize_recommendations(parsed.get("recommendations"), expected_phases),
        "total_estimated_time": parsed.get("total_estimated_time").strip() if isinstance(parsed.get("total_estimated_time"), str) else "",
        "weakest_links": _string_list(parsed.get("weakest_links")),
        "overall_risk_rating": _normalize_choice(parsed.get("overall_risk_rating"), VALID_RISK_RATINGS, ""),
        "attack_complexity": _normalize_choice(parsed.get("attack_complexity"), VALID_ATTACK_COMPLEXITY, ""),
        "coverage_score": _coerce_coverage_score(parsed.get("coverage_score"), phases),
        "critical_path": parsed.get("critical_path").strip() if isinstance(parsed.get("critical_path"), str) else "",
    }


def _validate_synthesis_payload(normalized: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if len(normalized.get("campaign_summary", "")) < MIN_SUMMARY_LENGTH:
        errors.append("Campaign summary is missing or too short.")
    if len(normalized.get("recommendations", [])) < MIN_RECOMMENDATIONS:
        errors.append(f"At least {MIN_RECOMMENDATIONS} actionable recommendations are required.")
    return errors


def _build_fallback_synthesis(
    *,
    phases: list[dict],
    overview: dict[str, Any],
    objective: str,
) -> dict[str, Any]:
    gap_phases = [
        phase for phase in phases
        if phase.get("defensive_coverage") in {"none", "minimal"}
    ]
    hard_phases = [
        phase for phase in phases
        if phase.get("difficulty") in {"hard", "very_hard"}
    ]
    coverage_score = _coerce_coverage_score(None, phases)
    weakest_links = [
        f"{phase.get('phase')}: {phase.get('coverage_notes') or 'minimal defensive coverage compared with the rest of the chain.'}"
        for phase in gap_phases[:3]
    ]
    recommendations = []
    for phase in (gap_phases[:2] + hard_phases[:2]):
        phase_name = phase.get("phase", "the current phase")
        recommendations.append({
            "priority": "high" if phase.get("defensive_coverage") in {"none", "minimal"} else "medium",
            "title": f"Strengthen controls for {phase_name}",
            "description": (
                f"Use the phase-specific log sources, break opportunities, and detection gaps in {phase_name} to tighten "
                "controls, improve alerting, and reduce attacker freedom of action."
            ),
            "addresses_phases": [phase_name],
            "effort": "medium",
        })
    recommendations = recommendations[:3] or [{
        "priority": "medium",
        "title": "Review the generated phase sequence",
        "description": "Use the staged phase details to validate where controls are weakest and prioritize the most exposed trust boundaries first.",
        "addresses_phases": [phases[0].get("phase", "Reconnaissance")] if phases else [],
        "effort": "medium",
    }]

    return {
        "campaign_summary": (
            f"{overview.get('overview_summary') or 'Fallback campaign summary:'} "
            f"The campaign is oriented toward {objective or 'the project objective'} and spans {len(phases)} populated phases. "
            f"Analyst attention should center on {', '.join(link.split(':', 1)[0] for link in weakest_links) or 'the phases with the lowest defensive coverage'}."
        ),
        "recommendations": recommendations,
        "total_estimated_time": "5-14 days" if len(phases) >= 10 else "2-7 days",
        "overall_risk_rating": "critical" if len(gap_phases) >= 4 else "high" if len(gap_phases) >= 2 else "medium",
        "attack_complexity": "very_high" if len(hard_phases) >= 4 else "high" if len(hard_phases) >= 2 else "medium",
        "coverage_score": coverage_score,
        "weakest_links": weakest_links,
        "critical_path": overview.get("critical_path_hypothesis") or "Follow the least-resisted path across the populated phases toward the stated objective.",
    }


async def _persist_kill_chain_generation_state(
    kc: KillChain,
    db: AsyncSession,
    *,
    phases: list[dict],
    analysis_metadata: dict[str, Any],
    summary: str,
    recommendations: list[dict],
    total_estimated_time: str,
    weakest_links: list[str],
    overall_risk_rating: str,
    attack_complexity: str,
    coverage_score: float,
    critical_path: str,
) -> None:
    kc.phases = phases
    kc.analysis_metadata = analysis_metadata
    kc.ai_summary = summary
    kc.recommendations = recommendations
    kc.total_estimated_time = total_estimated_time
    kc.weakest_links = weakest_links
    kc.overall_risk_rating = overall_risk_rating
    kc.attack_complexity = attack_complexity
    kc.coverage_score = coverage_score
    kc.critical_path = critical_path
    await db.commit()
    await db.refresh(kc)


def _normalize_kill_chain_payload(parsed: dict, expected_phases: list[str], node_lookup: dict[str, Node]) -> dict:
    expected_by_key = {_phase_key(phase): phase for phase in expected_phases}
    ordered_phases: dict[str, dict] = {}

    for raw_phase in parsed.get("phases", []):
        if not isinstance(raw_phase, dict):
            continue
        phase_name = expected_by_key.get(_phase_key(raw_phase.get("phase", "")))
        if not phase_name:
            continue
        normalized_phase = _normalize_phase_entry(raw_phase, phase_name, expected_phases.index(phase_name) + 1, node_lookup)
        if phase_name in ordered_phases:
            ordered_phases[phase_name] = _merge_phase_entries(ordered_phases[phase_name], normalized_phase)
        else:
            ordered_phases[phase_name] = normalized_phase

    normalized_phases = [
        ordered_phases[phase_name]
        for phase_name in expected_phases
        if phase_name in ordered_phases
    ]
    return {
        "phases": normalized_phases,
        "campaign_summary": parsed.get("campaign_summary").strip() if isinstance(parsed.get("campaign_summary"), str) else "",
        "recommendations": _normalize_recommendations(parsed.get("recommendations"), expected_phases),
        "total_estimated_time": parsed.get("total_estimated_time").strip() if isinstance(parsed.get("total_estimated_time"), str) else "",
        "weakest_links": _string_list(parsed.get("weakest_links")),
        "overall_risk_rating": _normalize_choice(parsed.get("overall_risk_rating"), VALID_RISK_RATINGS, ""),
        "attack_complexity": _normalize_choice(parsed.get("attack_complexity"), VALID_ATTACK_COMPLEXITY, ""),
        "coverage_score": _coerce_coverage_score(parsed.get("coverage_score"), normalized_phases),
        "critical_path": parsed.get("critical_path").strip() if isinstance(parsed.get("critical_path"), str) else "",
    }


def _validate_kill_chain_payload(normalized: dict, expected_phases: list[str]) -> list[str]:
    errors: list[str] = []
    normalized_phases = normalized.get("phases", [])
    actual_names = [phase.get("phase") for phase in normalized_phases]
    missing = [phase_name for phase_name in expected_phases if phase_name not in actual_names]
    if missing:
        errors.append(f"Missing required phases: {', '.join(missing)}.")

    sparse_descriptions = [
        phase.get("phase", "")
        for phase in normalized_phases
        if len(phase.get("description", "").strip()) < MIN_PHASE_DESCRIPTION_LENGTH
    ]
    if sparse_descriptions:
        errors.append(f"These phases need fuller operational descriptions: {', '.join(sparse_descriptions)}.")

    if len(normalized.get("campaign_summary", "")) < MIN_SUMMARY_LENGTH:
        errors.append("Campaign summary is missing or too short.")

    if len(normalized.get("recommendations", [])) < MIN_RECOMMENDATIONS:
        errors.append(f"At least {MIN_RECOMMENDATIONS} actionable recommendations are required.")

    return errors


def _clear_ai_analysis(kc: KillChain) -> None:
    kc.ai_summary = ""
    kc.phases = []
    kc.recommendations = []
    kc.total_estimated_time = ""
    kc.weakest_links = []
    kc.overall_risk_rating = ""
    kc.attack_complexity = ""
    kc.coverage_score = None
    kc.critical_path = ""
    kc.analysis_metadata = {}


def _build_overview_messages(
    *,
    project_name: str,
    objective: str,
    project_description: str,
    framework: str,
    expected_phases: list[str],
    planning_label: str,
    planning_domain: str,
    planning_guidance: str,
    operator_guidance: str,
    nodes_text: str,
) -> list[dict[str, str]]:
    prompt = f"""You are planning a multi-stage adversary campaign and must first produce the campaign blueprint before writing detailed phase notes.

**Campaign Context**
- Target / Project: {project_name}
- Root Objective: {objective or 'Not specified'}
- Project Description: {project_description[:400]}
- Kill Chain Framework: {framework}
- Required Phases: {_compact_json(expected_phases)}
- Planning Profile: {planning_label}
- Detected Planning Domain: {planning_domain}
{f"- Operator Guidance: {operator_guidance}" if operator_guidance else ""}

{planning_guidance}

**Attack Tree Nodes**
{nodes_text}

Return JSON only with:
{{
  "overview_summary": "4-6 sentences summarizing the overall campaign shape, likely operator intent, and major trust-boundary progression.",
  "campaign_concept": "1-2 sentences describing the campaign concept.",
  "threat_actor_profile": "1-2 sentences describing the operator capability and style.",
  "initial_compromise_hypothesis": "1-2 sentences describing the most plausible foothold path.",
  "priority_surfaces": ["3-6 specific surfaces, systems, or trust boundaries the campaign relies on"],
  "defensive_posture": "1-2 sentences describing where defender visibility looks strong or weak.",
  "control_pressures": ["3-5 concise statements about where defenders can impose cost on the campaign"],
  "critical_path_hypothesis": "The most plausible path from foothold to objective.",
  "phase_objectives": [
    {{"phase": "Exact framework phase", "objective": "1-2 sentences describing the attacker objective, target surface, and intended outcome for that phase"}}
  ]
}}

Rules:
1. Include every required phase exactly once in phase_objectives.
2. Keep the blueprint planning-focused; do not dump full phase detail yet.
3. Make the outputs concrete, environment-aware, and operationally credible."""
    return [
        {"role": "system", "content": "You are a senior red team lead. Produce concise but concrete campaign blueprints in strict JSON."},
        {"role": "user", "content": prompt},
    ]


def _build_phase_chunk_messages(
    *,
    project_name: str,
    objective: str,
    project_description: str,
    framework: str,
    planning_label: str,
    planning_domain: str,
    planning_guidance: str,
    operator_guidance: str,
    overview: dict[str, Any],
    chunk: dict[str, Any],
    nodes_text: str,
) -> list[dict[str, str]]:
    prompt = f"""You are writing the detailed kill-chain entry for a single campaign phase.

**Campaign Context**
- Target / Project: {project_name}
- Root Objective: {objective or 'Not specified'}
- Project Description: {project_description[:400]}
- Kill Chain Framework: {framework}
- Planning Profile: {planning_label}
- Detected Planning Domain: {planning_domain}
{f"- Operator Guidance: {operator_guidance}" if operator_guidance else ""}

{planning_guidance}

**Campaign Blueprint**
{_compact_json({
    "overview_summary": overview.get("overview_summary"),
    "campaign_concept": overview.get("campaign_concept"),
    "threat_actor_profile": overview.get("threat_actor_profile"),
    "initial_compromise_hypothesis": overview.get("initial_compromise_hypothesis"),
    "priority_surfaces": overview.get("priority_surfaces", []),
    "critical_path_hypothesis": overview.get("critical_path_hypothesis"),
    "phase_objectives": chunk.get("phase_objectives", []),
})}

**Attack Tree Nodes**
{nodes_text}

Return JSON only with:
{{
  "phases": [
    {{
      "phase": "Exact phase name",
      "phase_index": 1,
      "description": "4-6 sentences with concrete operator behavior, targets, tools, trust-boundary progression, and attacker intent.",
      "mapped_nodes": [
        {{
          "node_id": "exact node id when there is a confident mapping",
          "node_title": "node title",
          "technique_id": "valid ATT&CK technique ID when high confidence, else empty string",
          "technique_name": "technique name when technique_id is present, else empty string",
          "confidence": 0.85
        }}
      ],
      "tools": ["Specific real tools used in this phase"],
      "iocs": ["Operationally useful IOC statements"],
      "log_sources": ["Specific logs or telemetry sources"],
      "detection_window": "Realistic detection window",
      "dwell_time": "Realistic dwell time",
      "break_opportunities": ["Concrete analyst or defender intervention opportunities"],
      "difficulty": "trivial|easy|moderate|hard|very_hard",
      "defensive_coverage": "none|minimal|partial|good|strong",
      "coverage_notes": "Brief assessment of current defensive coverage for this phase"
    }}
  ]
}}

Rules:
1. Include exactly these phases and no others: {_compact_json(chunk.get("phase_names", []))}
2. Phase names must exactly match the requested phase names.
3. Use only valid node_id values from the supplied attack tree. If you are not confident, leave mapped_nodes empty.
4. Prefer depth over breadth because this phase is being generated independently.
5. Use practitioner language, not generic framework definitions."""
    return [
        {"role": "system", "content": "You are a senior red team lead. Produce detailed, technical phase notes in strict JSON."},
        {"role": "user", "content": prompt},
    ]


def _build_synthesis_messages(
    *,
    project_name: str,
    objective: str,
    framework: str,
    planning_label: str,
    planning_domain: str,
    operator_guidance: str,
    overview: dict[str, Any],
    phases: list[dict],
) -> list[dict[str, str]]:
    prompt = f"""You are writing the final campaign intelligence summary after the individual kill-chain phases have already been generated.

**Campaign Context**
- Target / Project: {project_name}
- Root Objective: {objective or 'Not specified'}
- Kill Chain Framework: {framework}
- Planning Profile: {planning_label}
- Detected Planning Domain: {planning_domain}
{f"- Operator Guidance: {operator_guidance}" if operator_guidance else ""}

**Campaign Blueprint**
{_compact_json(overview)}

**Detailed Phase Notes**
{_compact_json(phases)}

Return JSON only with:
{{
  "campaign_summary": "4-6 paragraphs summarizing the campaign, likely operator behavior, initial access path, post-compromise progression, defensive landscape, and likely impact.",
  "total_estimated_time": "Realistic full-campaign estimate",
  "overall_risk_rating": "critical|high|medium|low",
  "attack_complexity": "low|medium|high|very_high",
  "coverage_score": 0.45,
  "weakest_links": ["3-5 specific defensive weaknesses exposed by the phase details"],
  "critical_path": "Single most plausible path from foothold to objective",
  "recommendations": [
    {{
      "priority": "critical|high|medium|low",
      "title": "Specific recommendation title",
      "description": "2-3 sentences explaining what to implement and how it disrupts the campaign",
      "addresses_phases": ["Exact phase names"],
      "effort": "low|medium|high"
    }}
  ]
}}

Rules:
1. Use the provided phase notes as ground truth; do not invent phases that are not present.
2. Recommendations must be specific and tied back to the listed phases.
3. coverage_score must be between 0.0 and 1.0.
4. weakest_links must read like analyst findings, not slogans."""
    return [
        {"role": "system", "content": "You are a senior red team lead. Synthesize completed phase notes into campaign-level intelligence in strict JSON."},
        {"role": "user", "content": prompt},
    ]


async def _generate_phase_chunk(
    config: dict[str, Any],
    *,
    project_name: str,
    objective: str,
    project_description: str,
    framework: str,
    planning_label: str,
    planning_domain: str,
    planning_guidance: str,
    operator_guidance: str,
    overview: dict[str, Any],
    chunk: dict[str, Any],
    nodes_text: str,
    node_lookup: dict[str, Node],
    warnings: list[str],
) -> tuple[list[dict], bool]:
    messages = _build_phase_chunk_messages(
        project_name=project_name,
        objective=objective,
        project_description=project_description,
        framework=framework,
        planning_label=planning_label,
        planning_domain=planning_domain,
        planning_guidance=planning_guidance,
        operator_guidance=operator_guidance,
        overview=overview,
        chunk=chunk,
        nodes_text=nodes_text,
    )
    parsed, error_message = await _request_json_object_with_retries(
        config,
        messages,
        temperature=0.35,
        max_tokens=4096,
        timeout_override=120,
        required_keys=("phases",),
    )
    normalized = _normalize_kill_chain_payload(parsed, chunk.get("phase_names", []), node_lookup)
    validation_errors = _validate_phase_detail_payload(normalized, chunk.get("phase_names", []))
    if not validation_errors and normalized.get("phases"):
        return normalized["phases"], True

    split_chunks = _split_phase_chunk(chunk)
    if split_chunks:
        warnings.append(
            f"Phase chunk '{chunk.get('label', 'Phase chunk')}' was retried as smaller segments after a malformed or thin response."
        )
        split_results: list[dict] = []
        all_complete = True
        for split_chunk in split_chunks:
            child_results, child_complete = await _generate_phase_chunk(
                config,
                project_name=project_name,
                objective=objective,
                project_description=project_description,
                framework=framework,
                planning_label=planning_label,
                planning_domain=planning_domain,
                planning_guidance=planning_guidance,
                operator_guidance=operator_guidance,
                overview=overview,
                chunk=split_chunk,
                nodes_text=nodes_text,
                node_lookup=node_lookup,
                warnings=warnings,
            )
            split_results.extend(child_results)
            all_complete = all_complete and child_complete
        return split_results, all_complete

    warnings.append(
        f"Unable to generate detail for phase '{chunk.get('label', 'Phase chunk')}': "
        f"{'; '.join(validation_errors) if validation_errors else (error_message or 'empty response')}"
    )
    return [], False


def _kill_chain_planning_context(planning_profile: str, objective: str, scope: str, context_preset: str = "") -> tuple[str, str, str, str]:
    normalized_profile = llm_service.normalize_planning_profile(planning_profile)
    domain = llm_service.detect_planning_domain(objective, scope, context_preset)
    profile_label = llm_service.get_planning_profile_label(normalized_profile)
    guidance = "\n".join(
        section for section in [
            llm_service.get_domain_decomposition_guidance(domain),
            llm_service.get_planning_profile_guidance(normalized_profile, domain),
            build_environment_catalog_outline_for_context(objective, scope, context_preset),
            (
                "Kill-chain planning workflow:\n"
                "- First derive the campaign concept, likely footholds, decisive trust-boundary crossings, and phase objectives.\n"
                "- Then describe attacker activity per phase and attach ATT&CK mappings only where they materially clarify the activity.\n"
                "- Leave technique_id blank rather than forcing a weak or speculative ATT&CK mapping."
            ),
        ] if section
    )
    return normalized_profile, profile_label, domain, guidance


# --- Endpoints ---

@router.get("/project/{project_id}")
async def list_kill_chains(project_id: str, db: AsyncSession = Depends(get_db)):
    await require_project_access(project_id, db)
    result = await db.execute(
        select(KillChain).where(KillChain.project_id == project_id).order_by(KillChain.created_at.desc())
    )
    return [_to_dict(kc) for kc in result.scalars().all()]


@router.post("", status_code=201)
async def create_kill_chain(data: KillChainCreate, db: AsyncSession = Depends(get_db)):
    await require_project_access(data.project_id, db)
    kc = KillChain(**data.model_dump())
    db.add(kc)
    await db.commit()
    await db.refresh(kc)
    return _to_dict(kc)


@router.get("/{kc_id}")
async def get_kill_chain(kc_id: str, db: AsyncSession = Depends(get_db)):
    kc = await _get_or_404(kc_id, db)
    return _to_dict(kc)


@router.patch("/{kc_id}")
async def update_kill_chain(kc_id: str, data: KillChainUpdate, db: AsyncSession = Depends(get_db)):
    kc = await _get_or_404(kc_id, db)
    updates = data.model_dump(exclude_unset=True)
    if "framework" in updates or "phases" in updates:
        manual_phases = updates.get("phases", kc.phases)
        framework = updates.get("framework", kc.framework)
        _clear_ai_analysis(kc)
        kc.framework = framework
        kc.phases = manual_phases
        updates.pop("framework", None)
        updates.pop("phases", None)
    for key, value in updates.items():
        setattr(kc, key, value)
    await db.commit()
    await db.refresh(kc)
    return _to_dict(kc)


@router.delete("/{kc_id}", status_code=204)
async def delete_kill_chain(kc_id: str, db: AsyncSession = Depends(get_db)):
    kc = await _get_or_404(kc_id, db)
    await db.delete(kc)
    await db.commit()


@router.post("/{kc_id}/ai-map")
async def ai_map_to_kill_chain(kc_id: str, data: AIMapRequest, db: AsyncSession = Depends(get_db)):
    """AI maps attack tree nodes to kill chain phases with rich operational detail."""
    kc = await _get_or_404(kc_id, db)
    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    project = await require_project_access(kc.project_id, db)

    nodes_result = await db.execute(
        select(Node).where(Node.project_id == kc.project_id)
        .options(selectinload(Node.mitigations), selectinload(Node.detections))
    )
    nodes = nodes_result.scalars().all()

    # Build rich node descriptions with mitigations/detections context
    if nodes:
        node_lines = []
        for n in nodes[:80]:
            mit_names = ", ".join(m.title for m in (n.mitigations or [])[:5]) or "none"
            det_names = ", ".join(d.title for d in (n.detections or [])[:5]) or "none"
            node_lines.append(
                f"  - id=\"{n.id}\" type={n.node_type} title=\"{n.title}\"\n"
                f"    description: {(n.description or '')[:200]}\n"
                f"    threat_category=\"{n.threat_category}\" attack_surface=\"{n.attack_surface}\" "
                f"platform=\"{n.platform or ''}\" required_access=\"{n.required_access or ''}\"\n"
                f"    inherent_risk={n.inherent_risk or '?'} residual_risk={n.residual_risk or '?'} "
                f"likelihood={n.likelihood or '?'} impact={n.impact or '?'}\n"
                f"    mitigations=[{mit_names}] detections=[{det_names}]"
            )
        nodes_text = "\n".join(node_lines)
    else:
        nodes_text = "(No attack tree nodes exist yet)"

    phases = _framework_phases(kc.framework)
    _, planning_label, planning_domain, planning_guidance = _kill_chain_planning_context(
        data.planning_profile,
        project.root_objective or project.name,
        "\n".join(part for part in [project.description or "", nodes_text, data.user_guidance] if part),
        getattr(project, "context_preset", ""),
    )
    config = _provider_to_config(provider)
    node_lookup = {n.id: n for n in nodes} if nodes else {}

    request_signature = _kill_chain_request_signature(
        project_name=project.name if project else "Unknown",
        objective=project.root_objective or project.name,
        description=project.description or "",
        framework=kc.framework,
        user_guidance=data.user_guidance,
        planning_profile=data.planning_profile,
        context_preset=getattr(project, "context_preset", ""),
        nodes=nodes,
    )
    existing_metadata = kc.analysis_metadata if isinstance(kc.analysis_metadata, dict) else {}
    stored_chunk_plan = existing_metadata.get("phase_chunk_plan") if isinstance(existing_metadata.get("phase_chunk_plan"), list) else []
    resume_existing = (
        not data.refresh
        and existing_metadata.get("generation_status") in {"running", "partial"}
        and existing_metadata.get("request_signature") == request_signature
    )

    warnings: list[str] = [
        warning for warning in existing_metadata.get("generation_warnings", [])
        if isinstance(warning, str) and warning != "Resumed kill-chain generation from previously persisted partial results."
    ] if resume_existing else []
    overview = existing_metadata.get("overview") if resume_existing and isinstance(existing_metadata.get("overview"), dict) else {}
    phase_chunks = _normalize_phase_chunk_plan(stored_chunk_plan, phases, overview) if resume_existing else []
    completed_chunk_ids = {
        chunk_id
        for chunk_id in existing_metadata.get("completed_chunk_ids", [])
        if isinstance(chunk_id, str) and chunk_id
    } if resume_existing else set()
    synthesis_completed = existing_metadata.get("synthesis_status") == "completed" if resume_existing else False
    phases_state = _merge_phase_state([
        phase for phase in (kc.phases or [])
        if isinstance(phase, dict)
    ], [], phases) if resume_existing else []
    summary_state = kc.ai_summary or ""
    recommendations_state = kc.recommendations or []
    total_estimated_time_state = kc.total_estimated_time or ""
    weakest_links_state = kc.weakest_links or []
    overall_risk_rating_state = kc.overall_risk_rating or ""
    attack_complexity_state = kc.attack_complexity or ""
    coverage_score_state = kc.coverage_score if kc.coverage_score is not None else 0.0
    critical_path_state = kc.critical_path or ""

    async def _save_progress(status: str, current_stage: str) -> None:
        pending_chunk_ids = [
            chunk.get("id", "")
            for chunk in phase_chunks
            if isinstance(chunk, dict) and chunk.get("id") not in completed_chunk_ids
        ]
        metadata = {
            "generation_warnings": warnings,
            "generation_strategy": "staged",
            "generation_status": status,
            "current_stage": current_stage,
            "request_signature": request_signature,
            "phase_count": len(phases),
            "chunk_count": len(phase_chunks),
            "completed_chunk_ids": sorted(completed_chunk_ids),
            "pending_chunk_ids": pending_chunk_ids,
            "pending_chunk_count": len(pending_chunk_ids),
            "synthesis_status": "completed" if synthesis_completed else ("pending" if not pending_chunk_ids else "blocked"),
            "overview": overview,
            "phase_chunk_plan": phase_chunks,
        }
        await _persist_kill_chain_generation_state(
            kc,
            db,
            phases=phases_state,
            analysis_metadata=metadata,
            summary=summary_state,
            recommendations=recommendations_state,
            total_estimated_time=total_estimated_time_state,
            weakest_links=weakest_links_state,
            overall_risk_rating=overall_risk_rating_state,
            attack_complexity=attack_complexity_state,
            coverage_score=coverage_score_state,
            critical_path=critical_path_state,
        )

    if not resume_existing:
        _clear_ai_analysis(kc)
        await db.commit()
        await db.refresh(kc)
        await _save_progress("running", "overview")

        overview_messages = _build_overview_messages(
            project_name=project.name if project else "Unknown",
            objective=project.root_objective or project.name,
            project_description=project.description or "",
            framework=kc.framework,
            expected_phases=phases,
            planning_label=planning_label,
            planning_domain=planning_domain,
            planning_guidance=planning_guidance,
            operator_guidance=data.user_guidance,
            nodes_text=nodes_text,
        )
        overview_parsed, overview_error = await _request_json_object_with_retries(
            config,
            overview_messages,
            temperature=0.35,
            max_tokens=4096,
            timeout_override=90,
            required_keys=("phase_objectives",),
        )
        if overview_parsed:
            overview = _normalize_overview_payload(overview_parsed, phases)
        if not overview or not overview.get("overview_summary"):
            warnings.append(
                f"Kill-chain overview planning fell back to a deterministic blueprint: {overview_error or 'overview data was incomplete'}"
            )
            overview = _build_fallback_overview(
                project_name=project.name if project else "Unknown",
                objective=project.root_objective or project.name,
                framework=kc.framework,
                expected_phases=phases,
                nodes=nodes,
            )
        summary_state = overview.get("overview_summary", "")
        critical_path_state = overview.get("critical_path_hypothesis", "")
        phase_chunks = _build_phase_chunks(phases, overview)
        await _save_progress("running", "phase_chunks")
    else:
        if (
            existing_metadata.get("generation_status") in {"running", "partial"}
            and (
                existing_metadata.get("pending_chunk_ids")
                or existing_metadata.get("synthesis_status") != "completed"
            )
        ):
            warnings.append("Resumed kill-chain generation from previously persisted partial results.")
        if not overview:
            overview = _build_fallback_overview(
                project_name=project.name if project else "Unknown",
                objective=project.root_objective or project.name,
                framework=kc.framework,
                expected_phases=phases,
                nodes=nodes,
            )
        if not phase_chunks:
            phase_chunks = _build_phase_chunks(phases, overview)
        if not summary_state:
            summary_state = overview.get("overview_summary", "")
        if not critical_path_state:
            critical_path_state = overview.get("critical_path_hypothesis", "")

    for chunk in phase_chunks:
        chunk_id = chunk.get("id")
        if not isinstance(chunk_id, str) or chunk_id in completed_chunk_ids:
            continue
        chunk_results, chunk_complete = await _generate_phase_chunk(
            config,
            project_name=project.name if project else "Unknown",
            objective=project.root_objective or project.name,
            project_description=project.description or "",
            framework=kc.framework,
            planning_label=planning_label,
            planning_domain=planning_domain,
            planning_guidance=planning_guidance,
            operator_guidance=data.user_guidance,
            overview=overview,
            chunk=chunk,
            nodes_text=nodes_text,
            node_lookup=node_lookup,
            warnings=warnings,
        )
        if chunk_results:
            phases_state = _merge_phase_state(phases_state, chunk_results, phases)
        if chunk_complete:
            completed_chunk_ids.add(chunk_id)
        await _save_progress("running", "phase_chunks")

    pending_chunk_ids = [
        chunk.get("id", "")
        for chunk in phase_chunks
        if isinstance(chunk, dict) and chunk.get("id") not in completed_chunk_ids
    ]
    if pending_chunk_ids:
        await _save_progress("partial", "phase_chunks")
        if not phases_state:
            raise HTTPException(502, "Kill-chain generation did not produce any phase details. Resume is available on the existing kill chain.")
        return _to_dict(kc)

    synthesis_messages = _build_synthesis_messages(
        project_name=project.name if project else "Unknown",
        objective=project.root_objective or project.name,
        framework=kc.framework,
        planning_label=planning_label,
        planning_domain=planning_domain,
        operator_guidance=data.user_guidance,
        overview=overview,
        phases=phases_state,
    )
    synthesis_parsed, synthesis_error = await _request_json_object_with_retries(
        config,
        synthesis_messages,
        temperature=0.3,
        max_tokens=6144,
        timeout_override=120,
        required_keys=("campaign_summary", "recommendations"),
    )
    synthesis = _normalize_synthesis_payload(synthesis_parsed, phases, phases_state)
    synthesis_errors = _validate_synthesis_payload(synthesis)
    if synthesis_errors:
        warnings.append(
            f"Kill-chain synthesis used a deterministic fallback: {'; '.join(synthesis_errors) or synthesis_error or 'structured summary was not returned'}"
        )
        synthesis = _build_fallback_synthesis(
            phases=phases_state,
            overview=overview,
            objective=project.root_objective or project.name,
        )

    summary_state = synthesis["campaign_summary"]
    recommendations_state = synthesis["recommendations"]
    total_estimated_time_state = synthesis["total_estimated_time"]
    weakest_links_state = synthesis["weakest_links"]
    overall_risk_rating_state = synthesis["overall_risk_rating"]
    attack_complexity_state = synthesis["attack_complexity"]
    coverage_score_state = synthesis["coverage_score"]
    critical_path_state = synthesis["critical_path"] or critical_path_state
    synthesis_completed = True

    await _save_progress("completed", "synthesis")
    return _to_dict(kc)


@router.post("/project/{project_id}/ai-generate")
async def ai_generate_kill_chain(project_id: str, data: AIGenerateKillChainRequest = AIGenerateKillChainRequest(), db: AsyncSession = Depends(get_db)):
    """AI auto-generates a complete kill chain from the attack tree."""
    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    project = await require_project_access(project_id, db)

    kc = KillChain(
        project_id=project_id,
        name=f"Kill Chain — {project.name}",
        description="AI-generated kill chain analysis",
        framework=data.framework,
    )
    db.add(kc)
    await db.commit()
    await db.refresh(kc)
    try:
        return await ai_map_to_kill_chain(
            kc.id,
            AIMapRequest(user_guidance=data.user_guidance, planning_profile=data.planning_profile, refresh=data.refresh),
            db,
        )
    except HTTPException:
        await db.delete(kc)
        await db.commit()
        raise


# --- Helpers ---

async def _get_or_404(kc_id: str, db: AsyncSession) -> KillChain:
    return await require_kill_chain_access(kc_id, db)


def _provider_to_config(provider) -> dict:
    return {
        "base_url": provider.base_url,
        "api_key_encrypted": provider.api_key_encrypted,
        "model": provider.model,
        "custom_headers": provider.custom_headers or {},
        "timeout": provider.timeout,
        "tls_verify": provider.tls_verify,
        "ca_bundle_path": provider.ca_bundle_path,
        "client_cert_path": provider.client_cert_path,
        "client_key_path": provider.client_key_path,
    }


def _to_dict(kc: KillChain) -> dict:
    return {
        "id": kc.id,
        "project_id": kc.project_id,
        "name": kc.name,
        "description": kc.description,
        "framework": kc.framework,
        "phases": kc.phases or [],
        "ai_summary": kc.ai_summary or "",
        "recommendations": kc.recommendations or [],
        "total_estimated_time": kc.total_estimated_time or "",
        "weakest_links": kc.weakest_links or [],
        "overall_risk_rating": kc.overall_risk_rating or "",
        "attack_complexity": kc.attack_complexity or "",
        "coverage_score": kc.coverage_score if kc.coverage_score is not None else 0,
        "critical_path": kc.critical_path or "",
        "analysis_metadata": kc.analysis_metadata or {},
        "created_at": kc.created_at.isoformat() if kc.created_at else "",
        "updated_at": kc.updated_at.isoformat() if kc.updated_at else "",
    }
