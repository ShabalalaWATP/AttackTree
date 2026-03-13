"""
Threat Modeling API - STRIDE/PASTA workspace with AI-powered analysis.
"""
import copy
import hashlib
import json
import re
import uuid
from time import perf_counter
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..database import get_db
from ..models.threat_model import ThreatModel
from ..models.node import Node
from ..services.access_control import (
    get_active_provider_for_user,
    require_project_access,
    require_threat_model_access,
)
from ..services import llm_service
from ..services.analysis_runs import record_analysis_run
from ..services.environment_catalog_service import build_environment_catalog_outline_for_context
from ..services.reference_search_service import (
    dedupe_reference_links,
    format_reference_candidates_for_prompt,
    search_references,
)
from ..services.risk_engine import compute_inherent_risk

router = APIRouter(prefix="/threat-models", tags=["threat_models"])

THREAT_CHUNK_COMPONENT_LIMIT = 4
THREAT_REQUEST_RETRIES = 2
DFD_MAX_ZONE_COUNT = 6

SUPPORTED_THREAT_METHODOLOGIES = ("stride", "pasta", "linddun")

THREAT_CATEGORY_OPTIONS: dict[str, tuple[str, ...]] = {
    "stride": (
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege",
    ),
    "linddun": (
        "Linkability",
        "Identifiability",
        "Non-repudiation",
        "Detectability",
        "Disclosure",
        "Unawareness",
        "Non-compliance",
    ),
}

THREAT_STAGE_OPTIONS: dict[str, tuple[str, ...]] = {
    "pasta": (
        "Attack Simulation",
        "Vulnerability Analysis",
        "Risk Analysis",
        "Exploitation",
        "Impact",
    ),
}

THREAT_CATEGORY_ALIASES: dict[str, dict[str, str]] = {
    "stride": {
        "spoof": "Spoofing",
        "spoofing": "Spoofing",
        "tamper": "Tampering",
        "tampering": "Tampering",
        "repudiation": "Repudiation",
        "information disclosure": "Information Disclosure",
        "information leak": "Information Disclosure",
        "information leakage": "Information Disclosure",
        "disclosure of information": "Information Disclosure",
        "info disclosure": "Information Disclosure",
        "denial of service": "Denial of Service",
        "denial service": "Denial of Service",
        "dos": "Denial of Service",
        "elevation of privilege": "Elevation of Privilege",
        "privilege escalation": "Elevation of Privilege",
        "elevation": "Elevation of Privilege",
        "eop": "Elevation of Privilege",
    },
    "pasta": {
    },
    "linddun": {
        "linkability": "Linkability",
        "identifiability": "Identifiability",
        "non repudiation": "Non-repudiation",
        "nonrepudiation": "Non-repudiation",
        "detectability": "Detectability",
        "disclosure": "Disclosure",
        "unawareness": "Unawareness",
        "non compliance": "Non-compliance",
        "noncompliance": "Non-compliance",
    },
}

THREAT_STAGE_ALIASES: dict[str, dict[str, str]] = {
    "pasta": {
        "attack simulation": "Attack Simulation",
        "simulation": "Attack Simulation",
        "vulnerability analysis": "Vulnerability Analysis",
        "vulnerability": "Vulnerability Analysis",
        "risk analysis": "Risk Analysis",
        "risk": "Risk Analysis",
        "exploitation": "Exploitation",
        "impact": "Impact",
    },
}


# --- Schemas ---

class ThreatModelCreate(BaseModel):
    project_id: str
    name: str
    description: str = ""
    methodology: str = "stride"
    scope: str = ""


class ThreatModelUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    methodology: Optional[str] = None
    scope: Optional[str] = None
    components: Optional[list] = None
    data_flows: Optional[list] = None
    trust_boundaries: Optional[list] = None
    threats: Optional[list] = None


class AIGenerateDFDRequest(BaseModel):
    system_description: str
    user_guidance: str = ""
    methodology: str = "stride"
    name: str = ""
    planning_profile: str = "balanced"
    refresh: bool = False


class AIGenerateThreatsRequest(BaseModel):
    user_guidance: str = ""
    planning_profile: str = "balanced"
    refresh: bool = False


class AIDeepDiveRequest(BaseModel):
    threat_id: str
    refresh: bool = False


class AILinkToTreeRequest(BaseModel):
    threat_ids: list[str] = []  # empty = all threats


def _compact_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_methodology(value: Any) -> str:
    normalized = _normalize_text(value).lower()
    return normalized if normalized in SUPPORTED_THREAT_METHODOLOGIES else "stride"


def _category_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", _normalize_text(value).lower()).strip()


def _canonical_category_options(methodology: str) -> tuple[str, ...]:
    return THREAT_CATEGORY_OPTIONS.get(_normalize_methodology(methodology), ())


def _canonical_stage_options(methodology: str) -> tuple[str, ...]:
    return THREAT_STAGE_OPTIONS.get(_normalize_methodology(methodology), ())


def _canonicalize_threat_category(methodology: str, value: Any) -> str | None:
    normalized_key = _category_key(value)
    if not normalized_key:
        return None
    canonical_options = _canonical_category_options(methodology)
    canonical_lookup = {
        _category_key(option): option
        for option in canonical_options
    }
    if normalized_key in canonical_lookup:
        return canonical_lookup[normalized_key]
    return THREAT_CATEGORY_ALIASES.get(_normalize_methodology(methodology), {}).get(normalized_key)


def _canonicalize_threat_stage(methodology: str, value: Any) -> str | None:
    normalized_key = _category_key(value)
    if not normalized_key:
        return None
    canonical_options = _canonical_stage_options(methodology)
    canonical_lookup = {
        _category_key(option): option
        for option in canonical_options
    }
    if normalized_key in canonical_lookup:
        return canonical_lookup[normalized_key]
    return THREAT_STAGE_ALIASES.get(_normalize_methodology(methodology), {}).get(normalized_key)


def _coerce_score(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return max(1, min(100, int(round(value))))
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return max(1, min(100, int(stripped)))
    return None


def _flow_target_label(flow: dict[str, Any], component_lookup: dict[str, dict[str, Any]]) -> str:
    source = component_lookup.get(str(flow.get("source") or ""), {})
    target = component_lookup.get(str(flow.get("target") or ""), {})
    source_name = str(source.get("name") or flow.get("source") or "Unknown source")
    target_name = str(target.get("name") or flow.get("target") or "Unknown target")
    label = str(flow.get("label") or "").strip()
    if label:
        return f"{label} ({source_name} -> {target_name})"
    return f"{source_name} -> {target_name}"


def _resolve_target_details(
    target_id: str,
    components: list[dict[str, Any]] | None,
    data_flows: list[dict[str, Any]] | None,
) -> tuple[str, str]:
    normalized_target = str(target_id or "").strip()
    if not normalized_target:
        return "", ""
    component_lookup = {
        str(component.get("id") or ""): component
        for component in (components or [])
        if isinstance(component, dict)
    }
    if normalized_target in component_lookup:
        component = component_lookup[normalized_target]
        return str(component.get("name") or normalized_target), "component"

    flow_lookup = {
        str(flow.get("id") or ""): flow
        for flow in (data_flows or [])
        if isinstance(flow, dict)
    }
    if normalized_target in flow_lookup:
        return _flow_target_label(flow_lookup[normalized_target], component_lookup), "data_flow"
    return normalized_target, ""


def _severity_rank(value: Any) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }.get(_normalize_text(value).lower(), 0)


def _has_required_content(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(_normalize_text(value))
    if isinstance(value, (list, tuple, set)):
        return any(_has_required_content(item) for item in value)
    if isinstance(value, dict):
        return any(_has_required_content(item) for item in value.values())
    return True


def _has_required_keys(parsed: dict[str, Any], required_keys: tuple[str, ...]) -> bool:
    return all(_has_required_content(parsed.get(key)) for key in required_keys)


def _threat_signature(threat: dict[str, Any]) -> str:
    normalized_title = re.sub(r"[^a-z0-9]+", " ", _normalize_text(threat.get("title")).lower()).strip()
    return "|".join([
        _normalize_text(threat.get("component_id")).lower(),
        _normalize_text(threat.get("pasta_stage")).lower(),
        _normalize_text(threat.get("category")).lower(),
        normalized_title,
    ])


def _threat_quality_score(threat: dict[str, Any]) -> tuple[int, int, int, int]:
    detail_fields = (
        "attack_vector",
        "prerequisites",
        "mitigation",
        "real_world_examples",
        "mitre_technique",
        "entry_surface",
        "trust_boundary",
        "business_impact",
        "detection_notes",
        "references",
    )
    populated_details = sum(1 for key in detail_fields if _normalize_text(threat.get(key)))
    risk_score = _coerce_score(threat.get("risk_score")) or 0
    description_length = len(_normalize_text(threat.get("description")))
    return populated_details, risk_score, _severity_rank(threat.get("severity")), description_length


def _normalize_generated_threats(
    threats: list[Any],
    components: list[dict[str, Any]] | None,
    data_flows: list[dict[str, Any]] | None,
    methodology: str = "stride",
    seen_ids: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    normalized: list[dict[str, Any]] = []
    invalid_classifications: list[str] = []
    normalized_methodology = _normalize_methodology(methodology)
    if seen_ids is None:
        seen_ids = set()
    for item in threats:
        if not isinstance(item, dict):
            continue
        threat = dict(item)
        threat_id = _normalize_text(threat.get("id"))
        if not threat_id or threat_id in seen_ids:
            threat_id = f"threat-{uuid.uuid4()}"
        threat["id"] = threat_id
        seen_ids.add(threat_id)
        component_id = str(threat.get("component_id") or "").strip()
        component_name, target_type = _resolve_target_details(component_id, components, data_flows)
        if component_name and not str(threat.get("component_name") or "").strip():
            threat["component_name"] = component_name
        if target_type and not str(threat.get("target_type") or "").strip():
            threat["target_type"] = target_type
        if normalized_methodology == "pasta":
            raw_category = _normalize_text(threat.get("category"))
            raw_stage = (
                threat.get("pasta_stage")
                or threat.get("stage")
                or threat.get("pasta_phase")
                or threat.get("phase")
            )
            canonical_stage = _canonicalize_threat_stage(normalized_methodology, raw_stage)
            if not canonical_stage:
                legacy_stage = _canonicalize_threat_stage(normalized_methodology, raw_category)
                if legacy_stage:
                    canonical_stage = legacy_stage
                    raw_category = _normalize_text(
                        threat.get("technical_category")
                        or threat.get("threat_type")
                        or threat.get("stride_category")
                    )
            if not canonical_stage:
                invalid_classifications.append(_normalize_text(threat.get("title")) or threat_id)
                continue
            threat["pasta_stage"] = canonical_stage
            threat["category"] = _normalize_text(
                threat.get("technical_category")
                or threat.get("threat_type")
                or threat.get("stride_category")
                or raw_category
            )
        else:
            threat.pop("pasta_stage", None)
            canonical_category = _canonicalize_threat_category(normalized_methodology, threat.get("category"))
            if not canonical_category:
                invalid_classifications.append(_normalize_text(threat.get("title")) or threat_id)
                continue
            threat["category"] = canonical_category
        severity = _normalize_text(threat.get("severity")).lower()
        if severity:
            threat["severity"] = severity

        likelihood = _coerce_score(threat.get("likelihood"))
        impact = _coerce_score(threat.get("impact"))
        risk_score = _coerce_score(threat.get("risk_score"))
        if likelihood is not None:
            threat["likelihood"] = max(1, min(10, likelihood))
        if impact is not None:
            threat["impact"] = max(1, min(10, impact))
        if risk_score is None and likelihood is not None and impact is not None:
            risk_score = max(1, min(100, likelihood * impact))
        if risk_score is not None:
            threat["risk_score"] = risk_score
        threat["references"] = dedupe_reference_links(
            [item for item in threat.get("references", []) if isinstance(item, dict)]
        )

        normalized.append(threat)
    return normalized, invalid_classifications


def _merge_threats(threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for threat in threats:
        signature = _threat_signature(threat)
        existing = merged.get(signature)
        if existing is None or _threat_quality_score(threat) > _threat_quality_score(existing):
            merged_threat = dict(threat)
            if existing:
                merged_threat["references"] = dedupe_reference_links((existing.get("references") or []) + (threat.get("references") or []))
            merged[signature] = merged_threat
        elif existing is not None:
            existing["references"] = dedupe_reference_links((existing.get("references") or []) + (threat.get("references") or []))
    return sorted(
        merged.values(),
        key=lambda threat: (
            _coerce_score(threat.get("risk_score")) or 0,
            _severity_rank(threat.get("severity")),
            _normalize_text(threat.get("title")).lower(),
        ),
        reverse=True,
    )


def _threat_chunk_signature(chunk: dict[str, Any]) -> str:
    component_ids = [
        component_id for component_id in chunk.get("component_ids", [])
        if isinstance(component_id, str) and component_id
    ]
    return "|".join(sorted(component_ids))


def _covered_component_ids_from_threats(threats: list[dict[str, Any]]) -> set[str]:
    return {
        _normalize_text(threat.get("component_id"))
        for threat in threats
        if _normalize_text(threat.get("target_type")) != "data_flow" and _normalize_text(threat.get("component_id"))
    }


def _chunk_values(values: list[str], size: int) -> list[list[str]]:
    return [values[index:index + size] for index in range(0, len(values), size)]


def _compose_threat_chunk(
    label: str,
    component_ids: list[str],
    components: list[dict[str, Any]] | None,
    data_flows: list[dict[str, Any]] | None,
    trust_boundaries: list[dict[str, Any]] | None,
) -> dict[str, Any] | None:
    component_lookup = {
        _normalize_text(component.get("id")): component
        for component in (components or [])
        if isinstance(component, dict) and _normalize_text(component.get("id"))
    }
    ordered_component_ids = [
        component_id
        for component_id in component_ids
        if component_id in component_lookup
    ]
    if not ordered_component_ids:
        return None

    component_set = set(ordered_component_ids)
    relevant_flows = [
        flow for flow in (data_flows or [])
        if isinstance(flow, dict) and (
            _normalize_text(flow.get("source")) in component_set
            or _normalize_text(flow.get("target")) in component_set
        )
    ]
    relevant_boundaries = [
        boundary for boundary in (trust_boundaries or [])
        if isinstance(boundary, dict) and component_set.intersection(
            {component_id for component_id in boundary.get("component_ids", []) if isinstance(component_id, str)}
        )
    ]
    return {
        "label": label,
        "component_ids": ordered_component_ids,
        "components": [component_lookup[component_id] for component_id in ordered_component_ids],
        "data_flows": relevant_flows,
        "trust_boundaries": relevant_boundaries,
    }


def _build_threat_generation_chunks(
    components: list[dict[str, Any]] | None,
    data_flows: list[dict[str, Any]] | None,
    trust_boundaries: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    ordered_components = [
        component for component in (components or [])
        if isinstance(component, dict) and _normalize_text(component.get("id"))
    ]
    if not ordered_components:
        return []

    ordered_component_ids = [_normalize_text(component.get("id")) for component in ordered_components]
    assigned: set[str] = set()
    chunks: list[dict[str, Any]] = []

    for boundary in (trust_boundaries or []):
        if not isinstance(boundary, dict):
            continue
        boundary_name = _normalize_text(boundary.get("name")) or "Trust boundary"
        boundary_component_ids = [
            component_id
            for component_id in boundary.get("component_ids", [])
            if isinstance(component_id, str) and component_id in ordered_component_ids and component_id not in assigned
        ]
        if not boundary_component_ids:
            continue
        boundary_groups = _chunk_values(boundary_component_ids, THREAT_CHUNK_COMPONENT_LIMIT)
        for index, group in enumerate(boundary_groups, start=1):
            label = boundary_name if len(boundary_groups) == 1 else f"{boundary_name} (Part {index})"
            chunk = _compose_threat_chunk(label, group, ordered_components, data_flows, trust_boundaries)
            if chunk:
                chunks.append(chunk)
                assigned.update(group)

    remaining_component_ids = [component_id for component_id in ordered_component_ids if component_id not in assigned]
    for index, group in enumerate(_chunk_values(remaining_component_ids, THREAT_CHUNK_COMPONENT_LIMIT), start=1):
        chunk = _compose_threat_chunk(
            f"Component group {index}",
            group,
            ordered_components,
            data_flows,
            trust_boundaries,
        )
        if chunk:
            chunks.append(chunk)

    if not chunks:
        fallback_chunk = _compose_threat_chunk(
            "Entire threat model",
            ordered_component_ids,
            ordered_components,
            data_flows,
            trust_boundaries,
        )
        if fallback_chunk:
            chunks.append(fallback_chunk)

    return chunks


def _split_threat_chunk(
    chunk: dict[str, Any],
    components: list[dict[str, Any]] | None,
    data_flows: list[dict[str, Any]] | None,
    trust_boundaries: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    component_ids = [
        component_id for component_id in chunk.get("component_ids", [])
        if isinstance(component_id, str)
    ]
    if len(component_ids) <= 1:
        return []
    midpoint = max(1, len(component_ids) // 2)
    partitions = [component_ids[:midpoint], component_ids[midpoint:]]
    split_chunks: list[dict[str, Any]] = []
    for index, partition in enumerate(partitions, start=1):
        split_chunk = _compose_threat_chunk(
            f"{chunk.get('label', 'Threat chunk')} (Split {index})",
            partition,
            components,
            data_flows,
            trust_boundaries,
        )
        if split_chunk:
            split_chunks.append(split_chunk)
    return split_chunks


def _build_threat_overview_messages(
    project_name: str,
    scope: str,
    methodology: str,
    planning_label: str,
    planning_domain: str,
    planning_guidance: str,
    operator_guidance: str,
    components: list[dict[str, Any]] | None,
    data_flows: list[dict[str, Any]] | None,
    trust_boundaries: list[dict[str, Any]] | None,
) -> list[dict[str, str]]:
    prompt = f"""You are an expert red team operator building a concise threat landscape overview before detailed decomposition.

**Target Project:** {project_name}
**System Scope:** {scope}
**Methodology:** {methodology.upper()}
**Planning Profile:** {planning_label}
**Detected Planning Domain:** {planning_domain}
{f'**Operator Guidance:** {operator_guidance}' if operator_guidance else ''}

**Data Flow Diagram:**
Components: {_compact_json(components)}
Data Flows: {_compact_json(data_flows)}
Trust Boundaries: {_compact_json(trust_boundaries)}

{planning_guidance}

Return JSON:
{{
  "summary": "2-4 paragraphs explaining the attacker-relevant architecture, easiest entry paths, and crown jewels",
  "highest_risk_areas": ["Short, specific area + why it matters"],
  "attack_surface_score": 1-100,
  "recommended_attack_priorities": ["Specific attacker priority and rationale"]
}}

Rules:
1. Focus on trust boundaries, privileged transitions, crown-jewel flows, and easiest initial footholds
2. Keep the summary high-level but operationally useful
3. Make the attack priorities concrete and ordered

Return ONLY valid JSON."""
    return [
        {"role": "system", "content": "You are an expert red team operator. Produce a concise JSON threat overview only."},
        {"role": "user", "content": prompt},
    ]


def _build_chunk_threat_messages(
    project_name: str,
    scope: str,
    methodology: str,
    planning_label: str,
    planning_domain: str,
    planning_guidance: str,
    operator_guidance: str,
    chunk: dict[str, Any],
    overview: dict[str, Any],
    candidate_reference_block: str,
) -> list[dict[str, str]]:
    overview_context = _compact_json({
        "summary": _normalize_text(overview.get("summary")),
        "highest_risk_areas": overview.get("highest_risk_areas", []),
        "recommended_attack_priorities": overview.get("recommended_attack_priorities", []),
    })
    normalized_methodology = _normalize_methodology(methodology)
    allowed_categories = ", ".join(_canonical_category_options(methodology))
    allowed_stages = ", ".join(_canonical_stage_options(methodology))
    if normalized_methodology == "pasta":
        classification_fields = f"""      "pasta_stage": "Use exactly one of: {allowed_stages}",
      "category": "Short technical threat class or abuse type (for example: credential abuse, session hijack, data exfiltration)","""
        classification_rules = (
            f"7. Use one exact PASTA stage label in \"pasta_stage\" from: {allowed_stages}\n"
            "8. Keep \"category\" short and technical; do not reuse the PASTA stage label there"
        )
    else:
        classification_fields = f"""      "category": "Use exactly one of: {allowed_categories}","""
        classification_rules = f"7. Use one exact category label from this methodology only: {allowed_categories}"
    prompt = f"""You are an expert red team operator performing offensive threat modeling using {methodology.upper()}.
Focus only on the current chunk of the target architecture and generate concrete, technically credible threats.

**Target Project:** {project_name}
**System Scope:** {scope}
**Planning Profile:** {planning_label}
**Detected Planning Domain:** {planning_domain}
**Chunk Focus:** {chunk.get("label", "Threat chunk")}
{f'**Operator Guidance:** {operator_guidance}' if operator_guidance else ''}

**Global Threat Landscape Overview:** {overview_context}
**Chunk Components:** {_compact_json(chunk.get("components", []))}
**Chunk Data Flows:** {_compact_json(chunk.get("data_flows", []))}
**Relevant Trust Boundaries:** {_compact_json(chunk.get("trust_boundaries", []))}
{candidate_reference_block}

{planning_guidance}

Return JSON:
{{
  "threats": [
    {{
      "id": "threat-1",
      "component_id": "comp-1 or flow-1",
      "component_name": "Human-readable component or data-flow label",
      "target_type": "component|data_flow",
{classification_fields}
      "title": "Specific threat title",
      "description": "Attacker-perspective description of the abuse case",
      "severity": "critical|high|medium|low",
      "attack_vector": "Specific exploitation path, tools, or tradecraft",
      "prerequisites": "Access, knowledge, footholds, or dependencies required",
      "exploitation_complexity": "trivial|low|moderate|high|expert",
      "entry_surface": "Where the attacker begins this abuse path",
      "trust_boundary": "Boundary crossed or boundary adjacent to the abuse path",
      "business_impact": "Operational, mission, or business consequence",
      "detection_notes": "Best telemetry or defender visibility points",
      "mitigation": "Concrete mitigation guidance",
      "likelihood": 1-10,
      "impact": 1-10,
      "risk_score": 1-100,
      "real_world_examples": "Relevant real-world patterns, CVEs, or campaigns when useful",
      "mitre_technique": "MITRE ATT&CK technique ID if applicable",
      "references": [
        {{"framework": "validated local framework", "ref_id": "validated local id", "ref_name": "name", "confidence": 0.0-1.0, "rationale": "brief reason", "source": "ai"}}
      ]
    }}
  ]
}}

Rules:
1. Cover every listed component with at least one meaningful threat unless it is demonstrably out of scope
2. Include the most security-relevant flows touching this chunk, especially boundary-crossing flows
3. Prefer concrete threats over generic filler
4. Use deep technical detail when justified by the target and operator guidance
5. Keep the response strictly to this chunk so the JSON stays compact
6. Prefer the retrieved candidate references when assigning ATT&CK, CAPEC, CWE, OWASP, infrastructure, software-research, or environment-catalog references
{classification_rules}

Return ONLY valid JSON."""
    return [
        {"role": "system", "content": "You are an expert red team operator. Return valid JSON only."},
        {"role": "user", "content": prompt},
    ]


async def _request_json_object_with_retries(
    config: dict[str, Any],
    messages: list[dict[str, str]],
    *,
    temperature: float,
    max_tokens: int,
    timeout_override: int,
    required_keys: tuple[str, ...] = (),
) -> tuple[dict[str, Any], str]:
    last_error = ""
    for attempt in range(THREAT_REQUEST_RETRIES + 1):
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
        parsed = llm_service.parse_json_object_response(response["content"])
        if not required_keys or _has_required_keys(parsed, required_keys):
            return parsed, ""
        last_error = "LLM returned malformed or incomplete JSON"
    return {}, last_error


def _build_fallback_analysis_metadata(
    threats: list[dict[str, Any]],
    components: list[dict[str, Any]] | None,
    warnings: list[str],
) -> dict[str, Any]:
    component_lookup = {
        _normalize_text(component.get("id")): _normalize_text(component.get("name")) or _normalize_text(component.get("id"))
        for component in (components or [])
        if isinstance(component, dict)
    }
    by_target: dict[str, dict[str, Any]] = {}
    for threat in threats:
        target_id = _normalize_text(threat.get("component_id"))
        bucket = by_target.setdefault(target_id, {"name": threat.get("component_name") or component_lookup.get(target_id) or target_id, "count": 0, "risk": 0})
        bucket["count"] += 1
        bucket["risk"] += _coerce_score(threat.get("risk_score")) or 0

    ranked_targets = sorted(by_target.values(), key=lambda item: (item["risk"], item["count"], _normalize_text(item["name"]).lower()), reverse=True)
    highest_risk_areas = [
        f"{target['name']}: {target['count']} threats, aggregate risk {target['risk']}"
        for target in ranked_targets[:3]
        if _normalize_text(target.get("name"))
    ]
    recommended_attack_priorities = [
        f"Start with {_normalize_text(threat.get('title'))} against {_normalize_text(threat.get('component_name')) or _normalize_text(threat.get('component_id'))}"
        for threat in threats[:3]
        if _normalize_text(threat.get("title"))
    ]
    attack_surface_score = None
    if threats:
        attack_surface_score = max(1, min(100, round(sum((_coerce_score(threat.get("risk_score")) or 0) for threat in threats) / len(threats))))
    component_count = len([component for component in (components or []) if isinstance(component, dict)])
    summary = (
        f"Fallback summary: identified {len(threats)} threats across {component_count} components. "
        f"Primary pressure points center on {', '.join(highest_risk_areas[:2]) or 'the listed components and their trust boundaries'}."
    )
    return {
        "summary": summary,
        "highest_risk_areas": highest_risk_areas,
        "attack_surface_score": attack_surface_score,
        "recommended_attack_priorities": recommended_attack_priorities,
        "generation_warnings": warnings,
        "generation_strategy": "chunked",
    }


async def _persist_threat_generation_state(
    tm: ThreatModel,
    db: AsyncSession,
    *,
    threats: list[dict[str, Any]],
    summary: str,
    analysis_metadata: dict[str, Any],
    deep_dive_cache: dict[str, Any] | None = None,
) -> None:
    tm.threats = threats
    tm.ai_summary = summary
    tm.analysis_metadata = analysis_metadata
    if deep_dive_cache is not None:
        tm.deep_dive_cache = deep_dive_cache
    await db.commit()
    await db.refresh(tm)


async def _generate_chunk_threats(
    config: dict[str, Any],
    *,
    project_name: str,
    reference_context_preset: str,
    reference_objective: str,
    scope: str,
    methodology: str,
    planning_label: str,
    planning_domain: str,
    planning_guidance: str,
    operator_guidance: str,
    chunk: dict[str, Any],
    overview: dict[str, Any],
    components: list[dict[str, Any]] | None,
    data_flows: list[dict[str, Any]] | None,
    trust_boundaries: list[dict[str, Any]] | None,
    warnings: list[str],
    seen_ids: set[str],
) -> list[dict[str, Any]]:
    chunk_summary = " ".join(
        [
            _normalize_text(chunk.get("label")),
            " ".join(_normalize_text(component.get("name")) for component in chunk.get("components", []) if isinstance(component, dict)),
            " ".join(_normalize_text(flow.get("label")) for flow in chunk.get("data_flows", []) if isinstance(flow, dict)),
        ]
    )
    candidate_references = search_references(
        query=chunk_summary,
        artifact_type="threat_model",
        context_preset=reference_context_preset,
        objective=reference_objective,
        scope=scope,
        target_kind="threat_chunk",
        target_summary=chunk_summary,
        allowed_frameworks=[
            "attack",
            "capec",
            "cwe",
            "owasp",
            "infra_attack_patterns",
            "software_research_patterns",
            "environment_catalog",
        ],
        limit=12,
    )
    candidate_reference_block = format_reference_candidates_for_prompt(candidate_references)
    messages = _build_chunk_threat_messages(
        project_name,
        scope,
        methodology,
        planning_label,
        planning_domain,
        planning_guidance,
        operator_guidance,
        chunk,
        overview,
        candidate_reference_block,
    )
    parsed, error_message = await _request_json_object_with_retries(
        config,
        messages,
        temperature=0.4,
        max_tokens=6144,
        timeout_override=120,
        required_keys=("threats",),
    )
    if parsed.get("threats"):
        normalized_threats, invalid_classifications = _normalize_generated_threats(
            parsed.get("threats", []),
            components,
            data_flows,
            methodology=methodology,
            seen_ids=seen_ids,
        )
        if normalized_threats and not invalid_classifications:
            return normalized_threats
        if invalid_classifications:
            invalid_preview = ", ".join(invalid_classifications[:3])
            normalized_methodology = _normalize_methodology(methodology)
            if normalized_methodology == "pasta":
                error_message = "LLM returned threats without canonical PASTA stage labels"
            else:
                error_message = f"LLM returned threats with non-canonical {normalized_methodology.upper()} categories"
            error_message += f" ({invalid_preview})" if invalid_preview else ""

    split_chunks = _split_threat_chunk(chunk, components, data_flows, trust_boundaries)
    if split_chunks:
        warnings.append(
            f"Chunk '{chunk.get('label', 'Threat chunk')}' was retried as smaller segments after a malformed or empty response."
        )
        split_results: list[dict[str, Any]] = []
        for split_chunk in split_chunks:
            split_results.extend(await _generate_chunk_threats(
                config,
                project_name=project_name,
                reference_context_preset=reference_context_preset,
                reference_objective=reference_objective,
                scope=scope,
                methodology=methodology,
                planning_label=planning_label,
                planning_domain=planning_domain,
                planning_guidance=planning_guidance,
                operator_guidance=operator_guidance,
                chunk=split_chunk,
                overview=overview,
                components=components,
                data_flows=data_flows,
                trust_boundaries=trust_boundaries,
                warnings=warnings,
                seen_ids=seen_ids,
            ))
        return split_results

    warnings.append(
        f"Unable to generate threats for '{chunk.get('label', 'Threat chunk')}': {error_message or 'empty response'}"
    )
    return []


def _threat_model_planning_context(planning_profile: str, objective: str, scope: str, context_preset: str = "") -> tuple[str, str, str, str]:
    normalized_profile = llm_service.normalize_planning_profile(planning_profile)
    domain = llm_service.detect_planning_domain(objective, scope, context_preset)
    profile_label = llm_service.get_planning_profile_label(normalized_profile)
    guidance = "\n".join(
        section for section in [
            llm_service.get_domain_decomposition_guidance(domain),
            llm_service.get_planning_profile_guidance(normalized_profile, domain),
            build_environment_catalog_outline_for_context(objective, scope, context_preset),
            (
                "Threat-model planning workflow:\n"
                "- Start with major zones, user roles, entry surfaces, privileged paths, crown-jewel data stores, and trust-boundary crossings.\n"
                "- Then express specific components, data flows, and abuse cases inside those zones.\n"
                "- Use methodology labels, ATT&CK, CVEs, and weakness classes as enrichment once an abuse case is concrete enough to justify them."
            ),
        ] if section
    )
    return normalized_profile, profile_label, domain, guidance


def _string_list(value: Any, *, limit: int | None = None) -> list[str]:
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    for item in value:
        text = _normalize_text(item)
        if not text:
            continue
        normalized.append(text)
        if limit is not None and len(normalized) >= limit:
            break
    return normalized


def _safe_slug(value: Any) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", _normalize_text(value).lower()).strip("-")
    return slug or "item"


def _dfd_request_signature(
    *,
    project_name: str,
    methodology: str,
    system_description: str,
    user_guidance: str,
    planning_profile: str,
    context_preset: str,
) -> str:
    payload = {
        "project_name": _normalize_text(project_name),
        "methodology": _normalize_text(methodology).lower(),
        "system_description": _normalize_text(system_description),
        "user_guidance": _normalize_text(user_guidance),
        "planning_profile": _normalize_text(planning_profile),
        "context_preset": _normalize_text(context_preset),
    }
    return hashlib.sha256(_compact_json(payload).encode("utf-8")).hexdigest()


def _normalize_component_type(value: Any) -> str:
    normalized = _normalize_text(value).lower()
    return {
        "datastore": "database",
        "database": "database",
        "db": "database",
        "external_entity": "external",
        "external": "external",
        "external system": "external",
        "process": "process",
        "service": "service",
        "user": "user",
        "api": "api",
        "web_app": "web_app",
        "web application": "web_app",
    }.get(normalized, normalized or "service")


def _normalize_coordinate(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return max(80, min(820, int(round(value))))
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return max(80, min(820, int(stripped)))
    return None


def _component_quality_score(component: dict[str, Any]) -> tuple[int, int]:
    populated = sum(
        1
        for key in ("description", "technology", "attack_surface", "zone_name")
        if _normalize_text(component.get(key))
    )
    text_length = sum(len(_normalize_text(component.get(key))) for key in ("description", "attack_surface"))
    return populated, text_length


def _flow_signature(flow: dict[str, Any]) -> str:
    label = re.sub(r"[^a-z0-9]+", " ", _normalize_text(flow.get("label")).lower()).strip()
    protocol = _normalize_text(flow.get("protocol")).lower()
    return "|".join([
        _normalize_text(flow.get("source")).lower(),
        _normalize_text(flow.get("target")).lower(),
        label,
        protocol,
    ])


def _flow_quality_score(flow: dict[str, Any]) -> tuple[int, int]:
    populated = sum(
        1
        for key in ("label", "protocol", "authentication", "data_classification")
        if _normalize_text(flow.get(key))
    )
    text_length = len(_normalize_text(flow.get("label")))
    return populated, text_length


def _merge_dfd_components(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for component in components:
        component_id = _normalize_text(component.get("id"))
        if not component_id:
            continue
        existing = merged.get(component_id)
        if existing is None or _component_quality_score(component) > _component_quality_score(existing):
            merged[component_id] = component
    return list(merged.values())


def _merge_dfd_flows(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for flow in flows:
        signature = _flow_signature(flow)
        existing = merged.get(signature)
        if existing is None or _flow_quality_score(flow) > _flow_quality_score(existing):
            merged[signature] = flow
    return list(merged.values())


def _normalize_zone_plan(zones: list[Any] | None, system_description: str) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, zone in enumerate(zones or [], start=1):
        if not isinstance(zone, dict):
            continue
        zone_name = _normalize_text(zone.get("name")) or f"Zone {index}"
        zone_id = _safe_slug(zone.get("id") or zone_name)
        if not zone_id.startswith("zone-"):
            zone_id = f"zone-{zone_id}"
        suffix = 2
        candidate = zone_id
        while candidate in seen_ids:
            candidate = f"{zone_id}-{suffix}"
            suffix += 1
        zone_id = candidate
        seen_ids.add(zone_id)
        normalized.append({
            "id": zone_id,
            "name": zone_name,
            "description": _normalize_text(zone.get("description")) or zone_name,
            "focus_areas": _string_list(zone.get("focus_areas"), limit=6),
            "component_hints": _string_list(zone.get("component_hints"), limit=8),
            "external_interfaces": _string_list(zone.get("external_interfaces"), limit=6),
            "trust_boundary_name": _normalize_text(zone.get("trust_boundary_name")) or zone_name,
        })
        if len(normalized) >= DFD_MAX_ZONE_COUNT:
            break

    if normalized:
        return normalized

    fallback_name = "Core Environment"
    return [{
        "id": "zone-core-environment",
        "name": fallback_name,
        "description": _normalize_text(system_description)[:400] or "Primary target environment",
        "focus_areas": [],
        "component_hints": [],
        "external_interfaces": [],
        "trust_boundary_name": fallback_name,
    }]


def _resolve_zone_reference(raw_reference: Any, zone_plan: list[dict[str, Any]]) -> str:
    normalized_reference = _normalize_text(raw_reference)
    if not normalized_reference:
        return ""
    by_id = {zone["id"]: zone["id"] for zone in zone_plan}
    if normalized_reference in by_id:
        return by_id[normalized_reference]
    slug_reference = _safe_slug(normalized_reference)
    if not slug_reference.startswith("zone-"):
        slug_reference = f"zone-{slug_reference}"
    if slug_reference in by_id:
        return slug_reference
    by_name = {
        _safe_slug(zone.get("name")): zone["id"]
        for zone in zone_plan
    }
    return by_name.get(_safe_slug(normalized_reference), "")


def _normalize_cross_zone_paths(
    paths: list[Any] | None,
    zone_plan: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen_signatures: set[str] = set()
    for path in paths or []:
        if not isinstance(path, dict):
            continue
        source_zone_id = _resolve_zone_reference(path.get("source_zone_id") or path.get("source_zone"), zone_plan)
        target_zone_id = _resolve_zone_reference(path.get("target_zone_id") or path.get("target_zone"), zone_plan)
        if not source_zone_id or not target_zone_id or source_zone_id == target_zone_id:
            continue
        description = _normalize_text(path.get("description")) or f"{source_zone_id} to {target_zone_id}"
        signature = "|".join([source_zone_id, target_zone_id, description.lower()])
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)
        normalized.append({
            "source_zone_id": source_zone_id,
            "target_zone_id": target_zone_id,
            "description": description,
            "protocol_hint": _normalize_text(path.get("protocol_hint") or path.get("protocol")),
            "data_classification": _normalize_text(path.get("data_classification")),
            "authentication": _normalize_text(path.get("authentication")),
        })
    return normalized


def _split_zone_detail(zone: dict[str, Any]) -> list[dict[str, Any]]:
    split_seed = list(dict.fromkeys(
        _string_list(zone.get("focus_areas"))
        + _string_list(zone.get("component_hints"))
        + _string_list(zone.get("external_interfaces"))
    ))
    if len(split_seed) <= 1:
        return []

    midpoint = max(1, len(split_seed) // 2)
    partitions = [split_seed[:midpoint], split_seed[midpoint:]]
    split_zones: list[dict[str, Any]] = []
    focus_set = {item.lower() for item in _string_list(zone.get("focus_areas"))}
    hint_set = {item.lower() for item in _string_list(zone.get("component_hints"))}
    iface_set = {item.lower() for item in _string_list(zone.get("external_interfaces"))}
    for index, partition in enumerate(partitions, start=1):
        partition_lower = {item.lower() for item in partition}
        split_zones.append({
            **zone,
            "label": f"{zone.get('name', 'Zone')} (Split {index})",
            "focus_areas": [item for item in zone.get("focus_areas", []) if item.lower() in partition_lower or item.lower() in focus_set and item.lower() in partition_lower],
            "component_hints": [item for item in zone.get("component_hints", []) if item.lower() in partition_lower or item.lower() in hint_set and item.lower() in partition_lower],
            "external_interfaces": [item for item in zone.get("external_interfaces", []) if item.lower() in partition_lower or item.lower() in iface_set and item.lower() in partition_lower],
        })
    return split_zones


def _build_component_id(zone_id: str, name: str, component_type: str, technology: str = "") -> str:
    zone_slug = _safe_slug(zone_id).removeprefix("zone-")
    name_slug = _safe_slug(name)[:36]
    type_slug = _safe_slug(component_type)[:18]
    tech_slug = _safe_slug(technology)[:18] if technology else ""
    suffix = f"-{tech_slug}" if tech_slug else ""
    return f"comp-{zone_slug}-{name_slug}-{type_slug}{suffix}"


def _resolve_component_reference(raw_reference: Any, ref_map: dict[str, str]) -> str:
    normalized_reference = _normalize_text(raw_reference)
    if not normalized_reference:
        return ""
    return ref_map.get(normalized_reference) or ref_map.get(normalized_reference.lower(), "")


def _normalize_zone_detail_output(parsed: dict[str, Any], zone: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    components: list[dict[str, Any]] = []
    raw_components = parsed.get("components", [])
    raw_flows = parsed.get("data_flows", [])
    seen_component_ids: set[str] = set()
    ref_map: dict[str, str] = {}
    for index, component in enumerate(raw_components or [], start=1):
        if not isinstance(component, dict):
            continue
        name = _normalize_text(component.get("name")) or f"{zone.get('name', 'Zone')} Component {index}"
        component_type = _normalize_component_type(component.get("type"))
        technology = _normalize_text(component.get("technology"))
        base_id = _build_component_id(zone["id"], name, component_type, technology)
        component_id = base_id
        suffix = 2
        while component_id in seen_component_ids:
            component_id = f"{base_id}-{suffix}"
            suffix += 1
        seen_component_ids.add(component_id)
        local_id = _normalize_text(component.get("id"))
        ref_map[component_id] = component_id
        if local_id:
            ref_map[local_id] = component_id
            ref_map[local_id.lower()] = component_id
        ref_map[name] = component_id
        ref_map[name.lower()] = component_id
        components.append({
            "id": component_id,
            "type": component_type,
            "name": name,
            "description": _normalize_text(component.get("description")),
            "technology": technology,
            "x": _normalize_coordinate(component.get("x")),
            "y": _normalize_coordinate(component.get("y")),
            "attack_surface": _normalize_text(component.get("attack_surface")),
            "zone_id": zone["id"],
            "zone_name": zone.get("name"),
        })

    flows: list[dict[str, Any]] = []
    seen_flow_ids: set[str] = set()
    for flow in raw_flows or []:
        if not isinstance(flow, dict):
            continue
        source = _resolve_component_reference(flow.get("source"), ref_map)
        target = _resolve_component_reference(flow.get("target"), ref_map)
        if not source or not target or source == target:
            continue
        label = _normalize_text(flow.get("label"))
        flow_id = _normalize_text(flow.get("id")) or f"flow-{source}-{target}-{_safe_slug(label or flow.get('protocol') or 'data')}"
        while flow_id in seen_flow_ids:
            flow_id = f"{flow_id}-2"
        seen_flow_ids.add(flow_id)
        flows.append({
            "id": flow_id,
            "source": source,
            "target": target,
            "label": label,
            "data_classification": _normalize_text(flow.get("data_classification")).lower() or "internal",
            "protocol": _normalize_text(flow.get("protocol")),
            "authentication": _normalize_text(flow.get("authentication")),
        })

    return _merge_dfd_components(components), _merge_dfd_flows(flows)


def _build_component_reference_map(components: list[dict[str, Any]]) -> dict[str, str]:
    ref_map: dict[str, str] = {}
    name_counts: dict[str, int] = {}
    for component in components:
        name_key = _normalize_text(component.get("name")).lower()
        if name_key:
            name_counts[name_key] = name_counts.get(name_key, 0) + 1

    for component in components:
        component_id = _normalize_text(component.get("id"))
        if not component_id:
            continue
        component_name = _normalize_text(component.get("name"))
        zone_name = _normalize_text(component.get("zone_name"))
        ref_map[component_id] = component_id
        ref_map[component_id.lower()] = component_id
        if component_name and name_counts.get(component_name.lower()) == 1:
            ref_map[component_name] = component_id
            ref_map[component_name.lower()] = component_id
        if zone_name and component_name:
            zone_name_key = f"{zone_name}::{component_name}"
            ref_map[zone_name_key] = component_id
            ref_map[zone_name_key.lower()] = component_id
    return ref_map


def _normalize_cross_zone_flow_output(
    parsed: dict[str, Any],
    components: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    component_lookup = {
        _normalize_text(component.get("id")): component
        for component in components
        if _normalize_text(component.get("id"))
    }
    ref_map = _build_component_reference_map(components)
    flows: list[dict[str, Any]] = []
    seen_flow_ids: set[str] = set()
    for flow in parsed.get("data_flows", []) or []:
        if not isinstance(flow, dict):
            continue
        source = _resolve_component_reference(flow.get("source"), ref_map)
        target = _resolve_component_reference(flow.get("target"), ref_map)
        if not source or not target or source == target:
            continue
        source_zone = _normalize_text(component_lookup.get(source, {}).get("zone_id"))
        target_zone = _normalize_text(component_lookup.get(target, {}).get("zone_id"))
        if not source_zone or not target_zone or source_zone == target_zone:
            continue
        label = _normalize_text(flow.get("label"))
        flow_id = _normalize_text(flow.get("id")) or f"flow-{source}-{target}-{_safe_slug(label or flow.get('protocol') or 'cross-zone')}"
        while flow_id in seen_flow_ids:
            flow_id = f"{flow_id}-2"
        seen_flow_ids.add(flow_id)
        flows.append({
            "id": flow_id,
            "source": source,
            "target": target,
            "label": label,
            "data_classification": _normalize_text(flow.get("data_classification")).lower() or "internal",
            "protocol": _normalize_text(flow.get("protocol")),
            "authentication": _normalize_text(flow.get("authentication")),
        })
    return _merge_dfd_flows(flows)


def _build_trust_boundaries_from_zone_plan(
    zone_plan: list[dict[str, Any]],
    components: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    components_by_zone: dict[str, list[str]] = {}
    for component in components:
        zone_id = _normalize_text(component.get("zone_id"))
        component_id = _normalize_text(component.get("id"))
        if not zone_id or not component_id:
            continue
        components_by_zone.setdefault(zone_id, []).append(component_id)

    boundaries: list[dict[str, Any]] = []
    for zone in zone_plan:
        zone_id = _normalize_text(zone.get("id"))
        component_ids = sorted(set(components_by_zone.get(zone_id, [])))
        if not component_ids:
            continue
        boundaries.append({
            "id": f"tb-{_safe_slug(zone_id)}",
            "name": _normalize_text(zone.get("trust_boundary_name")) or _normalize_text(zone.get("name")) or zone_id,
            "component_ids": component_ids,
        })
    return boundaries


def _assign_dfd_layout(
    components: list[dict[str, Any]],
    zone_plan: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    zone_order = {
        _normalize_text(zone.get("id")): index
        for index, zone in enumerate(zone_plan)
    }
    positioned: list[dict[str, Any]] = []
    zone_counters: dict[str, int] = {}
    for component in components:
        component_copy = dict(component)
        current_x = _normalize_coordinate(component_copy.get("x"))
        current_y = _normalize_coordinate(component_copy.get("y"))
        if current_x is not None and current_y is not None:
            component_copy["x"] = current_x
            component_copy["y"] = current_y
            positioned.append(component_copy)
            continue

        zone_id = _normalize_text(component_copy.get("zone_id"))
        zone_index = zone_order.get(zone_id, len(zone_order))
        slot = zone_counters.get(zone_id, 0)
        zone_counters[zone_id] = slot + 1
        base_x = 110 + (zone_index % 3) * 240
        base_y = 120 + (zone_index // 3) * 250
        component_copy["x"] = max(80, min(820, base_x + (slot % 2) * 110))
        component_copy["y"] = max(80, min(820, base_y + (slot // 2) * 90))
        positioned.append(component_copy)
    return positioned


def _build_dfd_topology_messages(
    *,
    project_name: str,
    methodology: str,
    system_description: str,
    scope: str,
    planning_label: str,
    planning_domain: str,
    planning_guidance: str,
    operator_guidance: str,
    tree_context: str,
) -> list[dict[str, str]]:
    prompt = f"""You are an offensive security architect decomposing a target system into attack-relevant architectural zones before building a DFD.

**Target Project:** {project_name}
**Methodology:** {methodology.upper()}
**System Description:** {system_description}
**Scope:** {scope}
**Planning Profile:** {planning_label}
**Detected Planning Domain:** {planning_domain}
{f'**Operator Guidance:** {operator_guidance}' if operator_guidance else ''}
{tree_context}

{planning_guidance}

Return JSON:
{{
  "summary": "2-4 short paragraphs describing the attacker-relevant topology, privileged transitions, and crown-jewel paths",
  "zones": [
    {{
      "id": "zone-edge",
      "name": "Zone name",
      "description": "What belongs in this zone and why it matters to an attacker",
      "focus_areas": ["Short, attack-relevant focus area"],
      "component_hints": ["Likely components or roles expected in the zone"],
      "external_interfaces": ["Internet, vendor, partner, or adjacent-system interfaces"],
      "trust_boundary_name": "Boundary label to use in the DFD"
    }}
  ],
  "cross_zone_paths": [
    {{
      "source_zone_id": "zone-edge",
      "target_zone_id": "zone-ops",
      "description": "Why data or access crosses this boundary",
      "protocol_hint": "HTTPS|RDP|MQTT|SQL|etc",
      "data_classification": "public|internal|confidential|restricted",
      "authentication": "Authentication pattern if known"
    }}
  ]
}}

Rules:
1. Identify 1-6 major zones, not individual components
2. Zones should be attacker-relevant trust or privilege boundaries, not generic org charts
3. Keep the zone list compact enough for staged generation
4. Focus on where access, identity, safety, or mission data crosses boundaries

Return ONLY valid JSON."""
    return [
        {"role": "system", "content": "You are an expert offensive security architect. Return compact topology-planning JSON only."},
        {"role": "user", "content": prompt},
    ]


def _build_dfd_zone_messages(
    *,
    project_name: str,
    methodology: str,
    system_description: str,
    scope: str,
    planning_label: str,
    planning_domain: str,
    planning_guidance: str,
    operator_guidance: str,
    zone: dict[str, Any],
    topology_summary: str,
    relevant_cross_zone_paths: list[dict[str, Any]],
) -> list[dict[str, str]]:
    prompt = f"""You are an offensive security architect generating one zone of a staged Data Flow Diagram.

**Target Project:** {project_name}
**Methodology:** {methodology.upper()}
**System Description:** {system_description}
**Scope:** {scope}
**Planning Profile:** {planning_label}
**Detected Planning Domain:** {planning_domain}
**Zone Focus:** {zone.get("label") or zone.get("name")}
**Topology Summary:** {topology_summary or 'Not available'}
{f'**Operator Guidance:** {operator_guidance}' if operator_guidance else ''}

**Zone Definition:** {_compact_json(zone)}
**Relevant Cross-Zone Path Hints:** {_compact_json(relevant_cross_zone_paths)}

{planning_guidance}

Return JSON:
{{
  "components": [
    {{
      "id": "local-comp-1",
      "type": "process|datastore|external_entity|service|user|api|web_app",
      "name": "Component name",
      "description": "Brief description including attack-relevant details",
      "technology": "Specific technology or platform if known",
      "x": 100,
      "y": 100,
      "attack_surface": "Why this component matters to an attacker"
    }}
  ],
  "data_flows": [
    {{
      "id": "local-flow-1",
      "source": "local-comp-1",
      "target": "local-comp-2",
      "label": "What moves between these components",
      "data_classification": "public|internal|confidential|restricted",
      "protocol": "HTTPS|RDP|MQTT|SQL|etc",
      "authentication": "Authentication pattern or 'unauthenticated'"
    }}
  ]
}}

Rules:
1. Generate only the components that belong inside this zone
2. Include 2-7 concrete components unless the zone is truly tiny
3. Keep flows internal to this zone only; do not invent cross-zone targets here
4. Use specific names and technologies when justified by the system description
5. Prefer attacker-relevant components over exhaustive low-value detail

Return ONLY valid JSON."""
    return [
        {"role": "system", "content": "You are an expert offensive security architect. Return valid JSON only."},
        {"role": "user", "content": prompt},
    ]


def _build_dfd_cross_zone_flow_messages(
    *,
    project_name: str,
    methodology: str,
    system_description: str,
    scope: str,
    planning_label: str,
    planning_domain: str,
    planning_guidance: str,
    operator_guidance: str,
    topology_summary: str,
    zone_plan: list[dict[str, Any]],
    components: list[dict[str, Any]],
    cross_zone_paths: list[dict[str, Any]],
) -> list[dict[str, str]]:
    component_inventory = []
    for zone in zone_plan:
        zone_id = _normalize_text(zone.get("id"))
        zone_components = [
            {
                "id": component.get("id"),
                "name": component.get("name"),
                "type": component.get("type"),
                "technology": component.get("technology"),
                "attack_surface": component.get("attack_surface"),
            }
            for component in components
            if _normalize_text(component.get("zone_id")) == zone_id
        ]
        if zone_components:
            component_inventory.append({
                "zone_id": zone_id,
                "zone_name": zone.get("name"),
                "components": zone_components,
            })

    prompt = f"""You are an offensive security architect completing the cross-zone data flows for a staged Data Flow Diagram.

**Target Project:** {project_name}
**Methodology:** {methodology.upper()}
**System Description:** {system_description}
**Scope:** {scope}
**Planning Profile:** {planning_label}
**Detected Planning Domain:** {planning_domain}
**Topology Summary:** {topology_summary or 'Not available'}
{f'**Operator Guidance:** {operator_guidance}' if operator_guidance else ''}

**Zones:** {_compact_json(zone_plan)}
**Component Inventory:** {_compact_json(component_inventory)}
**Cross-Zone Path Hints:** {_compact_json(cross_zone_paths)}

{planning_guidance}

Return JSON:
{{
  "data_flows": [
    {{
      "id": "flow-1",
      "source": "Use an existing component id exactly",
      "target": "Use an existing component id exactly",
      "label": "Cross-zone flow description",
      "data_classification": "public|internal|confidential|restricted",
      "protocol": "HTTPS|RDP|MQTT|SQL|etc",
      "authentication": "Authentication pattern or 'unauthenticated'"
    }}
  ]
}}

Rules:
1. Use only the provided component IDs
2. Generate only flows that cross between different zones
3. Focus on privileged, sensitive, operational, or attacker-useful data paths
4. Keep the response compact and technically credible

Return ONLY valid JSON."""
    return [
        {"role": "system", "content": "You are an expert offensive security architect. Return valid JSON only."},
        {"role": "user", "content": prompt},
    ]


async def _persist_dfd_generation_state(
    tm: ThreatModel,
    db: AsyncSession,
    *,
    components: list[dict[str, Any]],
    data_flows: list[dict[str, Any]],
    zone_plan: list[dict[str, Any]],
    dfd_metadata: dict[str, Any],
) -> None:
    merged_components = _assign_dfd_layout(_merge_dfd_components(components), zone_plan)
    merged_flows = _merge_dfd_flows(data_flows)
    tm.components = merged_components
    tm.data_flows = merged_flows
    tm.trust_boundaries = _build_trust_boundaries_from_zone_plan(zone_plan, merged_components)
    tm.dfd_metadata = dfd_metadata
    await db.commit()
    await db.refresh(tm)


async def _generate_zone_dfd(
    config: dict[str, Any],
    *,
    project_name: str,
    methodology: str,
    system_description: str,
    scope: str,
    planning_label: str,
    planning_domain: str,
    planning_guidance: str,
    operator_guidance: str,
    zone: dict[str, Any],
    topology_summary: str,
    relevant_cross_zone_paths: list[dict[str, Any]],
    warnings: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    messages = _build_dfd_zone_messages(
        project_name=project_name,
        methodology=methodology,
        system_description=system_description,
        scope=scope,
        planning_label=planning_label,
        planning_domain=planning_domain,
        planning_guidance=planning_guidance,
        operator_guidance=operator_guidance,
        zone=zone,
        topology_summary=topology_summary,
        relevant_cross_zone_paths=relevant_cross_zone_paths,
    )
    parsed, error_message = await _request_json_object_with_retries(
        config,
        messages,
        temperature=0.45,
        max_tokens=4096,
        timeout_override=120,
        required_keys=("components",),
    )
    components, flows = _normalize_zone_detail_output(parsed, zone)
    if components:
        return components, flows

    split_zones = _split_zone_detail(zone)
    if split_zones:
        warnings.append(
            f"Zone '{zone.get('name', 'Zone')}' was retried as smaller segments after a malformed or empty response."
        )
        split_components: list[dict[str, Any]] = []
        split_flows: list[dict[str, Any]] = []
        for split_zone in split_zones:
            nested_components, nested_flows = await _generate_zone_dfd(
                config,
                project_name=project_name,
                methodology=methodology,
                system_description=system_description,
                scope=scope,
                planning_label=planning_label,
                planning_domain=planning_domain,
                planning_guidance=planning_guidance,
                operator_guidance=operator_guidance,
                zone=split_zone,
                topology_summary=topology_summary,
                relevant_cross_zone_paths=relevant_cross_zone_paths,
                warnings=warnings,
            )
            split_components.extend(nested_components)
            split_flows.extend(nested_flows)
        return _merge_dfd_components(split_components), _merge_dfd_flows(split_flows)

    warnings.append(
        f"Unable to generate DFD details for zone '{zone.get('name', 'Zone')}': {error_message or 'empty response'}"
    )
    return [], []


# --- Endpoints ---

@router.get("/project/{project_id}")
async def list_threat_models(project_id: str, db: AsyncSession = Depends(get_db)):
    await require_project_access(project_id, db)
    result = await db.execute(
        select(ThreatModel).where(ThreatModel.project_id == project_id).order_by(ThreatModel.created_at.desc())
    )
    return [_to_dict(tm) for tm in result.scalars().all()]


@router.post("", status_code=201)
async def create_threat_model(data: ThreatModelCreate, db: AsyncSession = Depends(get_db)):
    await require_project_access(data.project_id, db)
    payload = data.model_dump()
    payload["methodology"] = _normalize_methodology(payload.get("methodology"))
    tm = ThreatModel(**payload)
    db.add(tm)
    await db.commit()
    await db.refresh(tm)
    return _to_dict(tm)


@router.get("/{tm_id}")
async def get_threat_model(tm_id: str, db: AsyncSession = Depends(get_db)):
    tm = await _get_or_404(tm_id, db)
    return _to_dict(tm)


@router.patch("/{tm_id}")
async def update_threat_model(tm_id: str, data: ThreatModelUpdate, db: AsyncSession = Depends(get_db)):
    tm = await _get_or_404(tm_id, db)
    payload = data.model_dump(exclude_unset=True)
    if "methodology" in payload:
        payload["methodology"] = _normalize_methodology(payload.get("methodology"))
    if "threats" in payload:
        normalized_threats, invalid_classifications = _normalize_generated_threats(
            payload.get("threats") or [],
            payload.get("components") or tm.components or [],
            payload.get("data_flows") or tm.data_flows or [],
            methodology=payload.get("methodology") or tm.methodology,
        )
        if invalid_classifications:
            normalized_methodology = _normalize_methodology(payload.get("methodology") or tm.methodology)
            invalid_preview = ", ".join(invalid_classifications[:3])
            if normalized_methodology == "pasta":
                message = "Threats must include canonical PASTA stage labels"
            else:
                message = f"Threat categories must use canonical {normalized_methodology.upper()} labels"
            raise HTTPException(
                422,
                message
                + (f" (invalid: {invalid_preview})" if invalid_preview else ""),
            )
        payload["threats"] = normalized_threats
    methodology_changed = "methodology" in payload and payload["methodology"] != tm.methodology
    for key, value in payload.items():
        setattr(tm, key, value)
    if any(key in payload for key in ("components", "data_flows", "trust_boundaries")):
        if "threats" not in payload:
            tm.threats = []
        tm.ai_summary = ""
        tm.dfd_metadata = {}
        tm.analysis_metadata = {}
        tm.deep_dive_cache = {}
    elif methodology_changed:
        if "threats" not in payload:
            tm.threats = []
        tm.ai_summary = ""
        tm.analysis_metadata = {}
        tm.deep_dive_cache = {}
    await db.commit()
    await db.refresh(tm)
    return _to_dict(tm)


@router.delete("/{tm_id}", status_code=204)
async def delete_threat_model(tm_id: str, db: AsyncSession = Depends(get_db)):
    tm = await _get_or_404(tm_id, db)
    await db.delete(tm)
    await db.commit()


@router.post("/{tm_id}/ai-generate-dfd")
async def ai_generate_dfd(tm_id: str, data: AIGenerateDFDRequest, db: AsyncSession = Depends(get_db)):
    """AI generates a staged Data Flow Diagram from a system description."""
    started_at = perf_counter()
    tm = await _get_or_404(tm_id, db)
    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    project = await require_project_access(tm.project_id, db)

    nodes_result = await db.execute(
        select(Node).where(Node.project_id == tm.project_id)
    )
    nodes = nodes_result.scalars().all()
    tree_context = ""
    if nodes:
        tree_context = "\n**Existing Attack Tree Nodes (for context):**\n" + "\n".join(
            f"- [{n.node_type}] {n.title}" for n in nodes[:30]
        )

    _, planning_label, planning_domain, planning_guidance = _threat_model_planning_context(
        data.planning_profile,
        project.root_objective or data.system_description or tm.name,
        "\n".join(part for part in [project.description or "", tm.scope or "", data.system_description, data.user_guidance, tree_context] if part),
        getattr(project, "context_preset", ""),
    )

    config = _provider_to_config(provider)
    request_signature = _dfd_request_signature(
        project_name=project.name if project else "Unknown",
        methodology=tm.methodology,
        system_description=data.system_description,
        user_guidance=data.user_guidance,
        planning_profile=data.planning_profile,
        context_preset=getattr(project, "context_preset", ""),
    )
    existing_dfd_metadata = tm.dfd_metadata if isinstance(tm.dfd_metadata, dict) else {}
    stored_zone_plan = existing_dfd_metadata.get("zone_plan") if isinstance(existing_dfd_metadata.get("zone_plan"), list) else []
    resume_existing = (
        not data.refresh
        and existing_dfd_metadata.get("generation_status") in {"running", "partial"}
        and existing_dfd_metadata.get("request_signature") == request_signature
        and bool(stored_zone_plan)
    )

    warnings: list[str] = [
        warning for warning in existing_dfd_metadata.get("generation_warnings", [])
        if isinstance(warning, str)
        and not warning.startswith("Unable to generate DFD details for zone")
        and not warning.startswith("Cross-zone flow generation incomplete")
        and warning != "Resumed DFD generation from previously persisted partial results."
    ] if resume_existing else []
    topology_summary = _normalize_text(existing_dfd_metadata.get("topology_summary")) if resume_existing else ""
    zone_plan = _normalize_zone_plan(stored_zone_plan, data.system_description) if resume_existing else []
    cross_zone_paths = _normalize_cross_zone_paths(existing_dfd_metadata.get("cross_zone_paths"), zone_plan) if resume_existing else []
    completed_zone_ids = {
        zone_id
        for zone_id in existing_dfd_metadata.get("completed_zone_ids", [])
        if isinstance(zone_id, str) and zone_id
    } if resume_existing else set()
    flow_stage_completed = existing_dfd_metadata.get("cross_zone_flow_status") == "completed" if resume_existing else False
    components_state = _merge_dfd_components([
        component for component in (tm.components or [])
        if isinstance(component, dict)
    ]) if resume_existing else []
    data_flow_state = _merge_dfd_flows([
        flow for flow in (tm.data_flows or [])
        if isinstance(flow, dict)
    ]) if resume_existing else []

    tm.scope = data.system_description

    async def _save_dfd_progress(status: str, current_stage: str) -> None:
        pending_zone_ids = [
            _normalize_text(zone.get("id"))
            for zone in zone_plan
            if _normalize_text(zone.get("id")) and _normalize_text(zone.get("id")) not in completed_zone_ids
        ]
        flow_status = "completed" if zone_plan and (flow_stage_completed or len(zone_plan) <= 1) else "pending"
        metadata = {
            "generation_warnings": warnings,
            "generation_strategy": "staged",
            "generation_status": status,
            "current_stage": current_stage,
            "request_signature": request_signature,
            "zone_count": len(zone_plan),
            "completed_zone_ids": sorted(completed_zone_ids),
            "pending_zone_ids": pending_zone_ids,
            "pending_zone_count": len(pending_zone_ids),
            "cross_zone_flow_status": flow_status,
            "topology_summary": topology_summary,
            "zone_plan": zone_plan,
            "cross_zone_paths": cross_zone_paths,
        }
        await _persist_dfd_generation_state(
            tm,
            db,
            components=components_state,
            data_flows=data_flow_state,
            zone_plan=zone_plan,
            dfd_metadata=metadata,
        )

    if not resume_existing:
        tm.components = []
        tm.data_flows = []
        tm.trust_boundaries = []
        tm.threats = []
        tm.ai_summary = ""
        tm.dfd_metadata = {}
        tm.analysis_metadata = {}
        tm.deep_dive_cache = {}
        await db.commit()
        await db.refresh(tm)

        await _save_dfd_progress("running", "topology")
        topology_messages = _build_dfd_topology_messages(
            project_name=project.name if project else "Unknown",
            methodology=tm.methodology,
            system_description=data.system_description,
            scope=tm.scope,
            planning_label=planning_label,
            planning_domain=planning_domain,
            planning_guidance=planning_guidance,
            operator_guidance=data.user_guidance,
            tree_context=tree_context,
        )
        topology, topology_error = await _request_json_object_with_retries(
            config,
            topology_messages,
            temperature=0.35,
            max_tokens=4096,
            timeout_override=90,
            required_keys=("zones",),
        )
        zone_plan = _normalize_zone_plan(topology.get("zones"), data.system_description)
        cross_zone_paths = _normalize_cross_zone_paths(topology.get("cross_zone_paths"), zone_plan)
        topology_summary = _normalize_text(topology.get("summary"))
        if not topology.get("zones"):
            warnings.append(
                f"DFD topology planning fell back to a minimal zone plan: {topology_error or 'structured zones were not returned'}"
            )
        await _save_dfd_progress("running", "zones")
    else:
        if (
            existing_dfd_metadata.get("generation_status") in {"running", "partial"}
            and (
                existing_dfd_metadata.get("pending_zone_ids")
                or existing_dfd_metadata.get("cross_zone_flow_status") != "completed"
            )
        ):
            warnings.append("Resumed DFD generation from previously persisted partial results.")

    pending_zones = [
        zone for zone in zone_plan
        if _normalize_text(zone.get("id")) not in completed_zone_ids
    ]
    for zone in pending_zones:
        relevant_cross_zone_paths = [
            path for path in cross_zone_paths
            if zone.get("id") in {path.get("source_zone_id"), path.get("target_zone_id")}
        ]
        zone_components, zone_flows = await _generate_zone_dfd(
            config,
            project_name=project.name if project else "Unknown",
            methodology=tm.methodology,
            system_description=data.system_description,
            scope=tm.scope,
            planning_label=planning_label,
            planning_domain=planning_domain,
            planning_guidance=planning_guidance,
            operator_guidance=data.user_guidance,
            zone=zone,
            topology_summary=topology_summary,
            relevant_cross_zone_paths=relevant_cross_zone_paths,
            warnings=warnings,
        )
        if zone_components:
            completed_zone_ids.add(_normalize_text(zone.get("id")))
            components_state = _merge_dfd_components(components_state + zone_components)
            data_flow_state = _merge_dfd_flows(data_flow_state + zone_flows)
        await _save_dfd_progress("running", "zones")

    if not components_state:
        await _save_dfd_progress("failed", "zones")
        raise HTTPException(502, "AI returned an empty or malformed DFD across all staged attempts — try again or simplify the description")

    pending_zone_ids = [
        _normalize_text(zone.get("id"))
        for zone in zone_plan
        if _normalize_text(zone.get("id")) and _normalize_text(zone.get("id")) not in completed_zone_ids
    ]
    if not pending_zone_ids and not flow_stage_completed and len(zone_plan) > 1:
        if not cross_zone_paths:
            flow_stage_completed = True
        else:
            cross_zone_messages = _build_dfd_cross_zone_flow_messages(
                project_name=project.name if project else "Unknown",
                methodology=tm.methodology,
                system_description=data.system_description,
                scope=tm.scope,
                planning_label=planning_label,
                planning_domain=planning_domain,
                planning_guidance=planning_guidance,
                operator_guidance=data.user_guidance,
                topology_summary=topology_summary,
                zone_plan=zone_plan,
                components=components_state,
                cross_zone_paths=cross_zone_paths,
            )
            cross_zone_result, cross_zone_error = await _request_json_object_with_retries(
                config,
                cross_zone_messages,
                temperature=0.35,
                max_tokens=4096,
                timeout_override=90,
                required_keys=("data_flows",),
            )
            cross_zone_flows = _normalize_cross_zone_flow_output(cross_zone_result, components_state)
            if cross_zone_flows:
                data_flow_state = _merge_dfd_flows(data_flow_state + cross_zone_flows)
                flow_stage_completed = True
            else:
                warnings.append(f"Cross-zone flow generation incomplete: {cross_zone_error or 'empty response'}")
        await _save_dfd_progress("running" if flow_stage_completed else "partial", "cross_zone_flows")
    elif len(zone_plan) <= 1:
        flow_stage_completed = True

    final_pending_zone_ids = [
        _normalize_text(zone.get("id"))
        for zone in zone_plan
        if _normalize_text(zone.get("id")) and _normalize_text(zone.get("id")) not in completed_zone_ids
    ]
    final_status = "completed" if not final_pending_zone_ids and flow_stage_completed else "partial"
    await _save_dfd_progress(final_status, "completed" if final_status == "completed" else ("zones" if final_pending_zone_ids else "cross_zone_flows"))
    await record_analysis_run(
        db,
        project_id=tm.project_id,
        tool="threat_model",
        run_type="dfd_generation",
        status=final_status,
        artifact_kind="threat_model",
        artifact_id=tm.id,
        artifact_name=tm.name,
        summary=(
            f"DFD {final_status} with {len(tm.components or [])} component"
            f"{'' if len(tm.components or []) == 1 else 's'} and {len(tm.data_flows or [])} flow"
            f"{'' if len(tm.data_flows or []) == 1 else 's'}."
        ),
        metadata={
            "component_count": len(tm.components or []),
            "data_flow_count": len(tm.data_flows or []),
            "pending_zone_count": len(final_pending_zone_ids),
            "methodology": tm.methodology,
        },
        duration_ms=round((perf_counter() - started_at) * 1000),
    )
    return _to_dict(tm)


@router.post("/{tm_id}/ai-generate-threats")
async def ai_generate_threats(tm_id: str, data: AIGenerateThreatsRequest, db: AsyncSession = Depends(get_db)):
    """AI analyzes the DFD and generates STRIDE/PASTA threats."""
    started_at = perf_counter()
    tm = await _get_or_404(tm_id, db)
    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    if not tm.components:
        raise HTTPException(400, "Generate a DFD first before generating threats")
    dfd_metadata = tm.dfd_metadata if isinstance(tm.dfd_metadata, dict) else {}
    if dfd_metadata.get("generation_status") in {"running", "partial"}:
        raise HTTPException(409, "DFD generation is incomplete. Resume DFD generation and finish the remaining zones before generating threats.")

    project = await require_project_access(tm.project_id, db)

    _, planning_label, planning_domain, planning_guidance = _threat_model_planning_context(
        data.planning_profile,
        project.root_objective or tm.scope or tm.name,
        "\n".join(part for part in [
            project.description or "",
            tm.scope or "",
            data.user_guidance,
            _compact_json(tm.components),
            _compact_json(tm.data_flows),
            _compact_json(tm.trust_boundaries),
        ] if part),
        getattr(project, "context_preset", ""),
    )

    config = _provider_to_config(provider)
    existing_metadata = tm.analysis_metadata if isinstance(tm.analysis_metadata, dict) else {}
    resume_existing = (
        not data.refresh
        and existing_metadata.get("generation_status") in {"running", "partial"}
        and isinstance(tm.threats, list)
        and len(tm.threats) > 0
    )
    warnings: list[str] = [
        warning for warning in existing_metadata.get("generation_warnings", [])
        if isinstance(warning, str)
        and not warning.startswith("Unable to generate threats")
        and warning != "Resumed threat generation from previously persisted partial results."
    ] if resume_existing else []
    deep_dive_cache_state = dict(tm.deep_dive_cache or {}) if resume_existing else {}

    initial_chunks = _build_threat_generation_chunks(
        tm.components or [],
        tm.data_flows or [],
        tm.trust_boundaries or [],
    )
    if not initial_chunks:
        raise HTTPException(400, "Generate a DFD with components before generating threats")

    seen_ids: set[str] = set()
    if resume_existing:
        generated_threats, existing_invalid_classifications = _normalize_generated_threats(
            tm.threats or [],
            tm.components or [],
            tm.data_flows or [],
            methodology=tm.methodology,
            seen_ids=seen_ids,
        )
    else:
        generated_threats = []
        existing_invalid_classifications = []
    if resume_existing and existing_invalid_classifications:
        warnings.append(
            "Discarded previously persisted threats with invalid methodology classification while resuming generation."
        )
    completed_chunk_signatures = {
        signature for signature in existing_metadata.get("completed_chunk_signatures", [])
        if isinstance(signature, str) and signature
    } if resume_existing else set()

    overview = {
        "summary": tm.ai_summary or "",
        "highest_risk_areas": existing_metadata.get("highest_risk_areas", []),
        "attack_surface_score": existing_metadata.get("attack_surface_score"),
        "recommended_attack_priorities": existing_metadata.get("recommended_attack_priorities", []),
    } if resume_existing and (tm.ai_summary or existing_metadata) else {}

    if not _normalize_text(overview.get("summary")):
        overview_messages = _build_threat_overview_messages(
            project.name if project else "Unknown",
            tm.scope,
            tm.methodology,
            planning_label,
            planning_domain,
            planning_guidance,
            data.user_guidance,
            tm.components or [],
            tm.data_flows or [],
            tm.trust_boundaries or [],
        )
        overview, overview_error = await _request_json_object_with_retries(
            config,
            overview_messages,
            temperature=0.35,
            max_tokens=4096,
            timeout_override=90,
            required_keys=("summary",),
        )
        if not overview.get("summary"):
            warnings.append(f"Threat overview generation fell back to derived metadata: {overview_error or 'empty response'}")

    async def _save_progress(status: str, pending_chunk_count: int) -> None:
        merged = _merge_threats(generated_threats)
        fallback_metadata = _build_fallback_analysis_metadata(merged, tm.components or [], warnings)
        overview_attack_surface_score = _coerce_score(overview.get("attack_surface_score"))
        analysis_metadata = {
            "highest_risk_areas": overview.get("highest_risk_areas") or fallback_metadata["highest_risk_areas"],
            "attack_surface_score": overview_attack_surface_score if overview_attack_surface_score is not None else fallback_metadata["attack_surface_score"],
            "recommended_attack_priorities": overview.get("recommended_attack_priorities") or fallback_metadata["recommended_attack_priorities"],
            "generation_warnings": warnings,
            "generation_strategy": "chunked",
            "chunk_count": len(initial_chunks),
            "pending_chunk_count": pending_chunk_count,
            "completed_chunk_signatures": sorted(completed_chunk_signatures),
            "covered_component_ids": sorted(_covered_component_ids_from_threats(merged)),
            "generation_status": status,
        }
        await _persist_threat_generation_state(
            tm,
            db,
            threats=merged,
            summary=_normalize_text(overview.get("summary")) or fallback_metadata["summary"],
            analysis_metadata=analysis_metadata,
            deep_dive_cache=deep_dive_cache_state,
        )

    pending_initial_chunks: list[dict[str, Any]] = []
    covered_component_ids = _covered_component_ids_from_threats(generated_threats)
    for chunk in initial_chunks:
        signature = _threat_chunk_signature(chunk)
        component_ids = {
            component_id for component_id in chunk.get("component_ids", [])
            if isinstance(component_id, str) and component_id
        }
        if resume_existing and (
            signature in completed_chunk_signatures
            or (component_ids and component_ids.issubset(covered_component_ids))
        ):
            continue
        pending_initial_chunks.append(chunk)

    if resume_existing and pending_initial_chunks:
        warnings.append("Resumed threat generation from previously persisted partial results.")

    await _save_progress("running", len(pending_initial_chunks))

    for index, chunk in enumerate(pending_initial_chunks, start=1):
        chunk_results = await _generate_chunk_threats(
            config,
            project_name=project.name if project else "Unknown",
            reference_context_preset=getattr(project, "context_preset", ""),
            reference_objective=project.root_objective or tm.name or project.name,
            scope=tm.scope,
            methodology=tm.methodology,
            planning_label=planning_label,
            planning_domain=planning_domain,
            planning_guidance=planning_guidance,
            operator_guidance=data.user_guidance,
            chunk=chunk,
            overview=overview,
            components=tm.components or [],
            data_flows=tm.data_flows or [],
            trust_boundaries=tm.trust_boundaries or [],
            warnings=warnings,
            seen_ids=seen_ids,
        )
        if chunk_results:
            completed_chunk_signatures.add(_threat_chunk_signature(chunk))
            generated_threats.extend(chunk_results)
        pending_remaining = max(0, len(pending_initial_chunks) - index)
        await _save_progress("running", pending_remaining)

    merged_threats = _merge_threats(generated_threats)
    uncovered_components = [
        component for component in (tm.components or [])
        if isinstance(component, dict)
        and _normalize_text(component.get("id"))
        and _normalize_text(component.get("id")) not in _covered_component_ids_from_threats(merged_threats)
    ]
    if uncovered_components:
        warnings.append(
            "Ran targeted coverage supplements for components that did not receive a concrete threat in the first pass."
        )
        for index, component in enumerate(uncovered_components, start=1):
            supplement_chunk = _compose_threat_chunk(
                f"Coverage supplement: {_normalize_text(component.get('name')) or _normalize_text(component.get('id'))}",
                [_normalize_text(component.get("id"))],
                tm.components or [],
                tm.data_flows or [],
                tm.trust_boundaries or [],
            )
            if supplement_chunk:
                supplement_results = await _generate_chunk_threats(
                    config,
                    project_name=project.name if project else "Unknown",
                    reference_context_preset=getattr(project, "context_preset", ""),
                    reference_objective=project.root_objective or tm.name or project.name,
                    scope=tm.scope,
                    methodology=tm.methodology,
                    planning_label=planning_label,
                    planning_domain=planning_domain,
                    planning_guidance=planning_guidance,
                    operator_guidance=data.user_guidance,
                    chunk=supplement_chunk,
                    overview=overview,
                    components=tm.components or [],
                    data_flows=tm.data_flows or [],
                    trust_boundaries=tm.trust_boundaries or [],
                    warnings=warnings,
                    seen_ids=seen_ids,
                )
                if supplement_results:
                    generated_threats.extend(supplement_results)
            await _save_progress("running", max(0, len(uncovered_components) - index))
        merged_threats = _merge_threats(generated_threats)

    if not merged_threats:
        await _save_progress("failed", len(initial_chunks))
        raise HTTPException(502, "AI returned empty or malformed threats across all chunked attempts — try again or simplify the scope")

    final_uncovered_components = [
        component for component in (tm.components or [])
        if isinstance(component, dict)
        and _normalize_text(component.get("id"))
        and _normalize_text(component.get("id")) not in _covered_component_ids_from_threats(merged_threats)
    ]
    hard_failures = any(warning.startswith("Unable to generate threats") for warning in warnings)
    final_status = "partial" if final_uncovered_components or hard_failures else "completed"
    remaining_resume_chunks = [
        chunk for chunk in initial_chunks
        if not {
            component_id for component_id in chunk.get("component_ids", [])
            if isinstance(component_id, str) and component_id
        }.issubset(_covered_component_ids_from_threats(merged_threats))
    ]
    await _save_progress(final_status, len(remaining_resume_chunks) if final_status == "partial" else 0)
    await record_analysis_run(
        db,
        project_id=tm.project_id,
        tool="threat_model",
        run_type="threat_generation",
        status=final_status,
        artifact_kind="threat_model",
        artifact_id=tm.id,
        artifact_name=tm.name,
        summary=(
            f"Threat generation {final_status} with {len(tm.threats or [])} threat"
            f"{'' if len(tm.threats or []) == 1 else 's'} across {len(tm.components or [])} component"
            f"{'' if len(tm.components or []) == 1 else 's'}."
        ),
        metadata={
            "threat_count": len(tm.threats or []),
            "component_count": len(tm.components or []),
            "remaining_resume_chunks": len(remaining_resume_chunks),
            "methodology": tm.methodology,
        },
        duration_ms=round((perf_counter() - started_at) * 1000),
    )
    return {
        **_to_dict(tm),
    }


@router.post("/{tm_id}/link-to-tree")
async def link_threats_to_tree(tm_id: str, data: AILinkToTreeRequest, db: AsyncSession = Depends(get_db)):
    """Create attack tree nodes from identified threats."""
    tm = await _get_or_404(tm_id, db)
    if not tm.threats:
        raise HTTPException(400, "No threats generated yet")

    project = await require_project_access(tm.project_id, db)

    # Get existing root node if any
    root_result = await db.execute(
        select(Node).where(Node.project_id == tm.project_id, Node.parent_id == None)
        .order_by(Node.sort_order).limit(1)
    )
    root_node = root_result.scalar_one_or_none()

    threats_to_link = copy.deepcopy(tm.threats or [])
    if data.threat_ids:
        id_set = set(data.threat_ids)
        selected_threats = [(index, threat) for index, threat in enumerate(threats_to_link) if threat.get("id") in id_set]
    else:
        selected_threats = list(enumerate(threats_to_link))

    if not selected_threats:
        return {
            "created": 0,
            "skipped": 0,
            "node_ids": [],
            "created_threat_ids": [],
            "skipped_threat_ids": [],
        }

    linked_ids = {
        threat.get("linked_node_id")
        for _, threat in selected_threats
        if isinstance(threat.get("linked_node_id"), str) and threat.get("linked_node_id")
    }
    valid_linked_ids: set[str] = set()
    if linked_ids:
        linked_result = await db.execute(
            select(Node.id).where(Node.project_id == tm.project_id, Node.id.in_(linked_ids))
        )
        valid_linked_ids = set(linked_result.scalars().all())

    sibling_query = select(Node).where(Node.project_id == tm.project_id)
    if root_node:
        sibling_query = sibling_query.where(Node.parent_id == root_node.id)
    else:
        sibling_query = sibling_query.where(Node.parent_id == None)
    sibling_result = await db.execute(sibling_query)
    existing_siblings = sibling_result.scalars().all()
    next_sort_order = max((node.sort_order or 0 for node in existing_siblings), default=99) + 1

    created_ids: list[str] = []
    created_threat_ids: list[str] = []
    skipped_threat_ids: list[str] = []
    y_offset = 200
    for i, (_, threat) in enumerate(selected_threats):
        linked_node_id = threat.get("linked_node_id")
        if linked_node_id and linked_node_id in valid_linked_ids:
            if threat.get("id"):
                skipped_threat_ids.append(threat["id"])
            continue
        if linked_node_id and linked_node_id not in valid_linked_ids:
            threat.pop("linked_node_id", None)

        node = Node(
            project_id=tm.project_id,
            parent_id=root_node.id if root_node else None,
            node_type="weakness" if threat.get("severity") in ("critical", "high") else "attack_step",
            title=threat.get("title", "Threat"),
            description=threat.get("description", ""),
            threat_category=threat.get("category") or threat.get("pasta_stage", ""),
            attack_surface=threat.get("attack_vector", ""),
            likelihood=threat.get("likelihood"),
            impact=threat.get("impact"),
            status="draft",
            position_x=200 + (i % 4) * 300,
            position_y=y_offset + (i // 4) * 200,
            sort_order=next_sort_order,
            notes=f"From threat model: {tm.name}\nMitigation: {threat.get('mitigation', '')}",
        )
        node.inherent_risk = compute_inherent_risk(
            node.likelihood, node.impact, node.effort,
            node.exploitability, node.detectability,
        )
        db.add(node)
        await db.flush()
        next_sort_order += 1
        created_ids.append(node.id)
        if threat.get("id"):
            created_threat_ids.append(threat["id"])

        # Update threat with linked node id
        threat["linked_node_id"] = node.id

    tm.threats = threats_to_link
    await db.commit()
    return {
        "created": len(created_ids),
        "skipped": len(skipped_threat_ids),
        "node_ids": created_ids,
        "created_threat_ids": created_threat_ids,
        "skipped_threat_ids": skipped_threat_ids,
    }


@router.post("/{tm_id}/ai-deep-dive")
async def ai_deep_dive_threat(tm_id: str, data: AIDeepDiveRequest, db: AsyncSession = Depends(get_db)):
    """AI provides a detailed offensive exploitation analysis of a specific threat."""
    tm = await _get_or_404(tm_id, db)
    cached = tm.deep_dive_cache or {}
    if not data.refresh and isinstance(cached, dict) and data.threat_id in cached:
        return cached[data.threat_id]

    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    threat = next((t for t in (tm.threats or []) if t.get("id") == data.threat_id), None)
    if not threat:
        raise HTTPException(404, "Threat not found in this threat model")

    project = await require_project_access(tm.project_id, db)

    component = next((c for c in (tm.components or []) if c.get("id") == threat.get("component_id")), None)

    prompt = f"""You are an expert red team operator providing a detailed exploitation deep-dive for a specific threat.

**Target Project:** {project.name if project else 'Unknown'}
**System Scope:** {tm.scope}
**Target Component:** {_compact_json(component) if component else 'Unknown'}
**Threat Details:** {_compact_json(threat)}

Provide a comprehensive offensive analysis of this specific threat. Be detailed, technical, and realistic.

Return JSON:
{{
  "exploitation_narrative": "A 3-5 paragraph step-by-step narrative of how a skilled attacker would discover and exploit this vulnerability in a real engagement",
  "attack_chain": [
    {{
      "step": 1,
      "phase": "Reconnaissance|Weaponization|Delivery|Exploitation|Installation|C2|Actions",
      "action": "Specific action the attacker takes",
      "tools": "Tools or techniques used (e.g. Burp Suite, sqlmap, Metasploit, custom Python)",
      "output": "What the attacker gains from this step",
      "detection_risk": "low|medium|high — how likely defenders are to notice"
    }}
  ],
  "prerequisites": ["What the attacker needs before attempting this"],
  "indicators_of_compromise": ["Specific IOCs defenders should monitor"],
  "evasion_techniques": ["Specific techniques to avoid detection during exploitation"],
  "real_world_examples": ["CVE-XXXX-YYYY or named APT campaigns that used similar techniques"],
  "risk_rating": {{
    "exploitability": 1-10,
    "impact": 1-10,
    "overall": 1-100
  }},
  "pivot_opportunities": ["What the attacker could do next after successful exploitation — lateral movement, privilege escalation, data exfiltration"],
  "defensive_gaps": ["Specific defensive controls that would be weak or missing against this attack"]
}}

Be specific, technical, and reference real tools, techniques, and CVEs.
Return ONLY valid JSON."""

    config = _provider_to_config(provider)
    messages = [
        {"role": "system", "content": "You are an expert red team operator. Provide detailed, technical exploitation analysis as if briefing a penetration testing team. Respond only with valid JSON."},
        {"role": "user", "content": prompt},
    ]

    parsed, error_message = await _request_json_object_with_retries(
        config,
        messages,
        temperature=0.5,
        max_tokens=8192,
        timeout_override=180,
        required_keys=("exploitation_narrative", "attack_chain"),
    )
    if not parsed:
        raise HTTPException(502, f"LLM request failed: {error_message}")

    tm.deep_dive_cache = {
        **(tm.deep_dive_cache or {}),
        data.threat_id: parsed,
    }
    await db.commit()
    return parsed


@router.post("/project/{project_id}/ai-full-analysis")
async def ai_full_threat_model(project_id: str, data: AIGenerateDFDRequest, db: AsyncSession = Depends(get_db)):
    """One-shot: AI generates DFD + threats from a system description."""
    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    project = await require_project_access(project_id, db)

    methodology = data.methodology if data.methodology in ("stride", "pasta", "linddun") else "stride"

    # Create threat model
    tm = ThreatModel(
        project_id=project_id,
        name=data.name or f"Threat Model — {project.name}",
        description=data.system_description[:200],
        methodology=methodology,
        scope=data.system_description,
    )
    db.add(tm)
    await db.commit()
    await db.refresh(tm)

    try:
        # Step 1: Generate DFD
        await ai_generate_dfd(tm.id, data, db)
        await db.refresh(tm)
        dfd_metadata = tm.dfd_metadata if isinstance(tm.dfd_metadata, dict) else {}
        if dfd_metadata.get("generation_status") != "completed":
            raise HTTPException(502, "DFD generation only completed partially. Resume DFD generation from the threat model before running full analysis again.")
        # Step 2: Generate threats
        await ai_generate_threats(
            tm.id,
            AIGenerateThreatsRequest(
                user_guidance=data.user_guidance,
                planning_profile=data.planning_profile,
            ),
            db,
        )
    except HTTPException:
        # Clean up the half-created model on failure
        await db.refresh(tm)
        if not tm.components and not tm.threats:
            await db.delete(tm)
            await db.commit()
        raise

    await db.refresh(tm)
    return _to_dict(tm)


# --- Helpers ---

async def _get_or_404(tm_id: str, db: AsyncSession) -> ThreatModel:
    return await require_threat_model_access(tm_id, db)


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


def _to_dict(tm: ThreatModel) -> dict:
    return {
        "id": tm.id,
        "project_id": tm.project_id,
        "name": tm.name,
        "description": tm.description,
        "methodology": tm.methodology,
        "scope": tm.scope or "",
        "components": tm.components or [],
        "data_flows": tm.data_flows or [],
        "trust_boundaries": tm.trust_boundaries or [],
        "threats": tm.threats or [],
        "ai_summary": tm.ai_summary or "",
        "dfd_metadata": tm.dfd_metadata or {},
        "analysis_metadata": tm.analysis_metadata or {},
        "deep_dive_cache": tm.deep_dive_cache or {},
        "created_at": tm.created_at.isoformat() if tm.created_at else "",
        "updated_at": tm.updated_at.isoformat() if tm.updated_at else "",
    }
