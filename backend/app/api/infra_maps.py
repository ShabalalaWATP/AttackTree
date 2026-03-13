"""
Infrastructure Map API — AI-powered hardware/software mind-map builder.
"""
import json
import uuid
from time import perf_counter
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..database import get_db
from ..models.infra_map import InfraMap
from ..models.project import Project
from ..models.llm_config import LLMProviderConfig
from ..services.access_control import (
    get_active_provider_for_user,
    require_infra_map_access,
    require_project_access,
)
from ..services.auth import get_current_user_id
from ..services.analysis_runs import record_analysis_run
from ..services.environment_catalog_service import build_environment_catalog_outline_for_context
from ..services import llm_service
from ..services.reference_search_service import (
    candidate_to_reference_link,
    dedupe_reference_links,
    format_reference_candidates_for_prompt,
    search_references,
)

router = APIRouter(prefix="/infra-maps", tags=["infra_maps"])


VALID_CATEGORIES = {
    "infrastructure", "hardware", "software", "networking", "security",
    "ot_ics", "cloud", "service", "endpoint", "storage",
    "physical", "personnel", "process", "general",
}
VALID_ICONS = {
    "server", "database", "monitor", "network", "shield", "cloud",
    "lock", "cpu", "hard-drive", "radio", "building", "users",
    "cog", "globe", "terminal", "wifi", "camera", "printer",
    "phone", "router", "firewall", "switch",
}
CATEGORY_DEFAULT_ICONS = {
    "infrastructure": "building",
    "hardware": "server",
    "software": "terminal",
    "networking": "network",
    "security": "shield",
    "ot_ics": "cpu",
    "cloud": "cloud",
    "service": "globe",
    "endpoint": "monitor",
    "storage": "hard-drive",
    "physical": "building",
    "personnel": "users",
    "process": "cog",
    "general": "cog",
}


# --- Schemas ---

class InfraMapCreate(BaseModel):
    project_id: Optional[str] = None
    name: str
    description: str = ""


class InfraMapUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    nodes: Optional[list] = None


class AIExpandRequest(BaseModel):
    node_id: str
    user_guidance: str = ""
    planning_profile: str = "balanced"


class AIGenerateRequest(BaseModel):
    root_label: str = ""
    user_guidance: str = ""
    planning_profile: str = "balanced"


def _infra_map_planning_context(planning_profile: str, objective: str, scope: str, context_preset: str = "") -> tuple[str, str, str, str]:
    normalized_profile = llm_service.normalize_planning_profile(planning_profile)
    domain = llm_service.detect_planning_domain(objective, scope, context_preset)
    profile_label = llm_service.get_planning_profile_label(normalized_profile)

    if normalized_profile == "planning_first":
        artifact_guidance = (
            "Infrastructure-map planning workflow:\n"
            "- Use the first two layers to decompose the environment into meaningful operational domains, management planes, actor groups, and trust boundaries before listing specific products.\n"
            "- Prefer categories that help planners reason about dependencies, choke points, shared services, and blast radius.\n"
            "- Add concrete technologies deeper in each branch once the structure is useful for discussion."
        )
    elif normalized_profile == "reference_heavy":
        artifact_guidance = (
            "Infrastructure-map planning workflow:\n"
            "- Keep the top structure domain-oriented and planning-useful.\n"
            "- Move into specific technologies, product families, and notable control platforms earlier in each branch when the context is concrete.\n"
            "- Do not let the map collapse into a flat product inventory with no meaningful operating structure."
        )
    else:
        artifact_guidance = (
            "Infrastructure-map planning workflow:\n"
            "- Keep the first layer domain-oriented and useful for planning.\n"
            "- Use the next layers to turn each branch into concrete systems, platforms, dependencies, and security-relevant infrastructure.\n"
            "- Maintain coverage across management, identity, networking, storage, monitoring, remote access, and third-party dependencies where they matter."
        )

    guidance = "\n".join(
        section for section in [
            llm_service.get_domain_decomposition_guidance(domain),
            build_environment_catalog_outline_for_context(objective, scope, context_preset),
            artifact_guidance,
        ] if section
    )
    return normalized_profile, profile_label, domain, guidance


# --- Helpers ---

async def _get_or_404(im_id: str, db: AsyncSession) -> InfraMap:
    return await require_infra_map_access(im_id, db)


async def _get_project(project_id: str, db: AsyncSession) -> Project:
    return await require_project_access(project_id, db)


def _to_dict(im: InfraMap) -> dict:
    return {
        "id": im.id,
        "project_id": im.project_id,
        "name": im.name,
        "description": im.description,
        "nodes": im.nodes or [],
        "ai_summary": im.ai_summary or "",
        "analysis_metadata": im.analysis_metadata or {},
        "created_at": im.created_at.isoformat() if im.created_at else None,
        "updated_at": im.updated_at.isoformat() if im.updated_at else None,
    }


def _workspace_mode(project: Optional[Project]) -> str:
    if not project:
        return "standalone"
    return (project.metadata_json or {}).get("workspace_mode", "project_scan")


def _normalize_category(category: str | None) -> str:
    category_value = (category or "general").strip().lower().replace(" ", "_")
    return category_value if category_value in VALID_CATEGORIES else "general"


def _normalize_icon(icon_hint: str | None, category: str) -> str:
    icon_value = (icon_hint or "").strip().lower()
    if icon_value in VALID_ICONS:
        return icon_value
    return CATEGORY_DEFAULT_ICONS.get(category, "cog")


def _normalize_position(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and abs(float(value)) <= 100000:
        return int(round(float(value)))
    try:
        parsed = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if abs(parsed) > 100000:
        return None
    return int(round(parsed))


def _normalize_node(node: dict, *, parent_id: str | None = None, manually_added: Optional[bool] = None) -> dict:
    category = _normalize_category(node.get("category"))
    label = str(node.get("label") or "Unnamed node").strip() or "Unnamed node"
    return {
        "id": str(node.get("id") or uuid.uuid4()),
        "parent_id": parent_id if parent_id is not None else node.get("parent_id"),
        "label": label[:160],
        "category": category,
        "description": str(node.get("description") or "").strip(),
        "icon_hint": _normalize_icon(node.get("icon_hint"), category),
        "children_loaded": bool(node.get("children_loaded", False)),
        "manually_added": bool(node.get("manually_added", False)) if manually_added is None else manually_added,
        "position_x": _normalize_position(node.get("position_x")),
        "position_y": _normalize_position(node.get("position_y")),
        "references": dedupe_reference_links([item for item in node.get("references", []) if isinstance(item, dict)]),
    }


def _normalize_nodes(nodes: list[dict]) -> list[dict]:
    normalized = []
    seen_keys: set[tuple[str | None, str]] = set()

    for raw_node in nodes or []:
        node = _normalize_node(raw_node)
        dedupe_key = (node["parent_id"], node["label"].strip().lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        normalized.append(node)

    valid_ids = {node["id"] for node in normalized}
    parent_ids = {node["parent_id"] for node in normalized if node.get("parent_id")}

    for node in normalized:
        if node["parent_id"] and node["parent_id"] not in valid_ids:
            node["parent_id"] = None
        if node["id"] in parent_ids:
            node["children_loaded"] = True

    return normalized


def _attach_reference_links_to_nodes(
    nodes: list[dict],
    *,
    objective: str,
    scope: str,
    context_preset: str,
) -> list[dict]:
    attached: list[dict] = []
    for node in nodes:
        node_copy = dict(node)
        if node_copy.get("references"):
            attached.append(node_copy)
            continue
        query = " ".join(
            part for part in [
                str(node_copy.get("label") or ""),
                str(node_copy.get("category") or ""),
                str(node_copy.get("description") or ""),
            ] if part
        )
        node_copy["references"] = dedupe_reference_links(
            [
                candidate_to_reference_link(candidate, source="ai")
                for candidate in search_references(
                query=query,
                artifact_type="infra_map",
                context_preset=context_preset,
                objective=objective,
                scope=scope,
                target_kind="infra_node",
                target_summary=query,
                allowed_frameworks=[
                    "environment_catalog",
                    "infra_attack_patterns",
                    "software_research_patterns",
                    "attack",
                    "owasp",
                ],
                limit=4,
                )
            ]
        )
        attached.append(node_copy)
    return attached


def _infra_candidate_references(
    *,
    query: str,
    objective: str,
    scope: str,
    context_preset: str,
    target_kind: str,
    target_summary: str,
    limit: int = 10,
) -> list[dict[str, Any]]:
    return search_references(
        query=query,
        artifact_type="infra_map",
        context_preset=context_preset,
        objective=objective,
        scope=scope,
        target_kind=target_kind,
        target_summary=target_summary,
        allowed_frameworks=[
            "environment_catalog",
            "infra_attack_patterns",
            "software_research_patterns",
            "attack",
            "owasp",
        ],
        limit=limit,
    )


def _dedupe_children(nodes: list[dict], parent_id: str, raw_children: list[dict], *, manually_added: bool = False) -> list[dict]:
    existing_keys = {
        (node.get("parent_id"), str(node.get("label") or "").strip().lower())
        for node in nodes
    }
    new_children = []

    for raw_child in raw_children or []:
        child = _normalize_node(raw_child, parent_id=parent_id, manually_added=manually_added)
        dedupe_key = (parent_id, child["label"].strip().lower())
        if dedupe_key in existing_keys:
            continue
        existing_keys.add(dedupe_key)
        new_children.append(child)

    return new_children


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _node_structure_signature(nodes: list[dict]) -> str:
    signature_rows = []
    for raw_node in _normalize_nodes(nodes or []):
        signature_rows.append({
            "id": raw_node["id"],
            "parent_id": raw_node.get("parent_id"),
            "label": raw_node.get("label"),
            "category": raw_node.get("category"),
            "icon_hint": raw_node.get("icon_hint"),
            "children_loaded": bool(raw_node.get("children_loaded")),
            "manually_added": bool(raw_node.get("manually_added")),
        })
    signature_rows.sort(key=lambda item: item["id"])
    return _compact_json(signature_rows)


def _provider_to_config(provider: LLMProviderConfig) -> dict[str, Any]:
    return {
        "base_url": provider.base_url,
        "api_key_encrypted": provider.api_key_encrypted,
        "model": provider.model,
        "timeout": provider.timeout or 120,
        "custom_headers": provider.custom_headers or {},
        "tls_verify": provider.tls_verify,
        "ca_bundle_path": provider.ca_bundle_path or "",
        "client_cert_path": provider.client_cert_path or "",
        "client_key_path": provider.client_key_path or "",
    }


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
    for attempt in range(3):
        attempt_messages = messages
        if attempt:
            attempt_messages = [
                *messages,
                {
                    "role": "user",
                    "content": (
                        "The previous response was missing required structure or valid JSON. "
                        "Retry and return only valid JSON with all requested keys populated."
                    ),
                },
            ]
        response = await llm_service.chat_completion(
            config,
            attempt_messages,
            temperature=max(0.2, temperature - (attempt * 0.1)),
            max_tokens=max_tokens,
            timeout_override=timeout_override,
        )
        if response.get("status") != "success":
            last_error = response.get("message", "LLM request failed")
            continue
        parsed = llm_service.parse_json_object_response(response.get("content", ""))
        if not required_keys or all(key in parsed for key in required_keys):
            return parsed, ""
        last_error = "LLM returned malformed or incomplete JSON"
    return {}, last_error


DEFAULT_INFRA_BRANCHES = [
    {"label": "Identity and Access", "category": "security", "description": "Directory services, authentication paths, privileged access, and remote administration.", "icon_hint": "lock"},
    {"label": "Compute and Workloads", "category": "hardware", "description": "Server, virtualization, application hosting, and control-plane workloads.", "icon_hint": "server"},
    {"label": "Network and Segmentation", "category": "networking", "description": "Routing, switching, perimeter controls, segmentation, and remote connectivity.", "icon_hint": "network"},
    {"label": "Data, Storage, and Recovery", "category": "storage", "description": "Datastores, storage fabric, backup systems, and recovery dependencies.", "icon_hint": "database"},
    {"label": "Monitoring and Security Tooling", "category": "security", "description": "Logging, telemetry, monitoring, EDR, SIEM, and defensive tooling.", "icon_hint": "shield"},
    {"label": "Endpoints, Users, and Third Parties", "category": "endpoint", "description": "Operator endpoints, remote access clients, partner integrations, and user-facing systems.", "icon_hint": "monitor"},
]


def _fallback_overview(root_label: str) -> dict[str, Any]:
    branches = []
    for index, branch in enumerate(DEFAULT_INFRA_BRANCHES, start=1):
        branches.append({
            "temp_id": f"BRANCH_{index}",
            **branch,
        })
    return {
        "root": {
            "label": root_label,
            "category": "infrastructure",
            "description": f"Operational infrastructure map for {root_label}.",
        },
        "branches": branches,
        "ai_summary": f"{root_label} decomposed into core operational domains for infrastructure and attack-surface planning.",
    }


def _normalize_overview_payload(parsed: dict[str, Any], root_label: str) -> dict[str, Any]:
    fallback = _fallback_overview(root_label)
    root_raw = parsed.get("root") if isinstance(parsed.get("root"), dict) else {}
    root = {
        "label": _normalize_text(root_raw.get("label")) or root_label,
        "category": "infrastructure",
        "description": _normalize_text(root_raw.get("description")) or fallback["root"]["description"],
    }

    normalized_branches: list[dict[str, str]] = []
    seen_labels: set[str] = set()
    for index, raw_branch in enumerate(parsed.get("branches", []), start=1):
        if not isinstance(raw_branch, dict):
            continue
        label = _normalize_text(raw_branch.get("label"))
        if not label:
            continue
        key = label.lower()
        if key in seen_labels:
            continue
        seen_labels.add(key)
        category = _normalize_category(raw_branch.get("category"))
        normalized_branches.append({
            "temp_id": _normalize_text(raw_branch.get("temp_id")) or f"BRANCH_{index}",
            "label": label[:160],
            "category": category,
            "description": _normalize_text(raw_branch.get("description")) or f"{label} systems and dependencies.",
            "icon_hint": _normalize_icon(raw_branch.get("icon_hint"), category),
        })

    if len(normalized_branches) < 3:
        normalized_branches = fallback["branches"]

    return {
        "root": root,
        "branches": normalized_branches[:8],
        "ai_summary": _normalize_text(parsed.get("ai_summary")) or fallback["ai_summary"],
    }


def _normalize_branch_detail_payload(
    parsed: dict[str, Any],
    branch: dict[str, str],
) -> tuple[list[dict[str, str]], str]:
    nodes: list[dict[str, str]] = []
    seen_keys: set[tuple[str, str]] = set()
    seen_temp_ids = {branch["temp_id"]}

    for index, raw_node in enumerate(parsed.get("nodes", []), start=1):
        if not isinstance(raw_node, dict):
            continue
        label = _normalize_text(raw_node.get("label"))
        if not label:
            continue
        temp_id = _normalize_text(raw_node.get("temp_id")) or f"{branch['temp_id']}_NODE_{index}"
        parent_temp_id = _normalize_text(raw_node.get("parent_temp_id")) or branch["temp_id"]
        if parent_temp_id not in seen_temp_ids:
            parent_temp_id = branch["temp_id"]
        dedupe_key = (parent_temp_id, label.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        category = _normalize_category(raw_node.get("category"))
        nodes.append({
            "temp_id": temp_id,
            "parent_temp_id": parent_temp_id,
            "label": label[:160],
            "category": category,
            "description": _normalize_text(raw_node.get("description")) or f"{label} within {branch['label']}.",
            "icon_hint": _normalize_icon(raw_node.get("icon_hint"), category),
        })
        seen_temp_ids.add(temp_id)

    branch_summary = _normalize_text(parsed.get("branch_summary") or parsed.get("summary"))
    return nodes[:18], branch_summary


def _normalize_branch_children_payload(parsed: dict[str, Any], branch: dict[str, str]) -> tuple[list[dict[str, str]], str]:
    nodes: list[dict[str, str]] = []
    seen_labels: set[str] = set()
    for index, raw_node in enumerate(parsed.get("children", []), start=1):
        if not isinstance(raw_node, dict):
            continue
        label = _normalize_text(raw_node.get("label"))
        if not label or label.lower() in seen_labels:
            continue
        seen_labels.add(label.lower())
        category = _normalize_category(raw_node.get("category"))
        nodes.append({
            "temp_id": f"{branch['temp_id']}_CHILD_{index}",
            "parent_temp_id": branch["temp_id"],
            "label": label[:160],
            "category": category,
            "description": _normalize_text(raw_node.get("description")) or f"{label} within {branch['label']}.",
            "icon_hint": _normalize_icon(raw_node.get("icon_hint"), category),
        })
    branch_summary = _normalize_text(parsed.get("summary"))
    return nodes[:8], branch_summary


def _build_overview_messages(
    *,
    root_label: str,
    project_name: str,
    objective: str,
    description: str,
    environment_label: str,
    workspace_mode: str,
    planning_label: str,
    planning_domain: str,
    planning_guidance: str,
    operator_guidance: str,
    candidate_reference_block: str,
) -> list[dict[str, str]]:
    system_msg = (
        "You are a senior infrastructure architect and security consultant. "
        "Plan the top-level structure of an infrastructure mind map for security assessment and attack-surface analysis."
    )
    user_msg = f"""Create the top-level plan for an infrastructure mind map.

**Root / Top-level:** "{root_label}"
**Project context:** {project_name} — {objective}
**Environment type:** {environment_label}
**Workspace mode:** {workspace_mode}
**Description:** {description or 'No additional description provided'}
**Planning Profile:** {planning_label}
**Detected Planning Domain:** {planning_domain}
"""
    if operator_guidance:
        user_msg += f"\n**Operator guidance:** {operator_guidance}\n"
    if candidate_reference_block:
        user_msg += f"\n{candidate_reference_block}\n"
    user_msg += planning_guidance + """

Return a JSON object:
{
  "root": {
    "label": "root label",
    "category": "infrastructure",
    "description": "brief description of the infrastructure scope"
  },
  "branches": [
    {
      "temp_id": "BRANCH_1",
      "label": "top-level branch name",
      "category": "one of: infrastructure|hardware|software|networking|security|ot_ics|cloud|service|endpoint|storage|physical|personnel|process",
      "description": "1-2 sentence description",
      "icon_hint": "one of: server|database|monitor|network|shield|cloud|lock|cpu|hard-drive|radio|building|users|cog|globe|terminal|wifi|camera|printer|phone|router|firewall|switch"
    }
  ],
  "ai_summary": "2-3 sentence overview of the environment and the key security-relevant infrastructure domains"
}

Requirements:
- Produce 5-8 top-level branches.
- Make the branches planning-useful and mutually distinct.
- Cover identity, compute/workloads, networking, data/recovery, monitoring/security, and user/third-party dependencies where they matter.
- Return ONLY valid JSON.
"""
    return [{"role": "system", "content": system_msg}, {"role": "user", "content": user_msg}]


def _build_branch_messages(
    *,
    root_label: str,
    branch: dict[str, str],
    sibling_labels: list[str],
    overview_summary: str,
    planning_label: str,
    planning_domain: str,
    planning_guidance: str,
    operator_guidance: str,
    candidate_reference_block: str,
) -> list[dict[str, str]]:
    system_msg = (
        "You are a senior infrastructure architect and security consultant. "
        "Expand one branch of an infrastructure mind map into concrete child systems, dependencies, and management paths."
    )
    user_msg = f"""Expand a branch in an infrastructure mind map.

**Root / Top-level:** "{root_label}"
**Branch:** "{branch['label']}"
**Branch category:** {branch['category']}
**Branch description:** {branch['description']}
**Sibling branches (avoid duplication):** {json.dumps(sibling_labels) if sibling_labels else '[]'}
**Current map summary:** {overview_summary or 'No summary yet'}
**Planning Profile:** {planning_label}
**Detected Planning Domain:** {planning_domain}
"""
    if operator_guidance:
        user_msg += f"\n**Operator guidance:** {operator_guidance}\n"
    if candidate_reference_block:
        user_msg += f"\n{candidate_reference_block}\n"
    user_msg += planning_guidance + f"""

Return a JSON object:
{{
  "nodes": [
    {{
      "temp_id": "{branch['temp_id']}_NODE_1",
      "parent_temp_id": "{branch['temp_id']}",
      "label": "child node",
      "category": "one of: infrastructure|hardware|software|networking|security|ot_ics|cloud|service|endpoint|storage|physical|personnel|process",
      "description": "1-2 sentence description",
      "icon_hint": "one of: server|database|monitor|network|shield|cloud|lock|cpu|hard-drive|radio|building|users|cog|globe|terminal|wifi|camera|printer|phone|router|firewall|switch"
    }}
  ],
  "branch_summary": "one sentence on what this branch covers"
}}

Requirements:
- Generate 6-16 nodes total for this branch.
- Use 2-3 levels of depth under the branch when it adds planning value.
- Include management planes, trust boundaries, telemetry, remote access, third-party dependencies, and recovery elements when they belong in this branch.
- Avoid duplicating the sibling branches.
- Return ONLY valid JSON.
"""
    return [{"role": "system", "content": system_msg}, {"role": "user", "content": user_msg}]


def _build_branch_fallback_messages(
    *,
    root_label: str,
    branch: dict[str, str],
    overview_summary: str,
    planning_guidance: str,
    candidate_reference_block: str,
) -> list[dict[str, str]]:
    system_msg = (
        "You are a senior infrastructure architect and security consultant. "
        "Return a small set of direct children for one infrastructure branch."
    )
    user_msg = f"""Return only direct children for this branch.

**Root / Top-level:** "{root_label}"
**Branch:** "{branch['label']}"
**Branch description:** {branch['description']}
**Current map summary:** {overview_summary or 'No summary yet'}

{candidate_reference_block}

{planning_guidance}

Return a JSON object:
{{
  "children": [
    {{
      "label": "direct child",
      "category": "one of: infrastructure|hardware|software|networking|security|ot_ics|cloud|service|endpoint|storage|physical|personnel|process",
      "description": "1-2 sentence description",
      "icon_hint": "one of: server|database|monitor|network|shield|cloud|lock|cpu|hard-drive|radio|building|users|cog|globe|terminal|wifi|camera|printer|phone|router|firewall|switch"
    }}
  ],
  "summary": "one sentence on what this branch covers"
}}

Requirements:
- Generate 4-8 direct children only.
- Return ONLY valid JSON.
"""
    return [{"role": "system", "content": system_msg}, {"role": "user", "content": user_msg}]


async def _generate_branch_nodes(
    config: dict[str, Any],
    *,
    root_label: str,
    branch: dict[str, str],
    overview_summary: str,
    sibling_labels: list[str],
    planning_label: str,
    planning_domain: str,
    planning_guidance: str,
    operator_guidance: str,
    objective: str,
    scope: str,
    context_preset: str,
) -> tuple[list[dict[str, str]], str, list[str]]:
    warnings: list[str] = []
    candidate_references = _infra_candidate_references(
        query=" ".join(
            part for part in [
                branch["label"],
                branch["description"],
                overview_summary,
                " ".join(sibling_labels),
            ] if part
        ),
        objective=objective,
        scope=scope,
        context_preset=context_preset,
        target_kind="infra_branch",
        target_summary=" ".join(part for part in [root_label, branch["label"], branch["description"]] if part),
        limit=10,
    )
    candidate_reference_block = format_reference_candidates_for_prompt(candidate_references)
    messages = _build_branch_messages(
        root_label=root_label,
        branch=branch,
        sibling_labels=sibling_labels,
        overview_summary=overview_summary,
        planning_label=planning_label,
        planning_domain=planning_domain,
        planning_guidance=planning_guidance,
        operator_guidance=operator_guidance,
        candidate_reference_block=candidate_reference_block,
    )
    parsed, error_message = await _request_json_object_with_retries(
        config,
        messages,
        temperature=0.4,
        max_tokens=4096,
        timeout_override=120,
        required_keys=("nodes",),
    )
    nodes, branch_summary = _normalize_branch_detail_payload(parsed, branch)
    if nodes:
        return nodes, branch_summary, warnings

    warnings.append(
        f"Branch '{branch['label']}' fell back to direct-child generation: {error_message or 'empty response'}"
    )
    fallback_messages = _build_branch_fallback_messages(
        root_label=root_label,
        branch=branch,
        overview_summary=overview_summary,
        planning_guidance=planning_guidance,
        candidate_reference_block=candidate_reference_block,
    )
    fallback_parsed, fallback_error = await _request_json_object_with_retries(
        config,
        fallback_messages,
        temperature=0.3,
        max_tokens=2048,
        timeout_override=90,
        required_keys=("children",),
    )
    fallback_nodes, fallback_summary = _normalize_branch_children_payload(fallback_parsed, branch)
    if not fallback_nodes:
        warnings.append(
            f"Branch '{branch['label']}' remained top-level only: {fallback_error or 'empty response'}"
        )
    return fallback_nodes, fallback_summary, warnings


def _build_generated_nodes(root: dict[str, Any], branches: list[dict[str, str]], branch_nodes: dict[str, list[dict[str, str]]]) -> list[dict]:
    root_id = str(uuid.uuid4())
    id_map = {"root": root_id}
    generated_nodes = [_normalize_node({
        "id": root_id,
        "parent_id": None,
        "label": root["label"],
        "category": root.get("category", "infrastructure"),
        "description": root.get("description", ""),
        "icon_hint": "building",
        "children_loaded": True,
        "manually_added": False,
    })]

    for branch in branches:
        id_map[branch["temp_id"]] = str(uuid.uuid4())
    for branch in branches:
        generated_nodes.append(_normalize_node({
            "id": id_map[branch["temp_id"]],
            "parent_id": root_id,
            "label": branch["label"],
            "category": branch["category"],
            "description": branch["description"],
            "icon_hint": branch["icon_hint"],
            "children_loaded": bool(branch_nodes.get(branch["temp_id"])),
            "manually_added": False,
        }))

    all_branch_nodes = [node for nodes in branch_nodes.values() for node in nodes]
    for raw_node in all_branch_nodes:
        id_map[raw_node["temp_id"]] = str(uuid.uuid4())

    child_parent_ids = {raw_node["parent_temp_id"] for raw_node in all_branch_nodes}
    for raw_node in all_branch_nodes:
        generated_nodes.append(_normalize_node({
            "id": id_map[raw_node["temp_id"]],
            "parent_id": id_map.get(raw_node["parent_temp_id"], root_id),
            "label": raw_node["label"],
            "category": raw_node["category"],
            "description": raw_node["description"],
            "icon_hint": raw_node["icon_hint"],
            "children_loaded": raw_node["temp_id"] in child_parent_ids,
            "manually_added": False,
        }))

    return _normalize_nodes(generated_nodes)


async def _generate_infra_map_payload(
    config: dict[str, Any],
    *,
    root_label: str,
    project_name: str,
    objective: str,
    description: str,
    environment_label: str,
    workspace_mode: str,
    planning_label: str,
    planning_domain: str,
    planning_guidance: str,
    operator_guidance: str,
) -> tuple[str, str, list[dict], str, dict[str, Any]]:
    warnings: list[str] = []
    overview_candidates = _infra_candidate_references(
        query=" ".join(part for part in [root_label, objective, description, environment_label, operator_guidance] if part),
        objective=objective,
        scope=description,
        context_preset=environment_label,
        target_kind="infra_map_overview",
        target_summary=" ".join(part for part in [project_name, root_label, objective, description] if part),
        limit=12,
    )
    overview_reference_block = format_reference_candidates_for_prompt(overview_candidates)
    overview_messages = _build_overview_messages(
        root_label=root_label,
        project_name=project_name,
        objective=objective,
        description=description,
        environment_label=environment_label,
        workspace_mode=workspace_mode,
        planning_label=planning_label,
        planning_domain=planning_domain,
        planning_guidance=planning_guidance,
        operator_guidance=operator_guidance,
        candidate_reference_block=overview_reference_block,
    )
    overview_parsed, overview_error = await _request_json_object_with_retries(
        config,
        overview_messages,
        temperature=0.4,
        max_tokens=4096,
        timeout_override=120,
        required_keys=("branches",),
    )
    overview = _normalize_overview_payload(overview_parsed, root_label)
    if not overview_parsed:
        warnings.append(f"Infra-map overview generation fell back to default branch plan: {overview_error or 'empty response'}")

    branch_nodes: dict[str, list[dict[str, str]]] = {}
    branch_summaries: list[str] = []
    completed_branches: list[str] = []
    failed_branches: list[str] = []

    for branch in overview["branches"]:
        sibling_labels = [other["label"] for other in overview["branches"] if other["temp_id"] != branch["temp_id"]]
        generated_nodes, branch_summary, branch_warnings = await _generate_branch_nodes(
            config,
            root_label=overview["root"]["label"],
            branch=branch,
            overview_summary=overview["ai_summary"],
            sibling_labels=sibling_labels,
            planning_label=planning_label,
            planning_domain=planning_domain,
            planning_guidance=planning_guidance,
            operator_guidance=operator_guidance,
            objective=objective,
            scope=description,
            context_preset=environment_label,
        )
        if generated_nodes:
            branch_nodes[branch["temp_id"]] = generated_nodes
            completed_branches.append(branch["label"])
        else:
            failed_branches.append(branch["label"])
        if branch_summary:
            branch_summaries.append(f"{branch['label']}: {branch_summary}")
        warnings.extend(branch_warnings)

    if not completed_branches and not overview["branches"]:
        raise HTTPException(502, "Unable to generate a usable infra-map structure")

    ai_summary = overview["ai_summary"]
    if branch_summaries:
        ai_summary = " ".join([ai_summary, " ".join(branch_summaries[:3])]).strip()
    if warnings:
        ai_summary = f"{ai_summary} Coverage note: some branches required fallback generation."

    metadata = {
        "generation_strategy": "multi_pass",
        "generation_status": "partial" if failed_branches else "completed",
        "branch_count": len(overview["branches"]),
        "completed_branch_count": len(completed_branches),
        "failed_branch_count": len(failed_branches),
        "completed_branches": completed_branches,
        "failed_branches": failed_branches,
        "generation_warnings": warnings,
    }
    nodes = _build_generated_nodes(overview["root"], overview["branches"], branch_nodes)
    nodes = _attach_reference_links_to_nodes(
        nodes,
        objective=objective,
        scope=description,
        context_preset=environment_label,
    )
    return overview["root"]["label"], overview["root"]["description"], nodes, ai_summary, metadata


# --- Endpoints ---

@router.get("/project/{project_id}")
async def list_infra_maps(project_id: str, db: AsyncSession = Depends(get_db)):
    await require_project_access(project_id, db)
    result = await db.execute(
        select(InfraMap)
        .where(InfraMap.project_id == project_id, InfraMap.user_id == get_current_user_id())
        .order_by(InfraMap.created_at.desc())
    )
    return [_to_dict(im) for im in result.scalars().all()]


@router.get("/standalone")
async def list_standalone_infra_maps(db: AsyncSession = Depends(get_db)):
    """List infra maps not tied to any project."""
    result = await db.execute(
        select(InfraMap)
        .where(InfraMap.project_id == None, InfraMap.user_id == get_current_user_id())
        .order_by(InfraMap.created_at.desc())
    )
    return [_to_dict(im) for im in result.scalars().all()]


@router.post("", status_code=201)
async def create_infra_map(data: InfraMapCreate, db: AsyncSession = Depends(get_db)):
    if data.project_id:
        await _get_project(data.project_id, db)
    im = InfraMap(**data.model_dump(), user_id=get_current_user_id())
    db.add(im)
    await db.commit()
    await db.refresh(im)
    return _to_dict(im)


@router.get("/{im_id}")
async def get_infra_map(im_id: str, db: AsyncSession = Depends(get_db)):
    im = await _get_or_404(im_id, db)
    return _to_dict(im)


@router.patch("/{im_id}")
async def update_infra_map(im_id: str, data: InfraMapUpdate, db: AsyncSession = Depends(get_db)):
    im = await _get_or_404(im_id, db)
    update_data = data.model_dump(exclude_unset=True)
    if "nodes" in update_data:
        existing_signature = _node_structure_signature(im.nodes or [])
        normalized_nodes = _normalize_nodes(update_data["nodes"] or [])
        update_data["nodes"] = normalized_nodes
        if _node_structure_signature(normalized_nodes) != existing_signature:
            update_data["ai_summary"] = ""
            update_data["analysis_metadata"] = {}
    for key, value in update_data.items():
        setattr(im, key, value)
    await db.commit()
    await db.refresh(im)
    return _to_dict(im)


@router.delete("/{im_id}", status_code=204)
async def delete_infra_map(im_id: str, db: AsyncSession = Depends(get_db)):
    im = await _get_or_404(im_id, db)
    await db.delete(im)
    await db.commit()


@router.post("/{im_id}/ai-expand")
async def ai_expand_node(im_id: str, data: AIExpandRequest, db: AsyncSession = Depends(get_db)):
    """AI expands a specific node in the infra map, generating child nodes."""
    started_at = perf_counter()
    im = await _get_or_404(im_id, db)
    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    proj = None
    if im.project_id:
        proj = await require_project_access(im.project_id, db)
    project = proj

    nodes = im.nodes or []
    target_node = None
    for n in nodes:
        if n.get("id") == data.node_id:
            target_node = n
            break
    if not target_node:
        raise HTTPException(404, "Node not found in map")

    # Build the path from root to this node
    path_labels = _build_path(nodes, data.node_id)
    branch_context = _build_branch_context(nodes, data.node_id)
    existing_children = [n.get("label", "") for n in nodes if n.get("parent_id") == data.node_id]
    sibling_labels = [n.get("label", "") for n in nodes if n.get("parent_id") == target_node.get("parent_id") and n.get("id") != data.node_id]
    _, planning_label, planning_domain, planning_guidance = _infra_map_planning_context(
        data.planning_profile,
        (project.root_objective if project else "") or target_node.get("label", "") or im.name,
        "\n".join(
            part for part in [
                project.description if project else "",
                " → ".join(path_labels),
                target_node.get("description", ""),
                data.user_guidance,
            ] if part
        ),
        getattr(project, "context_preset", "") if project else "",
    )
    candidate_references = _infra_candidate_references(
        query=" ".join(
            part for part in [
                target_node.get("label", ""),
                target_node.get("description", ""),
                " ".join(path_labels),
                " ".join(existing_children),
                data.user_guidance,
            ] if part
        ),
        objective=(project.root_objective if project else "") or im.name,
        scope=(project.description if project else "") or im.description,
        context_preset=getattr(project, "context_preset", "") if project else "",
        target_kind="infra_node",
        target_summary=" ".join(part for part in [im.name, target_node.get("label", ""), target_node.get("description", "")] if part),
        limit=10,
    )
    candidate_reference_block = format_reference_candidates_for_prompt(candidate_references)

    system_msg = (
        "You are a senior infrastructure architect and security consultant. "
        "You are helping build a detailed hardware and software infrastructure map as a hierarchical mind-map. "
        "This map is used for security assessments, attack surface analysis, trust-boundary analysis, and asset inventory."
    )

    user_msg = f"""Expand the following node in an infrastructure mind-map by suggesting child items.

**Workspace mode:** {_workspace_mode(project)}
**Project context:** {project.name if project else 'Standalone infra map'} — {project.root_objective if project else 'Independent infrastructure planning'}
**Environment preset:** {llm_service.get_context_preset_label(project.context_preset) if project else 'infer from node path and operator guidance'}
**Planning Profile:** {planning_label}
**Detected Planning Domain:** {planning_domain}
**Map name:** {im.name}
**Map summary:** {im.ai_summary or 'No summary yet'}
**Node path (root → current):** {' → '.join(path_labels)}
**Ancestor branch context:** {json.dumps(branch_context["ancestors"]) if branch_context["ancestors"] else 'Root or no ancestor detail available'}
**Current node:** "{target_node.get('label', '')}"
**Category:** {target_node.get('category', 'general')}
**Sibling nodes near this branch (avoid duplication):** {json.dumps(sibling_labels) if sibling_labels else 'None'}
**Existing children (don't duplicate):** {json.dumps(existing_children) if existing_children else 'None yet'}
**Existing child detail under this branch:** {json.dumps(branch_context["existing_children"]) if branch_context["existing_children"] else 'No detailed child descriptions yet'}

{candidate_reference_block}

{planning_guidance}
"""
    if data.user_guidance:
        user_msg += f"\n**Operator guidance:** {data.user_guidance}\n"

    user_msg += """
Generate **4-8 relevant child nodes** that logically belong under this parent.

Think about what categories, systems, components, or technologies would exist here. Cover missing security-relevant detail where possible:
- If this is a high-level item (e.g. "Data Centre"), suggest major categories like Hardware, Software, Networking, Physical Security, etc.
- If this is a category (e.g. "Hardware"), suggest sub-categories like Servers, Storage, Networking Equipment, End-user Devices, etc.
- If this is a sub-category (e.g. "Servers"), suggest specific types like Web Servers, Database Servers, Application Servers, Domain Controllers, etc.
- If this is a specific type, suggest actual products/technologies/examples.
- Always consider both IT and OT/ICS systems where relevant.
- Include management planes, identity systems, telemetry, remote access, trust boundaries, third-party dependencies, and recovery paths when they are relevant to this branch.
- Prefer technical specificity over placeholders when the context is concrete.
- Avoid generic labels that add no planning value.

Return a JSON object:
{
  "children": [
    {
      "label": "short name",
      "category": "one of: infrastructure|hardware|software|networking|security|ot_ics|cloud|service|endpoint|storage|physical|personnel|process",
      "description": "1-2 sentence description of this item and its security relevance",
      "icon_hint": "one of: server|database|monitor|network|shield|cloud|lock|cpu|hard-drive|radio|building|users|cog|globe|terminal|wifi|camera|printer|phone|router|firewall|switch"
    }
  ],
  "summary": "brief one-line summary of what was added"
}

Return ONLY valid JSON, no markdown fences.
"""

    config = _provider_to_config(provider)
    parsed, error_message = await _request_json_object_with_retries(
        config,
        [{"role": "system", "content": system_msg}, {"role": "user", "content": user_msg}],
        temperature=0.45,
        max_tokens=4000,
        timeout_override=120,
        required_keys=("children",),
    )
    if not parsed:
        raise HTTPException(502, f"Unable to expand infra-map node: {error_message or 'empty response'}")
    children_raw = parsed.get("children", [])

    new_nodes = _dedupe_children(nodes, data.node_id, children_raw)
    new_nodes = _attach_reference_links_to_nodes(
        new_nodes,
        objective=project.root_objective if project else im.name,
        scope=project.description if project else im.description,
        context_preset=getattr(project, "context_preset", "") if project else "",
    )
    if not new_nodes and not existing_children:
        raise HTTPException(502, "Infra-map expansion returned no usable child nodes")

    # Merge into the map
    updated_nodes = list(nodes)
    # Mark the target as children_loaded
    for n in updated_nodes:
        if n.get("id") == data.node_id:
            n["children_loaded"] = True
            break
    updated_nodes.extend(new_nodes)
    updated_nodes = _normalize_nodes(updated_nodes)

    im.nodes = updated_nodes
    im.ai_summary = parsed.get("summary", im.ai_summary)
    im.analysis_metadata = {
        **(im.analysis_metadata or {}),
        "last_generation_strategy": "branch_expand",
        "last_generation_status": "completed",
        "last_generation_warnings": [] if new_nodes else ["Expansion produced no new nodes after deduplication."],
    }
    await db.commit()
    await db.refresh(im)
    await record_analysis_run(
        db,
        project_id=im.project_id,
        tool="infra_map",
        run_type="node_expand",
        status="completed",
        artifact_kind="infra_map",
        artifact_id=im.id,
        artifact_name=im.name,
        summary=(
            f"Expanded '{target_node.get('label', 'node')}' with {len(new_nodes)} child node"
            f"{'' if len(new_nodes) == 1 else 's'}."
        ),
        metadata={
            "node_id": data.node_id,
            "node_label": target_node.get("label", ""),
            "child_count": len(new_nodes),
        },
        duration_ms=round((perf_counter() - started_at) * 1000),
    )

    return _to_dict(im)


@router.post("/project/{project_id}/ai-generate")
async def ai_generate_infra_map(project_id: str, data: AIGenerateRequest, db: AsyncSession = Depends(get_db)):
    """AI generates a complete infrastructure map from a root label."""
    started_at = perf_counter()
    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    project = await _get_project(project_id, db)

    root_label = data.root_label.strip() or project.name or "Infrastructure"
    _, planning_label, planning_domain, planning_guidance = _infra_map_planning_context(
        data.planning_profile,
        project.root_objective or root_label,
        "\n".join(part for part in [project.description or "", root_label, data.user_guidance] if part),
        getattr(project, "context_preset", ""),
    )

    config = _provider_to_config(provider)
    map_name, map_description, map_nodes, ai_summary, analysis_metadata = await _generate_infra_map_payload(
        config,
        root_label=root_label,
        project_name=project.name,
        objective=project.root_objective or "No objective specified",
        description=project.description or "",
        environment_label=llm_service.get_context_preset_label(project.context_preset) or "General",
        workspace_mode=_workspace_mode(project),
        planning_label=planning_label,
        planning_domain=planning_domain,
        planning_guidance=planning_guidance,
        operator_guidance=data.user_guidance,
    )

    im = InfraMap(
        user_id=get_current_user_id(),
        project_id=project_id,
        name=map_name,
        description=map_description,
        nodes=map_nodes,
        ai_summary=ai_summary,
        analysis_metadata=analysis_metadata,
    )
    db.add(im)
    await db.commit()
    await db.refresh(im)
    await record_analysis_run(
        db,
        project_id=project_id,
        tool="infra_map",
        run_type="map_generation",
        status="completed",
        artifact_kind="infra_map",
        artifact_id=im.id,
        artifact_name=im.name,
        summary=(
            f"Generated infrastructure map with {len(im.nodes or [])} node"
            f"{'' if len(im.nodes or []) == 1 else 's'}."
        ),
        metadata={
            "node_count": len(im.nodes or []),
            "root_label": root_label,
        },
        duration_ms=round((perf_counter() - started_at) * 1000),
    )

    return _to_dict(im)


@router.post("/standalone/ai-generate")
async def ai_generate_standalone_infra_map(data: AIGenerateRequest, db: AsyncSession = Depends(get_db)):
    """AI generates a standalone infrastructure map (no project required)."""
    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    root_label = data.root_label.strip() or "Infrastructure"
    _, planning_label, planning_domain, planning_guidance = _infra_map_planning_context(
        data.planning_profile,
        root_label,
        "\n".join(part for part in [root_label, data.user_guidance] if part),
        "",
    )

    config = _provider_to_config(provider)
    map_name, map_description, map_nodes, ai_summary, analysis_metadata = await _generate_infra_map_payload(
        config,
        root_label=root_label,
        project_name="Standalone infra map",
        objective=root_label,
        description="Independent infrastructure planning",
        environment_label="General",
        workspace_mode="standalone",
        planning_label=planning_label,
        planning_domain=planning_domain,
        planning_guidance=planning_guidance,
        operator_guidance=data.user_guidance,
    )

    im = InfraMap(
        user_id=get_current_user_id(),
        project_id=None,
        name=map_name,
        description=map_description,
        nodes=map_nodes,
        ai_summary=ai_summary,
        analysis_metadata=analysis_metadata,
    )
    db.add(im)
    await db.commit()
    await db.refresh(im)

    return _to_dict(im)


# --- Internal helpers ---

def _build_path(nodes: list, node_id: str) -> list[str]:
    """Build path from root to the given node."""
    node_map = {n["id"]: n for n in nodes}
    path = []
    current_id = node_id
    seen = set()
    while current_id and current_id not in seen:
        seen.add(current_id)
        node = node_map.get(current_id)
        if not node:
            break
        path.append(node.get("label", "?"))
        current_id = node.get("parent_id")
    path.reverse()
    return path


def _build_branch_context(nodes: list[dict], node_id: str) -> dict[str, list[dict]]:
    node_map = {node["id"]: node for node in nodes if node.get("id")}
    lineage: list[dict] = []
    current_id = node_id
    seen: set[str] = set()

    while current_id and current_id not in seen:
        seen.add(current_id)
        node = node_map.get(current_id)
        if not node:
            break
        lineage.append(node)
        current_id = node.get("parent_id")

    lineage.reverse()
    ancestors = [
        {
            "label": node.get("label", ""),
            "category": node.get("category", "general"),
            "description": (node.get("description", "") or "")[:180],
        }
        for node in lineage[:-1][-4:]
    ]
    existing_children = [
        {
            "label": node.get("label", ""),
            "category": node.get("category", "general"),
            "description": (node.get("description", "") or "")[:180],
        }
        for node in nodes
        if node.get("parent_id") == node_id
    ][:8]

    return {
        "ancestors": ancestors,
        "existing_children": existing_children,
    }


def _has_children(temp_id: str, raw_nodes: list) -> bool:
    """Check if any raw nodes have this as parent."""
    return any(n.get("parent_temp_id") == temp_id for n in raw_nodes)
