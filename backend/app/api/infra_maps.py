"""
Infrastructure Map API — AI-powered hardware/software mind-map builder.
"""
import json
import uuid
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
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
from ..services import llm_service

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


class AIGenerateRequest(BaseModel):
    root_label: str = ""
    user_guidance: str = ""


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
        update_data["nodes"] = _normalize_nodes(update_data["nodes"] or [])
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
    existing_children = [n.get("label", "") for n in nodes if n.get("parent_id") == data.node_id]
    sibling_labels = [n.get("label", "") for n in nodes if n.get("parent_id") == target_node.get("parent_id") and n.get("id") != data.node_id]

    system_msg = (
        "You are a senior infrastructure architect and security consultant. "
        "You are helping build a detailed hardware and software infrastructure map as a hierarchical mind-map. "
        "This map is used for security assessments, attack surface analysis, trust-boundary analysis, and asset inventory."
    )

    user_msg = f"""Expand the following node in an infrastructure mind-map by suggesting child items.

**Workspace mode:** {_workspace_mode(project)}
**Project context:** {project.name if project else 'Standalone infra map'} — {project.root_objective if project else 'Independent infrastructure planning'}
**Environment preset:** {project.context_preset if project else 'infer from node path and operator guidance'}
**Map name:** {im.name}
**Map summary:** {im.ai_summary or 'No summary yet'}
**Node path (root → current):** {' → '.join(path_labels)}
**Current node:** "{target_node.get('label', '')}"
**Category:** {target_node.get('category', 'general')}
**Sibling nodes near this branch (avoid duplication):** {json.dumps(sibling_labels) if sibling_labels else 'None'}
**Existing children (don't duplicate):** {json.dumps(existing_children) if existing_children else 'None yet'}
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

    config = {
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

    result = await llm_service.chat_completion(
        config,
        [{"role": "system", "content": system_msg}, {"role": "user", "content": user_msg}],
        temperature=0.5,
        max_tokens=4000,
        timeout_override=120,
    )

    if result.get("status") != "success":
        raise HTTPException(502, f"LLM error: {result.get('message', 'Unknown error')}")

    parsed = llm_service.parse_json_object_response(result["content"])
    children_raw = parsed.get("children", [])

    new_nodes = _dedupe_children(nodes, data.node_id, children_raw)

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
    await db.commit()
    await db.refresh(im)

    return _to_dict(im)


@router.post("/project/{project_id}/ai-generate")
async def ai_generate_infra_map(project_id: str, data: AIGenerateRequest, db: AsyncSession = Depends(get_db)):
    """AI generates a complete infrastructure map from a root label."""
    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    project = await _get_project(project_id, db)

    root_label = data.root_label.strip() or project.name or "Infrastructure"

    system_msg = (
        "You are a senior infrastructure architect and security consultant. "
        "You are building a hierarchical infrastructure mind-map for security assessment and attack surface analysis. "
        "The map should cover all major asset categories relevant to the target environment."
    )

    user_msg = f"""Generate a comprehensive infrastructure mind-map for the following target:

**Root / Top-level:** "{root_label}"
**Project context:** {project.name} — {project.root_objective or 'No objective specified'}
**Environment type:** {project.context_preset or 'general'}
**Workspace mode:** {_workspace_mode(project)}
**Project description:** {project.description or 'No additional description provided'}
"""
    if data.user_guidance:
        user_msg += f"\n**Operator guidance:** {data.user_guidance}\n"

    user_msg += """
Generate a **3-4 level deep** infrastructure map with:
- **Level 1 (5-8 items):** Major categories (e.g. Hardware, Software, Networking, Cloud, OT/ICS, Physical Security, Identity, Monitoring)
- **Level 2 (3-6 per L1):** Sub-categories within each
- **Level 3 (2-5 per L2):** Specific systems, technologies, or components
- **Level 4 (optional on crown-jewel branches):** Important subsystems, dependencies, management planes, or trust-boundary components

Tailor the categories to the context — a data centre has different infrastructure than a web application or OT environment.
The map must be useful for cyber operations planning, so explicitly cover:
- compute and workload hosting
- identity and privileged access paths
- networking and segmentation
- data stores, backups, and recovery
- management/administration planes
- monitoring, logging, and security tooling
- remote access and third-party/supply-chain dependencies
- trust boundaries, choke points, and high-value systems

Avoid vague filler nodes. Prefer specific technologies, protocols, device classes, software roles, and operationally relevant assets.

Return a JSON object:
{
  "root": {
    "label": "root label",
    "category": "infrastructure",
    "description": "brief description of the infrastructure scope"
  },
  "nodes": [
    {
      "temp_id": "L1_1",
      "parent_temp_id": "root",
      "label": "short name",
      "category": "one of: infrastructure|hardware|software|networking|security|ot_ics|cloud|service|endpoint|storage|physical|personnel|process",
      "description": "1-2 sentence description",
      "icon_hint": "one of: server|database|monitor|network|shield|cloud|lock|cpu|hard-drive|radio|building|users|cog|globe|terminal|wifi|camera|printer|phone|router|firewall|switch"
    }
  ],
  "ai_summary": "2-3 sentence overview of the infrastructure and key security considerations"
}

Use temp_id like L1_1, L1_2, L2_1_1, etc. Set parent_temp_id to "root" for level-1 items.
Return ONLY valid JSON, no markdown fences.
"""

    config = {
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

    result = await llm_service.chat_completion(
        config,
        [{"role": "system", "content": system_msg}, {"role": "user", "content": user_msg}],
        temperature=0.5,
        max_tokens=8000,
        timeout_override=180,
    )

    if result.get("status") != "success":
        raise HTTPException(502, f"LLM error: {result.get('message', 'Unknown error')}")

    parsed = llm_service.parse_json_object_response(result["content"])

    root_data = parsed.get("root", {})
    root_id = str(uuid.uuid4())
    map_nodes = [_normalize_node({
        "id": root_id,
        "parent_id": None,
        "label": root_data.get("label", root_label),
        "category": root_data.get("category", "infrastructure"),
        "description": root_data.get("description", ""),
        "icon_hint": "building",
        "children_loaded": True,
        "manually_added": False,
    })]

    # Map temp IDs to real UUIDs
    id_map = {"root": root_id}
    raw_nodes = parsed.get("nodes", [])

    for rn in raw_nodes:
        real_id = str(uuid.uuid4())
        temp_id = rn.get("temp_id", "")
        id_map[temp_id] = real_id

    for rn in raw_nodes:
        temp_id = rn.get("temp_id", "")
        parent_temp_id = rn.get("parent_temp_id", "root")
        map_nodes.append(_normalize_node({
            "id": id_map.get(temp_id, str(uuid.uuid4())),
            "parent_id": id_map.get(parent_temp_id, root_id),
            "label": rn.get("label", "Unnamed node"),
            "category": rn.get("category", "general"),
            "description": rn.get("description", ""),
            "icon_hint": rn.get("icon_hint"),
            "children_loaded": _has_children(temp_id, raw_nodes),
            "manually_added": False,
        }))

    # Mark L2 nodes that have L3 children as children_loaded
    map_nodes = _normalize_nodes(map_nodes)

    im = InfraMap(
        user_id=get_current_user_id(),
        project_id=project_id,
        name=root_data.get("label", root_label),
        description=root_data.get("description", ""),
        nodes=map_nodes,
        ai_summary=parsed.get("ai_summary", ""),
    )
    db.add(im)
    await db.commit()
    await db.refresh(im)

    return _to_dict(im)


@router.post("/standalone/ai-generate")
async def ai_generate_standalone_infra_map(data: AIGenerateRequest, db: AsyncSession = Depends(get_db)):
    """AI generates a standalone infrastructure map (no project required)."""
    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    root_label = data.root_label.strip() or "Infrastructure"

    system_msg = (
        "You are a senior infrastructure architect and security consultant. "
        "You are building a hierarchical infrastructure mind-map for security assessment and attack surface analysis. "
        "The map should cover all major asset categories relevant to the target environment."
    )

    user_msg = f"""Generate a comprehensive infrastructure mind-map for the following target:

**Root / Top-level:** "{root_label}"
"""
    if data.user_guidance:
        user_msg += f"\n**Operator guidance:** {data.user_guidance}\n"

    user_msg += """
Generate a **3-4 level deep** infrastructure map with:
- **Level 1 (5-8 items):** Major categories (e.g. Hardware, Software, Networking, Cloud, OT/ICS, Physical Security, Identity, Monitoring)
- **Level 2 (3-6 per L1):** Sub-categories within each
- **Level 3 (2-5 per L2):** Specific systems, technologies, or components
- **Level 4 (optional on high-value branches):** Important subsystems, dependencies, management or control-plane components

Infer the environment type from the root concept and operator guidance. The map must be useful for cyber operations planning, so explicitly cover:
- compute and workload hosting
- identity and access paths
- networking and trust boundaries
- data stores and backups
- management/administration systems
- monitoring, logging, and security controls
- remote access, user endpoints, and third-party dependencies
- crown-jewel systems and choke points

Avoid vague filler nodes. Prefer concrete technologies, systems, and operationally relevant infrastructure.

Return a JSON object:
{
  "root": {
    "label": "root label",
    "category": "infrastructure",
    "description": "brief description of the infrastructure scope"
  },
  "nodes": [
    {
      "temp_id": "L1_1",
      "parent_temp_id": "root",
      "label": "short name",
      "category": "one of: infrastructure|hardware|software|networking|security|ot_ics|cloud|service|endpoint|storage|physical|personnel|process",
      "description": "1-2 sentence description",
      "icon_hint": "one of: server|database|monitor|network|shield|cloud|lock|cpu|hard-drive|radio|building|users|cog|globe|terminal|wifi|camera|printer|phone|router|firewall|switch"
    }
  ],
  "ai_summary": "2-3 sentence overview of the infrastructure and key security considerations"
}

Use temp_id like L1_1, L1_2, L2_1_1, etc. Set parent_temp_id to "root" for level-1 items.
Return ONLY valid JSON, no markdown fences.
"""

    config = {
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

    result = await llm_service.chat_completion(
        config,
        [{"role": "system", "content": system_msg}, {"role": "user", "content": user_msg}],
        temperature=0.5,
        max_tokens=8000,
        timeout_override=180,
    )

    if result.get("status") != "success":
        raise HTTPException(502, f"LLM error: {result.get('message', 'Unknown error')}")

    parsed = llm_service.parse_json_object_response(result["content"])

    root_data = parsed.get("root", {})
    root_id = str(uuid.uuid4())
    map_nodes = [_normalize_node({
        "id": root_id,
        "parent_id": None,
        "label": root_data.get("label", root_label),
        "category": root_data.get("category", "infrastructure"),
        "description": root_data.get("description", ""),
        "icon_hint": "building",
        "children_loaded": True,
        "manually_added": False,
    })]

    id_map = {"root": root_id}
    raw_nodes = parsed.get("nodes", [])

    for rn in raw_nodes:
        real_id = str(uuid.uuid4())
        temp_id = rn.get("temp_id", "")
        id_map[temp_id] = real_id

    for rn in raw_nodes:
        temp_id = rn.get("temp_id", "")
        parent_temp_id = rn.get("parent_temp_id", "root")
        map_nodes.append(_normalize_node({
            "id": id_map.get(temp_id, str(uuid.uuid4())),
            "parent_id": id_map.get(parent_temp_id, root_id),
            "label": rn.get("label", "Unnamed node"),
            "category": rn.get("category", "general"),
            "description": rn.get("description", ""),
            "icon_hint": rn.get("icon_hint"),
            "children_loaded": _has_children(temp_id, raw_nodes),
            "manually_added": False,
        }))

    map_nodes = _normalize_nodes(map_nodes)

    im = InfraMap(
        user_id=get_current_user_id(),
        project_id=None,
        name=root_data.get("label", root_label),
        description=root_data.get("description", ""),
        nodes=map_nodes,
        ai_summary=parsed.get("ai_summary", ""),
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


def _has_children(temp_id: str, raw_nodes: list) -> bool:
    """Check if any raw nodes have this as parent."""
    return any(n.get("parent_temp_id") == temp_id for n in raw_nodes)
