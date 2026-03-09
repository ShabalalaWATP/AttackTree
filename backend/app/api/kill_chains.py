"""
Kill Chain API — AI-powered campaign timeline analysis.
"""
import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..database import get_db
from ..models.kill_chain import KillChain
from ..models.node import Node
from ..models.project import Project
from ..models.llm_config import LLMProviderConfig
from ..services import llm_service

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


# --- Endpoints ---

@router.get("/project/{project_id}")
async def list_kill_chains(project_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(KillChain).where(KillChain.project_id == project_id).order_by(KillChain.created_at.desc())
    )
    return [_to_dict(kc) for kc in result.scalars().all()]


@router.post("", status_code=201)
async def create_kill_chain(data: KillChainCreate, db: AsyncSession = Depends(get_db)):
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
    for key, value in data.model_dump(exclude_unset=True).items():
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
    """AI maps attack tree nodes to kill chain phases, estimates dwell times and detection windows."""
    kc = await _get_or_404(kc_id, db)
    provider = await _get_active_provider(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    proj = await db.execute(select(Project).where(Project.id == kc.project_id))
    project = proj.scalar_one_or_none()

    nodes_result = await db.execute(
        select(Node).where(Node.project_id == kc.project_id)
        .options(selectinload(Node.mitigations), selectinload(Node.detections))
    )
    nodes = nodes_result.scalars().all()

    if nodes:
        nodes_text = "\n".join(
            f"- id={n.id} [{n.node_type}] \"{n.title}\" threat_category=\"{n.threat_category}\" "
            f"attack_surface=\"{n.attack_surface}\" risk={n.inherent_risk or '?'} "
            f"mitigations={len(n.mitigations or [])} detections={len(n.detections or [])}"
            for n in nodes[:60]
        )
        node_instruction = "Map each node to the appropriate kill chain phase."
    else:
        nodes_text = "(No attack tree nodes exist yet)"
        node_instruction = (
            "No attack tree nodes exist yet. Generate a realistic kill chain based on the project objective alone. "
            "For each phase, describe the likely attacker activities, techniques, and tools instead of mapping node IDs. "
            "Leave node_ids as empty arrays."
        )

    phases = MITRE_TACTICS if kc.framework == "mitre_attck" else CKC_PHASES
    phases_text = ", ".join(f'"{p}"' for p in phases)

    prompt = f"""You are an expert red team operator and campaign planner. Map the following attack tree nodes to a kill chain timeline.

**Project:** {project.name if project else 'Unknown'}
**Root Objective:** {project.root_objective if project else ''}
**Framework:** {kc.framework}
**Available Phases:** [{phases_text}]
{f'**User Guidance:** {data.user_guidance}' if data.user_guidance else ''}

**Attack Tree Nodes:**
{nodes_text}

{node_instruction} For each phase, estimate:
- Detection window (how long defenders have to detect activity in this phase)
- Estimated dwell time (how long the attacker spends here)
- Break-the-chain opportunities (where defenders can disrupt the attack)

Return JSON:
{{
  "phases": [
    {{
      "phase": "Phase name",
      "phase_index": 1,
      "description": "2-3 sentences describing what the attacker does in this phase for this specific campaign, including specific tools, techniques, or tradecraft",
      "mapped_nodes": [
        {{
          "node_id": "the node id from the attack tree, or empty string if no tree nodes",
          "node_title": "the node title",
          "technique": "MITRE ATT&CK technique or specific attack technique used",
          "confidence": 0.85
        }}
      ],
      "detection_window": "e.g. 1-4 hours",
      "dwell_time": "e.g. 2-8 hours",
      "break_opportunities": ["opportunity 1", "opportunity 2"],
      "difficulty": "trivial|easy|moderate|hard|very hard"
    }}
  ],
  "campaign_summary": "Overall campaign narrative (3-5 paragraphs) describing the end-to-end operation from initial recon through objectives, written as a red team operation report",
  "total_estimated_time": "e.g. 3-7 days",
  "weakest_links": ["Description of weakest defensive points in this campaign"],
  "recommendations": [
    {{"priority": "critical|high|medium|low", "title": "...", "description": "..."}}
  ]
}}

Rules:
1. Include ALL relevant phases for the framework, even if no tree nodes map directly — describe likely attacker activity anyway
2. Phase names MUST match the framework phases exactly
3. node_id must be the exact id from the attack tree nodes listed, or omit mapped_nodes for phases with no matching nodes
4. Descriptions should be specific to this campaign, not generic
5. Include at least 3 recommendations

Return ONLY valid JSON."""

    config = _provider_to_config(provider)
    messages = [
        {"role": "system", "content": "You are an expert red team operator and cyber security analyst. Respond only with valid JSON."},
        {"role": "user", "content": prompt},
    ]

    response = await llm_service.chat_completion(config, messages, temperature=0.5)
    if response["status"] != "success":
        raise HTTPException(502, f"LLM request failed: {response.get('message', '')}")

    parsed = llm_service.parse_json_object_response(response["content"])

    # Normalize phases: ensure mapped_nodes format and phase_index exist
    raw_phases = parsed.get("phases", [])
    # Build a node lookup for enriching node_ids → mapped_nodes
    node_lookup = {n.id: n for n in nodes} if nodes else {}
    normalized_phases = []
    for i, phase in enumerate(raw_phases):
        if not isinstance(phase, dict):
            continue
        # Normalize phase_index (AI might return "order" instead)
        if "phase_index" not in phase:
            phase["phase_index"] = phase.pop("order", i + 1)
        # Normalize mapped_nodes: AI might return "node_ids" (flat string list) instead
        if "mapped_nodes" not in phase and "node_ids" in phase:
            node_ids = phase.pop("node_ids", [])
            phase["mapped_nodes"] = []
            for nid in node_ids:
                node = node_lookup.get(nid)
                phase["mapped_nodes"].append({
                    "node_id": nid,
                    "node_title": node.title if node else nid,
                    "technique": node.threat_category or "" if node else "",
                    "confidence": 0.8,
                })
        # Ensure mapped_nodes is at least an empty list
        if "mapped_nodes" not in phase:
            phase["mapped_nodes"] = []
        normalized_phases.append(phase)

    kc.phases = normalized_phases
    kc.ai_summary = parsed.get("campaign_summary", "")
    kc.recommendations = parsed.get("recommendations", [])

    await db.commit()
    await db.refresh(kc)
    return {
        **_to_dict(kc),
        "total_estimated_time": parsed.get("total_estimated_time", ""),
        "weakest_links": parsed.get("weakest_links", []),
    }


class AIGenerateKillChainRequest(BaseModel):
    framework: str = "mitre_attck"


@router.post("/project/{project_id}/ai-generate")
async def ai_generate_kill_chain(project_id: str, data: AIGenerateKillChainRequest = AIGenerateKillChainRequest(), db: AsyncSession = Depends(get_db)):
    """AI auto-generates a complete kill chain from the attack tree."""
    provider = await _get_active_provider(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    proj = await db.execute(select(Project).where(Project.id == project_id))
    project = proj.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    # Create the kill chain and immediately map
    kc = KillChain(
        project_id=project_id,
        name=f"Kill Chain — {project.name}",
        description="AI-generated kill chain analysis",
        framework=data.framework,
    )
    db.add(kc)
    await db.commit()
    await db.refresh(kc)

    # Now map via AI
    return await ai_map_to_kill_chain(kc.id, AIMapRequest(), db)


# --- Helpers ---

async def _get_or_404(kc_id: str, db: AsyncSession) -> KillChain:
    result = await db.execute(select(KillChain).where(KillChain.id == kc_id))
    kc = result.scalar_one_or_none()
    if not kc:
        raise HTTPException(404, "Kill chain not found")
    return kc


async def _get_active_provider(db: AsyncSession):
    result = await db.execute(
        select(LLMProviderConfig).where(LLMProviderConfig.is_active == True).limit(1)
    )
    return result.scalar_one_or_none()


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
        "created_at": kc.created_at.isoformat() if kc.created_at else "",
        "updated_at": kc.updated_at.isoformat() if kc.updated_at else "",
    }
