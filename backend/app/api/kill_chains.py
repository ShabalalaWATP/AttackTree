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
from ..services.access_control import (
    get_active_provider_for_user,
    require_kill_chain_access,
    require_project_access,
)
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

UNIFIED_PHASES = [
    "Reconnaissance", "Weaponization", "Social Engineering", "Exploitation",
    "Persistence", "Defense Evasion", "Command & Control", "Pivoting",
    "Discovery", "Privilege Escalation", "Execution", "Credential Access",
    "Lateral Movement", "Collection", "Exfiltration", "Impact",
    "Objectives", "Anti-Forensics"
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


class AIGenerateKillChainRequest(BaseModel):
    framework: str = "mitre_attck"
    user_guidance: str = ""


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
        node_instruction = (
            "Map each attack tree node to its most appropriate kill chain phase. "
            "A node may appear in multiple phases if it spans multiple stages of the campaign. "
            "Evaluate each node's mitigations and detections to assess defensive coverage per phase."
        )
    else:
        nodes_text = "(No attack tree nodes exist yet)"
        node_instruction = (
            "No attack tree nodes exist yet. Generate a fully realistic kill chain based on the project "
            "objective alone — as if you were writing an actual red team operation plan. For each phase, "
            "describe specific attacker tradecraft, tools, and techniques. Leave mapped_nodes as empty arrays."
        )

    if kc.framework == "mitre_attck":
        phases = MITRE_TACTICS
    elif kc.framework == "unified":
        phases = UNIFIED_PHASES
    else:
        phases = CKC_PHASES
    phases_text = ", ".join(f'"{p}"' for p in phases)

    prompt = f"""You are a senior red team lead writing an operational campaign analysis. You have extensive experience conducting adversary simulations, purple team exercises, and breach assessments for Fortune 500 companies and government agencies.

**Campaign Context:**
- **Target / Project:** {project.name if project else 'Unknown'}
- **Root Objective:** {project.root_objective if project else 'Not specified'}
- **Project Description:** {(project.description or '')[:300] if project else ''}
- **Kill Chain Framework:** {kc.framework} — Phases: [{phases_text}]
{f"- **Operator Guidance:** {data.user_guidance}" if data.user_guidance else ""}

**Attack Tree Nodes (your intelligence feed):**
{nodes_text}

**Your Mission:** {node_instruction}

Produce a detailed operational kill chain analysis. For EVERY phase of the framework, provide:
1. A specific description of attacker activity grounded in real-world tradecraft
2. Named tools (e.g. Cobalt Strike, Impacket, BloodHound, Mimikatz, Burp Suite, Nuclei, subfinder, ffuf, Certipy, Rubeus)
3. Specific MITRE ATT&CK technique IDs (e.g. T1566.001, T1059.001, T1078.002)
4. Indicators of Compromise (IOCs) defenders should hunt for
5. Log sources where this activity would be visible
6. Actionable break-the-chain defensive opportunities

Return the following JSON structure:
{{
  "phases": [
    {{
      "phase": "Exact phase name from the framework",
      "phase_index": 1,
      "description": "3-5 sentences describing what the attacker does in this specific phase. Be concrete: name the tools, techniques, targets, and tradecraft. Write as operational notes, not generic descriptions.",
      "mapped_nodes": [
        {{
          "node_id": "exact node id from the list above",
          "node_title": "the node title",
          "technique_id": "MITRE ATT&CK ID e.g. T1566.001",
          "technique_name": "Technique name e.g. Spearphishing Attachment",
          "confidence": 0.85
        }}
      ],
      "tools": ["Specific tool names used in this phase"],
      "iocs": ["Specific IOC descriptions: suspicious process names, file hashes patterns, C2 domains, registry keys, etc."],
      "log_sources": ["Windows Security Event Log", "Sysmon", "EDR telemetry", "proxy logs", etc.],
      "detection_window": "Realistic time range e.g. '15 min - 2 hours'",
      "dwell_time": "How long the attacker operates in this phase e.g. '4-12 hours'",
      "break_opportunities": ["Specific, actionable defensive opportunity with what to do"],
      "difficulty": "trivial|easy|moderate|hard|very_hard",
      "defensive_coverage": "none|minimal|partial|good|strong",
      "coverage_notes": "Brief assessment of how well existing mitigations/detections cover this phase based on the attack tree data"
    }}
  ],
  "campaign_summary": "Write a 4-6 paragraph red team operation report. Paragraph 1: Executive overview of the campaign and the threat actor profile. Paragraph 2: The initial compromise path and how the attacker establishes a foothold. Paragraph 3: Post-exploitation, lateral movement, and how the attacker reaches the objective. Paragraph 4: The defensive landscape — where security controls are strong and where they are weak. Paragraph 5: Overall risk assessment and what would happen if this campaign succeeds. Paragraph 6 (optional): Comparison to known real-world campaigns or APT groups that use similar TTPs.",
  "total_estimated_time": "e.g. '5-14 days' with brief rationale",
  "overall_risk_rating": "critical|high|medium|low",
  "attack_complexity": "low|medium|high|very_high",
  "coverage_score": 0.45,
  "weakest_links": [
    "Specific defensive gap with explanation of why it matters and what an attacker gains by exploiting it"
  ],
  "critical_path": "Describe the single most likely path from initial access to objective — the path of least resistance for a motivated attacker",
  "recommendations": [
    {{
      "priority": "critical|high|medium|low",
      "title": "Specific, actionable recommendation title",
      "description": "2-3 sentences: what to implement, how it disrupts the kill chain, and which phase(s) it addresses. Reference specific products, configurations, or detection rules where possible.",
      "addresses_phases": ["Phase name 1", "Phase name 2"],
      "effort": "low|medium|high"
    }}
  ]
}}

**Critical Rules:**
1. Include ALL phases of the selected framework — even phases with no mapped nodes should have detailed descriptions of likely attacker activity for this campaign
2. Phase names MUST exactly match: [{phases_text}]
3. node_id values MUST exactly match IDs from the attack tree nodes listed above
4. Every tool name must be a real, well-known offensive security tool
5. Every technique_id must be a valid MITRE ATT&CK technique ID
6. IOCs must be specific enough to be operationally useful (not generic like "suspicious activity")
7. coverage_score is 0.0-1.0 representing how much of the kill chain has existing defensive coverage based on the mitigations/detections in the attack tree
8. Provide at least 5 recommendations, with at least 2 rated critical or high
9. Break opportunities should be specific enough that a SOC analyst could act on them immediately
10. Write as a practitioner — avoid filler phrases, be direct and technical

Return ONLY valid JSON, no markdown fences."""

    config = _provider_to_config(provider)
    messages = [
        {"role": "system", "content": "You are a senior red team lead and adversary simulation expert. You produce detailed, operationally accurate kill chain analyses grounded in real-world tradecraft. Respond only with valid JSON."},
        {"role": "user", "content": prompt},
    ]

    response = await llm_service.chat_completion(config, messages, temperature=0.4, max_tokens=16000, timeout_override=300)
    if response["status"] != "success":
        raise HTTPException(502, f"LLM request failed: {response.get('message', '')}")

    parsed = llm_service.parse_json_object_response(response["content"])

    # Normalize phases robustly
    raw_phases = parsed.get("phases", [])
    node_lookup = {n.id: n for n in nodes} if nodes else {}
    normalized_phases = []
    for i, phase in enumerate(raw_phases):
        if not isinstance(phase, dict):
            continue
        if "phase_index" not in phase:
            phase["phase_index"] = phase.pop("order", i + 1)
        # Normalize mapped_nodes from various AI output formats
        if "mapped_nodes" not in phase and "node_ids" in phase:
            node_ids = phase.pop("node_ids", [])
            phase["mapped_nodes"] = []
            for nid in node_ids:
                node = node_lookup.get(nid)
                phase["mapped_nodes"].append({
                    "node_id": nid,
                    "node_title": node.title if node else nid,
                    "technique_id": node.threat_category or "" if node else "",
                    "technique_name": "",
                    "confidence": 0.8,
                })
        if "mapped_nodes" not in phase:
            phase["mapped_nodes"] = []
        # Ensure all expected fields exist with defaults
        phase.setdefault("tools", [])
        phase.setdefault("iocs", [])
        phase.setdefault("log_sources", [])
        phase.setdefault("break_opportunities", [])
        phase.setdefault("detection_window", "")
        phase.setdefault("dwell_time", "")
        phase.setdefault("difficulty", "moderate")
        phase.setdefault("defensive_coverage", "none")
        phase.setdefault("coverage_notes", "")
        phase.setdefault("description", "")
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
        "overall_risk_rating": parsed.get("overall_risk_rating", ""),
        "attack_complexity": parsed.get("attack_complexity", ""),
        "coverage_score": parsed.get("coverage_score", 0),
        "critical_path": parsed.get("critical_path", ""),
    }


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

    return await ai_map_to_kill_chain(kc.id, AIMapRequest(user_guidance=data.user_guidance), db)


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
        "created_at": kc.created_at.isoformat() if kc.created_at else "",
        "updated_at": kc.updated_at.isoformat() if kc.updated_at else "",
    }
