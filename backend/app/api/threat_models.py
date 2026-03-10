"""
Threat Modeling API — STRIDE/PASTA workspace with AI-powered analysis.
"""
import json
import uuid
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..database import get_db
from ..models.threat_model import ThreatModel
from ..models.node import Node
from ..models.project import Project
from ..models.llm_config import LLMProviderConfig
from ..services.access_control import (
    get_active_provider_for_user,
    require_project_access,
    require_threat_model_access,
)
from ..services import llm_service
from ..services.risk_engine import compute_inherent_risk

router = APIRouter(prefix="/threat-models", tags=["threat_models"])


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


class AIGenerateThreatsRequest(BaseModel):
    user_guidance: str = ""


class AIDeepDiveRequest(BaseModel):
    threat_id: str


class AILinkToTreeRequest(BaseModel):
    threat_ids: list[str] = []  # empty = all threats


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
    tm = ThreatModel(**data.model_dump())
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
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(tm, key, value)
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
    """AI generates a Data Flow Diagram from a system description."""
    tm = await _get_or_404(tm_id, db)
    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    project = await require_project_access(tm.project_id, db)

    # Also get existing attack tree nodes for context
    nodes_result = await db.execute(
        select(Node).where(Node.project_id == tm.project_id)
    )
    nodes = nodes_result.scalars().all()
    tree_context = ""
    if nodes:
        tree_context = "\n**Existing Attack Tree Nodes (for context):**\n" + "\n".join(
            f"- [{n.node_type}] {n.title}" for n in nodes[:30]
        )

    prompt = f"""You are an offensive security architect mapping out a target system's architecture for attack surface analysis.

**Target Project:** {project.name if project else 'Unknown'}
**Methodology:** {tm.methodology.upper()}
**System Description:** {data.system_description}
**Scope:** {tm.scope}
{f'**Operator Guidance:** {data.user_guidance}' if data.user_guidance else ''}
{tree_context}

Generate a complete Data Flow Diagram identifying all components, data flows, and trust boundaries. Think like an attacker — focus on entry points, privilege boundaries, sensitive data stores, and external integrations that expand the attack surface.

Return JSON:
{{
  "components": [
    {{
      "id": "comp-1",
      "type": "process|datastore|external_entity|service|user",
      "name": "Component name",
      "description": "Brief description including attack-relevant details",
      "technology": "e.g. Node.js 18, PostgreSQL 15, AWS S3",
      "x": 100,
      "y": 100,
      "attack_surface": "Brief note on what attack surface this component exposes"
    }}
  ],
  "data_flows": [
    {{
      "id": "flow-1",
      "source": "comp-1",
      "target": "comp-2",
      "label": "What data flows",
      "data_classification": "public|internal|confidential|restricted",
      "protocol": "e.g. HTTPS, gRPC, SQL",
      "authentication": "How this flow is authenticated (or if unauthenticated)"
    }}
  ],
  "trust_boundaries": [
    {{
      "id": "tb-1",
      "name": "Boundary name (e.g. DMZ, Internal Network, Cloud VPC)",
      "component_ids": ["comp-1", "comp-2"]
    }}
  ]
}}

Rules:
1. Create 5-15 components that represent the real architecture
2. Position components logically (x,y coordinates, 100-800 range)
3. Components should reflect the described system — don't be generic
4. Include at least 2 trust boundaries
5. Data flows should show real data movement with protocols and authentication
6. Highlight components that are internet-facing or handle sensitive data
7. Identify unauthenticated or weakly-authenticated data flows

Return ONLY valid JSON."""

    config = _provider_to_config(provider)
    messages = [
        {"role": "system", "content": "You are an expert offensive security architect performing attack surface mapping. Respond only with valid JSON."},
        {"role": "user", "content": prompt},
    ]

    response = await llm_service.chat_completion(config, messages, temperature=0.6,
                                                    max_tokens=8192, timeout_override=180)
    if response["status"] != "success":
        raise HTTPException(502, f"LLM request failed: {response.get('message', '')}")

    parsed = llm_service.parse_json_object_response(response["content"])
    if not parsed.get("components"):
        raise HTTPException(502, "AI returned an empty or malformed DFD — try again or simplify the description")

    tm.components = parsed.get("components", [])
    tm.data_flows = parsed.get("data_flows", [])
    tm.trust_boundaries = parsed.get("trust_boundaries", [])
    tm.scope = data.system_description
    await db.commit()
    await db.refresh(tm)
    return _to_dict(tm)


@router.post("/{tm_id}/ai-generate-threats")
async def ai_generate_threats(tm_id: str, data: AIGenerateThreatsRequest, db: AsyncSession = Depends(get_db)):
    """AI analyzes the DFD and generates STRIDE/PASTA threats."""
    tm = await _get_or_404(tm_id, db)
    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    if not tm.components:
        raise HTTPException(400, "Generate a DFD first before generating threats")

    project = await require_project_access(tm.project_id, db)

    comp_text = json.dumps(tm.components, indent=2)
    flow_text = json.dumps(tm.data_flows, indent=2)
    tb_text = json.dumps(tm.trust_boundaries, indent=2)

    methodology_detail = {
        "stride": "STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)",
        "pasta": "PASTA (Process for Attack Simulation and Threat Analysis)",
        "linddun": "LINDDUN (Linkability, Identifiability, Non-repudiation, Detectability, Disclosure, Unawareness, Non-compliance)",
    }.get(tm.methodology, "STRIDE")

    prompt = f"""You are an expert red team operator performing offensive threat modeling using {methodology_detail}.
Think like an adversary — your goal is to enumerate every realistic attack vector against this system.

**Target Project:** {project.name if project else 'Unknown'}
**System Scope:** {tm.scope}
{f'**Operator Guidance:** {data.user_guidance}' if data.user_guidance else ''}

**Data Flow Diagram:**
Components: {comp_text}
Data Flows: {flow_text}
Trust Boundaries: {tb_text}

Analyze EVERY component and data flow from an attacker's perspective using {tm.methodology.upper()}.
For each threat:
- Identify the specific component or data flow targeted
- Classify by {tm.methodology.upper()} category
- Describe HOW an attacker would exploit it (tools, techniques, tradecraft)
- Assess severity, likelihood, and impact realistically
- Suggest both offensive exploitation steps AND defensive mitigations

Return JSON:
{{
  "threats": [
    {{
      "id": "threat-1",
      "component_id": "comp-1 or flow-1",
      "category": "{tm.methodology.upper()} category",
      "title": "Threat title — be specific (e.g. 'SQL Injection via search parameter' not just 'Injection')",
      "description": "Detailed description of the threat from the attacker's perspective",
      "severity": "critical|high|medium|low",
      "attack_vector": "Step-by-step exploitation approach including tools (e.g. Burp Suite, sqlmap, custom scripts)",
      "prerequisites": "What the attacker needs (e.g. network access, valid credentials, insider knowledge)",
      "exploitation_complexity": "trivial|low|moderate|high|expert",
      "mitigation": "Recommended defensive mitigation",
      "likelihood": 1-10,
      "impact": 1-10,
      "risk_score": 1-100,
      "real_world_examples": "Reference real CVEs, APT campaigns, or common exploit patterns where applicable",
      "mitre_technique": "MITRE ATT&CK technique ID if applicable (e.g. T1190, T1078)"
    }}
  ],
  "summary": "Overall threat landscape summary written from the attacker's perspective — what makes this system attractive, what are the easiest paths in, and where are the crown jewels",
  "highest_risk_areas": ["area 1 with brief explanation", "area 2 with brief explanation"],
  "attack_surface_score": 1-100,
  "recommended_attack_priorities": ["Priority 1: what to attack first and why", "Priority 2", "Priority 3"]
}}

Rules:
1. Generate threats for EACH component — no component should be threat-free
2. Focus on trust boundary crossings — these are prime attack targets
3. Be specific and realistic — reference real vulnerability classes, CVEs, and tools
4. For STRIDE, cover all 6 categories across the diagram
5. Include at least 12-15 threats total
6. risk_score = (likelihood * impact) normalized to 1-100
7. Think like a penetration tester: what would you try first?
8. Include at least 2 critical and 3 high severity threats if the system warrants it

Return ONLY valid JSON."""

    config = _provider_to_config(provider)
    messages = [
        {"role": "system", "content": "You are an expert red team operator performing offensive threat modeling. Think like an adversary. Respond only with valid JSON."},
        {"role": "user", "content": prompt},
    ]

    response = await llm_service.chat_completion(config, messages, temperature=0.5,
                                                    max_tokens=16384, timeout_override=240)
    if response["status"] != "success":
        raise HTTPException(502, f"LLM request failed: {response.get('message', '')}")

    parsed = llm_service.parse_json_object_response(response["content"])
    if not parsed.get("threats"):
        raise HTTPException(502, "AI returned empty or malformed threats — try again or simplify the scope")

    tm.threats = parsed.get("threats", [])
    tm.ai_summary = parsed.get("summary", "")
    await db.commit()
    await db.refresh(tm)
    return {
        **_to_dict(tm),
        "highest_risk_areas": parsed.get("highest_risk_areas", []),
        "attack_surface_score": parsed.get("attack_surface_score"),
        "recommended_attack_priorities": parsed.get("recommended_attack_priorities", []),
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

    threats_to_link = tm.threats
    if data.threat_ids:
        id_set = set(data.threat_ids)
        threats_to_link = [t for t in tm.threats if t.get("id") in id_set]

    created_ids = []
    y_offset = 200
    for i, threat in enumerate(threats_to_link):
        node = Node(
            project_id=tm.project_id,
            parent_id=root_node.id if root_node else None,
            node_type="weakness" if threat.get("severity") in ("critical", "high") else "attack_step",
            title=threat.get("title", "Threat"),
            description=threat.get("description", ""),
            threat_category=threat.get("category", ""),
            attack_surface=threat.get("attack_vector", ""),
            likelihood=threat.get("likelihood"),
            impact=threat.get("impact"),
            status="draft",
            position_x=200 + (i % 4) * 300,
            position_y=y_offset + (i // 4) * 200,
            sort_order=100 + i,
            notes=f"From threat model: {tm.name}\nMitigation: {threat.get('mitigation', '')}",
        )
        node.inherent_risk = compute_inherent_risk(
            node.likelihood, node.impact, node.effort,
            node.exploitability, node.detectability,
        )
        db.add(node)
        await db.flush()
        created_ids.append(node.id)

        # Update threat with linked node id
        threat["linked_node_id"] = node.id

    # Deep copy to reliably trigger SQLAlchemy JSON dirty detection
    import copy
    tm.threats = copy.deepcopy(tm.threats)
    await db.commit()
    return {"created": len(created_ids), "node_ids": created_ids}


@router.post("/{tm_id}/ai-deep-dive")
async def ai_deep_dive_threat(tm_id: str, data: AIDeepDiveRequest, db: AsyncSession = Depends(get_db)):
    """AI provides a detailed offensive exploitation analysis of a specific threat."""
    tm = await _get_or_404(tm_id, db)
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
**Target Component:** {json.dumps(component) if component else 'Unknown'}
**Threat Details:** {json.dumps(threat)}

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

    response = await llm_service.chat_completion(config, messages, temperature=0.5,
                                                    max_tokens=8192, timeout_override=180)
    if response["status"] != "success":
        raise HTTPException(502, f"LLM request failed: {response.get('message', '')}")

    return llm_service.parse_json_object_response(response["content"])


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
        # Step 2: Generate threats
        await ai_generate_threats(tm.id, AIGenerateThreatsRequest(user_guidance=data.user_guidance), db)
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
        "created_at": tm.created_at.isoformat() if tm.created_at else "",
        "updated_at": tm.updated_at.isoformat() if tm.updated_at else "",
    }
