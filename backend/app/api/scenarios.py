"""
Scenario simulation API — AI-powered what-if analysis.
"""
import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..database import get_db
from ..models.scenario import Scenario
from ..models.node import Node
from ..models.project import Project
from ..models.llm_config import LLMProviderConfig
from ..services import llm_service
from ..services.risk_engine import compute_inherent_risk, compute_residual_risk

router = APIRouter(prefix="/scenarios", tags=["scenarios"])


# --- Schemas ---

class ScenarioCreate(BaseModel):
    project_id: str
    name: str
    description: str = ""
    attacker_type: str = "opportunistic"
    attacker_skill: str = "Medium"
    attacker_resources: str = "Medium"
    attacker_motivation: str = ""
    assumptions: str = ""


class ScenarioUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    attacker_type: Optional[str] = None
    attacker_skill: Optional[str] = None
    attacker_resources: Optional[str] = None
    attacker_motivation: Optional[str] = None
    disabled_controls: Optional[list[str]] = None
    modified_scores: Optional[dict] = None
    assumptions: Optional[str] = None


class SimulateRequest(BaseModel):
    disabled_controls: list[str] = []
    modified_scores: dict = {}  # node_id -> {field: value}
    attacker_type: str = "opportunistic"
    attacker_skill: str = "Medium"
    attacker_resources: str = "Medium"


class AIAnalyzeRequest(BaseModel):
    question: str = ""  # optional user question to guide AI


# --- Endpoints ---

@router.get("/project/{project_id}")
async def list_scenarios(project_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scenario).where(Scenario.project_id == project_id).order_by(Scenario.created_at.desc())
    )
    return [_to_dict(s) for s in result.scalars().all()]


@router.post("", status_code=201)
async def create_scenario(data: ScenarioCreate, db: AsyncSession = Depends(get_db)):
    scenario = Scenario(**data.model_dump())
    db.add(scenario)
    await db.commit()
    await db.refresh(scenario)
    return _to_dict(scenario)


@router.get("/{scenario_id}")
async def get_scenario(scenario_id: str, db: AsyncSession = Depends(get_db)):
    scenario = await _get_or_404(scenario_id, db)
    return _to_dict(scenario)


@router.patch("/{scenario_id}")
async def update_scenario(scenario_id: str, data: ScenarioUpdate, db: AsyncSession = Depends(get_db)):
    scenario = await _get_or_404(scenario_id, db)
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(scenario, key, value)
    await db.commit()
    await db.refresh(scenario)
    return _to_dict(scenario)


@router.delete("/{scenario_id}", status_code=204)
async def delete_scenario(scenario_id: str, db: AsyncSession = Depends(get_db)):
    scenario = await _get_or_404(scenario_id, db)
    await db.delete(scenario)
    await db.commit()


@router.post("/{scenario_id}/simulate")
async def simulate(scenario_id: str, data: SimulateRequest, db: AsyncSession = Depends(get_db)):
    """Run a simulation: disable controls, modify scores, compute impact."""
    scenario = await _get_or_404(scenario_id, db)

    # Load all nodes with mitigations
    nodes_result = await db.execute(
        select(Node).where(Node.project_id == scenario.project_id)
        .options(selectinload(Node.mitigations))
    )
    nodes = nodes_result.scalars().all()
    if not nodes:
        # No nodes yet — return a zero-impact result instead of crashing
        impact_summary = {
            "original_risk": 0,
            "simulated_risk": 0,
            "delta": 0,
            "affected_nodes": 0,
            "node_details": [],
            "note": "No attack tree nodes in this project. Build an attack tree first using the Tree Editor or AI Agent to enable meaningful simulations.",
        }
        scenario.disabled_controls = data.disabled_controls
        scenario.modified_scores = data.modified_scores
        scenario.impact_summary = impact_summary
        scenario.status = "completed"
        await db.commit()
        await db.refresh(scenario)
        return _to_dict(scenario)

    disabled_set = set(data.disabled_controls)
    original_total = 0.0
    simulated_total = 0.0
    affected_nodes = []

    for node in nodes:
        orig_risk = node.inherent_risk or 0.0
        original_total += orig_risk

        # Apply score overrides
        overrides = data.modified_scores.get(node.id, {})
        likelihood = overrides.get("likelihood", node.likelihood)
        impact = overrides.get("impact", node.impact)
        effort = overrides.get("effort", node.effort)
        exploitability = overrides.get("exploitability", node.exploitability)
        detectability = overrides.get("detectability", node.detectability)

        sim_inherent = compute_inherent_risk(likelihood, impact, effort, exploitability, detectability)

        # Compute residual with disabled controls
        active_mitigations = [m for m in (node.mitigations or []) if m.id not in disabled_set]
        max_eff = max((m.effectiveness for m in active_mitigations), default=0.0) if active_mitigations else 0.0
        sim_residual = compute_residual_risk(sim_inherent, max_eff)

        sim_risk = sim_residual if sim_residual is not None else (sim_inherent or 0.0)
        simulated_total += sim_risk

        if abs(sim_risk - orig_risk) > 0.01:
            affected_nodes.append({
                "id": node.id,
                "title": node.title,
                "original_risk": round(orig_risk, 2),
                "simulated_risk": round(sim_risk, 2),
                "delta": round(sim_risk - orig_risk, 2),
                "controls_disabled": len([m for m in (node.mitigations or []) if m.id in disabled_set]),
            })

    # Save results to scenario
    impact_summary = {
        "original_risk": round(original_total, 2),
        "simulated_risk": round(simulated_total, 2),
        "delta": round(simulated_total - original_total, 2),
        "affected_nodes": len(affected_nodes),
        "node_details": sorted(affected_nodes, key=lambda x: x["delta"], reverse=True),
    }
    scenario.disabled_controls = data.disabled_controls
    scenario.modified_scores = data.modified_scores
    scenario.impact_summary = impact_summary
    scenario.status = "completed"
    await db.commit()
    await db.refresh(scenario)
    return _to_dict(scenario)


@router.post("/{scenario_id}/ai-analyze")
async def ai_analyze_scenario(scenario_id: str, data: AIAnalyzeRequest, db: AsyncSession = Depends(get_db)):
    """Use AI to narrate the scenario, assess impact, and make recommendations."""
    scenario = await _get_or_404(scenario_id, db)
    provider = await _get_active_provider(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    # Load project + nodes
    proj = await db.execute(select(Project).where(Project.id == scenario.project_id))
    project = proj.scalar_one_or_none()
    nodes_result = await db.execute(
        select(Node).where(Node.project_id == scenario.project_id)
        .options(selectinload(Node.mitigations))
    )
    nodes = nodes_result.scalars().all()

    if nodes:
        nodes_text = "\n".join(
            f"- [{n.node_type}] {n.title} (risk:{n.inherent_risk or '?'}, residual:{n.residual_risk or '?'}, "
            f"mitigations:{len(n.mitigations or [])}, status:{n.status})"
            for n in nodes[:60]
        )
    else:
        nodes_text = "(No attack tree nodes exist yet — analyse based on the scenario profile and project objective alone)"

    impact = scenario.impact_summary or {}
    disabled_names = []
    disabled_set = set(scenario.disabled_controls or [])
    for n in nodes:
        for m in (n.mitigations or []):
            if m.id in disabled_set:
                disabled_names.append(f"{m.title} (on node: {n.title})")

    prompt = f"""You are a senior cyber security risk analyst conducting a scenario simulation.

**Project:** {project.name if project else 'Unknown'}
**Root Objective:** {project.root_objective if project else ''}
**Scenario:** {scenario.name}
**Description:** {scenario.description}
**Attacker Profile:** Type={scenario.attacker_type}, Skill={scenario.attacker_skill}, Resources={scenario.attacker_resources}, Motivation={scenario.attacker_motivation}
**Assumptions:** {scenario.assumptions}

**Disabled Controls:** {', '.join(disabled_names) if disabled_names else 'None'}
**Score Overrides:** {json.dumps(scenario.modified_scores) if scenario.modified_scores else 'None'}

**Simulation Results:**
- Original total risk: {impact.get('original_risk', '?')}
- Simulated total risk: {impact.get('simulated_risk', '?')}
- Delta: {impact.get('delta', '?')}
- Affected nodes: {impact.get('affected_nodes', 0)}

**Attack Tree Nodes:**
{nodes_text}

{f'**User Question:** {data.question}' if data.question else ''}

Provide a comprehensive analysis in JSON format:
{{
  "narrative": "A 3-5 paragraph narrative describing what happens in this scenario from the attacker's perspective and the impact on the defender",
  "key_findings": ["finding 1", "finding 2", ...],
  "risk_assessment": "Overall risk assessment paragraph",
  "recommendations": [
    {{"priority": "critical|high|medium|low", "title": "...", "description": "..."}},
    ...
  ],
  "attack_paths_enabled": ["Description of attack paths that become viable or easier"],
  "answer": "Direct answer to the user's question if one was asked, otherwise empty string"
}}

Return ONLY valid JSON."""

    config = _provider_to_config(provider)
    messages = [
        {"role": "system", "content": "You are an expert cyber security risk analyst. Respond only with valid JSON."},
        {"role": "user", "content": prompt},
    ]

    response = await llm_service.chat_completion(config, messages, temperature=0.5)
    if response["status"] != "success":
        raise HTTPException(502, f"LLM request failed: {response.get('message', '')}")

    parsed = llm_service.parse_json_object_response(response["content"])

    scenario.ai_narrative = parsed.get("narrative", response["content"])
    scenario.ai_recommendations = parsed.get("recommendations", [])
    scenario.impact_summary = {
        **(scenario.impact_summary or {}),
        "key_findings": parsed.get("key_findings", []),
        "risk_assessment": parsed.get("risk_assessment", ""),
        "attack_paths_enabled": parsed.get("attack_paths_enabled", []),
        "answer": parsed.get("answer", ""),
    }
    await db.commit()
    await db.refresh(scenario)
    return _to_dict(scenario)


@router.post("/project/{project_id}/ai-generate")
async def ai_generate_scenario(project_id: str, db: AsyncSession = Depends(get_db)):
    """AI generates a scenario based on the current attack tree."""
    provider = await _get_active_provider(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    proj = await db.execute(select(Project).where(Project.id == project_id))
    project = proj.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    nodes_result = await db.execute(
        select(Node).where(Node.project_id == project_id)
        .options(selectinload(Node.mitigations))
    )
    nodes = nodes_result.scalars().all()

    if nodes:
        nodes_text = "\n".join(
            f"- [{n.node_type}] {n.title} (risk:{n.inherent_risk or '?'}, mitigations:{len(n.mitigations or [])})"
            for n in nodes[:40]
        )
    else:
        nodes_text = "(No attack tree nodes yet — generate scenarios based on the project objective and name alone)"

    prompt = f"""Analyze this project and suggest 3 interesting what-if scenarios to simulate.

**Project:** {project.name}
**Root Objective:** {project.root_objective}
**Nodes:**
{nodes_text}

For each scenario, return a JSON array:
[{{
  "name": "Scenario name",
  "description": "What changes in this scenario",
  "attacker_type": "script_kiddie|insider|apt|nation_state",
  "attacker_skill": "Low|Medium|High|Expert",
  "attacker_resources": "Low|Medium|High|Unlimited",
  "attacker_motivation": "motivation description",
  "assumptions": "Key assumptions",
  "rationale": "Why this scenario is interesting to simulate"
}}]

Return ONLY valid JSON array."""

    config = _provider_to_config(provider)
    messages = [
        {"role": "system", "content": "You are an expert cyber security risk analyst. Respond only with valid JSON."},
        {"role": "user", "content": prompt},
    ]

    response = await llm_service.chat_completion(config, messages, temperature=0.7)
    if response["status"] != "success":
        raise HTTPException(502, f"LLM request failed: {response.get('message', '')}")

    suggestions = llm_service.parse_json_response(response["content"])
    return {"suggestions": suggestions}


# --- Helpers ---

async def _get_or_404(scenario_id: str, db: AsyncSession) -> Scenario:
    result = await db.execute(select(Scenario).where(Scenario.id == scenario_id))
    scenario = result.scalar_one_or_none()
    if not scenario:
        raise HTTPException(404, "Scenario not found")
    return scenario


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


def _to_dict(s: Scenario) -> dict:
    return {
        "id": s.id,
        "project_id": s.project_id,
        "name": s.name,
        "description": s.description,
        "status": s.status,
        "attacker_type": s.attacker_type,
        "attacker_skill": s.attacker_skill,
        "attacker_resources": s.attacker_resources,
        "attacker_motivation": s.attacker_motivation,
        "disabled_controls": s.disabled_controls or [],
        "modified_controls": s.modified_scores or {},
        "assumptions": s.assumptions or "",
        "ai_narrative": s.ai_narrative or "",
        "ai_recommendations": s.ai_recommendations or [],
        "impact_summary": s.impact_summary or {},
        "created_at": s.created_at.isoformat() if s.created_at else "",
        "updated_at": s.updated_at.isoformat() if s.updated_at else "",
    }
