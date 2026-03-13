"""Scenario planning and simulation API."""

import json
from collections import Counter
from time import perf_counter
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..database import get_db
from ..models.llm_config import LLMProviderConfig
from ..models.node import Node
from ..models.project import Project
from ..models.scenario import Scenario
from ..services.access_control import (
    get_active_provider_for_user,
    require_project_access,
    require_scenario_access,
)
from ..services.auth import get_current_user_id
from ..services.analysis_runs import record_analysis_run
from ..services import llm_service
from ..services.environment_catalog_service import build_environment_catalog_outline_for_context
from ..services.reference_search_service import (
    dedupe_reference_links,
    format_reference_candidates_for_prompt,
    search_references,
)
from ..services.risk_engine import compute_inherent_risk, compute_residual_risk

router = APIRouter(prefix="/scenarios", tags=["scenarios"])


ATTACKER_TYPE_MODIFIERS: dict[str, dict[str, float]] = {
    "script_kiddie": {"likelihood": -0.7, "effort": 0.8, "exploitability": -0.4, "detectability": 0.7},
    "opportunistic": {},
    "insider": {"likelihood": 0.9, "effort": -0.8, "exploitability": 0.3, "detectability": -0.4},
    "apt": {"likelihood": 1.2, "impact": 0.4, "effort": -1.1, "exploitability": 0.8, "detectability": -0.6},
    "nation_state": {"likelihood": 1.6, "impact": 0.8, "effort": -1.5, "exploitability": 1.0, "detectability": -1.0},
    "red_team": {"likelihood": 0.7, "effort": -0.6, "exploitability": 0.4, "detectability": -0.2},
}
SKILL_MODIFIERS: dict[str, dict[str, float]] = {
    "Low": {"likelihood": -0.5, "effort": 0.5, "exploitability": -0.3},
    "Medium": {},
    "High": {"likelihood": 0.5, "effort": -0.4, "exploitability": 0.3, "detectability": -0.2},
    "Expert": {"likelihood": 0.9, "effort": -0.8, "exploitability": 0.5, "detectability": -0.5},
}
RESOURCE_MODIFIERS: dict[str, dict[str, float]] = {
    "Low": {"likelihood": -0.4, "impact": -0.1, "effort": 0.4},
    "Medium": {},
    "High": {"likelihood": 0.5, "impact": 0.2, "effort": -0.4, "exploitability": 0.2},
    "Unlimited": {"likelihood": 0.9, "impact": 0.4, "effort": -0.9, "exploitability": 0.4},
}
TEMPO_MODIFIERS: dict[str, dict[str, float]] = {
    "deliberate": {"likelihood": -0.1, "detectability": -0.5},
    "balanced": {},
    "rapid": {"likelihood": 0.5, "impact": 0.2, "detectability": 0.7},
}
STEALTH_MODIFIERS: dict[str, dict[str, float]] = {
    "covert": {"likelihood": -0.1, "detectability": -1.0},
    "balanced": {},
    "aggressive": {"likelihood": 0.6, "impact": 0.2, "detectability": 0.9},
}
ACCESS_MODIFIERS: dict[str, dict[str, float]] = {
    "external": {},
    "partner": {"likelihood": 0.3, "effort": -0.2},
    "insider": {"likelihood": 0.8, "effort": -0.6, "detectability": -0.4},
    "privileged": {"likelihood": 1.1, "impact": 0.4, "effort": -1.0, "detectability": -0.4},
}


class ScenarioBase(BaseModel):
    project_id: Optional[str] = None
    scope: Optional[str] = None
    name: str
    description: str = ""
    scenario_type: str = "campaign"
    operation_goal: str = ""
    target_profile: str = ""
    target_environment: str = ""
    execution_tempo: str = "balanced"
    stealth_level: str = "balanced"
    access_level: str = "external"
    attacker_type: str = "opportunistic"
    attacker_skill: str = "Medium"
    attacker_resources: str = "Medium"
    attacker_motivation: str = ""
    entry_vectors: list[str] = Field(default_factory=list)
    campaign_phases: list[str] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    intelligence_gaps: list[str] = Field(default_factory=list)
    success_criteria: list[str] = Field(default_factory=list)
    focus_node_ids: list[str] = Field(default_factory=list)
    focus_tags: list[str] = Field(default_factory=list)
    disabled_controls: list[str] = Field(default_factory=list)
    degraded_detections: list[str] = Field(default_factory=list)
    modified_scores: dict[str, dict[str, float]] = Field(default_factory=dict)
    assumptions: str = ""
    planning_notes: str = ""
    reference_mappings: list[dict[str, Any]] = Field(default_factory=list)


class ScenarioCreate(ScenarioBase):
    pass


class ScenarioUpdate(BaseModel):
    project_id: Optional[str] = None
    scope: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    scenario_type: Optional[str] = None
    operation_goal: Optional[str] = None
    target_profile: Optional[str] = None
    target_environment: Optional[str] = None
    execution_tempo: Optional[str] = None
    stealth_level: Optional[str] = None
    access_level: Optional[str] = None
    attacker_type: Optional[str] = None
    attacker_skill: Optional[str] = None
    attacker_resources: Optional[str] = None
    attacker_motivation: Optional[str] = None
    entry_vectors: Optional[list[str]] = None
    campaign_phases: Optional[list[str]] = None
    constraints: Optional[list[str]] = None
    dependencies: Optional[list[str]] = None
    intelligence_gaps: Optional[list[str]] = None
    success_criteria: Optional[list[str]] = None
    focus_node_ids: Optional[list[str]] = None
    focus_tags: Optional[list[str]] = None
    disabled_controls: Optional[list[str]] = None
    degraded_detections: Optional[list[str]] = None
    modified_scores: Optional[dict[str, dict[str, float]]] = None
    assumptions: Optional[str] = None
    planning_notes: Optional[str] = None
    reference_mappings: Optional[list[dict[str, Any]]] = None


class SimulateRequest(BaseModel):
    disabled_controls: list[str] = Field(default_factory=list)
    degraded_detections: list[str] = Field(default_factory=list)
    modified_scores: dict[str, dict[str, float]] = Field(default_factory=dict)
    attacker_type: str = "opportunistic"
    attacker_skill: str = "Medium"
    attacker_resources: str = "Medium"
    execution_tempo: str = "balanced"
    stealth_level: str = "balanced"
    access_level: str = "external"
    focus_node_ids: list[str] = Field(default_factory=list)
    focus_tags: list[str] = Field(default_factory=list)


class AIAnalyzeRequest(BaseModel):
    question: str = ""
    planning_profile: str = "balanced"


class AIGenerateRequest(BaseModel):
    project_id: Optional[str] = None
    focus: str = ""
    count: int = Field(default=6, ge=1, le=12)
    planning_profile: str = "balanced"


def _scenario_planning_context(planning_profile: str, objective: str, scope: str, context_preset: str = "") -> tuple[str, str, str, str]:
    normalized_profile = llm_service.normalize_planning_profile(planning_profile)
    domain = llm_service.detect_planning_domain(objective, scope, context_preset)
    profile_label = llm_service.get_planning_profile_label(normalized_profile)
    guidance = "\n".join(
        section for section in [
            llm_service.get_domain_decomposition_guidance(domain),
            llm_service.get_planning_profile_guidance(normalized_profile, domain),
            build_environment_catalog_outline_for_context(objective, scope, context_preset),
            (
                "Scenario planning workflow:\n"
                "- Start by framing the scenario across people, physical, technical, supply-chain, and process dependencies where they matter.\n"
                "- Identify decisive trust-boundary crossings, enabling conditions, and defender assumptions before writing detailed phase actions.\n"
                "- Use ATT&CK, CAPEC, CWE, and CVE references only as enrichment once a path is concrete enough to justify them."
            ),
        ] if section
    )
    return normalized_profile, profile_label, domain, guidance


def _normalize_reference_links(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return dedupe_reference_links([item for item in value if isinstance(item, dict)])


def _scenario_candidate_references(
    *,
    focus: str,
    objective: str,
    scope: str,
    context_preset: str,
    target_summary: str,
    limit: int = 10,
) -> list[dict[str, Any]]:
    return search_references(
        query=focus,
        artifact_type="scenario",
        context_preset=context_preset,
        objective=objective,
        scope=scope,
        target_kind="scenario",
        target_summary=target_summary,
        allowed_frameworks=[
            "attack",
            "capec",
            "cwe",
            "owasp",
            "infra_attack_patterns",
            "software_research_patterns",
            "environment_catalog",
        ],
        limit=limit,
    )


@router.get("")
async def list_scenarios(
    project_id: Optional[str] = None,
    scope: str = Query(default="all", pattern="^(all|project|standalone|workspace)$"),
    db: AsyncSession = Depends(get_db),
):
    if project_id:
        await require_project_access(project_id, db)
    query = select(Scenario).options(selectinload(Scenario.project)).order_by(
        Scenario.updated_at.desc(),
        Scenario.created_at.desc(),
    ).where(Scenario.user_id == get_current_user_id())
    if scope == "standalone":
        query = query.where(Scenario.project_id.is_(None))
    elif scope == "project":
        query = query.where(Scenario.project_id == project_id) if project_id else query.where(Scenario.project_id.is_not(None))
    elif scope == "workspace":
        query = query.where(or_(Scenario.project_id == project_id, Scenario.project_id.is_(None))) if project_id else query.where(Scenario.project_id.is_(None))
    elif project_id:
        query = query.where(Scenario.project_id == project_id)

    result = await db.execute(query)
    return [_to_dict(s) for s in result.scalars().all()]


@router.get("/project/{project_id}")
async def list_project_scenarios(project_id: str, db: AsyncSession = Depends(get_db)):
    await require_project_access(project_id, db)
    result = await db.execute(
        select(Scenario)
        .where(Scenario.project_id == project_id, Scenario.user_id == get_current_user_id())
        .options(selectinload(Scenario.project))
        .order_by(Scenario.updated_at.desc(), Scenario.created_at.desc())
    )
    return [_to_dict(s) for s in result.scalars().all()]


@router.post("", status_code=201)
async def create_scenario(data: ScenarioCreate, db: AsyncSession = Depends(get_db)):
    payload = await _normalise_scope_payload(data.model_dump(), db)
    payload["user_id"] = get_current_user_id()
    payload["reference_mappings"] = _normalize_reference_links(payload.get("reference_mappings"))
    scenario = Scenario(**payload)
    db.add(scenario)
    await db.commit()
    return _to_dict(await _get_or_404(scenario.id, db))


@router.get("/{scenario_id}")
async def get_scenario(scenario_id: str, db: AsyncSession = Depends(get_db)):
    return _to_dict(await _get_or_404(scenario_id, db))


@router.patch("/{scenario_id}")
async def update_scenario(scenario_id: str, data: ScenarioUpdate, db: AsyncSession = Depends(get_db)):
    scenario = await _get_or_404(scenario_id, db)
    update_data = await _normalise_scope_payload(data.model_dump(exclude_unset=True), db, scenario)
    if "reference_mappings" in update_data:
        update_data["reference_mappings"] = _normalize_reference_links(update_data.get("reference_mappings"))
    for key, value in update_data.items():
        setattr(scenario, key, value)
    await db.commit()
    return _to_dict(await _get_or_404(scenario_id, db))


@router.delete("/{scenario_id}", status_code=204)
async def delete_scenario(scenario_id: str, db: AsyncSession = Depends(get_db)):
    scenario = await _get_or_404(scenario_id, db)
    await db.delete(scenario)
    await db.commit()


@router.post("/{scenario_id}/simulate")
async def simulate(scenario_id: str, data: SimulateRequest, db: AsyncSession = Depends(get_db)):
    started_at = perf_counter()
    scenario = await _get_or_404(scenario_id, db)

    scenario.disabled_controls = data.disabled_controls
    scenario.degraded_detections = data.degraded_detections
    scenario.modified_scores = data.modified_scores
    scenario.attacker_type = data.attacker_type
    scenario.attacker_skill = data.attacker_skill
    scenario.attacker_resources = data.attacker_resources
    scenario.execution_tempo = data.execution_tempo
    scenario.stealth_level = data.stealth_level
    scenario.access_level = data.access_level
    scenario.focus_node_ids = data.focus_node_ids
    scenario.focus_tags = data.focus_tags

    if not scenario.project_id:
        scenario.impact_summary = _build_planning_only_summary(scenario)
        scenario.status = "completed"
        await db.commit()
        return _to_dict(await _get_or_404(scenario_id, db))

    nodes_result = await db.execute(
        select(Node)
        .where(Node.project_id == scenario.project_id)
        .options(selectinload(Node.mitigations), selectinload(Node.detections), selectinload(Node.tags))
    )
    nodes = nodes_result.scalars().all()
    if not nodes:
        scenario.impact_summary = _build_planning_only_summary(
            scenario,
            note="This scenario is linked to a project, but the project has no attack tree nodes yet.",
        )
        scenario.status = "completed"
        await db.commit()
        return _to_dict(await _get_or_404(scenario_id, db))

    disabled_set = set(scenario.disabled_controls or [])
    degraded_detection_set = set(scenario.degraded_detections or [])
    focus_node_set = set(scenario.focus_node_ids or [])
    focus_tag_set = {tag.lower() for tag in (scenario.focus_tags or []) if tag}
    modifiers = _compose_modifiers(
        scenario.attacker_type,
        scenario.attacker_skill,
        scenario.attacker_resources,
        scenario.execution_tempo,
        scenario.stealth_level,
        scenario.access_level,
    )

    original_total = 0.0
    simulated_total = 0.0
    affected_nodes: list[dict[str, Any]] = []
    disabled_controls_list: list[dict[str, Any]] = []
    degraded_detections_list: list[dict[str, Any]] = []
    focus_affected = 0

    for node in nodes:
        baseline_inherent = node.inherent_risk or compute_inherent_risk(
            node.likelihood,
            node.impact,
            node.effort,
            node.exploitability,
            node.detectability,
        )
        baseline_risk = node.residual_risk
        if baseline_risk is None:
            baseline_risk = compute_residual_risk(
                baseline_inherent,
                max((m.effectiveness for m in (node.mitigations or [])), default=0.0),
            )
        baseline_risk = baseline_risk if baseline_risk is not None else (baseline_inherent or 0.0)
        original_total += baseline_risk

        overrides = scenario.modified_scores.get(node.id, {})
        likelihood = _apply_modifier(overrides.get("likelihood", node.likelihood), modifiers.get("likelihood", 0.0))
        impact = _apply_modifier(overrides.get("impact", node.impact), modifiers.get("impact", 0.0))
        effort = _apply_modifier(overrides.get("effort", node.effort), modifiers.get("effort", 0.0))
        exploitability = _apply_modifier(
            overrides.get("exploitability", node.exploitability),
            modifiers.get("exploitability", 0.0),
        )
        detectability = _apply_modifier(
            overrides.get("detectability", node.detectability),
            modifiers.get("detectability", 0.0),
        )

        degraded_on_node = [d for d in (node.detections or []) if d.id in degraded_detection_set]
        degraded_coverage = sum((d.coverage or 0.0) for d in degraded_on_node)
        if detectability is not None:
            detectability = _apply_modifier(detectability, -min(2.5, degraded_coverage * 3.0))

        sim_inherent = compute_inherent_risk(likelihood, impact, effort, exploitability, detectability)
        active_mitigations = [m for m in (node.mitigations or []) if m.id not in disabled_set]
        sim_residual = compute_residual_risk(
            sim_inherent,
            max((m.effectiveness for m in active_mitigations), default=0.0),
        )
        sim_risk = sim_residual if sim_residual is not None else (sim_inherent or baseline_risk)
        simulated_total += sim_risk

        disabled_on_node = [m for m in (node.mitigations or []) if m.id in disabled_set]
        is_focus = node.id in focus_node_set or any(
            getattr(tag, "name", "").lower() in focus_tag_set for tag in (node.tags or [])
        )

        for control in disabled_on_node:
            disabled_controls_list.append(
                {
                    "id": control.id,
                    "title": control.title,
                    "node": node.title,
                    "effectiveness": round(control.effectiveness or 0.0, 2),
                }
            )
        for detection in degraded_on_node:
            degraded_detections_list.append(
                {
                    "id": detection.id,
                    "title": detection.title,
                    "node": node.title,
                    "coverage": round(detection.coverage or 0.0, 2),
                }
            )

        delta = round(sim_risk - baseline_risk, 2)
        if abs(delta) > 0.01 or disabled_on_node or degraded_on_node or is_focus:
            if is_focus:
                focus_affected += 1
            affected_nodes.append(
                {
                    "id": node.id,
                    "title": node.title,
                    "node_type": node.node_type,
                    "original_risk": round(baseline_risk, 2),
                    "simulated_risk": round(sim_risk, 2),
                    "delta": delta,
                    "controls_disabled": len(disabled_on_node),
                    "detections_degraded": len(degraded_on_node),
                    "focus_match": is_focus,
                    "attack_surface": node.attack_surface or "",
                    "platform": node.platform or "",
                }
            )

    scenario.impact_summary = {
        "simulation_mode": "tree",
        "original_risk": round(original_total, 2),
        "simulated_risk": round(simulated_total, 2),
        "delta": round(simulated_total - original_total, 2),
        "affected_nodes": len(affected_nodes),
        "focus_nodes_affected": focus_affected,
        "node_details": sorted(affected_nodes, key=lambda item: item["delta"], reverse=True),
        "top_exposed_controls": _top_entries(disabled_controls_list, "title"),
        "top_degraded_detections": _top_entries(degraded_detections_list, "title"),
        "campaign_profile": _build_campaign_profile(scenario, len(nodes), round(simulated_total - original_total, 2)),
        "planning_findings": _build_planning_findings(scenario, nodes_present=True),
        "modifier_profile": modifiers,
    }
    scenario.status = "completed"
    await db.commit()
    await record_analysis_run(
        db,
        project_id=scenario.project_id,
        tool="scenario",
        run_type="planning_pass",
        status="completed",
        artifact_kind="scenario",
        artifact_id=scenario.id,
        artifact_name=scenario.name,
        summary=(
            f"Planning pass completed with {len(affected_nodes)} affected node"
            f"{'' if len(affected_nodes) == 1 else 's'} and a risk delta of "
            f"{round(simulated_total - original_total, 2):+.2f}."
        ),
        metadata={
            "affected_nodes": len(affected_nodes),
            "focus_nodes_affected": focus_affected,
            "risk_delta": round(simulated_total - original_total, 2),
            "disabled_controls": len(disabled_controls_list),
            "degraded_detections": len(degraded_detections_list),
        },
        duration_ms=round((perf_counter() - started_at) * 1000),
    )
    return _to_dict(await _get_or_404(scenario_id, db))


@router.post("/{scenario_id}/ai-analyze")
async def ai_analyze_scenario(scenario_id: str, data: AIAnalyzeRequest, db: AsyncSession = Depends(get_db)):
    started_at = perf_counter()
    scenario = await _get_or_404(scenario_id, db)
    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    project = None
    nodes: list[Node] = []
    if scenario.project_id:
        project = await require_project_access(scenario.project_id, db)
        nodes_result = await db.execute(
            select(Node)
            .where(Node.project_id == scenario.project_id)
            .options(selectinload(Node.mitigations), selectinload(Node.detections), selectinload(Node.tags))
        )
        nodes = nodes_result.scalars().all()

    nodes_text = "\n".join(
        f"- [{n.node_type}] {n.title} (risk:{n.inherent_risk or '?'} residual:{n.residual_risk or '?'} "
        f"mitigations:{len(n.mitigations or [])} detections:{len(n.detections or [])} "
        f"surface:{n.attack_surface or 'n/a'} platform:{n.platform or 'n/a'})"
        for n in nodes[:80]
    ) if nodes else "(No linked attack tree nodes. Analyse this as a standalone planning scenario.)"
    _, planning_label, planning_domain, planning_guidance = _scenario_planning_context(
        data.planning_profile,
        " ".join(
            part for part in [
                project.root_objective if project else "",
                scenario.operation_goal,
                scenario.name,
            ] if part
        ),
        " ".join(
            part for part in [
                project.description if project else "",
                scenario.description,
                scenario.target_profile,
                scenario.target_environment,
                scenario.assumptions or "",
                " ".join(scenario.entry_vectors or []),
                " ".join(scenario.campaign_phases or []),
                " ".join(scenario.constraints or []),
                data.question,
            ] if part
        ),
        getattr(project, "context_preset", "") if project else "",
    )

    prompt = f"""You are a senior cyber operations planner and cyber security risk analyst.

Produce a deep planning brief for this scenario in valid JSON.

**Planning Profile:** {planning_label}
**Detected Planning Domain:** {planning_domain}
{planning_guidance}

**Scenario Name:** {scenario.name}
**Scope:** {scenario.scope}
**Scenario Type:** {scenario.scenario_type}
**Description:** {scenario.description}
**Operation Goal:** {scenario.operation_goal}
**Target Profile:** {scenario.target_profile}
**Target Environment:** {scenario.target_environment}
**Execution Tempo:** {scenario.execution_tempo}
**Stealth Level:** {scenario.stealth_level}
**Access Level:** {scenario.access_level}
**Attacker Profile:** Type={scenario.attacker_type}, Skill={scenario.attacker_skill}, Resources={scenario.attacker_resources}, Motivation={scenario.attacker_motivation}
**Entry Vectors:** {json.dumps(scenario.entry_vectors or [])}
**Campaign Phases:** {json.dumps(scenario.campaign_phases or [])}
**Constraints:** {json.dumps(scenario.constraints or [])}
**Dependencies:** {json.dumps(scenario.dependencies or [])}
**Intelligence Gaps:** {json.dumps(scenario.intelligence_gaps or [])}
**Success Criteria:** {json.dumps(scenario.success_criteria or [])}
**Focus Node IDs:** {json.dumps(scenario.focus_node_ids or [])}
**Focus Tags:** {json.dumps(scenario.focus_tags or [])}
**Disabled Controls:** {json.dumps(scenario.disabled_controls or [])}
**Degraded Detections:** {json.dumps(scenario.degraded_detections or [])}
**Assumptions:** {scenario.assumptions}
**Planning Notes:** {scenario.planning_notes}

**Project:** {project.name if project else 'Standalone Scenario'}
**Root Objective:** {project.root_objective if project else ''}

**Simulation Summary:** {json.dumps(scenario.impact_summary or {})}

**Tree Context:**
{nodes_text}

{f'**Analyst Question:** {data.question}' if data.question else ''}

Return ONLY valid JSON with this shape:
{{
  "executive_summary": "2-3 paragraphs",
  "narrative": "Detailed 3-5 paragraph scenario narrative",
  "phase_plan": [
    {{
      "phase": "short phase name",
      "objective": "what the attacker is trying to achieve",
      "actions": ["specific actions"],
      "dependencies": ["key dependencies"],
      "detection_considerations": ["likely defender visibility or blind spots"]
    }}
  ],
  "key_findings": ["important finding"],
  "risk_assessment": "overall assessment paragraph",
  "defender_pain_points": ["what will stress the defender"],
  "intelligence_priorities": ["what still needs to be learned"],
  "attack_paths_enabled": ["which paths become more viable"],
  "recommendations": [
    {{"priority": "critical|high|medium|low", "title": "short title", "description": "clear action"}}
  ],
  "answer": "direct answer to the analyst question if one was asked"
}}"""

    response = await llm_service.chat_completion(
        _provider_to_config(provider),
        [
            {"role": "system", "content": "You are an expert cyber operations planner. Respond only with valid JSON."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.4,
    )
    if response["status"] != "success":
        raise HTTPException(502, f"LLM request failed: {response.get('message', '')}")

    parsed = llm_service.parse_json_object_response(response["content"])
    scenario.ai_narrative = parsed.get("narrative") or parsed.get("executive_summary") or response["content"]
    scenario.ai_recommendations = parsed.get("recommendations", [])
    scenario.impact_summary = {
        **(scenario.impact_summary or {}),
        "executive_summary": parsed.get("executive_summary", ""),
        "phase_plan": parsed.get("phase_plan", []),
        "key_findings": parsed.get("key_findings", []),
        "risk_assessment": parsed.get("risk_assessment", ""),
        "defender_pain_points": parsed.get("defender_pain_points", []),
        "intelligence_priorities": parsed.get("intelligence_priorities", []),
        "attack_paths_enabled": parsed.get("attack_paths_enabled", []),
        "answer": parsed.get("answer", ""),
    }
    await db.commit()
    await record_analysis_run(
        db,
        project_id=scenario.project_id,
        tool="scenario",
        run_type="ai_brief",
        status="completed",
        artifact_kind="scenario",
        artifact_id=scenario.id,
        artifact_name=scenario.name,
        summary=(
            f"AI planning brief generated with {len(scenario.ai_recommendations or [])} recommendation"
            f"{'' if len(scenario.ai_recommendations or []) == 1 else 's'}."
        ),
        metadata={
            "recommendation_count": len(scenario.ai_recommendations or []),
            "phase_count": len(parsed.get("phase_plan", []) or []),
            "question_supplied": bool(data.question),
        },
        duration_ms=response.get("elapsed_ms", round((perf_counter() - started_at) * 1000)),
    )
    return _to_dict(await _get_or_404(scenario_id, db))


@router.post("/ai-generate")
async def ai_generate_scenarios(data: AIGenerateRequest, db: AsyncSession = Depends(get_db)):
    started_at = perf_counter()
    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    project = None
    nodes: list[Node] = []
    if data.project_id:
        project = await require_project_access(data.project_id, db)
        nodes_result = await db.execute(
            select(Node)
            .where(Node.project_id == data.project_id)
            .options(selectinload(Node.mitigations), selectinload(Node.detections))
        )
        nodes = nodes_result.scalars().all()

    nodes_text = "\n".join(
        f"- [{n.node_type}] {n.title} (risk:{n.inherent_risk or n.rolled_up_risk or '?'} surface:{n.attack_surface or 'n/a'} platform:{n.platform or 'n/a'})"
        for n in nodes[:50]
    ) if nodes else "(No project tree context supplied. Generate a diverse standalone scenario set.)"
    focus_text = data.focus or (f"{project.root_objective}. {project.description}" if project else "General cyber operations planning")
    _, planning_label, planning_domain, planning_guidance = _scenario_planning_context(
        data.planning_profile,
        focus_text,
        " ".join(
            part for part in [
                project.description if project else "",
                nodes_text,
            ] if part
        ),
        getattr(project, "context_preset", "") if project else "",
    )
    candidate_references = _scenario_candidate_references(
        focus=focus_text,
        objective=project.root_objective if project else focus_text,
        scope=" ".join(
            part for part in [
                project.description if project else "",
                nodes_text,
            ] if part
        ),
        context_preset=getattr(project, "context_preset", "") if project else "",
        target_summary=focus_text,
        limit=12,
    )
    candidate_reference_block = format_reference_candidates_for_prompt(candidate_references)

    prompt = f"""Generate {data.count} diverse cyber operation planning scenarios.

Cover a wide spread of operation types rather than repeating the same intrusion pattern.
Mix objectives such as collection, disruption, credential access, insider abuse, supply-chain compromise,
cloud control-plane abuse, identity attacks, ransomware, coercive impact, and tabletop / response exercises where relevant.

**Planning Profile:** {planning_label}
**Detected Planning Domain:** {planning_domain}
{planning_guidance}

**Project:** {project.name if project else 'Standalone Scenario Workspace'}
**Root Objective:** {project.root_objective if project else ''}
**Focus:** {focus_text}
**Tree Context:**
{nodes_text}
{f"\n{candidate_reference_block}\n" if candidate_reference_block else ""}

First diversify the scenario set across meaningful attack-surface domains, actor paths, and operation families before varying lower-level TTP details.
Use the retrieved candidate references to ground the scenarios in realistic attacker tradecraft and environment-relevant attack patterns. Include only references that are actually useful for that scenario.

Return ONLY a valid JSON array. Each item must contain:
{{
  "name": "specific scenario title",
  "description": "what changes and why it matters",
  "scenario_type": "campaign|collection|disruption|supply_chain|insider|red_team|tabletop|fraud|ransomware|identity",
  "operation_goal": "primary mission goal",
  "target_profile": "who or what is being targeted",
  "target_environment": "environment or terrain",
  "execution_tempo": "deliberate|balanced|rapid",
  "stealth_level": "covert|balanced|aggressive",
  "access_level": "external|partner|insider|privileged",
  "attacker_type": "script_kiddie|opportunistic|insider|apt|nation_state|red_team",
  "attacker_skill": "Low|Medium|High|Expert",
  "attacker_resources": "Low|Medium|High|Unlimited",
  "attacker_motivation": "short motivation",
  "entry_vectors": ["vector"],
  "campaign_phases": ["phase"],
  "constraints": ["constraint"],
  "dependencies": ["dependency"],
  "intelligence_gaps": ["unknown that matters"],
  "success_criteria": ["what defines success"],
  "reference_mappings": [
    {{"framework": "validated local framework", "ref_id": "validated local id", "ref_name": "name", "confidence": 0.0-1.0, "rationale": "brief reason", "source": "ai"}}
  ],
  "assumptions": "key assumptions",
  "planning_notes": "why this scenario is worth planning"
}}"""

    response = await llm_service.chat_completion(
        _provider_to_config(provider),
        [
            {"role": "system", "content": "You are an expert cyber operations planner. Respond only with valid JSON."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.7,
    )
    if response["status"] != "success":
        raise HTTPException(502, f"LLM request failed: {response.get('message', '')}")

    suggestions = [
        _clean_ai_suggestion(item, project.id if project else None)
        for item in llm_service.parse_json_response(response["content"])
    ]
    if project:
        await record_analysis_run(
            db,
            project_id=project.id,
            tool="scenario",
            run_type="suggestion_batch",
            status="completed",
            artifact_kind="scenario",
            artifact_name=project.name,
            summary=(
                f"Generated {len(suggestions)} project-linked scenario suggestion"
                f"{'' if len(suggestions) == 1 else 's'}."
            ),
            metadata={
                "suggestion_count": len(suggestions),
                "focus": focus_text,
            },
            duration_ms=response.get("elapsed_ms", round((perf_counter() - started_at) * 1000)),
        )
    return {"suggestions": suggestions}


@router.post("/project/{project_id}/ai-generate")
async def ai_generate_project_scenarios(project_id: str, db: AsyncSession = Depends(get_db)):
    return await ai_generate_scenarios(AIGenerateRequest(project_id=project_id), db)


async def _get_or_404(scenario_id: str, db: AsyncSession) -> Scenario:
    result = await db.execute(
        select(Scenario)
        .where(Scenario.id == scenario_id, Scenario.user_id == get_current_user_id())
        .options(selectinload(Scenario.project))
    )
    scenario = result.scalar_one_or_none()
    if not scenario:
        raise HTTPException(404, "Scenario not found")
    return scenario


async def _normalise_scope_payload(
    payload: dict[str, Any],
    db: AsyncSession,
    existing: Scenario | None = None,
) -> dict[str, Any]:
    if "project_id" in payload and payload["project_id"]:
        await _ensure_project_exists(payload["project_id"], db)

    if payload.get("scope") == "standalone":
        payload["project_id"] = None
    elif payload.get("scope") == "project" and not payload.get("project_id") and existing and existing.project_id:
        payload["project_id"] = existing.project_id

    if "project_id" not in payload and existing is not None:
        payload["project_id"] = existing.project_id

    payload["scope"] = "project" if payload.get("project_id") else "standalone"
    payload["user_id"] = existing.user_id if existing is not None else get_current_user_id()
    return payload


async def _ensure_project_exists(project_id: str, db: AsyncSession) -> None:
    await require_project_access(project_id, db)


def _compose_modifiers(
    attacker_type: str,
    attacker_skill: str,
    attacker_resources: str,
    execution_tempo: str,
    stealth_level: str,
    access_level: str,
) -> dict[str, float]:
    combined: dict[str, float] = {}
    for source in (
        ATTACKER_TYPE_MODIFIERS.get(attacker_type, {}),
        SKILL_MODIFIERS.get(attacker_skill, {}),
        RESOURCE_MODIFIERS.get(attacker_resources, {}),
        TEMPO_MODIFIERS.get(execution_tempo, {}),
        STEALTH_MODIFIERS.get(stealth_level, {}),
        ACCESS_MODIFIERS.get(access_level, {}),
    ):
        for key, value in source.items():
            combined[key] = combined.get(key, 0.0) + value
    return {key: round(value, 2) for key, value in combined.items()}


def _apply_modifier(value: Optional[float], delta: float) -> Optional[float]:
    if value is None:
        return None
    return round(min(10.0, max(1.0, value + delta)), 2)


def _build_campaign_profile(scenario: Scenario, node_count: int, delta: float | None) -> dict[str, Any]:
    coverage_units = sum(
        1
        for item in (
            scenario.operation_goal,
            scenario.target_profile,
            scenario.target_environment,
            scenario.entry_vectors,
            scenario.campaign_phases,
            scenario.constraints,
            scenario.dependencies,
            scenario.success_criteria,
            scenario.assumptions,
            scenario.planning_notes,
            scenario.focus_node_ids,
            scenario.focus_tags,
        )
        if item
    )
    coverage_score = round(min(10.0, coverage_units * 0.9), 1)
    complexity_score = round(
        min(
            10.0,
            2.5
            + len(scenario.campaign_phases or []) * 0.7
            + len(scenario.constraints or []) * 0.6
            + len(scenario.dependencies or []) * 0.5
            + (0.7 if scenario.execution_tempo == "rapid" else 0.3 if scenario.execution_tempo == "balanced" else 0.0)
            + (0.8 if scenario.attacker_skill in ("High", "Expert") else 0.2),
        ),
        1,
    )
    exposure_score = round(
        min(
            10.0,
            3.0
            + (0.7 if scenario.access_level in ("insider", "privileged") else 0.0)
            + (0.7 if scenario.stealth_level == "covert" else 0.0)
            + (0.6 if scenario.attacker_resources in ("High", "Unlimited") else 0.0)
            + max(delta or 0.0, 0.0) * 0.25,
        ),
        1,
    )
    readiness_score = round(
        max(
            0.0,
            min(
                10.0,
                7.5
                - len(scenario.intelligence_gaps or []) * 0.6
                - len(scenario.disabled_controls or []) * 0.3
                - len(scenario.degraded_detections or []) * 0.3
                + (0.4 if node_count else -1.0),
            ),
        ),
        1,
    )
    return {
        "coverage_score": coverage_score,
        "complexity_score": complexity_score,
        "exposure_score": exposure_score,
        "readiness_score": readiness_score,
        "entry_vector_count": len(scenario.entry_vectors or []),
        "phase_count": len(scenario.campaign_phases or []),
        "constraint_count": len(scenario.constraints or []),
        "dependency_count": len(scenario.dependencies or []),
        "intelligence_gap_count": len(scenario.intelligence_gaps or []),
        "success_criteria_count": len(scenario.success_criteria or []),
        "focus_count": len(scenario.focus_node_ids or []) + len(scenario.focus_tags or []),
    }


def _build_planning_findings(scenario: Scenario, nodes_present: bool) -> list[str]:
    findings: list[str] = []
    if not scenario.entry_vectors:
        findings.append("No initial access or entry vectors are defined.")
    if len(scenario.campaign_phases or []) < 2:
        findings.append("Campaign phases are shallow; sequence the operation more explicitly.")
    if scenario.intelligence_gaps:
        findings.append(f"{len(scenario.intelligence_gaps)} intelligence gaps remain unresolved.")
    if scenario.disabled_controls:
        findings.append(f"Simulation assumes {len(scenario.disabled_controls)} control failures or absences.")
    if scenario.degraded_detections:
        findings.append(f"Simulation assumes {len(scenario.degraded_detections)} degraded detections.")
    if not nodes_present:
        findings.append("This is a qualitative planning pass without a linked attack tree.")
    if scenario.focus_node_ids or scenario.focus_tags:
        findings.append("Scenario includes a focused subset of targets for deeper analysis.")
    if not findings:
        findings.append("Scenario definition is well-populated and ready for deeper analysis.")
    return findings


def _build_planning_only_summary(scenario: Scenario, note: str | None = None) -> dict[str, Any]:
    return {
        "simulation_mode": "planning",
        "original_risk": None,
        "simulated_risk": None,
        "delta": None,
        "affected_nodes": 0,
        "node_details": [],
        "campaign_profile": _build_campaign_profile(scenario, 0, None),
        "planning_findings": _build_planning_findings(scenario, nodes_present=False),
        "note": note or "Generated a qualitative planning profile without attack-tree node data.",
    }


def _top_entries(items: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    counter = Counter(item[key] for item in items)
    top: list[dict[str, Any]] = []
    seen = set()
    for item in sorted(items, key=lambda current: counter[current[key]], reverse=True):
        if item[key] in seen:
            continue
        seen.add(item[key])
        top.append({**item, "count": counter[item[key]]})
        if len(top) >= 5:
            break
    return top


def _provider_to_config(provider) -> dict[str, Any]:
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


def _clean_ai_suggestion(item: dict[str, Any], project_id: str | None) -> dict[str, Any]:
    return {
        "project_id": project_id,
        "scope": "project" if project_id else "standalone",
        "name": item.get("name", "Suggested Scenario"),
        "description": item.get("description", ""),
        "scenario_type": item.get("scenario_type", "campaign"),
        "operation_goal": item.get("operation_goal", ""),
        "target_profile": item.get("target_profile", ""),
        "target_environment": item.get("target_environment", ""),
        "execution_tempo": item.get("execution_tempo", "balanced"),
        "stealth_level": item.get("stealth_level", "balanced"),
        "access_level": item.get("access_level", "external"),
        "attacker_type": item.get("attacker_type", "opportunistic"),
        "attacker_skill": item.get("attacker_skill", "Medium"),
        "attacker_resources": item.get("attacker_resources", "Medium"),
        "attacker_motivation": item.get("attacker_motivation", ""),
        "entry_vectors": item.get("entry_vectors") or [],
        "campaign_phases": item.get("campaign_phases") or [],
        "constraints": item.get("constraints") or [],
        "dependencies": item.get("dependencies") or [],
        "intelligence_gaps": item.get("intelligence_gaps") or [],
        "success_criteria": item.get("success_criteria") or [],
        "assumptions": item.get("assumptions", ""),
        "planning_notes": item.get("planning_notes", ""),
        "reference_mappings": _normalize_reference_links(item.get("reference_mappings")),
    }


def _to_dict(s: Scenario) -> dict[str, Any]:
    return {
        "id": s.id,
        "project_id": s.project_id,
        "project_name": s.project.name if getattr(s, "project", None) else "",
        "scope": s.scope or ("project" if s.project_id else "standalone"),
        "name": s.name,
        "description": s.description or "",
        "status": s.status,
        "scenario_type": s.scenario_type or "campaign",
        "operation_goal": s.operation_goal or "",
        "target_profile": s.target_profile or "",
        "target_environment": s.target_environment or "",
        "execution_tempo": s.execution_tempo or "balanced",
        "stealth_level": s.stealth_level or "balanced",
        "access_level": s.access_level or "external",
        "attacker_type": s.attacker_type,
        "attacker_skill": s.attacker_skill,
        "attacker_resources": s.attacker_resources,
        "attacker_motivation": s.attacker_motivation or "",
        "entry_vectors": s.entry_vectors or [],
        "campaign_phases": s.campaign_phases or [],
        "constraints": s.constraints or [],
        "dependencies": s.dependencies or [],
        "intelligence_gaps": s.intelligence_gaps or [],
        "success_criteria": s.success_criteria or [],
        "focus_node_ids": s.focus_node_ids or [],
        "focus_tags": s.focus_tags or [],
        "disabled_controls": s.disabled_controls or [],
        "degraded_detections": s.degraded_detections or [],
        "modified_scores": s.modified_scores or {},
        "modified_controls": s.modified_scores or {},
        "assumptions": s.assumptions or "",
        "planning_notes": s.planning_notes or "",
        "reference_mappings": _normalize_reference_links(s.reference_mappings or []),
        "ai_narrative": s.ai_narrative or "",
        "ai_recommendations": s.ai_recommendations or [],
        "impact_summary": s.impact_summary or {},
        "created_at": s.created_at.isoformat() if s.created_at else "",
        "updated_at": s.updated_at.isoformat() if s.updated_at else "",
    }
