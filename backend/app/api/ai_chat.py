"""
AI Chat endpoints: Brainstorming, Red-Team Advisor, Risk Score Challenger.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..database import get_db
from ..models.llm_config import LLMProviderConfig
from ..models.node import Node
from ..services.access_control import require_provider_access
from ..services.crypto import decrypt_value
from ..services.environment_catalog_service import build_environment_catalog_outline_for_context
from ..services.llm_service import (
    chat_completion,
    detect_planning_domain,
    get_context_preset_label,
    get_domain_decomposition_guidance,
    get_planning_profile_guidance,
    get_planning_profile_label,
    normalize_planning_profile,
)

router = APIRouter(prefix="/ai-chat", tags=["ai-chat"])


# ── Schemas ─────────────────────────────────────────────────────
class ChatMessage(BaseModel):
    role: str  # "user" | "assistant" | "system"
    content: str


class BrainstormRequest(BaseModel):
    provider_id: str
    project_name: str = ""
    root_objective: str = ""
    context_preset: str = ""
    workspace_mode: str = ""
    planning_profile: str = "balanced"
    technical_depth: str = "standard"
    focus_mode: str = "broad"
    tree_context: str = ""
    context_packets: list[str] = []
    messages: list[ChatMessage] = []


class AdvisorRequest(BaseModel):
    provider_id: str
    question: str
    project_name: str = ""
    root_objective: str = ""
    tree_context: str = ""  # summary of nodes


class ChallengeRequest(BaseModel):
    provider_id: str
    node_title: str
    node_description: str = ""
    node_type: str = ""
    likelihood: int | None = None
    impact: int | None = None
    effort: int | None = None
    exploitability: int | None = None
    detectability: int | None = None
    inherent_risk: float | None = None
    mitigations_summary: str = ""
    tree_context: str = ""


class AIChatResponse(BaseModel):
    status: str
    content: str
    model: str = ""
    tokens: int = 0
    elapsed_ms: int = 0


# ── Helpers ─────────────────────────────────────────────────────
async def _get_provider(provider_id: str, db: AsyncSession) -> dict:
    provider = await require_provider_access(provider_id, db)
    return {
        "base_url": provider.base_url,
        "api_key_encrypted": provider.api_key_encrypted,
        "model": provider.model,
        "timeout": provider.timeout,
        "tls_verify": provider.tls_verify,
        "ca_bundle_path": provider.ca_bundle_path or "",
        "client_cert_path": provider.client_cert_path or "",
        "client_key_path": provider.client_key_path or "",
        "custom_headers": provider.custom_headers or {},
    }


# ── Brainstorm ──────────────────────────────────────────────────
BRAINSTORM_SYSTEM = """You are an elite offensive security strategist running a brainstorming session to help build an attack tree.

Your job is to explore the attack surface through Socratic dialogue. Ask probing questions, suggest attack vectors, challenge assumptions, and help the user think through:
- Threat actors and their motivations / capabilities
- Crown-jewel assets and what an attacker would target
- Attack-surface domains and trust boundaries across people, physical, operational, technical, and supply-chain layers
- Realistic attack paths, pivots, and campaign logic
- Reference mappings such as MITRE ATT&CK, CAPEC, CWE, and CVEs only when they sharpen a concrete branch
- Preconditions, pivot points, and chained exploits

Be concise but insightful. When the user provides context, respond with concrete attack scenarios, numbered for reference. Use markdown formatting. Keep each response focused and actionable.

If this is the start of the session, introduce yourself briefly and ask the first probing question about the target environment."""

FOCUS_MODE_GUIDANCE = {
    "broad": "Keep coverage broad and balanced across attack surfaces, attacker paths, and operational constraints.",
    "attack_surface": "Prioritize entry points, exposed trust boundaries, reachable services, remote access paths, and likely initial footholds.",
    "technical_research": "Prioritize deeply technical analysis: vulnerability classes, reverse engineering targets, exploit primitives, parser logic, protocol edge cases, and concrete implementation weaknesses.",
    "chain_building": "Prioritize chained attack paths, preconditions, pivots, privilege escalation, collection, and objective completion.",
    "defense_pressure": "Prioritize mitigation gaps, detection blind spots, trust assumptions, control bypasses, and defender failure modes.",
    "prioritization": "Prioritize which hypotheses should be investigated first based on exploitability, likely impact, evidence gaps, and attacker leverage.",
}

TECHNICAL_DEPTH_GUIDANCE = {
    "standard": "Default to concise but concrete analysis. Use specific tradecraft, but do not over-index on exploit development unless the user asks for it.",
    "deep_technical": (
        "Respond at a deeply technical level. When relevant, discuss exploit primitives, memory corruption behaviors, protocol/state-machine edge cases, "
        "software architecture, trust boundaries, patch-diffing ideas, reverse engineering angles, and artifact-level evidence the team should collect next."
    ),
}


def _brainstorm_domain(req: BrainstormRequest) -> str:
    scope = "\n".join(
        part for part in [
            req.project_name,
            req.tree_context,
            *[packet for packet in req.context_packets if packet],
        ] if part
    )
    return detect_planning_domain(req.root_objective, scope, req.context_preset)


def _build_brainstorm_system_prompt(req: BrainstormRequest) -> str:
    sections = [BRAINSTORM_SYSTEM]

    planning_profile = normalize_planning_profile(req.planning_profile)
    planning_label = get_planning_profile_label(planning_profile)
    planning_domain = _brainstorm_domain(req)
    catalog_context = build_environment_catalog_outline_for_context(
        req.root_objective,
        "\n".join([req.project_name, req.tree_context, *req.context_packets]),
        req.context_preset,
    )
    focus = FOCUS_MODE_GUIDANCE.get(req.focus_mode, FOCUS_MODE_GUIDANCE["broad"])
    technical_depth = TECHNICAL_DEPTH_GUIDANCE.get(req.technical_depth, TECHNICAL_DEPTH_GUIDANCE["standard"])

    sections.append(f"Planning Profile: {planning_label}")
    sections.append(f"Detected Planning Domain: {planning_domain}")
    sections.append(get_domain_decomposition_guidance(planning_domain))
    sections.append(get_planning_profile_guidance(planning_profile, planning_domain))
    if catalog_context:
        sections.append(catalog_context)
    sections.append(
        "Brainstorming workflow:\n"
        "- Start by surfacing the major domains, trust boundaries, trusted roles, and operational constraints that shape the target.\n"
        "- Then turn those broad domains into concrete attacker hypotheses, phased attack paths, and investigation questions.\n"
        "- Attach references, ATT&CK mappings, CVEs, or weakness classes only when a branch is already specific enough to benefit from them."
    )
    sections.append(f"Focus Mode: {req.focus_mode or 'broad'}")
    sections.append(focus)
    sections.append(f"Technical Depth: {req.technical_depth or 'standard'}")
    sections.append(technical_depth)

    if (req.technical_depth or "").lower() == "deep_technical":
        sections.append(
            "Deep technical requirements:\n"
            "- Prefer technically specific hypotheses over generic lists.\n"
            "- Call out likely implementation details, attacker prerequisites, and failure conditions.\n"
            "- Where useful, suggest concrete artifacts to inspect next: binaries, handlers, parsers, logs, configs, packet captures, crash traces, firmware images, or update packages."
        )

    if req.workspace_mode:
        sections.append(f"Workspace Mode: {req.workspace_mode}")
    if req.context_preset:
        sections.append(f"Environment Preset: {get_context_preset_label(req.context_preset)}")
    if req.project_name:
        sections.append(f"Project: {req.project_name}")
    if req.root_objective:
        sections.append(f"Attacker Objective: {req.root_objective}")
    if req.tree_context:
        sections.append(f"Existing Tree Context:\n{req.tree_context}")
    if req.context_packets:
        sections.append("Supplemental Context:\n" + "\n".join(f"- {packet}" for packet in req.context_packets if packet))

    return "\n\n".join(section for section in sections if section)


def _build_brainstorm_seed(req: BrainstormRequest) -> str:
    seed_parts = ["Start the brainstorming session."]
    planning_profile = normalize_planning_profile(req.planning_profile)
    if planning_profile == "planning_first":
        seed_parts.append(
            "Open by decomposing the target into major attack-surface domains, trusted roles, trust boundaries, and operational dependencies before drilling into low-level weaknesses or reference mappings."
        )
    elif planning_profile == "reference_heavy":
        seed_parts.append(
            "Start with a planning-useful domain breakdown, then move quickly into concrete attack paths and the most relevant ATT&CK, CAPEC, CWE, or vulnerability mappings."
        )
    else:
        seed_parts.append(
            "Start with a broad conceptual breakdown of the environment, then turn the strongest branches into concrete attack hypotheses and technical follow-up questions."
        )
    if req.focus_mode and req.focus_mode != "broad":
        seed_parts.append(f"Focus first on {req.focus_mode.replace('_', ' ')}.")
    if req.technical_depth == "deep_technical":
        seed_parts.append("Use deep technical detail where the context supports it.")
    return " ".join(seed_parts)


@router.post("/brainstorm", response_model=AIChatResponse)
async def brainstorm_chat(req: BrainstormRequest, db: AsyncSession = Depends(get_db)):
    config = await _get_provider(req.provider_id, db)
    system_content = _build_brainstorm_system_prompt(req)

    messages = [{"role": "system", "content": system_content}]

    if not req.messages:
        messages.append({"role": "user", "content": _build_brainstorm_seed(req)})
    else:
        for m in req.messages:
            messages.append({"role": m.role, "content": m.content})

    result = await chat_completion(config, messages, temperature=0.8)
    return AIChatResponse(
        status=result.get("status", "error"),
        content=result.get("content", result.get("message", "No response")),
        model=result.get("model", ""),
        tokens=result.get("tokens", 0),
        elapsed_ms=result.get("elapsed_ms", 0),
    )


# ── Red-Team Advisor ────────────────────────────────────────────
ADVISOR_SYSTEM = """You are a senior red-team advisor embedded in an offensive cyber planning tool. The user is building attack trees and needs expert tactical advice.

Provide authoritative, detailed answers referencing:
- MITRE ATT&CK techniques (with IDs like T1566)
- Real-world tradecraft and TTPs
- Tool recommendations (open-source where possible)
- Operational considerations (OPSEC, detection avoidance)
- Chained attack sequences and kill-chain progression

Be direct and tactical. Use markdown with headers and bullet points. If the user's question is vague, ask one clarifying question before answering."""


@router.post("/advisor", response_model=AIChatResponse)
async def advisor_chat(req: AdvisorRequest, db: AsyncSession = Depends(get_db)):
    config = await _get_provider(req.provider_id, db)

    system_content = ADVISOR_SYSTEM
    if req.project_name:
        system_content += f"\n\nCurrent Project: {req.project_name}"
    if req.root_objective:
        system_content += f"\nAttacker Objective: {req.root_objective}"
    if req.tree_context:
        system_content += f"\n\nTree Context (existing nodes):\n{req.tree_context}"

    messages = [
        {"role": "system", "content": system_content},
        {"role": "user", "content": req.question},
    ]

    result = await chat_completion(config, messages, temperature=0.7)
    return AIChatResponse(
        status=result.get("status", "error"),
        content=result.get("content", result.get("message", "No response")),
        model=result.get("model", ""),
        tokens=result.get("tokens", 0),
        elapsed_ms=result.get("elapsed_ms", 0),
    )


# ── Risk Score Challenger ───────────────────────────────────────
CHALLENGER_SYSTEM = """You are a skeptical risk analyst who challenges human-assigned risk scores on attack tree nodes. Your job is to find blind spots, biases, and errors in risk assessments.

For each score dimension, you MUST:
1. State whether you think the score is too high, too low, or reasonable
2. Provide a concrete justification with real-world evidence or precedent
3. Suggest a revised score if you disagree

Score dimensions (all 1-10):
- Likelihood: probability of attacker attempting this (10 = certain)
- Impact: damage severity if successful (10 = catastrophic)
- Effort: attacker effort required (1 = trivial, 10 = months of work)
- Exploitability: ease of exploitation (10 = trivially exploitable)
- Detectability: how detectable (1 = stealthy, 10 = easily detected)

Use markdown formatting. Be specific and cite real attack examples or CVEs where relevant. End with a summary verdict."""


@router.post("/challenge-scores", response_model=AIChatResponse)
async def challenge_scores(req: ChallengeRequest, db: AsyncSession = Depends(get_db)):
    config = await _get_provider(req.provider_id, db)

    system_content = CHALLENGER_SYSTEM
    if req.tree_context:
        system_content += f"\n\nBroader tree context:\n{req.tree_context}"

    score_text = f"""Please challenge the following risk scores for this attack tree node:

**Node:** {req.node_title}
**Type:** {req.node_type}
**Description:** {req.node_description}

**Current Scores:**
- Likelihood: {req.likelihood}/10
- Impact: {req.impact}/10
- Effort: {req.effort}/10
- Exploitability: {req.exploitability}/10
- Detectability: {req.detectability}/10
- Calculated Inherent Risk: {req.inherent_risk}

**Mitigations in place:** {req.mitigations_summary or 'None'}

Analyze each score dimension, challenge the assessment, and provide your recommended adjustments."""

    messages = [
        {"role": "system", "content": system_content},
        {"role": "user", "content": score_text},
    ]

    result = await chat_completion(config, messages, temperature=0.6)
    return AIChatResponse(
        status=result.get("status", "error"),
        content=result.get("content", result.get("message", "No response")),
        model=result.get("model", ""),
        tokens=result.get("tokens", 0),
        elapsed_ms=result.get("elapsed_ms", 0),
    )
