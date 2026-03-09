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
from ..services.crypto import decrypt_value
from ..services.llm_service import chat_completion

router = APIRouter(prefix="/ai-chat", tags=["ai-chat"])


# ── Schemas ─────────────────────────────────────────────────────
class ChatMessage(BaseModel):
    role: str  # "user" | "assistant" | "system"
    content: str


class BrainstormRequest(BaseModel):
    provider_id: str
    project_name: str = ""
    root_objective: str = ""
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
    result = await db.execute(
        select(LLMProviderConfig).where(LLMProviderConfig.id == provider_id)
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=404, detail="LLM provider not found")
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
- Attack surfaces (network, physical, social, supply-chain, insider, wireless, cloud)
- Realistic attack paths with MITRE ATT&CK references
- Preconditions, pivot points, and chained exploits

Be concise but insightful. When the user provides context, respond with concrete attack scenarios, numbered for reference. Use markdown formatting. Keep each response focused and actionable.

If this is the start of the session, introduce yourself briefly and ask the first probing question about the target environment."""


@router.post("/brainstorm", response_model=AIChatResponse)
async def brainstorm_chat(req: BrainstormRequest, db: AsyncSession = Depends(get_db)):
    config = await _get_provider(req.provider_id, db)

    system_content = BRAINSTORM_SYSTEM
    if req.project_name:
        system_content += f"\n\nProject: {req.project_name}"
    if req.root_objective:
        system_content += f"\nAttacker Objective: {req.root_objective}"

    messages = [{"role": "system", "content": system_content}]

    if not req.messages:
        messages.append({"role": "user", "content": "Start the brainstorming session."})
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
