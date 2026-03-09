from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from ..database import get_db
from ..models.llm_config import LLMProviderConfig, LLMJobHistory
from ..models.node import Node
from ..models.project import Project
from ..schemas.llm_config import LLMProviderConfigCreate, LLMProviderConfigUpdate, LLMProviderConfigResponse
from ..schemas.llm_request import LLMSuggestRequest, LLMSuggestResponse, LLMSummaryRequest, LLMSummaryResponse, SuggestedNode
from ..services.crypto import encrypt_value
from ..services import llm_service

router = APIRouter(prefix="/llm", tags=["llm"])


@router.get("/providers", response_model=list[LLMProviderConfigResponse])
async def list_providers(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(LLMProviderConfig).order_by(LLMProviderConfig.created_at))
    providers = result.scalars().all()
    return [_provider_response(p) for p in providers]


@router.post("/providers", response_model=LLMProviderConfigResponse, status_code=201)
async def create_provider(data: LLMProviderConfigCreate, db: AsyncSession = Depends(get_db)):
    provider = LLMProviderConfig(
        name=data.name,
        base_url=data.base_url,
        api_key_encrypted=encrypt_value(data.api_key) if data.api_key else "",
        model=data.model,
        custom_headers=data.custom_headers,
        timeout=data.timeout,
        stream_enabled=data.stream_enabled,
        tls_verify=data.tls_verify,
        ca_bundle_path=data.ca_bundle_path,
        client_cert_path=data.client_cert_path,
        client_key_path=data.client_key_path,
    )
    db.add(provider)
    await db.commit()
    await db.refresh(provider)
    return _provider_response(provider)


@router.patch("/providers/{provider_id}", response_model=LLMProviderConfigResponse)
async def update_provider(provider_id: str, data: LLMProviderConfigUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(LLMProviderConfig).where(LLMProviderConfig.id == provider_id))
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(404, "Provider not found")

    update_data = data.model_dump(exclude_unset=True)
    if "api_key" in update_data:
        api_key = update_data.pop("api_key")
        if api_key:
            provider.api_key_encrypted = encrypt_value(api_key)
    for key, value in update_data.items():
        setattr(provider, key, value)

    await db.commit()
    await db.refresh(provider)
    return _provider_response(provider)


@router.delete("/providers/{provider_id}", status_code=204)
async def delete_provider(provider_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(LLMProviderConfig).where(LLMProviderConfig.id == provider_id))
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(404, "Provider not found")
    await db.delete(provider)
    await db.commit()


@router.post("/providers/{provider_id}/test")
async def test_provider(provider_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(LLMProviderConfig).where(LLMProviderConfig.id == provider_id))
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(404, "Provider not found")

    config = _provider_to_config_dict(provider)
    test_result = await llm_service.test_connection(config)

    provider.last_tested_at = datetime.now(timezone.utc)
    provider.last_test_result = test_result["status"]
    provider.last_test_message = test_result.get("message", "")
    await db.commit()

    return test_result


@router.post("/suggest", response_model=LLMSuggestResponse)
async def suggest_branches(data: LLMSuggestRequest, db: AsyncSession = Depends(get_db)):
    # Get active provider
    provider = await _get_active_provider(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured. Configure one in Settings.")

    # Get node and tree context
    node_result = await db.execute(select(Node).where(Node.id == data.node_id))
    node = node_result.scalar_one_or_none()
    if not node:
        raise HTTPException(404, "Node not found")

    # Get tree context (ancestors + siblings for context)
    all_nodes = await db.execute(select(Node).where(Node.project_id == data.project_id))
    nodes_list = all_nodes.scalars().all()
    tree_context = "\n".join(f"- [{n.node_type}] {n.title}" for n in nodes_list[:30])

    node_data = {
        "title": node.title, "node_type": node.node_type,
        "description": node.description, "platform": node.platform,
    }

    config = _provider_to_config_dict(provider)
    messages = llm_service.build_branch_suggestion_prompt(
        node_data, tree_context, data.suggestion_type
    )

    response = await llm_service.chat_completion(config, messages, temperature=0.7)

    if response["status"] != "success":
        raise HTTPException(502, f"LLM request failed: {response.get('message', 'Unknown error')}")

    parsed = llm_service.parse_json_response(response["content"])
    suggestions = []
    for item in parsed:
        suggestions.append(SuggestedNode(
            title=item.get("title", "Suggested step"),
            description=item.get("description", ""),
            node_type=item.get("node_type", "attack_step"),
            logic_type=item.get("logic_type", "OR"),
            threat_category=item.get("threat_category", ""),
            likelihood=item.get("likelihood"),
            impact=item.get("impact"),
        ))

    # Record job history
    job = LLMJobHistory(
        provider_id=provider.id,
        project_id=data.project_id,
        node_id=data.node_id,
        job_type=f"suggest_{data.suggestion_type}",
        prompt_summary=messages[-1]["content"][:500],
        response_summary=response["content"][:500],
        status="success",
        tokens_used=response.get("tokens", 0),
        duration_ms=response.get("elapsed_ms", 0),
    )
    db.add(job)
    await db.commit()

    return LLMSuggestResponse(
        suggestions=suggestions,
        prompt_used=messages[-1]["content"][:200] + "...",
        model_used=response.get("model", ""),
        raw_response=response["content"][:1000],
    )


@router.post("/summarize", response_model=LLMSummaryResponse)
async def generate_summary(data: LLMSummaryRequest, db: AsyncSession = Depends(get_db)):
    provider = await _get_active_provider(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    # Get project and nodes
    proj_result = await db.execute(select(Project).where(Project.id == data.project_id))
    project = proj_result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    nodes_result = await db.execute(
        select(Node).where(Node.project_id == data.project_id)
        .options(selectinload(Node.mitigations))
    )
    nodes = nodes_result.scalars().all()

    project_data = {"name": project.name, "root_objective": project.root_objective}
    nodes_data = [
        {"title": n.title, "node_type": n.node_type, "inherent_risk": n.inherent_risk,
         "rolled_up_risk": n.rolled_up_risk, "status": n.status}
        for n in nodes
    ]

    config = _provider_to_config_dict(provider)
    messages = llm_service.build_summary_prompt(project_data, nodes_data, data.summary_type)
    response = await llm_service.chat_completion(config, messages, temperature=0.5)

    if response["status"] != "success":
        raise HTTPException(502, f"LLM request failed: {response.get('message', '')}")

    return LLMSummaryResponse(
        summary=response["content"],
        prompt_used=messages[-1]["content"][:200] + "...",
        model_used=response.get("model", ""),
    )


async def _get_active_provider(db: AsyncSession) -> LLMProviderConfig | None:
    result = await db.execute(
        select(LLMProviderConfig).where(LLMProviderConfig.is_active == True).limit(1)
    )
    return result.scalar_one_or_none()


def _provider_to_config_dict(provider: LLMProviderConfig) -> dict:
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


def _provider_response(p: LLMProviderConfig) -> LLMProviderConfigResponse:
    return LLMProviderConfigResponse(
        id=p.id,
        name=p.name or "Unnamed",
        base_url=p.base_url or "",
        has_api_key=bool(p.api_key_encrypted),
        model=p.model or "",
        custom_headers=p.custom_headers or {},
        timeout=p.timeout or 120,
        stream_enabled=bool(p.stream_enabled),
        tls_verify=p.tls_verify if p.tls_verify is not None else True,
        ca_bundle_path=p.ca_bundle_path or "",
        client_cert_path=p.client_cert_path or "",
        client_key_path=p.client_key_path or "",
        is_active=bool(p.is_active),
        last_tested_at=p.last_tested_at,
        last_test_result=p.last_test_result or "",
        last_test_message=p.last_test_message or "",
        created_at=p.created_at,
        updated_at=p.updated_at or p.created_at,
    )
