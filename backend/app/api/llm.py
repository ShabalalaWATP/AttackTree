from datetime import datetime, timezone
import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from ..database import get_db
from ..models.llm_config import LLMProviderConfig, LLMJobHistory
from ..models.node import Node
from ..models.project import Project
from ..schemas.llm_config import LLMProviderConfigCreate, LLMProviderConfigUpdate, LLMProviderConfigResponse
from ..schemas.llm_request import LLMSuggestRequest, LLMSuggestResponse, LLMSummaryRequest, LLMSummaryResponse, SuggestedNode, LLMAgentRequest, LLMAgentResponse
from ..services.access_control import (
    get_active_provider_for_user,
    require_node_access,
    require_project_access,
    require_provider_access,
)
from ..services.auth import get_current_user_id
from ..services.crypto import encrypt_value
from ..services import llm_service
from ..services.risk_engine import compute_inherent_risk

router = APIRouter(prefix="/llm", tags=["llm"])


@router.get("/providers", response_model=list[LLMProviderConfigResponse])
async def list_providers(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(LLMProviderConfig)
        .where(LLMProviderConfig.user_id == get_current_user_id())
        .order_by(LLMProviderConfig.created_at)
    )
    providers = result.scalars().all()
    return [_provider_response(p) for p in providers]


@router.post("/providers", response_model=LLMProviderConfigResponse, status_code=201)
async def create_provider(data: LLMProviderConfigCreate, db: AsyncSession = Depends(get_db)):
    provider = LLMProviderConfig(
        user_id=get_current_user_id(),
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
    if provider.is_active:
        await _deactivate_other_providers(db)
    db.add(provider)
    await db.commit()
    await db.refresh(provider)
    return _provider_response(provider)


@router.patch("/providers/{provider_id}", response_model=LLMProviderConfigResponse)
async def update_provider(provider_id: str, data: LLMProviderConfigUpdate, db: AsyncSession = Depends(get_db)):
    provider = await require_provider_access(provider_id, db)

    update_data = data.model_dump(exclude_unset=True)
    if "api_key" in update_data:
        api_key = update_data.pop("api_key")
        if api_key:
            provider.api_key_encrypted = encrypt_value(api_key)
    if update_data.get("is_active"):
        await _deactivate_other_providers(db, exclude_provider_id=provider.id)
    for key, value in update_data.items():
        setattr(provider, key, value)

    await db.commit()
    await db.refresh(provider)
    return _provider_response(provider)


@router.delete("/providers/{provider_id}", status_code=204)
async def delete_provider(provider_id: str, db: AsyncSession = Depends(get_db)):
    provider = await require_provider_access(provider_id, db)
    await db.delete(provider)
    await db.commit()


@router.post("/providers/{provider_id}/test")
async def test_provider(provider_id: str, db: AsyncSession = Depends(get_db)):
    provider = await require_provider_access(provider_id, db)

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
    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured. Configure one in Settings.")

    # Get node and tree context
    node = await require_node_access(data.node_id, db)
    project = await require_project_access(data.project_id, db)
    if node.project_id != project.id:
        raise HTTPException(400, "Node does not belong to the supplied project")

    # Get tree context (ancestors + siblings for context)
    all_nodes = await db.execute(select(Node).where(Node.project_id == data.project_id))
    nodes_list = all_nodes.scalars().all()
    tree_context = "\n".join(
        f"- [{n.node_type}] {n.title} | surface={n.attack_surface or 'n/a'} | "
        f"platform={n.platform or 'n/a'} | category={n.threat_category or 'n/a'}"
        for n in nodes_list[:40]
    )

    node_data = {
        "title": node.title,
        "node_type": node.node_type,
        "description": node.description,
        "platform": node.platform,
        "attack_surface": node.attack_surface,
        "threat_category": node.threat_category,
        "required_access": node.required_access,
        "required_privileges": node.required_privileges,
        "required_tools": node.required_tools,
        "required_skill": node.required_skill,
        "notes": node.notes,
        "cve_references": node.cve_references,
        "extended_metadata": node.extended_metadata or {},
        "project_context": {
            "name": project.name,
            "context_preset": project.context_preset,
            "root_objective": project.root_objective,
            "workspace_mode": (project.metadata_json or {}).get("workspace_mode", "project_scan"),
        },
    }

    config = _provider_to_config_dict(provider)
    messages = llm_service.build_branch_suggestion_prompt(
        node_data,
        tree_context,
        data.suggestion_type,
        additional_context=data.additional_context,
        technical_depth=data.technical_depth,
        prompt_profile=data.prompt_profile,
    )

    response = await llm_service.chat_completion(config, messages, temperature=0.7,
                                                  max_tokens=8192, timeout_override=120)

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
        user_id=get_current_user_id(),
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
    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured")

    # Get project and nodes
    project = await require_project_access(data.project_id, db)

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


@router.post("/agent", response_model=LLMAgentResponse)
async def agent_generate_tree(data: LLMAgentRequest, db: AsyncSession = Depends(get_db)):
    """AI Agent mode: generate a full attack tree from a high-level objective.

    Supports three modes:
      - generate: build from scratch with domain-aware few-shot prompting
      - from_template: expand a selected template skeleton with AI enrichment
      - expand: gap-analysis on existing tree to add missing attack paths
    """
    import json as _json
    from pathlib import Path as _Path

    provider = await get_active_provider_for_user(db)
    if not provider:
        raise HTTPException(400, "No active LLM provider configured. Configure one in Settings.")

    project = await require_project_access(data.project_id, db)

    config = _provider_to_config_dict(provider)
    total_tokens = 0
    total_elapsed = 0
    passes_completed = 0

    # ── Resolve template for few-shot / from_template mode ──────────
    template_data = None
    if data.template_id:
        templates_dir = _Path(__file__).parent.parent / "templates_data"
        tpl_path = templates_dir / f"{data.template_id}.json"
        if tpl_path.exists():
            template_data = _json.loads(tpl_path.read_text(encoding="utf-8"))
    elif data.mode == "generate":
        # Auto-find best matching template for few-shot prompting
        template_data = llm_service.find_best_template_for_objective(
            data.objective,
            data.scope,
            context_preset=project.context_preset,
        )

    # ── PASS 1: Structure Generation ────────────────────────────────
    if data.mode == "from_template" and template_data:
        messages = llm_service.build_template_expand_prompt(
            template_data,
            data.objective,
            data.scope,
            data.depth,
            data.breadth,
            generation_profile=data.generation_profile,
            context_preset=project.context_preset,
        )
    elif data.mode == "expand":
        # Load existing tree for gap analysis
        existing_result = await db.execute(
        select(Node).where(Node.project_id == data.project_id)
        )
        existing_nodes = existing_result.scalars().all()
        existing_summary = [
            {"title": n.title, "node_type": n.node_type, "description": (n.description or "")[:80]}
            for n in existing_nodes
        ]
        messages = llm_service.build_gap_analysis_prompt(
            existing_summary,
            data.objective,
            data.scope,
            generation_profile=data.generation_profile,
            context_preset=project.context_preset,
        )
    else:
        # Default: generate with domain-aware few-shot prompting
        messages = llm_service.build_agent_tree_prompt(
            data.objective,
            data.scope,
            data.depth,
            data.breadth,
            template_example=template_data,
            generation_profile=data.generation_profile,
            context_preset=project.context_preset,
        )

    response = await llm_service.chat_completion(
        config, messages, temperature=0.7,
        max_tokens=16384, timeout_override=300,
    )

    if response["status"] != "success":
        msg = response.get("message", "Unknown error")
        if "timeout" in msg.lower() or "timed out" in msg.lower():
            raise HTTPException(
                504, "LLM request timed out — try reducing depth/breadth or use a faster model."
            )
        raise HTTPException(502, f"LLM request failed: {msg}")

    tree_data = llm_service.parse_json_object_response(response["content"])
    if not tree_data or "title" not in tree_data:
        raise HTTPException(
            502,
            "LLM returned invalid tree structure. This can happen when depth/breadth "
            "are too high for the model's output limit. Try reducing depth or breadth."
        )

    total_tokens += response.get("tokens", 0)
    total_elapsed += response.get("elapsed_ms", 0)
    passes_completed = 1

    # Recursively create nodes from the tree
    nodes_created = []
    _ENRICHABLE = {"description", "status", "platform", "attack_surface", "threat_category",
                   "required_access", "required_privileges", "required_skill",
                   "effort", "exploitability", "detectability"}

    def _flatten_tree(node_data: dict, parent_id: str | None, depth: int, x: float, y: float, sibling_index: int, sibling_count: int):
        spread = max(250, 500 / (depth + 1))
        offset_x = (sibling_index - (sibling_count - 1) / 2) * spread

        node_info = {
            "parent_id": parent_id,
            "node_type": node_data.get("node_type", "attack_step"),
            "title": node_data.get("title", "Untitled"),
            "description": node_data.get("description", ""),
            "logic_type": node_data.get("logic_type", "OR"),
            "status": node_data.get("status", "draft"),
            "platform": node_data.get("platform", ""),
            "attack_surface": node_data.get("attack_surface", ""),
            "threat_category": node_data.get("threat_category", ""),
            "required_access": node_data.get("required_access", ""),
            "required_privileges": node_data.get("required_privileges", ""),
            "required_skill": node_data.get("required_skill", ""),
            "likelihood": _clamp(node_data.get("likelihood"), 1, 10),
            "impact": _clamp(node_data.get("impact"), 1, 10),
            "effort": _clamp(node_data.get("effort"), 1, 10),
            "exploitability": _clamp(node_data.get("exploitability"), 1, 10),
            "detectability": _clamp(node_data.get("detectability"), 1, 10),
            "position_x": x + offset_x,
            "position_y": y,
        }
        nodes_created.append(node_info)
        current_index = len(nodes_created) - 1

        children = node_data.get("children", [])
        for i, child in enumerate(children):
            _flatten_tree(child, current_index, depth + 1, x + offset_x, y + 200, i, len(children))

    _flatten_tree(tree_data, None, 0, 400, 50, 0, 1)

    # ── PASS 2: Field enrichment ────────────────────────────────────
    BATCH_SIZE = 20
    nodes_needing_enrichment = []
    for idx, ni in enumerate(nodes_created):
        missing = [f for f in _ENRICHABLE if not ni.get(f)]
        if missing:
            nodes_needing_enrichment.append({"index": idx, "title": ni["title"], "node_type": ni["node_type"], "missing": missing})

    if nodes_needing_enrichment:
        for batch_start in range(0, len(nodes_needing_enrichment), BATCH_SIZE):
            batch = nodes_needing_enrichment[batch_start:batch_start + BATCH_SIZE]
            enrich_messages = llm_service.build_enrich_nodes_prompt(batch)
            enrich_resp = await llm_service.chat_completion(
                config, enrich_messages, temperature=0.4,
                max_tokens=16384, timeout_override=240,
            )
            total_tokens += enrich_resp.get("tokens", 0)
            total_elapsed += enrich_resp.get("elapsed_ms", 0)

            if enrich_resp["status"] == "success":
                enriched = llm_service.parse_json_response(enrich_resp["content"])
                for item in enriched:
                    target_idx = item.get("index")
                    if target_idx is not None and 0 <= target_idx < len(nodes_created):
                        ni = nodes_created[target_idx]
                        for field in _ENRICHABLE:
                            val = item.get(field)
                            if val and not ni.get(field):
                                if field in ("effort", "exploitability", "detectability"):
                                    ni[field] = _clamp(val, 1, 10)
                                else:
                                    ni[field] = val
        passes_completed = 2

    # ── PASS 3: MITRE ATT&CK / CAPEC / CWE reference mapping ──────
    leaf_nodes = [
        {"index": i, "title": n["title"], "description": (n.get("description") or "")[:100],
         "attack_surface": n.get("attack_surface", ""), "threat_category": n.get("threat_category", "")}
        for i, n in enumerate(nodes_created)
        if not any(c["parent_id"] == i for c in nodes_created)
    ]
    if leaf_nodes:
        mapping_messages = llm_service.build_reference_mapping_pass_prompt(
            leaf_nodes[:30]  # Limit to 30 for token budget
        )
        mapping_resp = await llm_service.chat_completion(
            config, mapping_messages, temperature=0.3,
            max_tokens=4096, timeout_override=120,
        )
        total_tokens += mapping_resp.get("tokens", 0)
        total_elapsed += mapping_resp.get("elapsed_ms", 0)

        if mapping_resp["status"] == "success":
            mappings = llm_service.parse_json_response(mapping_resp["content"])
            for item in mappings:
                target_idx = item.get("index")
                if target_idx is not None and 0 <= target_idx < len(nodes_created):
                    ni = nodes_created[target_idx]
                    ni["_att_ck_ids"] = item.get("att_ck_ids", [])
                    ni["_capec_ids"] = item.get("capec_ids", [])
                    ni["_cwe_ids"] = item.get("cwe_ids", [])
            passes_completed = 3

    # ── PASS 4: Mitigations & detections for leaf nodes ─────────────
    if leaf_nodes:
        mitdet_messages = llm_service.build_mitigations_detections_pass_prompt(
            leaf_nodes[:30]
        )
        mitdet_resp = await llm_service.chat_completion(
            config, mitdet_messages, temperature=0.4,
            max_tokens=16384, timeout_override=240,
        )
        total_tokens += mitdet_resp.get("tokens", 0)
        total_elapsed += mitdet_resp.get("elapsed_ms", 0)

        if mitdet_resp["status"] == "success":
            mitdet_data = llm_service.parse_json_response(mitdet_resp["content"])
            for item in mitdet_data:
                target_idx = item.get("index")
                if target_idx is not None and 0 <= target_idx < len(nodes_created):
                    ni = nodes_created[target_idx]
                    ni["_mitigations"] = item.get("mitigations", [])
                    ni["_detections"] = item.get("detections", [])
            passes_completed = 4

    # ── Persist nodes to database ───────────────────────────────────
    id_map = {}
    for idx, node_info in enumerate(nodes_created):
        node_id = str(uuid.uuid4())
        parent_db_id = id_map.get(node_info["parent_id"]) if node_info["parent_id"] is not None else None
        node = Node(
            id=node_id,
            project_id=data.project_id,
            parent_id=parent_db_id,
            node_type=node_info["node_type"],
            title=node_info["title"],
            description=node_info["description"],
            logic_type=node_info["logic_type"],
            status=node_info.get("status", "draft"),
            platform=node_info.get("platform", ""),
            attack_surface=node_info.get("attack_surface", ""),
            threat_category=node_info["threat_category"],
            required_access=node_info.get("required_access", ""),
            required_privileges=node_info.get("required_privileges", ""),
            required_skill=node_info.get("required_skill", ""),
            likelihood=node_info["likelihood"],
            impact=node_info["impact"],
            effort=node_info.get("effort"),
            exploitability=node_info.get("exploitability"),
            detectability=node_info.get("detectability"),
            position_x=node_info["position_x"],
            position_y=node_info["position_y"],
            sort_order=idx,
        )
        node.inherent_risk = compute_inherent_risk(
            node.likelihood, node.impact, node.effort,
            node.exploitability, node.detectability,
        )
        db.add(node)
        id_map[idx] = node_id

    # ── Persist mitigations & detections from Pass 4 ────────────────
    from ..models.mitigation import Mitigation
    from ..models.detection import Detection

    for idx, node_info in enumerate(nodes_created):
        node_db_id = id_map[idx]
        for mit in node_info.get("_mitigations", []):
            if isinstance(mit, dict) and mit.get("title"):
                m = Mitigation(
                    node_id=node_db_id,
                    title=mit["title"],
                    description=mit.get("description", ""),
                    effectiveness=mit.get("effectiveness", ""),
                    status="proposed",
                )
                db.add(m)
        for det in node_info.get("_detections", []):
            if isinstance(det, dict) and det.get("title"):
                d = Detection(
                    node_id=node_db_id,
                    title=det["title"],
                    description=det.get("description", ""),
                    detection_type=det.get("type", ""),
                    data_source=det.get("data_source", ""),
                    status="proposed",
                )
                db.add(d)

    project.root_objective = data.objective
    await db.flush()

    # Record job history
    job = LLMJobHistory(
        provider_id=provider.id,
        user_id=get_current_user_id(),
        project_id=data.project_id,
        job_type="agent_generate_tree",
        prompt_summary=messages[-1]["content"][:500],
        response_summary=response["content"][:500],
        status="success",
        tokens_used=total_tokens,
        duration_ms=total_elapsed,
    )
    db.add(job)
    await db.commit()

    return LLMAgentResponse(
        nodes_created=len(nodes_created),
        model_used=response.get("model", ""),
        elapsed_ms=total_elapsed,
        passes_completed=passes_completed,
    )


async def _deactivate_other_providers(db: AsyncSession, exclude_provider_id: str | None = None) -> None:
    result = await db.execute(
        select(LLMProviderConfig).where(LLMProviderConfig.user_id == get_current_user_id())
    )
    for provider in result.scalars().all():
        if exclude_provider_id and provider.id == exclude_provider_id:
            continue
        provider.is_active = False


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


def _clamp(value, lo, hi):
    """Clamp a numeric value to [lo, hi], returning None if input is None."""
    if value is None:
        return None
    try:
        return max(lo, min(hi, float(value)))
    except (TypeError, ValueError):
        return None


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
