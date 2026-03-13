"""Integration tests for the API endpoints."""
import asyncio
import json
import re
from datetime import datetime, timedelta, timezone
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import backend.app.database as db_module
import backend.app.main as main_module
from backend.app.main import app
from backend.app.database import Base
from backend.app.api.ai_chat import BrainstormRequest, _build_brainstorm_system_prompt, _build_brainstorm_seed
from backend.app.api.infra_maps import _infra_map_planning_context, _normalize_nodes
from backend.app.api.kill_chains import CKC_PHASES, _kill_chain_planning_context
from backend.app.api.scenarios import _scenario_planning_context
from backend.app.api.threat_models import _threat_model_planning_context
from backend.app.models.analysis_run import AnalysisRun
from backend.app.models.node import Node
from backend.app.models.snapshot import Snapshot
from backend.app.models.user import User
from backend.app.services.environment_catalog_service import build_environment_catalog_outline_for_context
from backend.app.services import llm_service
from backend.app.services.auth import hash_password


@pytest_asyncio.fixture(autouse=True)
async def setup_db(tmp_path):
    original_engine = db_module.engine
    original_session_factory = db_module.async_session_factory
    original_main_session_factory = main_module.async_session_factory

    test_db_path = tmp_path / "attacktree_test.db"
    test_database_url = f"sqlite+aiosqlite:///{test_db_path.resolve().as_posix()}"
    test_engine = create_async_engine(
        test_database_url,
        echo=False,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(test_engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    db_module.engine = test_engine
    db_module.async_session_factory = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    main_module.async_session_factory = db_module.async_session_factory

    await db_module.init_db()
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await test_engine.dispose()
    db_module.engine = original_engine
    db_module.async_session_factory = original_session_factory
    main_module.async_session_factory = original_main_session_factory


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def _signup_or_login(client: AsyncClient, *, name: str, email: str, password: str) -> dict[str, str]:
    username = email.split("@", 1)[0].replace("+", ".").replace(" ", ".").lower()
    response = await client.post("/api/auth/signup", json={
        "name": name,
        "email": email,
        "username": username,
        "password": password,
    })
    assert response.status_code in (201, 409), response.text

    response = await client.post("/api/auth/login", json={
        "identifier": email,
        "password": password,
    })
    if response.status_code == 403:
        assert "pending admin approval" in response.text.lower()
        await _approve_user(client, email=email)
        response = await client.post("/api/auth/login", json={
            "identifier": email,
            "password": password,
        })

    assert response.status_code == 200, response.text
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


async def _login_as_seed_admin(client: AsyncClient) -> dict[str, str]:
    response = await client.post("/api/auth/login", json={
        "identifier": "admin12345",
        "password": "admin12345",
    })
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _approve_user(client: AsyncClient, *, email: str, role: str = "user") -> dict:
    admin_headers = await _login_as_seed_admin(client)
    response = await client.get("/api/auth/users", headers=admin_headers)
    assert response.status_code == 200, response.text
    target = next(user for user in response.json() if user["email"] == email.lower())
    response = await client.patch(
        f"/api/auth/users/{target['id']}",
        json={"is_active": True, "role": role},
        headers=admin_headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_signup_requires_username(client: AsyncClient):
    response = await client.post("/api/auth/signup", json={
        "name": "Missing Username",
        "email": "missing.username@example.com",
        "password": "supersecure1",
    })
    assert response.status_code == 422, response.text


@pytest.mark.asyncio
async def test_signup_requires_admin_approval(client: AsyncClient):
    response = await client.post("/api/auth/signup", json={
        "name": "Pending Analyst",
        "email": "pending.analyst@example.com",
        "username": "pending.analyst",
        "password": "Approvals!123",
    })
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["approval_required"] is True
    assert body["user"]["is_active"] is False
    assert body["user"]["approval_status"] == "pending"

    response = await client.post("/api/auth/login", json={
        "identifier": "pending.analyst@example.com",
        "password": "Approvals!123",
    })
    assert response.status_code == 403, response.text
    assert "pending admin approval" in response.json()["detail"].lower()

    approved = await _approve_user(client, email="pending.analyst@example.com")
    assert approved["is_active"] is True
    assert approved["approval_status"] == "approved"

    response = await client.post("/api/auth/login", json={
        "identifier": "pending.analyst@example.com",
        "password": "Approvals!123",
    })
    assert response.status_code == 200, response.text
    assert response.json()["user"]["approval_status"] == "approved"


@pytest.mark.asyncio
async def test_project_brainstorm_records_analysis_run(authed_client: AsyncClient, monkeypatch):
    provider = await _create_active_provider(authed_client, name="Brainstorm Ledger Provider")

    resp = await authed_client.post("/api/projects", json={
        "name": "Brainstorm Ledger Project",
        "root_objective": "Assess remote access and supplier pathways",
        "context_preset": "airport",
    })
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]

    async def fake_chat_completion(*args, **kwargs):
        return {
            "status": "success",
            "content": "Start with supplier remote access, maintenance trust paths, and exposed identity workflows.",
            "model": "test-model",
            "tokens": 88,
            "elapsed_ms": 321,
        }

    monkeypatch.setattr("backend.app.api.ai_chat.chat_completion", fake_chat_completion)

    resp = await authed_client.post("/api/ai-chat/brainstorm", json={
        "provider_id": provider["id"],
        "project_id": project_id,
        "messages": [{"role": "user", "content": "Focus on vendor VPN and maintenance access."}],
    })
    assert resp.status_code == 200, resp.text

    resp = await authed_client.get(f"/api/analysis-runs/project/{project_id}")
    assert resp.status_code == 200, resp.text
    runs = resp.json()
    assert runs[0]["tool"] == "brainstorm"
    assert runs[0]["run_type"] == "brainstorm_turn"
    assert runs[0]["status"] == "completed"


@pytest.mark.asyncio
async def test_llm_chat_completion_retries_with_alternate_token_parameter(monkeypatch):
    calls: list[dict] = []

    class FakeResponse:
        def __init__(self, status_code: int, *, payload: dict | None = None, text: str = ""):
            self.status_code = status_code
            self._payload = payload or {}
            self.text = text

        def json(self):
            return self._payload

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, headers=None, json=None):
            calls.append(json)
            if len(calls) == 1:
                return FakeResponse(
                    400,
                    text=json_module.dumps({
                        "error": {
                            "message": "Unsupported parameter: 'max_tokens' is not supported with this model. Use 'max_completion_tokens' instead.",
                            "type": "invalid_request_error",
                            "param": "max_tokens",
                        }
                    }),
                )
            return FakeResponse(
                200,
                payload={
                    "choices": [{"message": {"content": "completed"}}],
                    "usage": {"total_tokens": 42},
                    "model": "test-model",
                },
            )

    json_module = json
    monkeypatch.setattr(llm_service, "decrypt_value", lambda value: "")
    monkeypatch.setattr(llm_service.httpx, "AsyncClient", FakeAsyncClient)

    result = await llm_service.chat_completion(
        {
            "base_url": "http://example.test/v1",
            "api_key_encrypted": "",
            "model": "test-model",
            "timeout": 30,
        },
        [{"role": "user", "content": "hello"}],
        max_tokens=256,
    )

    assert result["status"] == "success"
    assert len(calls) == 2
    assert "max_tokens" in calls[0]
    assert "max_completion_tokens" not in calls[0]
    assert "max_completion_tokens" in calls[1]
    assert "max_tokens" not in calls[1]


@pytest.mark.asyncio
async def test_llm_agent_rejects_unsafe_generation_modes(authed_client: AsyncClient):
    await _create_active_provider(authed_client, name="Agent Guardrails Provider")

    resp = await authed_client.post("/api/projects", json={"name": "Agent Empty Project"})
    assert resp.status_code == 201, resp.text
    empty_project = resp.json()

    resp = await authed_client.post("/api/llm/agent", json={
        "project_id": empty_project["id"],
        "objective": "",
        "scope": "",
        "depth": 4,
        "breadth": 5,
        "mode": "expand",
    })
    assert resp.status_code == 400, resp.text
    assert "existing tree" in resp.json()["detail"].lower()

    resp = await authed_client.post("/api/llm/agent", json={
        "project_id": empty_project["id"],
        "objective": "Compromise airport operations systems",
        "scope": "AODB, FIDS, baggage, and partner links",
        "depth": 4,
        "breadth": 4,
        "mode": "from_template",
        "template_id": "missing_template",
    })
    assert resp.status_code == 400, resp.text
    assert "valid template" in resp.json()["detail"].lower()

    resp = await authed_client.post("/api/projects", json={
        "name": "Agent Existing Tree Project",
        "root_objective": "Exfiltrate operations data",
    })
    assert resp.status_code == 201, resp.text
    populated_project = resp.json()

    resp = await authed_client.post("/api/nodes", json={
        "project_id": populated_project["id"],
        "title": "Existing root",
        "node_type": "goal",
        "logic_type": "OR",
    })
    assert resp.status_code == 201, resp.text

    resp = await authed_client.post("/api/llm/agent", json={
        "project_id": populated_project["id"],
        "objective": "Exfiltrate operations data",
        "scope": "Existing project should not be overwritten",
        "depth": 4,
        "breadth": 4,
        "mode": "generate",
    })
    assert resp.status_code == 409, resp.text
    assert "already contains nodes" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_llm_agent_rejects_tree_shapes_above_robust_budget(authed_client: AsyncClient):
    await _create_active_provider(authed_client, name="Agent Budget Provider")

    resp = await authed_client.post("/api/projects", json={"name": "Agent Budget Project"})
    assert resp.status_code == 201, resp.text
    project = resp.json()

    resp = await authed_client.post("/api/llm/agent", json={
        "project_id": project["id"],
        "objective": "Compromise airport operations systems",
        "scope": "AODB, FIDS, baggage, and partner links",
        "depth": 5,
        "breadth": 4,
        "mode": "generate",
    })
    assert resp.status_code == 422, resp.text
    assert "Requested tree size is too large" in resp.text


@pytest.mark.asyncio
async def test_llm_agent_prompt_trims_template_example_to_small_few_shot_context(
    authed_client: AsyncClient,
    monkeypatch,
):
    await _create_active_provider(authed_client, name="Agent Template Prompt Provider")

    resp = await authed_client.post("/api/projects", json={"name": "Agent Template Prompt Project"})
    assert resp.status_code == 201, resp.text
    project = resp.json()

    template = {
        "name": "Large Template",
        "nodes": [
            {
                "id": "root",
                "parent_id": None,
                "title": "Template Root",
                "description": "Root template node.",
                "node_type": "goal",
                "logic_type": "OR",
                "status": "validated",
                "likelihood": 7,
                "impact": 8,
                "effort": 6,
                "exploitability": 7,
                "detectability": 4,
            },
            *[
                {
                    "id": f"child-{index}",
                    "parent_id": "root",
                    "title": f"Template Child {index}",
                    "description": f"Template child {index}.",
                    "node_type": "sub_goal",
                    "logic_type": "OR",
                    "status": "validated",
                    "likelihood": 6,
                    "impact": 6,
                    "effort": 5,
                    "exploitability": 6,
                    "detectability": 4,
                }
                for index in range(1, 9)
            ],
        ],
    }

    captured_prompt: dict[str, str] = {}

    async def fake_chat_completion(config, messages, temperature=0.7, max_tokens=0, timeout_override=None):
        prompt = messages[-1]["content"]
        if "Generate a complete attack tree" in prompt:
            captured_prompt["content"] = prompt
            return {
                "status": "success",
                "content": json.dumps({
                    "title": "Generated Root",
                    "description": "Operator gains an initial planning foothold and frames the objective.",
                    "node_type": "goal",
                    "logic_type": "OR",
                    "status": "validated",
                    "platform": "Airport Operations Environment",
                    "attack_surface": "Operations Management Plane",
                    "threat_category": "Initial Access",
                    "required_access": "None/Public",
                    "required_privileges": "None",
                    "required_skill": "Medium",
                    "likelihood": 6,
                    "impact": 7,
                    "effort": 4,
                    "exploitability": 6,
                    "detectability": 5,
                    "children": [],
                }),
                "model": "test-model",
                "tokens": 120,
                "elapsed_ms": 40,
            }

        if "suggest the most relevant reference mappings" in prompt:
            return {
                "status": "success",
                "content": "[]",
                "model": "test-model",
                "tokens": 10,
                "elapsed_ms": 5,
            }

        if "suggest detailed mitigations and detections" in prompt:
            return {
                "status": "success",
                "content": "[]",
                "model": "test-model",
                "tokens": 10,
                "elapsed_ms": 5,
            }

        pytest.fail(f"Unexpected AI prompt: {prompt[:120]}")

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)
    monkeypatch.setattr(llm_service, "find_best_template_for_objective", lambda *args, **kwargs: template)

    resp = await authed_client.post("/api/llm/agent", json={
        "project_id": project["id"],
        "objective": "Compromise airport operations systems",
        "scope": "AODB, FIDS, baggage, and partner links",
        "depth": 3,
        "breadth": 3,
        "mode": "generate",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["background_processing"] is True
    await _wait_for_agent_run_completion(authed_client, body["agent_run_id"])

    prompt = captured_prompt["content"]
    assert "Template Root" in prompt
    assert "Template Child 1" in prompt
    assert "Template Child 5" in prompt
    assert "Template Child 6" not in prompt
    assert "Template Child 8" not in prompt


@pytest.mark.asyncio
async def test_llm_agent_batches_leaf_analysis_persists_mappings_and_surfaces_warnings(
    authed_client: AsyncClient,
    monkeypatch,
):
    await _create_active_provider(authed_client, name="Agent Multi-pass Provider")

    resp = await authed_client.post("/api/projects", json={
        "name": "Agent Multi-pass Project",
        "context_preset": "airport",
    })
    assert resp.status_code == 201, resp.text
    project = resp.json()

    structure_branch_prompts: list[str] = []
    mapping_batches: list[list[int]] = []
    mitdet_batches: list[list[int]] = []

    async def fake_chat_completion(config, messages, temperature=0.7, max_tokens=0, timeout_override=None):
        prompt = messages[-1]["content"]
        if "Generate a complete attack tree" in prompt:
            return {
                "status": "success",
                "content": json.dumps(_build_agent_tree_payload(leaves_per_branch=0)),
                "model": "test-model",
                "tokens": 120,
                "elapsed_ms": 40,
            }

        if "Expand one branch of an attack tree using only the local branch context below." in prompt:
            structure_branch_prompts.append(prompt)
            match = re.search(r'"title":\s*"Branch (\d+)"', prompt)
            assert match is not None, prompt
            branch_index = int(match.group(1))
            return {
                "status": "success",
                "content": json.dumps(_build_agent_branch_children_payload(branch_index, child_count=6)),
                "model": "test-model",
                "tokens": 90,
                "elapsed_ms": 30,
            }

        if "suggest the most relevant reference mappings" in prompt:
            indexes = [int(value) for value in re.findall(r'"index"\s*:\s*(\d+)', prompt)]
            mapping_batches.append(indexes)
            if len(mapping_batches) == 2:
                return {
                    "status": "error",
                    "message": "provider overload",
                    "tokens": 0,
                    "elapsed_ms": 15,
                }
            return {
                "status": "success",
                "content": json.dumps([
                    {
                        "index": idx,
                        "mappings": [
                            {"framework": "attack", "ref_id": "T1595", "ref_name": "Active Scanning"},
                            {"framework": "capec", "ref_id": "CAPEC-66", "ref_name": "SQL Injection"},
                        ],
                    }
                    for idx in indexes
                ]),
                "model": "test-model",
                "tokens": 55,
                "elapsed_ms": 20,
            }

        if "suggest detailed mitigations and detections" in prompt:
            indexes = [int(value) for value in re.findall(r'"index"\s*:\s*(\d+)', prompt)]
            mitdet_batches.append(indexes)
            return {
                "status": "success",
                "content": json.dumps([
                    {
                        "index": idx,
                        "mitigations": [
                            {
                                "title": f"Mitigate {idx}",
                                "description": "Apply a concrete preventative control with product-specific tuning.",
                                "effectiveness": 0.8,
                            }
                        ],
                        "detections": [
                            {
                                "title": f"Detect {idx}",
                                "description": "Detect the operator behaviour with endpoint or proxy telemetry.",
                                "coverage": 0.6,
                                "data_source": "EDR telemetry",
                            }
                        ],
                    }
                    for idx in indexes
                ]),
                "model": "test-model",
                "tokens": 75,
                "elapsed_ms": 25,
            }

        pytest.fail(f"Unexpected AI prompt: {prompt[:120]}")

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)
    monkeypatch.setattr(llm_service, "find_best_template_for_objective", lambda *args, **kwargs: None)

    resp = await authed_client.post("/api/llm/agent", json={
        "project_id": project["id"],
        "objective": "Compromise airport operations systems",
        "scope": "AODB, FIDS, baggage handling, and partner maintenance links",
        "depth": 3,
        "breadth": 6,
        "mode": "generate",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["nodes_created"] == 43
    assert body["passes_completed"] == 1
    assert body["background_processing"] is True
    run_status = await _wait_for_agent_run_completion(authed_client, body["agent_run_id"])
    assert run_status["passes_completed"] == 4
    assert len(structure_branch_prompts) == 6
    assert len(mapping_batches) == 3
    assert len(mitdet_batches) == 3
    assert any("Reference-mapping batch 2 failed" in warning for warning in run_status["warnings"])

    resp = await authed_client.get(f"/api/nodes/project/{project['id']}")
    assert resp.status_code == 200, resp.text
    nodes = resp.json()
    assert len(nodes) == 43

    total_reference_mappings = sum(len(node["reference_mappings"]) for node in nodes)
    total_mitigations = sum(len(node["mitigations"]) for node in nodes)
    total_detections = sum(len(node["detections"]) for node in nodes)

    assert total_reference_mappings == 48
    assert total_mitigations == 36
    assert total_detections == 36


@pytest.mark.asyncio
async def test_llm_agent_reference_mapping_uses_candidates_and_drops_unknown_ids(
    authed_client: AsyncClient,
    monkeypatch,
):
    await _create_active_provider(authed_client, name="Agent Reference Validation Provider")

    resp = await authed_client.post("/api/projects", json={
        "name": "Agent Reference Validation Project",
        "context_preset": "telecoms_base_station",
        "root_objective": "Assess exposed telecom management and timing surfaces",
        "description": "Telecom site with GNSS timing, management interfaces, and remote access dependencies.",
    })
    assert resp.status_code == 201, resp.text
    project = resp.json()

    mapping_prompts: list[str] = []

    async def fake_chat_completion(config, messages, temperature=0.7, max_tokens=0, timeout_override=None):
        prompt = messages[-1]["content"]
        if "Generate a complete attack tree" in prompt:
            return {
                "status": "success",
                "content": json.dumps(
                    _build_agent_node_payload(
                        "Assess telecom management exposure",
                        "Model the operator objective across exposed remote access and timing dependencies.",
                        node_type="goal",
                        logic_type="OR",
                        status="validated",
                        platform="Telecom Base Station",
                        attack_surface="Multiple",
                        threat_category="Reconnaissance",
                        required_access="None/Public",
                        required_privileges="None",
                        required_skill="Medium",
                        likelihood=6,
                        impact=7,
                        effort=4,
                        exploitability=6,
                        detectability=5,
                        children=[
                            _build_agent_node_payload(
                                "Active Scanning",
                                "Probe exposed management and timing endpoints to discover reachable services.",
                                node_type="attack_step",
                                logic_type="OR",
                                status="validated",
                                platform="Telecom Base Station",
                                attack_surface="Management Interface",
                                threat_category="Reconnaissance",
                                required_access="None/Public",
                                required_privileges="None",
                                required_skill="Medium",
                                likelihood=6,
                                impact=5,
                                effort=3,
                                exploitability=6,
                                detectability=5,
                                children=[],
                            )
                        ],
                    )
                ),
                "model": "test-model",
                "tokens": 90,
                "elapsed_ms": 25,
            }

        if "suggest the most relevant reference mappings" in prompt:
            mapping_prompts.append(prompt)
            assert '"candidate_references"' in prompt
            assert "T1595" in prompt
            indexes = [int(value) for value in re.findall(r'"index"\s*:\s*(\d+)', prompt)]
            return {
                "status": "success",
                "content": json.dumps([
                    {
                        "index": idx,
                        "mappings": [
                            {
                                "framework": "attack",
                                "ref_id": "T1595",
                                "ref_name": "Active Scanning",
                                "confidence": 0.93,
                                "rationale": "Matches the node's active discovery behaviour.",
                            },
                            {
                                "framework": "attack",
                                "ref_id": "T999999",
                                "ref_name": "Hallucinated Technique",
                                "confidence": 0.91,
                                "rationale": "Should be rejected because it is not in the local corpus.",
                            },
                            {
                                "framework": "software_research_patterns",
                                "ref_id": "SRP-001",
                                "ref_name": "Attack Surface Inventory and Exposure Mapping",
                                "confidence": 0.58,
                                "rationale": "Supports the exposure-discovery angle of the node.",
                            },
                        ],
                    }
                    for idx in indexes
                ]),
                "model": "test-model",
                "tokens": 60,
                "elapsed_ms": 20,
            }

        if "suggest detailed mitigations and detections" in prompt:
            indexes = [int(value) for value in re.findall(r'"index"\s*:\s*(\d+)', prompt)]
            return {
                "status": "success",
                "content": json.dumps([
                    {
                        "index": idx,
                        "mitigations": [],
                        "detections": [],
                    }
                    for idx in indexes
                ]),
                "model": "test-model",
                "tokens": 30,
                "elapsed_ms": 10,
            }

        pytest.fail(f"Unexpected AI prompt: {prompt[:160]}")

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)
    monkeypatch.setattr(llm_service, "find_best_template_for_objective", lambda *args, **kwargs: None)

    resp = await authed_client.post("/api/llm/agent", json={
        "project_id": project["id"],
        "objective": "Assess exposed telecom management and timing surfaces",
        "scope": "GNSS timing, management interfaces, and remote access gateways",
        "depth": 2,
        "breadth": 2,
        "mode": "generate",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["background_processing"] is True

    run_status = await _wait_for_agent_run_completion(authed_client, body["agent_run_id"])
    assert run_status["status"] in {"completed", "completed_with_warnings"}
    assert len(mapping_prompts) == 1

    resp = await authed_client.get(f"/api/analysis-runs/project/{project['id']}")
    assert resp.status_code == 200, resp.text
    runs = resp.json()
    assert runs[0]["tool"] == "attack_tree"
    assert runs[0]["run_type"] == "agent_generate"
    assert runs[0]["status"] in {"completed", "partial"}

    resp = await authed_client.get(f"/api/nodes/project/{project['id']}")
    assert resp.status_code == 200, resp.text
    nodes = resp.json()
    all_mappings = [mapping for node in nodes for mapping in node["reference_mappings"]]
    assert any(mapping["ref_id"] == "T1595" for mapping in all_mappings)
    assert any(mapping["ref_id"] == "SRP-001" for mapping in all_mappings)
    assert all(mapping["ref_id"] != "T999999" for mapping in all_mappings)
    attack_mapping = next(mapping for mapping in all_mappings if mapping["ref_id"] == "T1595")
    assert attack_mapping["confidence"] == 0.93
    assert attack_mapping["source"] == "ai"
    assert attack_mapping["rationale"].startswith("Matches the node")


@pytest.mark.asyncio
async def test_llm_suggest_filters_duplicate_branch_titles_against_existing_siblings(
    authed_client: AsyncClient,
    monkeypatch,
):
    await _create_active_provider(authed_client, name="Suggestion Dedupe Provider")

    resp = await authed_client.post("/api/projects", json={"name": "Suggestion Dedupe Project"})
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "title": "Root Goal",
        "node_type": "goal",
        "logic_type": "OR",
    })
    assert resp.status_code == 201, resp.text
    root = resp.json()

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "parent_id": root["id"],
        "title": "Active Scanning",
        "node_type": "attack_step",
    })
    assert resp.status_code == 201, resp.text

    async def fake_chat_completion(*args, **kwargs):
        return {
            "status": "success",
            "content": json.dumps([
                {
                    "title": "Active Scanning",
                    "description": "Duplicate of an existing sibling.",
                    "node_type": "attack_step",
                    "logic_type": "OR",
                    "threat_category": "Reconnaissance",
                    "likelihood": 6,
                    "impact": 4,
                },
                {
                    "title": "Active Scannings",
                    "description": "Normalized duplicate of an existing sibling.",
                    "node_type": "attack_step",
                    "logic_type": "OR",
                    "threat_category": "Reconnaissance",
                    "likelihood": 6,
                    "impact": 4,
                },
                {
                    "title": "Credential Token",
                    "description": "Distinct new branch suggestion.",
                    "node_type": "attack_step",
                    "logic_type": "OR",
                    "threat_category": "Credential Access",
                    "likelihood": 7,
                    "impact": 6,
                },
                {
                    "title": "Credential Tokens",
                    "description": "Normalized duplicate of the new suggestion.",
                    "node_type": "attack_step",
                    "logic_type": "OR",
                    "threat_category": "Credential Access",
                    "likelihood": 7,
                    "impact": 6,
                },
            ]),
            "model": "test-model",
            "tokens": 30,
            "elapsed_ms": 10,
        }

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)

    resp = await authed_client.post("/api/llm/suggest", json={
        "node_id": root["id"],
        "project_id": project_id,
        "suggestion_type": "branches",
    })
    assert resp.status_code == 200, resp.text
    suggestions = resp.json()["suggestions"]
    assert len(suggestions) == 1
    assert suggestions[0]["title"] == "Credential Token"


@pytest.mark.asyncio
async def test_llm_suggest_returns_typed_items_for_non_branch_suggestions(
    authed_client: AsyncClient,
    monkeypatch,
):
    await _create_active_provider(authed_client, name="Typed Suggestion Provider")

    resp = await authed_client.post("/api/projects", json={"name": "Typed Suggestion Project"})
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "title": "Phishing Step",
        "node_type": "attack_step",
        "attack_surface": "Email",
    })
    assert resp.status_code == 201, resp.text
    node = resp.json()

    async def fake_chat_completion(*args, **kwargs):
        prompt = args[1][-1]["content"]
        if "suggest 3-5 specific mitigations" in prompt:
            content = [
                {
                    "title": "Enforce phishing-resistant MFA",
                    "description": "Require phishing-resistant MFA on mailbox and SSO entry points.",
                    "effectiveness": 0.8,
                }
            ]
        elif "suggest 3-5 specific detection opportunities" in prompt:
            content = [
                {
                    "title": "Monitor suspicious inbox rule creation",
                    "description": "Alert on mailbox forwarding and inbox-rule creation anomalies.",
                    "coverage": 0.7,
                    "data_source": "M365 audit log",
                }
            ]
        else:
            content = [
                {
                    "framework": "attack",
                    "ref_id": "T1566",
                    "ref_name": "Phishing",
                    "confidence": 0.9,
                    "rationale": "Direct match to email-driven initial access.",
                },
                {
                    "framework": "attack",
                    "ref_id": "T0000",
                    "ref_name": "Invalid Technique",
                    "confidence": 0.2,
                    "rationale": "Should be filtered out.",
                },
            ]
        return {
            "status": "success",
            "content": json.dumps(content),
            "model": "test-model",
            "tokens": 40,
            "elapsed_ms": 12,
        }

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)

    resp = await authed_client.post("/api/llm/suggest", json={
        "node_id": node["id"],
        "project_id": project_id,
        "suggestion_type": "mitigations",
    })
    assert resp.status_code == 200, resp.text
    mitigation_suggestion = resp.json()["suggestions"][0]
    assert mitigation_suggestion["kind"] == "mitigation"
    assert mitigation_suggestion["effectiveness"] == 0.8

    resp = await authed_client.post("/api/llm/suggest", json={
        "node_id": node["id"],
        "project_id": project_id,
        "suggestion_type": "detections",
    })
    assert resp.status_code == 200, resp.text
    detection_suggestion = resp.json()["suggestions"][0]
    assert detection_suggestion["kind"] == "detection"
    assert detection_suggestion["data_source"] == "M365 audit log"

    resp = await authed_client.post("/api/llm/suggest", json={
        "node_id": node["id"],
        "project_id": project_id,
        "suggestion_type": "mappings",
    })
    assert resp.status_code == 200, resp.text
    mapping_suggestions = resp.json()["suggestions"]
    assert len(mapping_suggestions) == 1
    assert mapping_suggestions[0]["kind"] == "mapping"
    assert mapping_suggestions[0]["ref_id"] == "T1566"


@pytest.mark.asyncio
async def test_llm_agent_dedupes_duplicate_sibling_titles_before_persisting(
    authed_client: AsyncClient,
    monkeypatch,
):
    await _create_active_provider(authed_client, name="Agent Dedupe Provider")

    resp = await authed_client.post("/api/projects", json={
        "name": "Agent Dedupe Project",
        "root_objective": "Model duplicate suppression",
    })
    assert resp.status_code == 201, resp.text
    project = resp.json()

    async def fake_chat_completion(config, messages, temperature=0.7, max_tokens=0, timeout_override=None):
        prompt = messages[-1]["content"]
        if "Generate a complete attack tree" in prompt:
            return {
                "status": "success",
                "content": json.dumps(
                    _build_agent_node_payload(
                        "Assess duplicate handling",
                        "Root node for duplicate suppression tests.",
                        node_type="goal",
                        logic_type="OR",
                        status="validated",
                        platform="Enterprise Environment",
                        attack_surface="Multiple",
                        threat_category="Reconnaissance",
                        required_access="None/Public",
                        required_privileges="None",
                        required_skill="Medium",
                        likelihood=6,
                        impact=6,
                        effort=4,
                        exploitability=6,
                        detectability=5,
                        children=[
                            _build_agent_node_payload(
                                "Credential Token",
                                "First sibling title.",
                                node_type="attack_step",
                                logic_type="OR",
                                status="validated",
                                platform="Enterprise Environment",
                                attack_surface="Identity",
                                threat_category="Credential Access",
                                required_access="Authenticated User",
                                required_privileges="User",
                                required_skill="Medium",
                                likelihood=6,
                                impact=6,
                                effort=4,
                                exploitability=6,
                                detectability=5,
                                children=[],
                            ),
                            _build_agent_node_payload(
                                "Credential Tokens",
                                "Normalized duplicate sibling title that should be dropped.",
                                node_type="attack_step",
                                logic_type="OR",
                                status="validated",
                                platform="Enterprise Environment",
                                attack_surface="Identity",
                                threat_category="Credential Access",
                                required_access="Authenticated User",
                                required_privileges="User",
                                required_skill="Medium",
                                likelihood=6,
                                impact=6,
                                effort=4,
                                exploitability=6,
                                detectability=5,
                                children=[],
                            ),
                            _build_agent_node_payload(
                                "Remote Support Tunnel Hijack",
                                "Distinct sibling title that should remain.",
                                node_type="attack_step",
                                logic_type="OR",
                                status="validated",
                                platform="Enterprise Environment",
                                attack_surface="Remote Access",
                                threat_category="Initial Access",
                                required_access="None/Public",
                                required_privileges="None",
                                required_skill="Medium",
                                likelihood=6,
                                impact=7,
                                effort=5,
                                exploitability=6,
                                detectability=5,
                                children=[],
                            ),
                        ],
                    )
                ),
                "model": "test-model",
                "tokens": 60,
                "elapsed_ms": 20,
            }

        if "suggest the most relevant reference mappings" in prompt:
            return {
                "status": "success",
                "content": "[]",
                "model": "test-model",
                "tokens": 10,
                "elapsed_ms": 5,
            }

        if "suggest detailed mitigations and detections" in prompt:
            return {
                "status": "success",
                "content": "[]",
                "model": "test-model",
                "tokens": 10,
                "elapsed_ms": 5,
            }

        pytest.fail(f"Unexpected AI prompt: {prompt[:160]}")

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)
    monkeypatch.setattr(llm_service, "find_best_template_for_objective", lambda *args, **kwargs: None)

    resp = await authed_client.post("/api/llm/agent", json={
        "project_id": project["id"],
        "objective": "Model duplicate suppression",
        "scope": "Focus on sibling-title dedupe in generated trees",
        "depth": 2,
        "breadth": 3,
        "mode": "generate",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    run_status = await _wait_for_agent_run_completion(authed_client, body["agent_run_id"])
    assert any("duplicate AI-generated child titles" in warning for warning in run_status["warnings"])

    resp = await authed_client.get(f"/api/nodes/project/{project['id']}")
    assert resp.status_code == 200, resp.text
    nodes = resp.json()
    titles = [node["title"] for node in nodes]
    assert titles.count("Credential Token") == 1
    assert "Credential Tokens" not in titles
    assert "Remote Support Tunnel Hijack" in titles
    assert len(nodes) == 3


@pytest.mark.asyncio
async def test_llm_agent_generates_large_tree_via_branch_local_expansion_prompts(
    authed_client: AsyncClient,
    monkeypatch,
):
    await _create_active_provider(authed_client, name="Agent Large Tree Provider")

    resp = await authed_client.post("/api/projects", json={
        "name": "Agent Large Tree Project",
        "context_preset": "airport",
    })
    assert resp.status_code == 201, resp.text
    project = resp.json()

    skeleton_prompts: list[str] = []
    branch_prompts: list[str] = []

    async def fake_chat_completion(config, messages, temperature=0.7, max_tokens=0, timeout_override=None):
        prompt = messages[-1]["content"]
        if "Generate a complete attack tree" in prompt:
            skeleton_prompts.append(prompt)
            assert "**Tree Depth:** up to 2 levels deep" in prompt
            return {
                "status": "success",
                "content": json.dumps(_build_agent_tree_payload(branch_count=6, leaves_per_branch=0)),
                "model": "test-model",
                "tokens": 140,
                "elapsed_ms": 45,
            }

        if "Expand one branch of an attack tree using only the local branch context below." in prompt:
            branch_prompts.append(prompt)
            assert "Sibling Branches Already Covered Elsewhere" in prompt
            assert "Leaf 1-1" not in prompt
            match = re.search(r'"title":\s*"Branch (\d+)"', prompt)
            assert match is not None, prompt
            branch_index = int(match.group(1))
            return {
                "status": "success",
                "content": json.dumps(
                    _build_agent_branch_children_payload(
                        branch_index,
                        child_count=6,
                        grandchild_count=6,
                    )
                ),
                "model": "test-model",
                "tokens": 220,
                "elapsed_ms": 55,
            }

        if "suggest the most relevant reference mappings" in prompt:
            indexes = [int(value) for value in re.findall(r'"index"\s*:\s*(\d+)', prompt)]
            return {
                "status": "success",
                "content": json.dumps([
                    {
                        "index": idx,
                        "mappings": [
                            {"framework": "attack", "ref_id": "T1595", "ref_name": "Active Scanning"},
                        ],
                    }
                    for idx in indexes
                ]),
                "model": "test-model",
                "tokens": 50,
                "elapsed_ms": 15,
            }

        if "suggest detailed mitigations and detections" in prompt:
            indexes = [int(value) for value in re.findall(r'"index"\s*:\s*(\d+)', prompt)]
            return {
                "status": "success",
                "content": json.dumps([
                    {
                        "index": idx,
                        "mitigations": [
                            {
                                "title": f"Mitigate {idx}",
                                "description": "Apply a concrete preventative control with product-specific tuning.",
                                "effectiveness": 0.8,
                            }
                        ],
                        "detections": [
                            {
                                "title": f"Detect {idx}",
                                "description": "Detect the operator behaviour with endpoint or proxy telemetry.",
                                "coverage": 0.6,
                                "data_source": "EDR telemetry",
                            }
                        ],
                    }
                    for idx in indexes
                ]),
                "model": "test-model",
                "tokens": 70,
                "elapsed_ms": 20,
            }

        pytest.fail(f"Unexpected AI prompt: {prompt[:120]}")

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)
    monkeypatch.setattr(llm_service, "find_best_template_for_objective", lambda *args, **kwargs: None)

    resp = await authed_client.post("/api/llm/agent", json={
        "project_id": project["id"],
        "objective": "Compromise airport operations systems",
        "scope": "AODB, FIDS, baggage handling, and partner maintenance links",
        "depth": 4,
        "breadth": 6,
        "mode": "generate",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["nodes_created"] == 259
    assert body["passes_completed"] == 1
    assert body["background_processing"] is True
    run_status = await _wait_for_agent_run_completion(authed_client, body["agent_run_id"])
    assert run_status["passes_completed"] == 4
    assert len(skeleton_prompts) == 1
    assert len(branch_prompts) == 6

    resp = await authed_client.get(f"/api/nodes/project/{project['id']}")
    assert resp.status_code == 200, resp.text
    nodes = resp.json()
    assert len(nodes) == 259


async def _create_active_provider(client: AsyncClient, *, name: str = "Test Provider") -> dict:
    response = await client.post("/api/llm/providers", json={
        "name": name,
        "base_url": "http://localhost:11434/v1",
        "model": "test-model",
    })
    assert response.status_code == 201, response.text
    return response.json()


async def _wait_for_agent_run_completion(client: AsyncClient, run_id: str) -> dict:
    for _ in range(100):
        response = await client.get(f"/api/llm/agent-runs/{run_id}")
        assert response.status_code == 200, response.text
        body = response.json()
        if body["status"] in {"completed", "completed_with_warnings", "failed"}:
            return body
        await asyncio.sleep(0.02)
    pytest.fail(f"Agent run {run_id} did not complete in time")


def _kill_chain_overview_payload(phases: list[str]) -> dict:
    return {
        "overview_summary": (
            "This overview describes a staged intrusion path that begins with the most plausible exposed surfaces, "
            "progresses through execution and control objectives, and ends with objective-focused actions against the target. "
            "It is deliberately concrete enough to drive independent phase generation while preserving campaign coherence."
        ),
        "campaign_concept": "A disciplined intrusion path that chains the most exposed administrative and operational surfaces together.",
        "threat_actor_profile": "Assume a capable operator who can blend commodity tooling with targeted access abuse.",
        "initial_compromise_hypothesis": "Initial access is most likely to come from exposed remote access or trusted user workflows.",
        "priority_surfaces": ["Remote access", "Identity infrastructure", "Administrative workstations"],
        "defensive_posture": "Visibility exists in several phases but cross-phase correlation remains uneven.",
        "control_pressures": ["Remote access controls", "Identity monitoring", "Egress and command-channel visibility"],
        "critical_path_hypothesis": "Reach the stated objective by chaining the least-resisted route through authentication, execution, and control surfaces.",
        "phase_objectives": [
            {
                "phase": phase_name,
                "objective": f"Advance the campaign by using {phase_name} to pressure the next trust boundary and support the final objective.",
            }
            for phase_name in phases
        ],
    }


def _kill_chain_phase_payload(phase_name: str, *, node_ids: list[str] | None = None, alias_phase: str | None = None) -> dict:
    return {
        "phase": alias_phase or phase_name,
        "description": (
            f"{phase_name} activity focuses on concrete operator actions against the target, including infrastructure preparation, "
            f"authentication abuse, tooling choices, and the trust-boundary crossings required to move the campaign forward."
        ),
        "node_ids": node_ids or [],
        "tools": [f"{phase_name} Tool", "Impacket"],
        "iocs": [f"{phase_name} IOC 1", f"{phase_name} IOC 2"],
        "log_sources": ["EDR telemetry", "Proxy logs"],
        "detection_window": "15 min - 2 hours",
        "dwell_time": "4-12 hours",
        "break_opportunities": [f"Break {phase_name} before the next control boundary is crossed."],
        "difficulty": "hard" if "Exploitation" in phase_name or "Installation" in phase_name else "moderate",
        "defensive_coverage": "partial",
        "coverage_notes": f"{phase_name} has useful telemetry but incomplete correlation.",
    }


def _kill_chain_synthesis_payload(
    *,
    risk: str = "high",
    complexity: str = "high",
    coverage: float = 0.62,
    critical_path: str = "Phishing and VPN exploitation combine to reach privileged identity paths and then sensitive file services.",
    weakest_links: list[str] | None = None,
) -> dict:
    return {
        "campaign_summary": (
            "This campaign models a capable intrusion set using a deliberate sequence of reconnaissance, delivery, exploitation, "
            "and post-compromise actions to reach sensitive enterprise records. The operator begins with target discovery and lure "
            "development, then uses externally reachable systems and user trust to create a foothold. Once access is obtained, the "
            "campaign transitions into persistence, remote command execution, and objective-driven data staging. Defensive control "
            "strength is uneven: gateway and proxy telemetry provide useful signals, but identity, remote access, and data egress "
            "paths still allow a skilled operator to chain actions together before responders can fully contain the intrusion."
        ),
        "total_estimated_time": "3-7 days",
        "overall_risk_rating": risk,
        "attack_complexity": complexity,
        "coverage_score": coverage,
        "weakest_links": weakest_links or ["Remote access infrastructure lacks strong pre-auth anomaly detection."],
        "critical_path": critical_path,
        "recommendations": [
            {"priority": "critical", "title": "Harden remote access controls", "description": "Require phishing-resistant MFA and conditional access for remote gateways to disrupt the initial compromise chain.", "addresses_phases": ["Delivery", "Exploitation"], "effort": "medium"},
            {"priority": "high", "title": "Tighten beacon detection", "description": "Tune proxy and EDR detections for periodic C2 patterns and suspicious JA3 changes to catch operator control channels quickly.", "addresses_phases": ["Command & Control"], "effort": "medium"},
            {"priority": "high", "title": "Constrain data staging paths", "description": "Detect and block archive creation plus unusual outbound transfer combinations on sensitive shares.", "addresses_phases": ["Actions on Objectives"], "effort": "high"},
        ],
    }


def _infra_overview_payload(root_label: str, branches: list[tuple[str, str]]) -> dict:
    return {
        "root": {
            "label": root_label,
            "category": "infrastructure",
            "description": f"Infrastructure model for {root_label}.",
        },
        "branches": [
            {
                "temp_id": f"BRANCH_{index}",
                "label": label,
                "category": category,
                "description": f"{label} branch",
                "icon_hint": "network" if category == "networking" else "shield" if category == "security" else "server",
            }
            for index, (label, category) in enumerate(branches, start=1)
        ],
        "ai_summary": f"{root_label} decomposed into planning-useful infrastructure branches.",
    }


def _infra_branch_payload(branch_temp_id: str, branch_label: str, category: str) -> dict:
    return {
        "nodes": [
            {
                "temp_id": f"{branch_temp_id}_NODE_1",
                "parent_temp_id": branch_temp_id,
                "label": f"{branch_label} Core",
                "category": category,
                "description": f"Core {branch_label.lower()} systems.",
                "icon_hint": "network" if category == "networking" else "shield" if category == "security" else "server",
            },
            {
                "temp_id": f"{branch_temp_id}_NODE_2",
                "parent_temp_id": f"{branch_temp_id}_NODE_1",
                "label": f"{branch_label} Management",
                "category": "service",
                "description": f"Management plane for {branch_label.lower()}.",
                "icon_hint": "cog",
            },
        ],
        "branch_summary": f"{branch_label} branch covers core systems and management paths.",
    }


def _infra_branch_fallback_payload(branch_label: str, category: str) -> dict:
    return {
        "children": [
            {
                "label": f"{branch_label} Access",
                "category": category,
                "description": f"Direct access surface for {branch_label.lower()}.",
                "icon_hint": "monitor" if category == "endpoint" else "network",
            },
            {
                "label": f"{branch_label} Telemetry",
                "category": "security",
                "description": f"Monitoring coverage for {branch_label.lower()}.",
                "icon_hint": "shield",
            },
        ],
        "summary": f"{branch_label} fallback coverage.",
    }


def _build_agent_node_payload(
    title: str,
    description: str,
    *,
    node_type: str,
    logic_type: str,
    status: str,
    platform: str,
    attack_surface: str,
    threat_category: str,
    required_access: str,
    required_privileges: str,
    required_skill: str,
    likelihood: int,
    impact: int,
    effort: int,
    exploitability: int,
    detectability: int,
    children: list[dict],
) -> dict:
    return {
        "title": title,
        "description": description,
        "node_type": node_type,
        "logic_type": logic_type,
        "status": status,
        "platform": platform,
        "attack_surface": attack_surface,
        "threat_category": threat_category,
        "required_access": required_access,
        "required_privileges": required_privileges,
        "required_skill": required_skill,
        "likelihood": likelihood,
        "impact": impact,
        "effort": effort,
        "exploitability": exploitability,
        "detectability": detectability,
        "children": children,
    }


def _build_agent_branch_children_payload(
    branch_index: int,
    *,
    child_count: int = 6,
    grandchild_count: int = 0,
) -> list[dict]:
    children = []
    for child_index in range(1, child_count + 1):
        grandchildren = [
            _build_agent_node_payload(
                f"Leaf {branch_index}-{child_index}-{grandchild_index}",
                (
                    f"Leaf {branch_index}-{child_index}-{grandchild_index} models a concrete operator action "
                    "with tooling, access preconditions, and the expected control impact on success."
                ),
                node_type="attack_step",
                logic_type="OR",
                status="validated",
                platform="Windows Server 2022",
                attack_surface="Identity Infrastructure",
                threat_category="Credential Access",
                required_access="Authenticated User",
                required_privileges="User",
                required_skill="High",
                likelihood=7,
                impact=8,
                effort=6,
                exploitability=7,
                detectability=4,
                children=[],
            )
            for grandchild_index in range(1, grandchild_count + 1)
        ]
        children.append(
            _build_agent_node_payload(
                f"Leaf {branch_index}-{child_index}",
                (
                    f"Leaf {branch_index}-{child_index} models a concrete operator action with tooling, "
                    "access preconditions, and the expected control impact on success."
                ),
                node_type="sub_goal" if grandchildren else "attack_step",
                logic_type="OR",
                status="validated",
                platform="Windows Server 2022",
                attack_surface="Identity Infrastructure",
                threat_category="Credential Access",
                required_access="Authenticated User",
                required_privileges="User",
                required_skill="High",
                likelihood=7,
                impact=8,
                effort=6,
                exploitability=7,
                detectability=4,
                children=grandchildren,
            )
        )
    return children


def _build_agent_tree_payload(branch_count: int = 6, leaves_per_branch: int = 6) -> dict:
    children = []
    for branch_index in range(1, branch_count + 1):
        children.append(
            _build_agent_node_payload(
                f"Branch {branch_index}",
                (
                    f"Branch {branch_index} represents a distinct operational path with concrete access abuse "
                    "and follow-on intrusion opportunities."
                ),
                node_type="sub_goal",
                logic_type="OR",
                status="validated",
                platform="Hybrid Enterprise",
                attack_surface="Remote Access",
                threat_category="Initial Access",
                required_access="None/Public",
                required_privileges="None",
                required_skill="Medium",
                likelihood=6,
                impact=7,
                effort=5,
                exploitability=7,
                detectability=5,
                children=_build_agent_branch_children_payload(
                    branch_index,
                    child_count=leaves_per_branch,
                ),
            )
        )
    return _build_agent_node_payload(
        "Compromise target environment",
        (
            "The root goal models the complete intrusion objective across the exposed trust boundaries, "
            "operator workflows, and business-critical systems in scope."
        ),
        node_type="goal",
        logic_type="OR",
        status="validated",
        platform="Enterprise Environment",
        attack_surface="Multiple",
        threat_category="Impact",
        required_access="None/Public",
        required_privileges="None",
        required_skill="High",
        likelihood=6,
        impact=9,
        effort=6,
        exploitability=7,
        detectability=4,
        children=children,
    )


@pytest_asyncio.fixture
async def authed_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        ac.headers.update(await _signup_or_login(
            ac,
            name="Test Analyst",
            email="tester@example.com",
            password="Password!123",
        ))
        yield ac


@pytest_asyncio.fixture
async def admin_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        ac.headers.update(await _login_as_seed_admin(ac))
        yield ac


@pytest.mark.asyncio
async def test_health(client: AsyncClient):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_seeded_adminaccount_can_login_by_username(client: AsyncClient):
    resp = await client.post("/api/auth/login", json={
        "identifier": "admin12345",
        "password": "admin12345",
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["user"]["name"] == "adminaccount"
    assert resp.json()["user"]["username"] == "admin12345"
    assert resp.json()["user"]["role"] == "admin"


@pytest.mark.asyncio
async def test_only_admin12345_is_seeded_by_default(client: AsyncClient):
    admin_headers = await _login_as_seed_admin(client)
    resp = await client.get("/api/auth/users", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    users = resp.json()
    assert len(users) == 1
    assert users[0]["username"] == "admin12345"
    assert users[0]["approval_status"] == "approved"


@pytest.mark.asyncio
async def test_init_db_preserves_non_legacy_users_with_seed_like_usernames():
    async with db_module.async_session_factory() as session:
        session.add(User(
            name="Alice Real",
            username="alice",
            email="alice.real@example.com",
            password_hash=hash_password("Password!123"),
            role="user",
            is_active=True,
            approval_status="approved",
        ))
        await session.commit()

    await db_module.init_db()

    async with db_module.async_session_factory() as session:
        result = await session.execute(select(User).where(User.email == "alice.real@example.com"))
        user = result.scalar_one_or_none()
        assert user is not None
        assert user.username == "alice"


@pytest.mark.asyncio
async def test_project_crud(authed_client: AsyncClient):
    # Create
    resp = await authed_client.post("/api/projects", json={
        "name": "Test Project",
        "description": "A test",
        "context_preset": "web_application",
        "root_objective": "Test objective",
        "workspace_mode": "standalone_scan",
    })
    assert resp.status_code == 201
    project = resp.json()
    assert project["name"] == "Test Project"
    assert project["workspace_mode"] == "standalone_scan"
    project_id = project["id"]

    # List
    resp = await authed_client.get("/api/projects")
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1
    assert any(item["id"] == project_id and item["workspace_mode"] == "standalone_scan" for item in resp.json()["projects"])

    # Update
    resp = await authed_client.patch(f"/api/projects/{project_id}", json={"name": "Updated", "workspace_mode": "project_scan"})
    assert resp.status_code == 200
    assert resp.json()["name"] == "Updated"
    assert resp.json()["workspace_mode"] == "project_scan"

    # Delete
    resp = await authed_client.delete(f"/api/projects/{project_id}")
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_project_list_reports_node_counts(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Node Count A"})
    assert resp.status_code == 201, resp.text
    project_a = resp.json()["id"]

    resp = await authed_client.post("/api/projects", json={"name": "Node Count B"})
    assert resp.status_code == 201, resp.text
    project_b = resp.json()["id"]

    for title in ("A-Root", "A-Child"):
        resp = await authed_client.post("/api/nodes", json={
            "project_id": project_a,
            "title": title,
            "node_type": "attack_step",
        })
        assert resp.status_code == 201, resp.text

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_b,
        "title": "B-Only",
        "node_type": "attack_step",
    })
    assert resp.status_code == 201, resp.text

    resp = await authed_client.get("/api/projects")
    assert resp.status_code == 200, resp.text
    projects = {project["id"]: project for project in resp.json()["projects"]}
    assert projects[project_a]["node_count"] == 2
    assert projects[project_b]["node_count"] == 1


@pytest.mark.asyncio
async def test_project_dashboard_aggregates_workspace_data(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={
        "name": "Dashboard Project",
        "context_preset": "web_application",
        "workspace_mode": "standalone_scan",
    })
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "title": "Compromise VPN Gateway",
        "node_type": "attack_step",
        "status": "validated",
        "attack_surface": "Edge",
        "platform": "Network",
        "required_access": "external",
        "likelihood": 9,
        "impact": 9,
        "effort": 2,
        "exploitability": 9,
        "detectability": 2,
    })
    assert resp.status_code == 201, resp.text
    covered_node = resp.json()

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "title": "Abuse inherited admin session",
        "node_type": "attack_step",
        "status": "validated",
        "attack_surface": "Identity",
        "platform": "Cloud",
        "required_access": "partner",
        "likelihood": 8,
        "impact": 8,
        "effort": 3,
        "exploitability": 8,
        "detectability": 3,
    })
    assert resp.status_code == 201, resp.text
    gap_node = resp.json()

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "title": "Review operational assumptions",
        "node_type": "goal",
    })
    assert resp.status_code == 201, resp.text
    draft_node = resp.json()

    resp = await authed_client.post("/api/mitigations", json={
        "node_id": covered_node["id"],
        "title": "Harden edge access policy",
        "effectiveness": 0.75,
    })
    assert resp.status_code == 201, resp.text

    resp = await authed_client.post("/api/detections", json={
        "node_id": covered_node["id"],
        "title": "Alert on impossible travel",
        "coverage": 0.8,
    })
    assert resp.status_code == 201, resp.text

    resp = await authed_client.post("/api/references", json={
        "node_id": covered_node["id"],
        "framework": "attack",
        "ref_id": "T1133",
        "ref_name": "External Remote Services",
    })
    assert resp.status_code == 201, resp.text

    resp = await authed_client.post("/api/scenarios", json={
        "project_id": project_id,
        "name": "Remote access intrusion",
        "operation_goal": "Exercise the edge compromise path",
        "entry_vectors": ["VPN"],
        "campaign_phases": ["Initial access", "Credential access"],
    })
    assert resp.status_code == 201, resp.text

    resp = await authed_client.post("/api/kill-chains", json={
        "project_id": project_id,
        "name": "Edge intrusion chain",
        "framework": "unified",
    })
    assert resp.status_code == 201, resp.text

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "Remote Access Threat Model",
        "scope": "VPN and identity control plane",
        "methodology": "stride",
    })
    assert resp.status_code == 201, resp.text

    resp = await authed_client.post("/api/infra-maps", json={
        "project_id": project_id,
        "name": "Edge Infrastructure",
    })
    assert resp.status_code == 201, resp.text

    now = datetime.now(timezone.utc)
    async with db_module.async_session_factory() as session:
        session.add_all([
            Snapshot(
                project_id=project_id,
                label="baseline",
                tree_data={"nodes": []},
                created_by="test-suite",
            ),
            AnalysisRun(
                project_id=project_id,
                tool="tree_builder",
                run_type="workspace_refresh",
                status="completed",
                artifact_kind="project",
                artifact_name="Dashboard Project",
                summary="Refreshed attack tree coverage",
                metadata_json={"source": "test"},
                duration_ms=1200,
                created_at=now - timedelta(minutes=10),
            ),
            AnalysisRun(
                project_id=project_id,
                tool="threat_model",
                run_type="threat_enrichment",
                status="partial",
                artifact_kind="threat_model",
                artifact_name="Remote Access Threat Model",
                summary="Mapped threats to the access layer",
                metadata_json={"source": "test"},
                duration_ms=2600,
                created_at=now,
            ),
        ])
        await session.commit()

    resp = await authed_client.get(f"/api/dashboard/project/{project_id}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    analysis = body["analysis"]

    assert body["project"]["id"] == project_id
    assert body["project"]["node_count"] == 3
    assert body["artifacts"] == {
        "scenarios": 1,
        "kill_chains": 1,
        "threat_models": 1,
        "infra_maps": 1,
        "snapshots": 1,
    }
    assert analysis["total_nodes"] == 3
    assert analysis["scored"] == 2
    assert analysis["review_backlog"] == 1
    assert analysis["no_mitigation_count"] == 2
    assert analysis["no_detection_count"] == 2
    assert analysis["no_mapping_count"] == 2
    expected_gap_count = sum(
        1
        for node in (covered_node, gap_node, draft_node)
        if node.get("inherent_risk") is not None
        and node["inherent_risk"] >= 6.0
        and node["id"] != covered_node["id"]
    )
    assert analysis["gap_count"] == expected_gap_count
    assert analysis["top_risks"][0]["id"] == max(
        (covered_node, gap_node),
        key=lambda node: node["inherent_risk"] or 0.0,
    )["id"]
    assert [run["tool"] for run in body["analysis_runs"]] == ["threat_model", "tree_builder"]


@pytest.mark.asyncio
async def test_portfolio_dashboard_aggregates_workspaces(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={
        "name": "Project Scan Workspace",
        "context_preset": "web_application",
        "workspace_mode": "project_scan",
    })
    assert resp.status_code == 201, resp.text
    project_scan_id = resp.json()["id"]

    resp = await authed_client.post("/api/projects", json={
        "name": "Standalone Workspace",
        "context_preset": "telecoms_base_station",
        "workspace_mode": "standalone_scan",
    })
    assert resp.status_code == 201, resp.text
    standalone_id = resp.json()["id"]

    for project_id, title in (
        (project_scan_id, "Web foothold"),
        (project_scan_id, "API abuse"),
        (standalone_id, "Timing disruption"),
    ):
        resp = await authed_client.post("/api/nodes", json={
            "project_id": project_id,
            "title": title,
            "node_type": "attack_step",
            "status": "validated",
            "likelihood": 7,
            "impact": 7,
            "effort": 4,
            "exploitability": 7,
            "detectability": 4,
        })
        assert resp.status_code == 201, resp.text

    resp = await authed_client.post("/api/scenarios", json={
        "project_id": project_scan_id,
        "name": "Web application scenario",
        "operation_goal": "Validate project scan coverage",
    })
    assert resp.status_code == 201, resp.text

    resp = await authed_client.post("/api/infra-maps", json={
        "project_id": standalone_id,
        "name": "Standalone infra map",
    })
    assert resp.status_code == 201, resp.text

    resp = await authed_client.get("/api/dashboard/portfolio")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    workspaces = {workspace["project"]["id"]: workspace for workspace in body["workspaces"]}

    assert len(body["workspaces"]) == 2
    assert body["project_scans"] == 1
    assert body["standalone_scans"] == 1
    assert body["contexts"] == {
        "web_application": 1,
        "telecoms_base_station": 1,
    }
    assert body["aggregate"]["total_nodes"] == 3
    assert body["artifact_totals"]["scenarios"] == 1
    assert body["artifact_totals"]["infra_maps"] == 1
    assert workspaces[project_scan_id]["project"]["node_count"] == 2
    assert workspaces[project_scan_id]["total_artifacts"] == 1
    assert workspaces[standalone_id]["project"]["node_count"] == 1
    assert workspaces[standalone_id]["total_artifacts"] == 1


@pytest.mark.asyncio
async def test_node_crud(authed_client: AsyncClient):
    # Create project first
    resp = await authed_client.post("/api/projects", json={"name": "Node Test"})
    project_id = resp.json()["id"]

    # Create root node
    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "node_type": "goal",
        "title": "Root Goal",
        "logic_type": "OR",
    })
    assert resp.status_code == 201
    root = resp.json()
    root_id = root["id"]
    assert root["title"] == "Root Goal"

    # Create child node
    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "parent_id": root_id,
        "node_type": "attack_step",
        "title": "SQL Injection",
        "likelihood": 7,
        "impact": 9,
        "effort": 3,
        "exploitability": 8,
        "detectability": 5,
    })
    assert resp.status_code == 201
    child = resp.json()
    assert child["inherent_risk"] is not None

    # List nodes
    resp = await authed_client.get(f"/api/nodes/project/{project_id}")
    assert resp.status_code == 200
    assert len(resp.json()) == 2

    # Update node
    resp = await authed_client.patch(f"/api/nodes/{child['id']}", json={"title": "SQL Injection (Updated)"})
    assert resp.status_code == 200
    assert resp.json()["title"] == "SQL Injection (Updated)"

    # Duplicate
    resp = await authed_client.post(f"/api/nodes/{child['id']}/duplicate")
    assert resp.status_code == 201
    assert "copy" in resp.json()["title"]


@pytest.mark.asyncio
async def test_node_parent_validation_blocks_cross_project_links_and_cycles(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Project A"})
    assert resp.status_code == 201
    project_a = resp.json()["id"]

    resp = await authed_client.post("/api/projects", json={"name": "Project B"})
    assert resp.status_code == 201
    project_b = resp.json()["id"]

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_a,
        "title": "Root A",
        "node_type": "goal",
    })
    assert resp.status_code == 201
    root_a = resp.json()

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_b,
        "title": "Root B",
        "node_type": "goal",
    })
    assert resp.status_code == 201
    root_b = resp.json()

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_a,
        "parent_id": root_a["id"],
        "title": "Child A",
    })
    assert resp.status_code == 201
    child_a = resp.json()

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_a,
        "parent_id": root_b["id"],
        "title": "Cross Project Parent",
    })
    assert resp.status_code == 400
    assert "same project" in resp.text.lower()

    resp = await authed_client.patch(f"/api/nodes/{root_a['id']}", json={"parent_id": root_a["id"]})
    assert resp.status_code == 400
    assert "own parent" in resp.text.lower()

    resp = await authed_client.patch(f"/api/nodes/{root_a['id']}", json={"parent_id": child_a["id"]})
    assert resp.status_code == 400
    assert "descendant" in resp.text.lower()


@pytest.mark.asyncio
async def test_mitigation_creation(authed_client: AsyncClient):
    # Setup
    resp = await authed_client.post("/api/projects", json={"name": "Mit Test"})
    project_id = resp.json()["id"]
    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id, "title": "Step", "likelihood": 7, "impact": 8,
    })
    node_id = resp.json()["id"]

    # Create mitigation
    resp = await authed_client.post("/api/mitigations", json={
        "node_id": node_id, "title": "WAF", "effectiveness": 0.6,
    })
    assert resp.status_code == 201
    assert resp.json()["title"] == "WAF"


@pytest.mark.asyncio
async def test_rollups_recalculate_automatically_after_tree_edits(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Auto Rollup"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "title": "Root",
        "node_type": "goal",
        "logic_type": "OR",
    })
    assert resp.status_code == 201
    root_id = resp.json()["id"]

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "parent_id": root_id,
        "title": "Child",
        "likelihood": 8,
        "impact": 8,
        "effort": 4,
        "exploitability": 6,
        "detectability": 5,
    })
    assert resp.status_code == 201
    child = resp.json()

    resp = await authed_client.get(f"/api/nodes/project/{project_id}")
    assert resp.status_code == 200
    nodes = resp.json()
    root = next(node for node in nodes if node["id"] == root_id)
    child = next(node for node in nodes if node["id"] == child["id"])
    assert root["rolled_up_risk"] == child["inherent_risk"]
    original_rollup = root["rolled_up_risk"]

    resp = await authed_client.patch(f"/api/nodes/{child['id']}", json={"likelihood": 4})
    assert resp.status_code == 200

    resp = await authed_client.get(f"/api/nodes/project/{project_id}")
    assert resp.status_code == 200
    nodes = resp.json()
    root = next(node for node in nodes if node["id"] == root_id)
    child = next(node for node in nodes if node["id"] == child["id"])
    assert root["rolled_up_risk"] == child["inherent_risk"]
    assert root["rolled_up_risk"] != original_rollup

    resp = await authed_client.delete(f"/api/nodes/{child['id']}")
    assert resp.status_code == 204

    resp = await authed_client.get(f"/api/nodes/project/{project_id}")
    assert resp.status_code == 200
    root = next(node for node in resp.json() if node["id"] == root_id)
    assert root["rolled_up_risk"] is None


@pytest.mark.asyncio
async def test_reference_browsing(authed_client: AsyncClient):
    resp = await authed_client.get("/api/references/browse/attack")
    assert resp.status_code == 200
    data = resp.json()
    assert data["framework"] == "attack"
    assert data["count"] > 0

    resp = await authed_client.get("/api/references/browse/infra_attack_patterns")
    assert resp.status_code == 200
    infra_data = resp.json()
    assert infra_data["framework"] == "infra_attack_patterns"
    assert infra_data["count"] >= 20
    assert infra_data["filter_field"] == "category"
    assert "Timing / PNT" in infra_data["filter_options"]

    resp = await authed_client.get("/api/references/browse/infra_attack_patterns?filter=Timing%20%2F%20PNT")
    assert resp.status_code == 200
    timing_data = resp.json()
    assert timing_data["count"] >= 3
    assert all(item["category"] == "Timing / PNT" for item in timing_data["items"])

    resp = await authed_client.get("/api/references/browse/software_research_patterns")
    assert resp.status_code == 200
    software_data = resp.json()
    assert software_data["framework"] == "software_research_patterns"
    assert software_data["count"] >= 60
    assert software_data["filter_field"] == "category"
    assert "Trust Boundary Review" in software_data["filter_options"]
    assert "Binary and Reverse Engineering" in software_data["filter_options"]
    assert "Dynamic Observation and Instrumentation" in software_data["filter_options"]

    resp = await authed_client.get("/api/references/browse/software_research_patterns?filter=Runtime%20and%20Isolation")
    assert resp.status_code == 200
    runtime_data = resp.json()
    assert runtime_data["count"] >= 6
    assert all(item["category"] == "Runtime and Isolation" for item in runtime_data["items"])

    resp = await authed_client.get("/api/references/browse/software_research_patterns?filter=Dynamic%20Observation%20and%20Instrumentation")
    assert resp.status_code == 200
    dynamic_data = resp.json()
    assert dynamic_data["count"] >= 5
    assert all(item["category"] == "Dynamic Observation and Instrumentation" for item in dynamic_data["items"])


@pytest.mark.asyncio
async def test_tree_analysis_endpoints_reject_malformed_cycles(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Malformed Tree"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "title": "Root",
        "node_type": "goal",
    })
    assert resp.status_code == 201
    root = resp.json()

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "parent_id": root["id"],
        "title": "Child",
    })
    assert resp.status_code == 201
    child = resp.json()

    async with db_module.async_session_factory() as session:
        result = await session.execute(select(Node).where(Node.id.in_([root["id"], child["id"]])))
        by_id = {node.id: node for node in result.scalars().all()}
        by_id[root["id"]].parent_id = child["id"]
        await session.commit()

    resp = await authed_client.get(f"/api/nodes/project/{project_id}/critical-path")
    assert resp.status_code == 409
    assert "cycle" in resp.text.lower()

    resp = await authed_client.get(f"/api/export/risk-engine/{project_id}")
    assert resp.status_code == 409
    assert "cycle" in resp.text.lower()

    resp = await authed_client.get("/api/references/browse/software_research_patterns?q=deserialization")
    assert resp.status_code == 200
    search_data = resp.json()
    assert search_data["count"] > 0

    resp = await authed_client.get("/api/references/browse/owasp")
    assert resp.status_code == 200
    owasp_data = resp.json()
    assert owasp_data["framework"] == "owasp"
    assert owasp_data["count"] >= 115
    assert owasp_data["filter_field"] == "category"
    assert "Infrastructure" in owasp_data["filter_options"]
    assert "Non-Human Identities" in owasp_data["filter_options"]
    assert "MCP" in owasp_data["filter_options"]

    resp = await authed_client.get("/api/references/browse/owasp?filter=Infrastructure")
    assert resp.status_code == 200
    infrastructure_data = resp.json()
    assert infrastructure_data["count"] >= 10
    assert all(item["category"] == "Infrastructure" for item in infrastructure_data["items"])


@pytest.mark.asyncio
async def test_bulk_delete_reparents_descendants_to_surviving_ancestor(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Bulk Delete Project"})
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "title": "Root",
        "node_type": "goal",
    })
    assert resp.status_code == 201, resp.text
    root = resp.json()

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "parent_id": root["id"],
        "title": "Child",
        "node_type": "attack_step",
    })
    assert resp.status_code == 201, resp.text
    child = resp.json()

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "parent_id": child["id"],
        "title": "Grandchild",
        "node_type": "attack_step",
    })
    assert resp.status_code == 201, resp.text
    grandchild = resp.json()

    resp = await authed_client.post("/api/nodes/bulk/delete", json={
        "node_ids": [root["id"], child["id"]],
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["deleted"] == 2

    resp = await authed_client.get(f"/api/nodes/project/{project_id}")
    assert resp.status_code == 200, resp.text
    nodes = resp.json()
    assert len(nodes) == 1
    assert nodes[0]["id"] == grandchild["id"]
    assert nodes[0]["parent_id"] is None


@pytest.mark.asyncio
async def test_critical_path_uses_local_node_risk_without_double_counting_rollups(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Critical Path Project"})
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "title": "Root",
        "node_type": "goal",
        "logic_type": "OR",
    })
    assert resp.status_code == 201, resp.text
    root = resp.json()

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "parent_id": root["id"],
        "title": "Child",
        "node_type": "attack_step",
        "likelihood": 5,
        "impact": 10,
        "effort": 5,
        "exploitability": 10,
        "detectability": 5,
    })
    assert resp.status_code == 201, resp.text
    child = resp.json()

    resp = await authed_client.get(f"/api/nodes/project/{project_id}/critical-path")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["path"] == [root["id"], child["id"]]
    assert body["cumulative_risk"] == pytest.approx(child["inherent_risk"])

    # Search
    resp = await authed_client.get("/api/references/browse/cwe?q=injection")
    assert resp.status_code == 200
    assert resp.json()["count"] > 0


@pytest.mark.asyncio
async def test_reference_search_ranks_exact_ids_and_applies_context_boosts(authed_client: AsyncClient):
    resp = await authed_client.post("/api/references/search", json={
        "query": "T1595",
        "artifact_type": "attack_tree",
        "allowed_frameworks": ["attack", "infra_attack_patterns"],
        "limit": 5,
    })
    assert resp.status_code == 200, resp.text
    exact_items = resp.json()["items"]
    assert exact_items[0]["framework"] == "attack"
    assert exact_items[0]["ref_id"] == "T1595"
    assert "exact id match" in exact_items[0]["reasons"]

    resp = await authed_client.post("/api/references/search", json={
        "query": "timing",
        "artifact_type": "infra_map",
        "context_preset": "telecoms_base_station",
        "objective": "Assess GNSS, PTP, and timing assurance resilience",
        "scope": "Telecom base station with GNSS antenna, PTP grandmaster, and boundary clocks",
        "target_kind": "infra_node",
        "target_summary": "Timing distribution and timing assurance dependencies",
        "allowed_frameworks": ["attack", "infra_attack_patterns", "environment_catalog"],
        "limit": 5,
    })
    assert resp.status_code == 200, resp.text
    timing_items = resp.json()["items"]
    assert timing_items[0]["framework"] in {"environment_catalog", "infra_attack_patterns"}
    assert "artifact relevance" in timing_items[0]["reasons"]
    assert any(item["framework"] == "environment_catalog" for item in timing_items[:3])

    resp = await authed_client.post("/api/references/search", json={
        "query": "phishing",
        "artifact_type": "kill_chain",
        "objective": "Run a phishing-led intrusion path",
        "scope": "Corporate users, identity infrastructure, and cloud mail platform",
        "allowed_frameworks": ["attack", "capec", "owasp"],
        "limit": 5,
    })
    assert resp.status_code == 200, resp.text
    phishing_items = resp.json()["items"]
    assert phishing_items[0]["framework"] == "attack"
    assert phishing_items[0]["ref_id"] == "T1566"
    assert "artifact relevance" in phishing_items[0]["reasons"]


@pytest.mark.asyncio
async def test_reference_mapping_validation_and_metadata_round_trip(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Reference Validation Project"})
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "title": "Review software attack surface",
        "node_type": "attack_step",
    })
    assert resp.status_code == 201, resp.text
    node = resp.json()

    resp = await authed_client.post("/api/references", json={
        "node_id": node["id"],
        "framework": "software_research_patterns",
        "ref_id": "SRP-001",
        "ref_name": "Attack Surface Inventory and Exposure Mapping",
        "confidence": 0.84,
        "rationale": "Grounds the node in concrete exposure-mapping activity.",
        "source": "manual",
    })
    assert resp.status_code == 201, resp.text
    mapping = resp.json()
    assert mapping["framework"] == "software_research_patterns"
    assert mapping["ref_id"] == "SRP-001"
    assert mapping["confidence"] == 0.84
    assert mapping["source"] == "manual"

    resp = await authed_client.get(f"/api/references/node/{node['id']}")
    assert resp.status_code == 200, resp.text
    mappings = resp.json()
    assert len(mappings) == 1
    assert mappings[0]["rationale"].startswith("Grounds the node")

    resp = await authed_client.patch(f"/api/references/{mapping['id']}", json={
        "framework": "attack",
        "ref_id": "T1595",
        "ref_name": "Active Scanning",
        "confidence": 0.91,
        "rationale": "Updated to the primary ATT&CK technique for active discovery.",
    })
    assert resp.status_code == 200, resp.text
    updated = resp.json()
    assert updated["framework"] == "attack"
    assert updated["ref_id"] == "T1595"
    assert updated["confidence"] == 0.91
    assert updated["rationale"].startswith("Updated to the primary")

    resp = await authed_client.post("/api/references", json={
        "node_id": node["id"],
        "framework": "attack",
        "ref_id": "T999999",
        "ref_name": "Imaginary Technique",
    })
    assert resp.status_code == 400, resp.text
    assert "Unknown reference identifier" in resp.text

    resp = await authed_client.patch(f"/api/references/{mapping['id']}", json={
        "framework": "environment_catalog",
        "ref_id": "missing-reference-id",
    })
    assert resp.status_code == 400, resp.text
    assert "Unknown reference identifier" in resp.text


@pytest.mark.asyncio
async def test_templates(authed_client: AsyncClient):
    resp = await authed_client.get("/api/templates")
    assert resp.status_code == 200
    templates = resp.json()["templates"]
    assert len(templates) >= 5
    assert any(t["id"] == "file_parser_memory_corruption" for t in templates)

    parser_template = next(t for t in templates if t["id"] == "file_parser_memory_corruption")
    assert parser_template["template_family"] == "software_research"
    assert parser_template["technical_profile"] == "vulnerability_research"
    assert parser_template["focus_areas"]
    assert parser_template["prompt_hints"]

    # Get specific template
    if templates:
        resp = await authed_client.get(f"/api/templates/{templates[0]['id']}")
        assert resp.status_code == 200
        assert "nodes" in resp.json()

    resp = await authed_client.get("/api/templates/secure_updater_abuse")
    assert resp.status_code == 200
    assert resp.json()["context_preset"] == "software_reverse_engineering"
    assert resp.json()["technical_profile"] == "reverse_engineering"


@pytest.mark.asyncio
async def test_snapshot_crud(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Snap Test"})
    project_id = resp.json()["id"]

    # Create snapshot
    resp = await authed_client.post("/api/snapshots", json={
        "project_id": project_id, "label": "v1"
    })
    assert resp.status_code == 201
    snap_id = resp.json()["id"]

    # List snapshots
    resp = await authed_client.get(f"/api/snapshots/project/{project_id}")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1

    # Get snapshot detail
    resp = await authed_client.get(f"/api/snapshots/{snap_id}")
    assert resp.status_code == 200
    assert "tree_data" in resp.json()


@pytest.mark.asyncio
async def test_export_json(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Export Test", "workspace_mode": "standalone_scan"})
    project_id = resp.json()["id"]
    await authed_client.post("/api/nodes", json={"project_id": project_id, "title": "Root"})

    resp = await authed_client.post("/api/export/json", json={"project_id": project_id})
    assert resp.status_code == 200
    exported = resp.json()
    assert exported["project"]["workspace_mode"] == "standalone_scan"
    assert exported["project"]["metadata_json"]["workspace_mode"] == "standalone_scan"

    resp = await authed_client.post("/api/export/import", json=exported)
    assert resp.status_code == 200
    imported_project_id = resp.json()["project_id"]

    resp = await authed_client.get(f"/api/projects/{imported_project_id}")
    assert resp.status_code == 200
    assert resp.json()["workspace_mode"] == "standalone_scan"

    resp = await authed_client.post("/api/export/markdown", json={"project_id": project_id})
    assert resp.status_code == 200

    resp = await authed_client.post("/api/export/csv", json={"project_id": project_id})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_export_import_preserves_reference_mapping_metadata(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Reference Export Project"})
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "title": "Catalogue exposed services",
        "node_type": "attack_step",
    })
    assert resp.status_code == 201, resp.text
    node = resp.json()

    resp = await authed_client.post("/api/references", json={
        "node_id": node["id"],
        "framework": "attack",
        "ref_id": "T1595",
        "ref_name": "Active Scanning",
        "confidence": 0.77,
        "rationale": "Used to model deliberate network discovery against exposed services.",
        "source": "manual",
    })
    assert resp.status_code == 201, resp.text

    resp = await authed_client.post("/api/export/json", json={"project_id": project_id})
    assert resp.status_code == 200, resp.text
    exported = resp.json()
    exported_node = next(item for item in exported["nodes"] if item["title"] == "Catalogue exposed services")
    assert exported_node["reference_mappings"][0]["ref_id"] == "T1595"
    assert exported_node["reference_mappings"][0]["confidence"] == 0.77
    assert exported_node["reference_mappings"][0]["source"] == "manual"
    assert exported_node["reference_mappings"][0]["rationale"].startswith("Used to model deliberate")

    resp = await authed_client.post("/api/export/import", json=exported)
    assert resp.status_code == 200, resp.text
    imported_project_id = resp.json()["project_id"]

    resp = await authed_client.get(f"/api/nodes/project/{imported_project_id}")
    assert resp.status_code == 200, resp.text
    imported_node = next(item for item in resp.json() if item["title"] == "Catalogue exposed services")
    assert len(imported_node["reference_mappings"]) == 1
    assert imported_node["reference_mappings"][0]["ref_id"] == "T1595"
    assert imported_node["reference_mappings"][0]["confidence"] == 0.77
    assert imported_node["reference_mappings"][0]["source"] == "manual"
    assert imported_node["reference_mappings"][0]["rationale"].startswith("Used to model deliberate")


@pytest.mark.asyncio
async def test_vulnerability_cards_persist_through_node_updates_and_import_export(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={
        "name": "Research Workspace",
        "context_preset": "vulnerability_research",
        "workspace_mode": "standalone_scan",
    })
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    initial_card = {
        "id": "card-1",
        "title": "Heap overflow in parser",
        "software_family": "Desktop importer",
        "software_version": "5.4.1",
        "affected_component": "Thumbnail parser",
        "vulnerability_type": "heap overflow",
        "attack_surface": "Imported project file",
        "entry_point": "Preview generation before sandboxing",
        "root_cause": "Length field trusted before allocation sizing",
        "primitive": "Controlled 16-byte overwrite",
        "reproduction_steps": "Open crafted project package with ASan-enabled build",
        "exploitation_notes": "Likely exploitable with heap grooming after cache warmup",
        "references": "INT-4172",
        "severity": "Critical",
        "observed_impact": "Crash with RIP adjacent object corruption",
    }

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "title": "Investigate parser bug",
        "node_type": "attack_step",
        "attack_surface": "Imported project file",
        "platform": "Windows desktop client",
        "cve_references": "CVE-2026-1234",
        "extended_metadata": {
            "prompt_profile": "vulnerability_research",
            "research_domain": "file parser reversing",
            "investigation_summary": "Crash appears before sandbox handoff in preview path",
            "vulnerability_cards": [initial_card],
        },
    })
    assert resp.status_code == 201, resp.text
    node = resp.json()
    assert node["extended_metadata"]["prompt_profile"] == "vulnerability_research"
    assert node["extended_metadata"]["vulnerability_cards"][0]["title"] == "Heap overflow in parser"
    assert node["cve_references"] == "CVE-2026-1234"

    updated_card = {
        **initial_card,
        "primitive": "Controlled 16-byte overwrite with adjacent vtable influence",
        "references": "INT-4172, PoC-88",
    }
    resp = await authed_client.patch(f"/api/nodes/{node['id']}", json={
        "cve_references": "CVE-2026-1234, GHSA-test",
        "extended_metadata": {
            "prompt_profile": "vulnerability_research",
            "research_domain": "file parser reversing",
            "investigation_summary": "Crash reproduced under PageHeap and ASan",
            "vulnerability_cards": [updated_card],
        },
    })
    assert resp.status_code == 200, resp.text
    updated = resp.json()
    assert updated["extended_metadata"]["vulnerability_cards"][0]["primitive"].startswith("Controlled 16-byte overwrite")
    assert updated["cve_references"] == "CVE-2026-1234, GHSA-test"

    resp = await authed_client.post("/api/export/json", json={"project_id": project_id})
    assert resp.status_code == 200
    exported = resp.json()
    exported_node = next(item for item in exported["nodes"] if item["id"] == node["id"])
    assert exported_node["extended_metadata"]["vulnerability_cards"][0]["references"] == "INT-4172, PoC-88"
    assert exported_node["cve_references"] == "CVE-2026-1234, GHSA-test"

    resp = await authed_client.post("/api/export/import", json=exported)
    assert resp.status_code == 200
    imported_project_id = resp.json()["project_id"]

    resp = await authed_client.get(f"/api/nodes/project/{imported_project_id}")
    assert resp.status_code == 200
    imported_node = next(item for item in resp.json() if item["title"] == "Investigate parser bug")
    assert imported_node["extended_metadata"]["prompt_profile"] == "vulnerability_research"
    assert imported_node["extended_metadata"]["vulnerability_cards"][0]["primitive"].startswith("Controlled 16-byte overwrite")
    assert imported_node["cve_references"] == "CVE-2026-1234, GHSA-test"


@pytest.mark.asyncio
async def test_risk_recalculation(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Risk Test"})
    project_id = resp.json()["id"]
    await authed_client.post("/api/nodes", json={
        "project_id": project_id, "title": "Root", "node_type": "goal", "logic_type": "OR",
    })

    resp = await authed_client.get(f"/api/export/risk-engine/{project_id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"


@pytest.mark.asyncio
async def test_standalone_scenario_workspace(authed_client: AsyncClient):
    resp = await authed_client.post("/api/scenarios", json={
        "name": "Standalone Planning Scenario",
        "scope": "standalone",
        "scenario_type": "campaign",
        "operation_goal": "Assess options for a broad intrusion path",
        "entry_vectors": ["Phishing", "Third-party access"],
        "campaign_phases": ["Initial access", "Collection", "Exfiltration"],
        "constraints": ["Limited execution window"],
        "intelligence_gaps": ["Unknown supplier trust paths"],
        "success_criteria": ["Obtain sensitive business data"],
    })
    assert resp.status_code == 201, resp.text
    scenario = resp.json()
    assert scenario["project_id"] is None
    assert scenario["scope"] == "standalone"

    resp = await authed_client.get("/api/scenarios?scope=standalone")
    assert resp.status_code == 200
    assert any(item["id"] == scenario["id"] for item in resp.json())

    resp = await authed_client.post(f"/api/scenarios/{scenario['id']}/simulate", json={})
    assert resp.status_code == 200, resp.text
    simulated = resp.json()
    assert simulated["impact_summary"]["simulation_mode"] == "planning"
    assert simulated["impact_summary"]["campaign_profile"]["coverage_score"] > 0
    assert simulated["impact_summary"]["planning_findings"]


@pytest.mark.asyncio
async def test_project_scenario_simulation_with_controls_and_detections(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Scenario Project", "root_objective": "Exfiltrate design files"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "title": "Compromise engineering workstation",
        "node_type": "attack_step",
        "attack_surface": "Email",
        "platform": "Windows",
        "likelihood": 8,
        "impact": 8,
        "effort": 4,
        "exploitability": 7,
        "detectability": 6,
    })
    assert resp.status_code == 201
    node = resp.json()

    resp = await authed_client.post("/api/mitigations", json={
        "node_id": node["id"],
        "title": "Mailbox detonation",
        "effectiveness": 0.6,
    })
    assert resp.status_code == 201
    mitigation = resp.json()

    resp = await authed_client.post("/api/detections", json={
        "node_id": node["id"],
        "title": "Suspicious attachment execution",
        "coverage": 0.7,
    })
    assert resp.status_code == 201
    detection = resp.json()

    resp = await authed_client.post("/api/scenarios", json={
        "project_id": project_id,
        "name": "Email intrusion with degraded controls",
        "operation_goal": "Model a successful phishing path under pressure",
        "focus_node_ids": [node["id"]],
        "entry_vectors": ["Phishing"],
        "campaign_phases": ["Initial access", "Execution", "Collection"],
        "success_criteria": ["Stage sensitive files"],
    })
    assert resp.status_code == 201, resp.text
    scenario = resp.json()
    assert scenario["scope"] == "project"

    resp = await authed_client.post(f"/api/scenarios/{scenario['id']}/simulate", json={
        "disabled_controls": [mitigation["id"]],
        "degraded_detections": [detection["id"]],
        "attacker_type": "apt",
        "attacker_skill": "High",
        "attacker_resources": "High",
        "execution_tempo": "rapid",
        "stealth_level": "covert",
        "access_level": "external",
        "focus_node_ids": [node["id"]],
    })
    assert resp.status_code == 200, resp.text
    simulated = resp.json()
    impact = simulated["impact_summary"]
    assert impact["simulation_mode"] == "tree"
    assert impact["simulated_risk"] > impact["original_risk"]
    assert impact["affected_nodes"] >= 1
    assert impact["focus_nodes_affected"] >= 1
    assert impact["top_exposed_controls"][0]["title"] == "Mailbox detonation"
    assert impact["top_degraded_detections"][0]["title"] == "Suspicious attachment execution"

    resp = await authed_client.get(f"/api/analysis-runs/project/{project_id}")
    assert resp.status_code == 200, resp.text
    runs = resp.json()
    assert runs[0]["tool"] == "scenario"
    assert runs[0]["run_type"] == "planning_pass"
    assert runs[0]["status"] == "completed"
    assert runs[0]["artifact_id"] == scenario["id"]


@pytest.mark.asyncio
async def test_scenario_reference_mappings_round_trip(authed_client: AsyncClient):
    resp = await authed_client.post("/api/scenarios", json={
        "name": "Timing Support Path Scenario",
        "scope": "standalone",
        "scenario_type": "campaign",
        "operation_goal": "Assess abuse of vendor timing and support paths",
        "reference_mappings": [
            {
                "framework": "infra_attack_patterns",
                "ref_id": "IAP-004",
                "ref_name": "Remote Support Tunnel Hijack",
                "confidence": 0.72,
                "rationale": "Vendor support tunnels are central to the scenario.",
                "source": "manual",
            },
            {
                "framework": "attack",
                "ref_id": "T1566",
                "ref_name": "Phishing",
                "confidence": 0.64,
                "rationale": "One plausible initial-access path for operator credential theft.",
                "source": "manual",
            },
        ],
    })
    assert resp.status_code == 201, resp.text
    scenario = resp.json()
    assert len(scenario["reference_mappings"]) == 2
    assert {item["ref_id"] for item in scenario["reference_mappings"]} == {"IAP-004", "T1566"}

    resp = await authed_client.patch(f"/api/scenarios/{scenario['id']}", json={
        "reference_mappings": [
            {
                "framework": "environment_catalog",
                "ref_id": "timing_assurance_pnt_monitoring",
                "ref_name": "GNSS Jamming, Spoofing, and Timing Assurance Monitoring",
                "confidence": 0.66,
                "rationale": "Captures the telecom timing branch in scope.",
                "source": "manual",
            },
            {
                "framework": "environment_catalog",
                "ref_id": "timing_assurance_pnt_monitoring",
                "ref_name": "GNSS Jamming, Spoofing, and Timing Assurance Monitoring",
                "confidence": 0.41,
                "rationale": "Lower-confidence duplicate that should be folded away.",
                "source": "manual",
            },
            {
                "framework": "infra_attack_patterns",
                "ref_id": "IAP-004",
                "ref_name": "Remote Support Tunnel Hijack",
                "confidence": 0.72,
                "rationale": "Vendor support tunnels remain relevant.",
                "source": "manual",
            },
        ],
    })
    assert resp.status_code == 200, resp.text
    updated = resp.json()
    assert len(updated["reference_mappings"]) == 2
    timing_mapping = next(item for item in updated["reference_mappings"] if item["ref_id"] == "timing_assurance_pnt_monitoring")
    assert timing_mapping["confidence"] == 0.66
    assert timing_mapping["rationale"].startswith("Captures the telecom timing")

    resp = await authed_client.get(f"/api/scenarios/{scenario['id']}")
    assert resp.status_code == 200, resp.text
    reloaded = resp.json()
    assert len(reloaded["reference_mappings"]) == 2
    assert {item["ref_id"] for item in reloaded["reference_mappings"]} == {"IAP-004", "timing_assurance_pnt_monitoring"}


@pytest.mark.asyncio
async def test_kill_chain_crud(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Kill Chain Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/kill-chains", json={
        "project_id": project_id,
        "name": "Campaign Plan",
        "description": "Operational timeline",
        "framework": "unified",
    })
    assert resp.status_code == 201, resp.text
    kill_chain = resp.json()
    assert kill_chain["framework"] == "unified"
    assert kill_chain["name"] == "Campaign Plan"

    resp = await authed_client.get(f"/api/kill-chains/project/{project_id}")
    assert resp.status_code == 200
    assert any(item["id"] == kill_chain["id"] for item in resp.json())

    resp = await authed_client.get(f"/api/kill-chains/{kill_chain['id']}")
    assert resp.status_code == 200
    assert resp.json()["id"] == kill_chain["id"]

    resp = await authed_client.patch(f"/api/kill-chains/{kill_chain['id']}", json={
        "framework": "mitre_attck",
        "description": "Updated campaign timeline",
    })
    assert resp.status_code == 200
    assert resp.json()["framework"] == "mitre_attck"
    assert resp.json()["description"] == "Updated campaign timeline"


@pytest.mark.asyncio
async def test_kill_chain_phase_references_round_trip(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Kill Chain Reference Project"})
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "title": "Enumerate exposed services",
        "node_type": "attack_step",
        "attack_surface": "Internet-facing management plane",
    })
    assert resp.status_code == 201, resp.text
    node = resp.json()

    resp = await authed_client.post("/api/kill-chains", json={
        "project_id": project_id,
        "name": "Reference-backed Kill Chain",
        "framework": "mitre_attck",
    })
    assert resp.status_code == 201, resp.text
    kill_chain = resp.json()

    resp = await authed_client.patch(f"/api/kill-chains/{kill_chain['id']}", json={
        "phases": [
            {
                "id": "phase-recon",
                "phase": "Reconnaissance",
                "phase_index": 1,
                "description": "Identify reachable services and management paths before delivery.",
                "mapped_nodes": [
                    {
                        "node_id": node["id"],
                        "technique_id": "T1595",
                        "technique_name": "Active Scanning",
                        "confidence": 0.88,
                    }
                ],
                "references": [
                    {
                        "framework": "attack",
                        "ref_id": "T1595",
                        "ref_name": "Active Scanning",
                        "confidence": 0.88,
                        "rationale": "Primary ATT&CK technique for this phase.",
                        "source": "ai",
                    },
                    {
                        "framework": "infra_attack_patterns",
                        "ref_id": "IAP-001",
                        "ref_name": "Management Interface Exposure and Enumeration",
                        "confidence": 0.71,
                        "rationale": "Supports the management-plane targeting in this phase.",
                        "source": "manual",
                    },
                ],
            }
        ]
    })
    assert resp.status_code == 200, resp.text
    updated = resp.json()
    assert len(updated["phases"]) == 1
    phase = updated["phases"][0]
    assert phase["id"] == "phase-recon"
    assert phase["mapped_nodes"][0]["technique_id"] == "T1595"
    assert {item["ref_id"] for item in phase["references"]} == {"T1595", "IAP-001"}

    resp = await authed_client.get(f"/api/kill-chains/{kill_chain['id']}")
    assert resp.status_code == 200, resp.text
    reloaded = resp.json()
    assert reloaded["phases"][0]["id"] == "phase-recon"
    assert {item["ref_id"] for item in reloaded["phases"][0]["references"]} == {"T1595", "IAP-001"}


@pytest.mark.asyncio
async def test_kill_chain_ai_map_retries_persists_overview_fields_and_canonicalizes(authed_client: AsyncClient, monkeypatch):
    resp = await authed_client.post("/api/projects", json={
        "name": "Kill Chain AI Project",
        "root_objective": "Compromise the enterprise and exfiltrate sensitive records",
        "description": "Environment includes email, VPN, Active Directory, EDR, and core file services.",
    })
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/nodes", json={
        "project_id": project_id,
        "title": "Exploit exposed VPN appliance",
        "node_type": "attack_step",
        "threat_category": "Initial Access",
        "attack_surface": "Remote access",
        "platform": "VPN gateway",
    })
    assert resp.status_code == 201, resp.text
    node = resp.json()

    await _create_active_provider(authed_client)

    resp = await authed_client.post("/api/kill-chains", json={
        "project_id": project_id,
        "name": "Operational Plan",
        "framework": "cyber_kill_chain",
    })
    assert resp.status_code == 201, resp.text
    kill_chain = resp.json()

    overview_attempts = 0
    all_calls: list[str] = []

    async def fake_chat_completion(*args, **kwargs):
        nonlocal overview_attempts
        prompt = args[1][-1]["content"]
        all_calls.append(prompt)

        if "phase_objectives" in prompt and "Campaign Blueprint" not in prompt:
            overview_attempts += 1
            if overview_attempts == 1:
                return {"status": "success", "content": "{}"}
            return {"status": "success", "content": json.dumps(_kill_chain_overview_payload(CKC_PHASES))}

        if '["Reconnaissance"]' in prompt:
            return {"status": "success", "content": json.dumps({"phases": [_kill_chain_phase_payload("Reconnaissance")]})}
        if '["Weaponization"]' in prompt:
            return {"status": "success", "content": json.dumps({"phases": [_kill_chain_phase_payload("Weaponization")]})}
        if '["Delivery"]' in prompt:
            return {"status": "success", "content": json.dumps({"phases": [_kill_chain_phase_payload("Delivery")]})}
        if '["Exploitation"]' in prompt:
            return {"status": "success", "content": json.dumps({"phases": [_kill_chain_phase_payload("Exploitation", node_ids=[node["id"]])]})}
        if '["Installation"]' in prompt:
            return {"status": "success", "content": json.dumps({"phases": [_kill_chain_phase_payload("Installation")]})}
        if '["Command & Control"]' in prompt:
            return {
                "status": "success",
                "content": json.dumps({
                    "phases": [_kill_chain_phase_payload("Command & Control", alias_phase="Command and Control")]
                }),
            }
        if '["Actions on Objectives"]' in prompt:
            return {"status": "success", "content": json.dumps({"phases": [_kill_chain_phase_payload("Actions on Objectives")]})}
        return {
            "status": "success",
            "content": json.dumps(_kill_chain_synthesis_payload()),
        }

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)

    resp = await authed_client.post(f"/api/kill-chains/{kill_chain['id']}/ai-map", json={})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert overview_attempts == 2
    assert len(all_calls) >= len(CKC_PHASES) + 3
    assert [phase["phase"] for phase in body["phases"]] == CKC_PHASES
    assert body["overall_risk_rating"] == "high"
    assert body["attack_complexity"] == "high"
    assert body["total_estimated_time"] == "3-7 days"
    assert body["coverage_score"] == pytest.approx(0.62)
    assert body["analysis_metadata"]["generation_strategy"] == "staged"
    assert body["analysis_metadata"]["generation_status"] == "completed"
    assert body["analysis_metadata"]["chunk_count"] == len(CKC_PHASES)
    c2_phase = next(phase for phase in body["phases"] if phase["phase"] == "Command & Control")
    assert c2_phase["description"].startswith("Command")
    exploitation = next(phase for phase in body["phases"] if phase["phase"] == "Exploitation")
    assert exploitation["mapped_nodes"][0]["node_id"] == node["id"]
    assert exploitation["mapped_nodes"][0]["technique_id"] == ""

    resp = await authed_client.get(f"/api/kill-chains/{kill_chain['id']}")
    assert resp.status_code == 200, resp.text
    persisted = resp.json()
    assert persisted["overall_risk_rating"] == "high"
    assert persisted["critical_path"].startswith("Phishing and VPN exploitation")
    assert persisted["coverage_score"] == pytest.approx(0.62)
    assert persisted["analysis_metadata"]["generation_status"] == "completed"

    resp = await authed_client.get(f"/api/kill-chains/project/{project_id}")
    assert resp.status_code == 200, resp.text
    listed = next(item for item in resp.json() if item["id"] == kill_chain["id"])
    assert listed["total_estimated_time"] == "3-7 days"
    assert listed["weakest_links"] == ["Remote access infrastructure lacks strong pre-auth anomaly detection."]

    resp = await authed_client.get(f"/api/analysis-runs/project/{project_id}")
    assert resp.status_code == 200, resp.text
    runs = resp.json()
    assert runs[0]["tool"] == "kill_chain"
    assert runs[0]["run_type"] == "ai_map"
    assert runs[0]["status"] == "completed"
    assert runs[0]["artifact_id"] == kill_chain["id"]


@pytest.mark.asyncio
async def test_kill_chain_ai_map_resumes_partial_checkpoint(authed_client: AsyncClient, monkeypatch):
    resp = await authed_client.post("/api/projects", json={
        "name": "Kill Chain Stability Project",
        "root_objective": "Validate kill chain retry behavior",
    })
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]

    await _create_active_provider(authed_client)

    resp = await authed_client.post("/api/kill-chains", json={
        "project_id": project_id,
        "name": "Stable Plan",
        "framework": "cyber_kill_chain",
    })
    assert resp.status_code == 201, resp.text
    kill_chain = resp.json()

    phase_prompts_seen: list[str] = []
    first_run_counts = {"overview": 0, "recon": 0}

    async def first_run_chat_completion(*args, **kwargs):
        prompt = args[1][-1]["content"]
        phase_prompts_seen.append(prompt)
        if "phase_objectives" in prompt and "Campaign Blueprint" not in prompt:
            first_run_counts["overview"] += 1
            return {"status": "success", "content": json.dumps(_kill_chain_overview_payload(CKC_PHASES))}
        if '["Reconnaissance"]' in prompt:
            first_run_counts["recon"] += 1
            return {"status": "success", "content": json.dumps({"phases": [_kill_chain_phase_payload("Reconnaissance")]})}
        return {"status": "success", "content": "{}"}

    monkeypatch.setattr(llm_service, "chat_completion", first_run_chat_completion)
    resp = await authed_client.post(f"/api/kill-chains/{kill_chain['id']}/ai-map", json={})
    assert resp.status_code == 200, resp.text
    partial = resp.json()
    assert partial["analysis_metadata"]["generation_status"] == "partial"
    assert partial["analysis_metadata"]["pending_chunk_count"] == len(CKC_PHASES) - 1
    assert [phase["phase"] for phase in partial["phases"]] == ["Reconnaissance"]
    assert first_run_counts["overview"] == 1
    assert first_run_counts["recon"] == 1

    second_run_counts = {"overview": 0, "recon": 0, "synthesis": 0}

    async def second_run_chat_completion(*args, **kwargs):
        prompt = args[1][-1]["content"]
        if "phase_objectives" in prompt and "Campaign Blueprint" not in prompt:
            second_run_counts["overview"] += 1
            return {"status": "success", "content": json.dumps(_kill_chain_overview_payload(CKC_PHASES))}
        if '["Reconnaissance"]' in prompt:
            second_run_counts["recon"] += 1
            return {"status": "success", "content": json.dumps({"phases": [_kill_chain_phase_payload("Reconnaissance")]})}
        if '["Weaponization"]' in prompt:
            return {"status": "success", "content": json.dumps({"phases": [_kill_chain_phase_payload("Weaponization")]})}
        if '["Delivery"]' in prompt:
            return {"status": "success", "content": json.dumps({"phases": [_kill_chain_phase_payload("Delivery")]})}
        if '["Exploitation"]' in prompt:
            return {"status": "success", "content": json.dumps({"phases": [_kill_chain_phase_payload("Exploitation")]})}
        if '["Installation"]' in prompt:
            return {"status": "success", "content": json.dumps({"phases": [_kill_chain_phase_payload("Installation")]})}
        if '["Command & Control"]' in prompt:
            return {"status": "success", "content": json.dumps({"phases": [_kill_chain_phase_payload("Command & Control")]})}
        if '["Actions on Objectives"]' in prompt:
            return {"status": "success", "content": json.dumps({"phases": [_kill_chain_phase_payload("Actions on Objectives")]})}
        second_run_counts["synthesis"] += 1
        return {
            "status": "success",
            "content": json.dumps(_kill_chain_synthesis_payload(
                risk="medium",
                complexity="medium",
                coverage=0.5,
                critical_path="Identity abuse leads to lateral movement and then data collection.",
                weakest_links=["Credential hygiene remains inconsistent on remote admin paths."],
            )),
        }

    monkeypatch.setattr(llm_service, "chat_completion", second_run_chat_completion)
    resp = await authed_client.post(f"/api/kill-chains/{kill_chain['id']}/ai-map", json={})
    assert resp.status_code == 200, resp.text

    resp = await authed_client.get(f"/api/kill-chains/{kill_chain['id']}")
    assert resp.status_code == 200, resp.text
    persisted = resp.json()
    assert persisted["overall_risk_rating"] == "medium"
    assert persisted["coverage_score"] == pytest.approx(0.5)
    assert persisted["critical_path"] == "Identity abuse leads to lateral movement and then data collection."
    assert persisted["analysis_metadata"]["generation_status"] == "completed"
    assert len(persisted["phases"]) == len(CKC_PHASES)
    assert second_run_counts["overview"] == 0
    assert second_run_counts["recon"] == 0
    assert second_run_counts["synthesis"] == 1


@pytest.mark.asyncio
async def test_kill_chain_ai_generate_cleans_up_failed_placeholder_record(authed_client: AsyncClient, monkeypatch):
    resp = await authed_client.post("/api/projects", json={
        "name": "Kill Chain Generate Failure",
        "root_objective": "Ensure failed generation does not leave empty records",
    })
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]

    await _create_active_provider(authed_client)

    async def invalid_chat_completion(*args, **kwargs):
        return {"status": "success", "content": "{}"}

    monkeypatch.setattr(llm_service, "chat_completion", invalid_chat_completion)

    resp = await authed_client.post(f"/api/kill-chains/project/{project_id}/ai-generate", json={})
    assert resp.status_code == 502, resp.text

    resp = await authed_client.get(f"/api/kill-chains/project/{project_id}")
    assert resp.status_code == 200, resp.text
    assert resp.json() == []


@pytest.mark.asyncio
async def test_kill_chain_manual_structure_change_clears_stale_ai_analysis(authed_client: AsyncClient, monkeypatch):
    resp = await authed_client.post("/api/projects", json={"name": "Kill Chain Manual Update"})
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]

    await _create_active_provider(authed_client)

    resp = await authed_client.post("/api/kill-chains", json={
        "project_id": project_id,
        "name": "Mutable Plan",
        "framework": "cyber_kill_chain",
    })
    assert resp.status_code == 201, resp.text
    kill_chain = resp.json()

    async def valid_chat_completion(*args, **kwargs):
        prompt = args[1][-1]["content"]
        if "phase_objectives" in prompt and "Campaign Blueprint" not in prompt:
            return {"status": "success", "content": json.dumps(_kill_chain_overview_payload(CKC_PHASES))}
        for phase_name in CKC_PHASES:
            compact_phase_token = f'["{phase_name}"]'
            if compact_phase_token in prompt:
                return {"status": "success", "content": json.dumps({"phases": [_kill_chain_phase_payload(phase_name)]})}
        return {
            "status": "success",
            "content": json.dumps(_kill_chain_synthesis_payload(
                risk="high",
                complexity="medium",
                coverage=0.4,
                critical_path="Delivery through exploitation leads into installation and then objectives.",
            )),
        }

    monkeypatch.setattr(llm_service, "chat_completion", valid_chat_completion)
    resp = await authed_client.post(f"/api/kill-chains/{kill_chain['id']}/ai-map", json={})
    assert resp.status_code == 200, resp.text
    assert resp.json()["overall_risk_rating"] == "high"

    resp = await authed_client.patch(f"/api/kill-chains/{kill_chain['id']}", json={
        "framework": "mitre_attck",
        "phases": [{"phase": "Reconnaissance", "phase_index": 1, "description": "Manual placeholder"}],
    })
    assert resp.status_code == 200, resp.text
    updated = resp.json()
    assert updated["framework"] == "mitre_attck"
    assert len(updated["phases"]) == 1
    assert updated["phases"][0]["id"] == "phase-1"
    assert updated["phases"][0]["phase"] == "Reconnaissance"
    assert updated["phases"][0]["phase_index"] == 1
    assert updated["phases"][0]["description"] == "Manual placeholder"
    assert updated["phases"][0]["references"] == []
    assert updated["ai_summary"] == ""
    assert updated["recommendations"] == []
    assert updated["overall_risk_rating"] == ""
    assert updated["coverage_score"] == 0


@pytest.mark.asyncio
async def test_threat_model_crud(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Threat Model Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "Web App STRIDE",
        "scope": "Internet-facing web app with API and database",
        "methodology": "stride",
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()
    assert threat_model["name"] == "Web App STRIDE"
    assert threat_model["methodology"] == "stride"

    resp = await authed_client.get(f"/api/threat-models/project/{project_id}")
    assert resp.status_code == 200
    assert any(item["id"] == threat_model["id"] for item in resp.json())

    resp = await authed_client.get(f"/api/threat-models/{threat_model['id']}")
    assert resp.status_code == 200
    assert resp.json()["scope"] == "Internet-facing web app with API and database"

    resp = await authed_client.patch(f"/api/threat-models/{threat_model['id']}", json={
        "scope": "Updated scope",
        "components": [{"id": "comp-1", "name": "Frontend", "type": "process"}],
        "trust_boundaries": [{"id": "tb-1", "name": "DMZ", "component_ids": ["comp-1"]}],
    })
    assert resp.status_code == 200
    assert resp.json()["scope"] == "Updated scope"
    assert len(resp.json()["components"]) == 1
    assert len(resp.json()["trust_boundaries"]) == 1


@pytest.mark.asyncio
async def test_threat_model_references_round_trip(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Threat Reference Project"})
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "Reference-backed Threat Model",
        "scope": "Internet-facing platform with admin APIs",
        "methodology": "stride",
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()

    resp = await authed_client.patch(f"/api/threat-models/{threat_model['id']}", json={
        "components": [{"id": "comp-1", "name": "Admin API", "type": "service"}],
        "trust_boundaries": [{"id": "tb-1", "name": "External Boundary", "component_ids": ["comp-1"]}],
        "threats": [
            {
                "id": "threat-1",
                "component_id": "comp-1",
                "category": "Spoofing",
                "title": "Abuse trusted admin access path",
                "description": "Compromise or misuse a trusted ingress into the admin API.",
                "severity": "high",
                "references": [
                    {
                        "framework": "attack",
                        "ref_id": "T1078",
                        "ref_name": "Valid Accounts",
                        "confidence": 0.83,
                        "rationale": "Trusted credential abuse is central to the threat.",
                        "source": "manual",
                    },
                    {
                        "framework": "infra_attack_patterns",
                        "ref_id": "IAP-004",
                        "ref_name": "Remote Support Tunnel Hijack",
                        "confidence": 0.69,
                        "rationale": "Mirrors abuse of trusted remote access paths.",
                        "source": "manual",
                    },
                ],
            }
        ],
    })
    assert resp.status_code == 200, resp.text
    updated = resp.json()
    assert len(updated["threats"]) == 1
    threat = updated["threats"][0]
    assert threat["component_name"] == "Admin API"
    assert {item["ref_id"] for item in threat["references"]} == {"T1078", "IAP-004"}

    resp = await authed_client.get(f"/api/threat-models/{threat_model['id']}")
    assert resp.status_code == 200, resp.text
    reloaded = resp.json()
    assert {item["ref_id"] for item in reloaded["threats"][0]["references"]} == {"T1078", "IAP-004"}


@pytest.mark.asyncio
async def test_threat_model_update_clears_stale_threats_when_structure_changes(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Threat Update Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "Manual DFD Model",
        "scope": "Initial scope",
        "methodology": "stride",
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()

    resp = await authed_client.patch(f"/api/threat-models/{threat_model['id']}", json={
        "threats": [{"id": "threat-old", "title": "Stale threat", "category": "Spoofing", "severity": "high"}],
    })
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["threats"]) == 1

    resp = await authed_client.patch(f"/api/threat-models/{threat_model['id']}", json={
        "components": [{"id": "comp-1", "name": "Gateway", "type": "service"}],
        "data_flows": [],
        "trust_boundaries": [{"id": "tb-1", "name": "DMZ", "component_ids": ["comp-1"]}],
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["threats"] == []
    assert resp.json()["ai_summary"] == ""


@pytest.mark.asyncio
async def test_threat_model_link_to_tree_is_idempotent_and_skips_existing_links(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Threat Link Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "Threat Link Model",
        "scope": "Operator access and remote administration",
        "methodology": "stride",
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()

    resp = await authed_client.patch(f"/api/threat-models/{threat_model['id']}", json={
        "threats": [
            {
                "id": "threat-1",
                "component_id": "comp-edge",
                "component_name": "VPN Gateway",
                "category": "Spoofing",
                "title": "Gateway credential abuse",
                "description": "Replay harvested remote-access credentials.",
                "severity": "high",
                "attack_vector": "Replay valid remote-access credentials.",
                "mitigation": "Require phishing-resistant MFA.",
                "likelihood": 8,
                "impact": 7,
            },
            {
                "id": "threat-2",
                "component_id": "comp-admin",
                "component_name": "Admin Console",
                "category": "Tampering",
                "title": "Unauthorized admin workflow changes",
                "description": "Modify trusted admin workflows after foothold.",
                "severity": "medium",
                "attack_vector": "Abuse weak session controls.",
                "mitigation": "Record privileged sessions and approve changes.",
                "likelihood": 6,
                "impact": 7,
            },
        ],
    })
    assert resp.status_code == 200, resp.text

    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/link-to-tree", json={})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["created"] == 2
    assert body["skipped"] == 0
    assert set(body["created_threat_ids"]) == {"threat-1", "threat-2"}

    resp = await authed_client.get(f"/api/nodes/project/{project_id}")
    assert resp.status_code == 200, resp.text
    initial_node_ids = {node["id"] for node in resp.json()}
    assert len(initial_node_ids) == 2

    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/link-to-tree", json={})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["created"] == 0
    assert body["skipped"] == 2
    assert body["node_ids"] == []
    assert set(body["skipped_threat_ids"]) == {"threat-1", "threat-2"}

    resp = await authed_client.get(f"/api/nodes/project/{project_id}")
    assert resp.status_code == 200, resp.text
    assert {node["id"] for node in resp.json()} == initial_node_ids

    resp = await authed_client.get(f"/api/threat-models/{threat_model['id']}")
    assert resp.status_code == 200, resp.text
    linked_ids = {threat["linked_node_id"] for threat in resp.json()["threats"]}
    assert linked_ids == initial_node_ids


@pytest.mark.asyncio
async def test_threat_model_link_to_tree_recreates_stale_linked_node(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Threat Relink Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "Threat Relink Model",
        "scope": "Support ingress to admin tooling",
        "methodology": "stride",
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()

    resp = await authed_client.patch(f"/api/threat-models/{threat_model['id']}", json={
        "threats": [
            {
                "id": "threat-1",
                "component_id": "comp-edge",
                "component_name": "Support Gateway",
                "category": "Spoofing",
                "title": "Support credential abuse",
                "description": "Reuse weakly protected support credentials.",
                "severity": "high",
                "attack_vector": "Replay support credentials from a prior breach.",
                "mitigation": "Rotate credentials and enforce hardware-backed MFA.",
                "likelihood": 8,
                "impact": 8,
            }
        ],
    })
    assert resp.status_code == 200, resp.text

    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/link-to-tree", json={})
    assert resp.status_code == 200, resp.text
    first_node_id = resp.json()["node_ids"][0]

    resp = await authed_client.delete(f"/api/nodes/{first_node_id}")
    assert resp.status_code == 204, resp.text

    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/link-to-tree", json={})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["created"] == 1
    assert body["skipped"] == 0
    assert body["created_threat_ids"] == ["threat-1"]
    assert body["node_ids"][0] != first_node_id

    resp = await authed_client.get(f"/api/nodes/project/{project_id}")
    assert resp.status_code == 200, resp.text
    nodes = resp.json()
    assert len(nodes) == 1
    assert nodes[0]["id"] == body["node_ids"][0]

    resp = await authed_client.get(f"/api/threat-models/{threat_model['id']}")
    assert resp.status_code == 200, resp.text
    assert resp.json()["threats"][0]["linked_node_id"] == body["node_ids"][0]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("methodology", "category_input", "expected_category"),
    [
        ("stride", "dos", "Denial of Service"),
        ("linddun", "non compliance", "Non-compliance"),
    ],
)
async def test_threat_model_update_normalizes_methodology_categories(
    authed_client: AsyncClient,
    methodology: str,
    category_input: str,
    expected_category: str,
):
    resp = await authed_client.post("/api/projects", json={"name": f"{methodology} Category Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": f"{methodology.upper()} Category Model",
        "scope": "Threat category normalization coverage",
        "methodology": methodology,
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()

    resp = await authed_client.patch(f"/api/threat-models/{threat_model['id']}", json={
        "threats": [
            {
                "id": "threat-1",
                "component_id": "target-1",
                "component_name": "Test Target",
                "category": category_input,
                "title": "Category normalization check",
                "description": "Ensure non-canonical categories are stored canonically.",
                "severity": "high",
                "attack_vector": "Exercise normalization path.",
                "mitigation": "Not relevant for this test.",
                "likelihood": 5,
                "impact": 6,
            }
        ],
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["threats"][0]["category"] == expected_category

    resp = await authed_client.get(f"/api/threat-models/{threat_model['id']}")
    assert resp.status_code == 200, resp.text
    assert resp.json()["threats"][0]["category"] == expected_category


@pytest.mark.asyncio
async def test_threat_model_update_normalizes_pasta_stage_and_preserves_technical_category(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "PASTA Stage Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "PASTA Stage Model",
        "scope": "Threat stage normalization coverage",
        "methodology": "pasta",
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()

    resp = await authed_client.patch(f"/api/threat-models/{threat_model['id']}", json={
        "threats": [
            {
                "id": "threat-1",
                "component_id": "target-1",
                "component_name": "Test Target",
                "category": "risk",
                "technical_category": "Credential abuse",
                "title": "PASTA stage normalization check",
                "description": "Ensure legacy stage values map into pasta_stage while preserving the technical category.",
                "severity": "high",
                "attack_vector": "Exercise PASTA normalization path.",
                "mitigation": "Not relevant for this test.",
                "likelihood": 5,
                "impact": 6,
            }
        ],
    })
    assert resp.status_code == 200, resp.text
    threat = resp.json()["threats"][0]
    assert threat["pasta_stage"] == "Risk Analysis"
    assert threat["category"] == "Credential abuse"

    resp = await authed_client.get(f"/api/threat-models/{threat_model['id']}")
    assert resp.status_code == 200, resp.text
    threat = resp.json()["threats"][0]
    assert threat["pasta_stage"] == "Risk Analysis"
    assert threat["category"] == "Credential abuse"


@pytest.mark.asyncio
async def test_threat_model_update_rejects_pasta_threats_without_stage(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "PASTA Validation Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "PASTA Validation Model",
        "scope": "Threat stage validation coverage",
        "methodology": "pasta",
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()

    resp = await authed_client.patch(f"/api/threat-models/{threat_model['id']}", json={
        "threats": [
            {
                "id": "threat-1",
                "component_id": "target-1",
                "component_name": "Test Target",
                "category": "Credential abuse",
                "title": "PASTA validation check",
                "description": "Reject PASTA threats that do not identify a canonical stage.",
                "severity": "high",
                "attack_vector": "Exercise PASTA validation path.",
                "mitigation": "Not relevant for this test.",
                "likelihood": 5,
                "impact": 6,
            }
        ],
    })
    assert resp.status_code == 422, resp.text
    assert "PASTA stage labels" in resp.text


@pytest.mark.asyncio
async def test_threat_model_update_normalizes_flow_targeted_threats(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Flow Threat Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "Flow Threat Model",
        "scope": "Remote engineering path to operator systems",
        "methodology": "stride",
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()

    resp = await authed_client.patch(f"/api/threat-models/{threat_model['id']}", json={
        "components": [
            {"id": "comp-edge", "name": "Gateway", "type": "service"},
            {"id": "comp-hmi", "name": "HMI", "type": "process"},
        ],
        "data_flows": [
            {
                "id": "flow-1",
                "source": "comp-edge",
                "target": "comp-hmi",
                "label": "Engineering session",
                "protocol": "RDP",
                "data_classification": "restricted",
            }
        ],
        "threats": [
            {
                "id": "threat-flow",
                "component_id": "flow-1",
                "category": "tamper",
                "title": "Session hijack on engineering flow",
                "description": "Abuse the engineering channel to alter operator traffic.",
                "severity": "high",
                "attack_vector": "Proxy and manipulate the engineering session.",
                "mitigation": "Record and isolate engineering sessions.",
                "likelihood": 6,
                "impact": 9,
            }
        ],
    })
    assert resp.status_code == 200, resp.text
    threat = resp.json()["threats"][0]
    assert threat["category"] == "Tampering"
    assert threat["target_type"] == "data_flow"
    assert threat["component_name"] == "Engineering session (Gateway -> HMI)"
    assert threat["risk_score"] == 54


@pytest.mark.asyncio
async def test_threat_model_ai_generate_dfd_replaces_stale_analysis(authed_client: AsyncClient, monkeypatch):
    await _create_active_provider(authed_client, name="Threat Model Provider")

    resp = await authed_client.post("/api/projects", json={"name": "Threat Model Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "Refinery STRIDE",
        "scope": "Legacy scope",
        "methodology": "stride",
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()

    resp = await authed_client.patch(f"/api/threat-models/{threat_model['id']}", json={
        "threats": [{"id": "threat-old", "title": "Stale threat", "category": "Spoofing", "severity": "high"}],
    })
    assert resp.status_code == 200, resp.text

    responses = iter([
        {
            "status": "success",
            "content": json.dumps({
                "summary": "The refinery is split between vendor ingress and the control environment.",
                "zones": [
                    {
                        "id": "zone-vendor-access",
                        "name": "Vendor Access",
                        "description": "Remote support entry points and vendor identity trust",
                        "focus_areas": ["Remote support", "Vendor identity"],
                        "component_hints": ["VPN gateway", "Support jump host"],
                        "trust_boundary_name": "Vendor Access",
                    }
                ],
                "cross_zone_paths": [],
            }),
        },
        {
            "status": "success",
            "content": json.dumps({
                "components": [
                    {
                        "id": "local-vpn",
                        "type": "service",
                        "name": "Vendor VPN Gateway",
                        "description": "Remote support ingress used by refinery vendors",
                        "technology": "IPsec concentrator",
                        "x": 120,
                        "y": 140,
                        "attack_surface": "Internet-facing VPN portal with contractor authentication",
                    },
                    {
                        "id": "local-jump",
                        "type": "process",
                        "name": "Support Jump Host",
                        "description": "Broker for remote engineering sessions into plant systems",
                        "technology": "Windows Server",
                        "x": 360,
                        "y": 180,
                        "attack_surface": "Privileged remote administration and file transfer tooling",
                    },
                ],
                "data_flows": [
                    {
                        "id": "flow-1",
                        "source": "local-vpn",
                        "target": "local-jump",
                        "label": "Remote engineering session",
                        "data_classification": "restricted",
                        "protocol": "RDP",
                        "authentication": "Password + OTP",
                    }
                ],
            }),
        },
    ])

    async def fake_chat_completion(*args, **kwargs):
        return next(responses)

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)

    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/ai-generate-dfd", json={
        "system_description": "Oil refinery with vendor remote access and operator HMIs",
        "user_guidance": "Focus on privileged ingress and process control pathways",
        "planning_profile": "planning_first",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["scope"] == "Oil refinery with vendor remote access and operator HMIs"
    assert body["components"][0]["description"] == "Remote support ingress used by refinery vendors"
    assert body["components"][0]["attack_surface"].startswith("Internet-facing VPN portal")
    assert body["threats"] == []
    assert body["ai_summary"] == ""
    assert body["dfd_metadata"]["generation_strategy"] == "staged"
    assert body["dfd_metadata"]["generation_status"] == "completed"
    assert body["dfd_metadata"]["zone_count"] == 1
    assert body["analysis_metadata"] == {}
    assert body["deep_dive_cache"] == {}


@pytest.mark.asyncio
async def test_threat_model_ai_generate_dfd_recovers_by_splitting_zone_detail(authed_client: AsyncClient, monkeypatch):
    await _create_active_provider(authed_client, name="DFD Split Provider")

    resp = await authed_client.post("/api/projects", json={"name": "DFD Split Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "DFD Split Model",
        "scope": "Manufacturing environment with multiple operator systems",
        "methodology": "stride",
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()

    call_count = 0

    async def fake_chat_completion(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {
                "status": "success",
                "content": json.dumps({
                    "summary": "The environment is best expressed as a single production zone.",
                    "zones": [
                        {
                            "id": "zone-production",
                            "name": "Production Zone",
                            "description": "Operator workstations, historians, and manufacturing control services",
                            "focus_areas": ["Workstations", "Historians", "Manufacturing control", "Operations data"],
                            "component_hints": ["Engineering workstation", "Historian", "MES", "Cell gateway"],
                            "trust_boundary_name": "Production Zone",
                        }
                    ],
                    "cross_zone_paths": [],
                }),
            }
        if call_count in (2, 3, 4):
            return {"status": "error", "message": "provider timeout on oversized zone"}
        if call_count == 5:
            return {
                "status": "success",
                "content": json.dumps({
                    "components": [
                        {
                            "id": "comp-a",
                            "type": "process",
                            "name": "Engineering Workstation",
                            "description": "Privileged engineering endpoint for plant changes",
                            "attack_surface": "Remote admin utilities and engineering software",
                        },
                        {
                            "id": "comp-b",
                            "type": "database",
                            "name": "Historian",
                            "description": "Operational data store for process telemetry",
                            "attack_surface": "Broad query access and export interfaces",
                        },
                    ],
                    "data_flows": [
                        {
                            "id": "flow-a",
                            "source": "comp-a",
                            "target": "comp-b",
                            "label": "Telemetry review",
                            "data_classification": "restricted",
                            "protocol": "SQL",
                            "authentication": "Domain credentials",
                        }
                    ],
                }),
            }
        return {
            "status": "success",
            "content": json.dumps({
                "components": [
                    {
                        "id": "comp-c",
                        "type": "service",
                        "name": "MES",
                        "description": "Manufacturing execution scheduling and orchestration",
                        "attack_surface": "Operator web console and ERP integration",
                    },
                    {
                        "id": "comp-d",
                        "type": "service",
                        "name": "Robot Cell Gateway",
                        "description": "Gateway into automated production cells",
                        "attack_surface": "Industrial protocol translation and supervisory APIs",
                    },
                ],
                "data_flows": [
                    {
                        "id": "flow-b",
                        "source": "comp-c",
                        "target": "comp-d",
                        "label": "Production dispatch",
                        "data_classification": "internal",
                        "protocol": "OPC UA",
                        "authentication": "Service account",
                    }
                ],
            }),
        }

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)

    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/ai-generate-dfd", json={
        "system_description": "Manufacturing environment with engineering workstations, historian, MES, and robot cell gateways",
        "planning_profile": "planning_first",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert call_count == 6
    assert len(body["components"]) == 4
    assert body["dfd_metadata"]["generation_status"] == "completed"
    assert body["dfd_metadata"]["generation_strategy"] == "staged"
    assert any("retried as smaller segments" in warning for warning in body["dfd_metadata"]["generation_warnings"])


@pytest.mark.asyncio
async def test_threat_model_ai_generate_dfd_resumes_partial_checkpoint_and_blocks_threats(authed_client: AsyncClient, monkeypatch):
    await _create_active_provider(authed_client, name="DFD Resume Provider")

    resp = await authed_client.post("/api/projects", json={"name": "DFD Resume Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "DFD Resume Model",
        "scope": "Airport operations and baggage automation",
        "methodology": "stride",
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()

    call_count = 0

    async def first_run_chat_completion(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {
                "status": "success",
                "content": json.dumps({
                    "summary": "The airport spans terminal operations and baggage automation.",
                    "zones": [
                        {
                            "id": "zone-terminal-ops",
                            "name": "Terminal Operations",
                            "description": "Operator consoles, admin portals, and maintenance workflows",
                            "focus_areas": ["Operations portal", "Maintenance access"],
                            "component_hints": ["Airport Ops Portal"],
                            "trust_boundary_name": "Airport Operations",
                        },
                        {
                            "id": "zone-baggage-automation",
                            "name": "Baggage Automation",
                            "description": "Baggage routing and supervisory control systems",
                            "focus_areas": ["Baggage routing", "Supervisory control"],
                            "component_hints": ["Baggage HMI"],
                            "trust_boundary_name": "Baggage Automation",
                        },
                    ],
                    "cross_zone_paths": [
                        {
                            "source_zone_id": "zone-terminal-ops",
                            "target_zone_id": "zone-baggage-automation",
                            "description": "Operations commands to baggage systems",
                            "protocol_hint": "HTTPS",
                            "data_classification": "restricted",
                            "authentication": "SSO + role-based access",
                        }
                    ],
                }),
            }
        if call_count == 2:
            return {
                "status": "success",
                "content": json.dumps({
                    "components": [
                        {
                            "id": "ops-portal",
                            "type": "web_app",
                            "name": "Airport Ops Portal",
                            "description": "Central portal for airport operations oversight",
                            "attack_surface": "Admin UI, integrations, and reporting exports",
                        }
                    ],
                    "data_flows": [],
                }),
            }
        return {"status": "error", "message": "provider timeout on baggage zone"}

    monkeypatch.setattr(llm_service, "chat_completion", first_run_chat_completion)

    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/ai-generate-dfd", json={
        "system_description": "Airport operations platform linked to baggage automation and vendor maintenance paths",
        "planning_profile": "planning_first",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert call_count > 2
    assert body["dfd_metadata"]["generation_status"] == "partial"
    assert body["dfd_metadata"]["pending_zone_count"] == 1
    assert any(warning.startswith("Unable to generate DFD details for zone") for warning in body["dfd_metadata"]["generation_warnings"])

    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/ai-generate-threats", json={
        "planning_profile": "planning_first",
    })
    assert resp.status_code == 409
    assert "DFD generation is incomplete" in resp.text

    second_run_calls = 0

    async def second_run_chat_completion(*args, **kwargs):
        nonlocal second_run_calls
        second_run_calls += 1
        if second_run_calls == 1:
            return {
                "status": "success",
                "content": json.dumps({
                    "components": [
                        {
                            "id": "baggage-hmi",
                            "type": "process",
                            "name": "Baggage HMI",
                            "description": "Supervisory interface for baggage routing",
                            "attack_surface": "Maintenance sessions and privileged routing changes",
                        }
                    ],
                    "data_flows": [],
                }),
            }
        return {
            "status": "success",
            "content": json.dumps({
                "data_flows": [
                    {
                        "id": "flow-ops-baggage",
                        "source": "comp-terminal-ops-airport-ops-portal-web-app",
                        "target": "comp-baggage-automation-baggage-hmi-process",
                        "label": "Operations commands to baggage systems",
                        "data_classification": "restricted",
                        "protocol": "HTTPS",
                        "authentication": "SSO + role-based access",
                    }
                ]
            }),
        }

    monkeypatch.setattr(llm_service, "chat_completion", second_run_chat_completion)

    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/ai-generate-dfd", json={
        "system_description": "Airport operations platform linked to baggage automation and vendor maintenance paths",
        "planning_profile": "planning_first",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert second_run_calls == 2
    assert body["dfd_metadata"]["generation_status"] == "completed"
    assert body["dfd_metadata"]["pending_zone_count"] == 0
    assert body["dfd_metadata"]["cross_zone_flow_status"] == "completed"
    assert "Resumed DFD generation from previously persisted partial results." in body["dfd_metadata"]["generation_warnings"]
    assert len(body["components"]) == 2
    assert len(body["data_flows"]) == 1


@pytest.mark.asyncio
async def test_threat_model_ai_generate_threats_persists_analysis_metadata_and_target_labels(authed_client: AsyncClient, monkeypatch):
    await _create_active_provider(authed_client, name="Threat Analysis Provider")

    resp = await authed_client.post("/api/projects", json={
        "name": "Threat Analysis Project",
        "context_preset": "oil_refinery",
    })
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "Refinery STRIDE",
        "scope": "Refinery with vendor VPN, process HMIs, and historian flows",
        "methodology": "stride",
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()

    resp = await authed_client.patch(f"/api/threat-models/{threat_model['id']}", json={
        "components": [
            {"id": "comp-edge", "name": "Vendor VPN Gateway", "type": "service", "technology": "IPsec concentrator"},
            {"id": "comp-hmi", "name": "Process HMI", "type": "process", "technology": "Windows 11"},
        ],
        "data_flows": [
            {
                "id": "flow-1",
                "source": "comp-edge",
                "target": "comp-hmi",
                "label": "Remote engineering session",
                "protocol": "RDP",
                "data_classification": "restricted",
                "authentication": "Password + OTP",
            }
        ],
        "trust_boundaries": [
            {"id": "tb-1", "name": "Vendor Access", "component_ids": ["comp-edge"]},
            {"id": "tb-2", "name": "Process Control", "component_ids": ["comp-hmi"]},
        ],
    })
    assert resp.status_code == 200, resp.text

    call_count = 0

    async def fake_chat_completion(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {
                "status": "success",
                "content": json.dumps({
                    "summary": "The refinery is most exposed through vendor ingress and remote engineering trust paths.",
                    "highest_risk_areas": [
                        "Vendor remote access forms the easiest bridge into process-adjacent systems.",
                        "Engineering-session trust allows high-impact tampering once the edge is compromised.",
                    ],
                    "attack_surface_score": 81,
                    "recommended_attack_priorities": [
                        "Abuse contractor identity paths into the VPN edge.",
                        "Pivot into the engineering session to reach the HMI trust boundary.",
                    ],
                }),
            }
        if call_count == 2:
            return {
                "status": "success",
                "content": json.dumps({
                    "threats": [
                        {
                            "id": "threat-1",
                            "component_id": "comp-edge",
                            "category": "Spoofing",
                            "title": "Credential replay against vendor VPN",
                            "description": "An attacker reuses harvested contractor credentials to establish remote ingress.",
                            "severity": "critical",
                            "attack_vector": "Replay valid VPN credentials, bypass weak MFA reset workflow, and land on the management plane.",
                            "prerequisites": "Harvested vendor credentials and knowledge of support windows",
                            "exploitation_complexity": "moderate",
                            "entry_surface": "Internet-facing VPN portal",
                            "trust_boundary": "Vendor Access",
                            "business_impact": "Creates privileged remote access into refinery support networks.",
                            "detection_notes": "Monitor impossible-travel sign-ins and unusual support-window sessions.",
                            "mitigation": "Enforce phishing-resistant MFA and ephemeral vendor access.",
                            "likelihood": 9,
                            "impact": 8,
                            "real_world_examples": "Common contractor-access intrusion pattern in ICS environments",
                            "mitre_technique": "T1078",
                        }
                    ]
                }),
            }
        return {
            "status": "success",
            "content": json.dumps({
                "threats": [
                    {
                        "id": "threat-1",
                        "component_id": "comp-hmi",
                        "category": "Tampering",
                        "title": "Unauthorized operator-session abuse on the HMI",
                        "description": "An attacker leverages trusted remote support to reach the process HMI and issue changes.",
                        "severity": "high",
                        "attack_vector": "Pivot from the VPN appliance into the operator workstation and hijack privileged sessions.",
                        "prerequisites": "Initial foothold on the vendor-access edge",
                        "exploitation_complexity": "high",
                        "entry_surface": "Process HMI remote support path",
                        "trust_boundary": "Process Control",
                        "business_impact": "Enables direct manipulation of refinery operator workflows.",
                        "detection_notes": "Alert on anomalous HMI sessions during maintenance windows.",
                        "mitigation": "Require jump hosts and session recording for HMI access.",
                        "likelihood": 8,
                        "impact": 8,
                        "real_world_examples": "Observed in remote-access to HMI abuse cases",
                    },
                    {
                        "id": "threat-2",
                        "component_id": "flow-1",
                        "category": "Tampering",
                        "title": "Session hijack on engineering channel",
                        "description": "An attacker tampers with remote engineering traffic after gaining a foothold.",
                        "severity": "high",
                        "attack_vector": "Proxy the engineering flow to intercept commands and responses.",
                        "prerequisites": "Initial foothold on the vendor-access edge",
                        "exploitation_complexity": "high",
                        "entry_surface": "Remote engineering session",
                        "trust_boundary": "Vendor Access -> Process Control",
                        "business_impact": "Enables process changes without direct operator action.",
                        "detection_notes": "Baseline engineering sessions and alert on anomalous session chaining.",
                        "mitigation": "Use jump hosts with session recording and protocol isolation.",
                        "likelihood": 7,
                        "impact": 9,
                        "risk_score": 63,
                        "real_world_examples": "Observed in remote-access to HMI abuse cases",
                    },
                ]
            }),
        }

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)

    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/ai-generate-threats", json={
        "user_guidance": "Include defender visibility notes for each abuse path",
        "planning_profile": "planning_first",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert call_count == 3
    assert body["threats"][0]["component_name"] == "Vendor VPN Gateway"
    assert body["threats"][0]["risk_score"] == 72
    assert any(threat["component_name"] == "Remote engineering session (Vendor VPN Gateway -> Process HMI)" and threat["target_type"] == "data_flow" for threat in body["threats"])
    assert len({threat["id"] for threat in body["threats"]}) == len(body["threats"])
    assert body["analysis_metadata"]["attack_surface_score"] == 81
    assert body["analysis_metadata"]["highest_risk_areas"][0].startswith("Vendor remote access")
    assert body["analysis_metadata"]["generation_strategy"] == "chunked"
    assert body["analysis_metadata"]["chunk_count"] == 2
    assert body["analysis_metadata"]["generation_warnings"] == []

    resp = await authed_client.get(f"/api/threat-models/{threat_model['id']}")
    assert resp.status_code == 200, resp.text
    persisted = resp.json()
    assert persisted["analysis_metadata"]["recommended_attack_priorities"][0].startswith("Abuse contractor identity")
    assert persisted["threats"][0]["detection_notes"].startswith("Monitor impossible-travel")


@pytest.mark.asyncio
async def test_threat_model_ai_generate_threats_recovers_by_splitting_failed_chunks(authed_client: AsyncClient, monkeypatch):
    await _create_active_provider(authed_client, name="Threat Split Provider")

    resp = await authed_client.post("/api/projects", json={"name": "Chunk Split Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "Chunk Split Model",
        "scope": "Manufacturing zone with multiple tightly coupled operator systems",
        "methodology": "stride",
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()

    resp = await authed_client.patch(f"/api/threat-models/{threat_model['id']}", json={
        "components": [
            {"id": "comp-1", "name": "Engineering Workstation", "type": "process"},
            {"id": "comp-2", "name": "Historian", "type": "service"},
            {"id": "comp-3", "name": "MES", "type": "service"},
            {"id": "comp-4", "name": "Robot Cell Gateway", "type": "service"},
        ],
        "trust_boundaries": [
            {"id": "tb-1", "name": "Production Zone", "component_ids": ["comp-1", "comp-2", "comp-3", "comp-4"]},
        ],
    })
    assert resp.status_code == 200, resp.text

    call_count = 0

    async def fake_chat_completion(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {
                "status": "success",
                "content": json.dumps({
                    "summary": "The production zone is attractive because trusted engineering systems bridge directly into operations.",
                    "highest_risk_areas": ["Engineering workstation trust inside the production zone"],
                    "attack_surface_score": 74,
                    "recommended_attack_priorities": ["Abuse engineering trust to pivot into supervisory platforms"],
                }),
            }
        if call_count in (2, 3, 4):
            return {"status": "error", "message": "timeout during oversized chunk"}
        if call_count == 5:
            return {
                "status": "success",
                "content": json.dumps({
                    "threats": [
                        {
                            "id": "threat-1",
                            "component_id": "comp-1",
                            "category": "Spoofing",
                            "title": "Abuse engineering credentials",
                            "description": "Compromise engineering trust to access plant systems.",
                            "severity": "high",
                            "attack_vector": "Steal engineering credentials and log on remotely.",
                            "mitigation": "Use phishing-resistant MFA and privileged access workstations.",
                            "likelihood": 8,
                            "impact": 8,
                        },
                        {
                            "id": "threat-2",
                            "component_id": "comp-2",
                            "category": "Information Disclosure",
                            "title": "Historian query abuse",
                            "description": "Extract sensitive operations data from the historian.",
                            "severity": "medium",
                            "attack_vector": "Use trusted credentials to run broad historian exports.",
                            "mitigation": "Constrain historian query roles and alert on bulk export.",
                            "likelihood": 6,
                            "impact": 6,
                        },
                    ]
                }),
            }
        return {
            "status": "success",
            "content": json.dumps({
                "threats": [
                    {
                        "id": "threat-1",
                        "component_id": "comp-3",
                        "category": "Tampering",
                        "title": "MES schedule tampering",
                        "description": "Manipulate manufacturing execution scheduling to disrupt output.",
                        "severity": "high",
                        "attack_vector": "Alter trusted schedule data from an internal foothold.",
                        "mitigation": "Require approval and integrity validation on schedule changes.",
                        "likelihood": 7,
                        "impact": 8,
                    },
                    {
                        "id": "threat-2",
                        "component_id": "comp-4",
                        "category": "Denial of Service",
                        "title": "Gateway overload against robot cell bridge",
                        "description": "Overload or deadlock the robot cell gateway.",
                        "severity": "high",
                        "attack_vector": "Flood the gateway with malformed or excessive supervisory traffic.",
                        "mitigation": "Rate-limit supervisory interfaces and segment robot gateways.",
                        "likelihood": 7,
                        "impact": 7,
                    },
                ]
            }),
        }

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)

    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/ai-generate-threats", json={
        "planning_profile": "planning_first",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert call_count == 6
    assert len(body["threats"]) == 4
    assert any("retried as smaller segments" in warning for warning in body["analysis_metadata"]["generation_warnings"])
    assert body["analysis_metadata"]["chunk_count"] == 1
    assert body["analysis_metadata"]["generation_strategy"] == "chunked"


@pytest.mark.asyncio
async def test_threat_model_ai_generate_threats_resumes_from_partial_checkpoint(authed_client: AsyncClient, monkeypatch):
    await _create_active_provider(authed_client, name="Threat Resume Provider")

    resp = await authed_client.post("/api/projects", json={"name": "Resume Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "Resume Model",
        "scope": "Two isolated environment chunks with one flaky provider response",
        "methodology": "stride",
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()

    resp = await authed_client.patch(f"/api/threat-models/{threat_model['id']}", json={
        "components": [
            {"id": "comp-a", "name": "DMZ Gateway", "type": "service"},
            {"id": "comp-b", "name": "Internal Admin Console", "type": "process"},
        ],
        "trust_boundaries": [
            {"id": "tb-1", "name": "DMZ", "component_ids": ["comp-a"]},
            {"id": "tb-2", "name": "Internal", "component_ids": ["comp-b"]},
        ],
    })
    assert resp.status_code == 200, resp.text

    call_count = 0

    async def first_run_chat_completion(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {
                "status": "success",
                "content": json.dumps({
                    "summary": "The environment is divided into a DMZ edge and an internal admin zone.",
                    "highest_risk_areas": ["DMZ access is easier to reach than the internal admin zone."],
                    "attack_surface_score": 58,
                    "recommended_attack_priorities": ["Abuse the DMZ edge first, then pursue the admin console if reachable."],
                }),
            }
        if call_count == 2:
            return {
                "status": "success",
                "content": json.dumps({
                    "threats": [
                        {
                            "id": "threat-1",
                            "component_id": "comp-a",
                            "category": "Spoofing",
                            "title": "DMZ session abuse",
                            "description": "Abuse exposed edge trust to gain a foothold.",
                            "severity": "high",
                            "attack_vector": "Replay or hijack edge sessions.",
                            "mitigation": "Harden session controls on the DMZ edge.",
                            "likelihood": 7,
                            "impact": 7,
                        }
                    ]
                }),
            }
        return {"status": "error", "message": "provider timeout on comp-b"}

    monkeypatch.setattr(llm_service, "chat_completion", first_run_chat_completion)

    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/ai-generate-threats", json={
        "planning_profile": "planning_first",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert call_count == 8
    assert len(body["threats"]) == 1
    assert body["analysis_metadata"]["generation_status"] == "partial"
    assert body["analysis_metadata"]["pending_chunk_count"] == 1
    assert any(warning.startswith("Unable to generate threats") for warning in body["analysis_metadata"]["generation_warnings"])

    async def second_run_chat_completion(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return {
            "status": "success",
            "content": json.dumps({
                "threats": [
                    {
                        "id": "threat-1",
                        "component_id": "comp-b",
                        "category": "Elevation of Privilege",
                        "title": "Admin console privilege escalation",
                        "description": "Escalate through the internal admin console after reaching the zone.",
                        "severity": "high",
                        "attack_vector": "Exploit weak console authorization paths.",
                        "mitigation": "Require strong authorization boundaries and approvals.",
                        "likelihood": 8,
                        "impact": 8,
                    }
                ]
            }),
        }

    monkeypatch.setattr(llm_service, "chat_completion", second_run_chat_completion)

    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/ai-generate-threats", json={
        "planning_profile": "planning_first",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert call_count == 9
    assert len(body["threats"]) == 2
    assert body["analysis_metadata"]["generation_status"] == "completed"
    assert body["analysis_metadata"]["chunk_count"] == 2
    assert "Resumed threat generation from previously persisted partial results." in body["analysis_metadata"]["generation_warnings"]
    assert not any(warning.startswith("Unable to generate threats") for warning in body["analysis_metadata"]["generation_warnings"])

@pytest.mark.asyncio
async def test_threat_model_ai_deep_dive_returns_structured_analysis_and_uses_cache(authed_client: AsyncClient, monkeypatch):
    await _create_active_provider(authed_client, name="Threat Deep Dive Provider")

    resp = await authed_client.post("/api/projects", json={"name": "Deep Dive Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "Deep Dive Model",
        "scope": "Airport baggage and operations systems",
        "methodology": "stride",
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()

    resp = await authed_client.patch(f"/api/threat-models/{threat_model['id']}", json={
        "components": [{"id": "comp-1", "name": "Baggage HMI", "type": "process"}],
        "threats": [{
            "id": "threat-1",
            "component_id": "comp-1",
            "category": "Tampering",
            "title": "Unauthorized baggage-routing changes",
            "description": "Abuse baggage HMI access to alter sortation logic",
            "severity": "high",
        }],
    })
    assert resp.status_code == 200, resp.text

    async def fake_chat_completion(*args, **kwargs):
        return {
            "status": "success",
            "content": json.dumps({
                "exploitation_narrative": "Attacker targets an exposed maintenance path, pivots to the HMI, and stages routing changes during low-visibility hours.",
                "attack_chain": [
                    {
                        "step": 1,
                        "phase": "Reconnaissance",
                        "action": "Identify exposed maintenance workflows",
                        "tools": "Shodan, vendor documentation",
                        "output": "Potential ingress paths and default support assumptions",
                        "detection_risk": "low",
                    }
                ],
                "prerequisites": ["Access to support credentials or maintenance VPN"],
                "indicators_of_compromise": ["Unexpected HMI sessions outside operational windows"],
                "evasion_techniques": ["Blend changes with scheduled maintenance"],
                "real_world_examples": ["Similar OT support-path abuse patterns"],
                "risk_rating": {"exploitability": 7, "impact": 8, "overall": 56},
                "pivot_opportunities": ["Move from baggage operations into adjacent airport support systems"],
                "defensive_gaps": ["Limited session recording on engineering access"],
            }),
        }

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)

    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/ai-deep-dive", json={
        "threat_id": "threat-1",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["attack_chain"][0]["phase"] == "Reconnaissance"
    assert body["risk_rating"]["overall"] == 56
    assert body["defensive_gaps"][0].startswith("Limited session recording")

    resp = await authed_client.get(f"/api/threat-models/{threat_model['id']}")
    assert resp.status_code == 200, resp.text
    assert resp.json()["deep_dive_cache"]["threat-1"]["risk_rating"]["overall"] == 56

    async def should_not_run(*args, **kwargs):
        raise AssertionError("cached deep-dive should have been returned without calling the LLM")

    monkeypatch.setattr(llm_service, "chat_completion", should_not_run)
    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/ai-deep-dive", json={
        "threat_id": "threat-1",
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["risk_rating"]["overall"] == 56

    async def refreshed_chat_completion(*args, **kwargs):
        return {
            "status": "success",
            "content": json.dumps({
                "exploitation_narrative": "Refreshed analysis for the same threat.",
                "attack_chain": [
                    {
                        "step": 1,
                        "phase": "Exploitation",
                        "action": "Use refreshed operator-access abuse path",
                        "tools": "RDP",
                        "output": "Updated exploitation path",
                        "detection_risk": "medium",
                    }
                ],
                "prerequisites": ["Updated prerequisite"],
                "indicators_of_compromise": ["Updated IOC"],
                "evasion_techniques": ["Updated evasion"],
                "real_world_examples": ["Updated example"],
                "risk_rating": {"exploitability": 8, "impact": 8, "overall": 64},
                "pivot_opportunities": ["Updated pivot"],
                "defensive_gaps": ["Updated defensive gap"],
            }),
        }

    monkeypatch.setattr(llm_service, "chat_completion", refreshed_chat_completion)
    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/ai-deep-dive", json={
        "threat_id": "threat-1",
        "refresh": True,
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["risk_rating"]["overall"] == 64


@pytest.mark.asyncio
async def test_threat_model_ai_deep_dive_rejects_incomplete_payload_without_caching(authed_client: AsyncClient, monkeypatch):
    await _create_active_provider(authed_client, name="Threat Deep Dive Incomplete Provider")

    resp = await authed_client.post("/api/projects", json={"name": "Deep Dive Incomplete Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/threat-models", json={
        "project_id": project_id,
        "name": "Deep Dive Incomplete Model",
        "scope": "Airport support access and operator systems",
        "methodology": "stride",
    })
    assert resp.status_code == 201, resp.text
    threat_model = resp.json()

    resp = await authed_client.patch(f"/api/threat-models/{threat_model['id']}", json={
        "components": [{"id": "comp-1", "name": "Operations HMI", "type": "process"}],
        "threats": [{
            "id": "threat-1",
            "component_id": "comp-1",
            "category": "Tampering",
            "title": "Unauthorized operations changes",
            "description": "Alter operator workflows through abused maintenance access.",
            "severity": "high",
            "attack_vector": "Exploit weak maintenance segmentation.",
            "mitigation": "Record and approve privileged maintenance sessions.",
            "likelihood": 7,
            "impact": 8,
        }],
    })
    assert resp.status_code == 200, resp.text

    call_count = 0

    async def fake_chat_completion(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return {
            "status": "success",
            "content": json.dumps({
                "exploitation_narrative": "Incomplete payload without an attack chain should be rejected.",
            }),
        }

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)

    resp = await authed_client.post(f"/api/threat-models/{threat_model['id']}/ai-deep-dive", json={
        "threat_id": "threat-1",
    })
    assert resp.status_code == 502
    assert call_count == 3

    resp = await authed_client.get(f"/api/threat-models/{threat_model['id']}")
    assert resp.status_code == 200, resp.text
    assert resp.json()["deep_dive_cache"] == {}


@pytest.mark.asyncio
async def test_full_threat_model_analysis_returns_persisted_overview_fields(authed_client: AsyncClient, monkeypatch):
    await _create_active_provider(authed_client, name="Threat Full Analysis Provider")

    resp = await authed_client.post("/api/projects", json={
        "name": "Full Analysis Project",
        "context_preset": "airport",
    })
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    responses = iter([
        {
            "status": "success",
            "content": json.dumps({
                "summary": "Airport operations rely on a separate baggage automation zone with privileged maintenance paths.",
                "zones": [
                    {
                        "id": "zone-airport-operations",
                        "name": "Airport Operations",
                        "description": "Scheduling, coordination, and operational oversight systems",
                        "focus_areas": ["Operations scheduling", "Administrative workflows"],
                        "component_hints": ["Airport Operations DB"],
                        "trust_boundary_name": "Airport Operations",
                    },
                    {
                        "id": "zone-baggage-automation",
                        "name": "Baggage Automation",
                        "description": "Baggage sortation and maintenance control systems",
                        "focus_areas": ["Baggage routing", "Maintenance access"],
                        "component_hints": ["Baggage HMI"],
                        "trust_boundary_name": "Baggage Automation",
                    },
                ],
                "cross_zone_paths": [
                    {
                        "source_zone_id": "zone-airport-operations",
                        "target_zone_id": "zone-baggage-automation",
                        "description": "Sortation plans",
                        "protocol_hint": "HTTPS",
                        "data_classification": "internal",
                        "authentication": "SSO",
                    }
                ],
            }),
        },
        {
            "status": "success",
            "content": json.dumps({
                "components": [
                    {
                        "id": "comp-ops",
                        "type": "service",
                        "name": "Airport Operations DB",
                        "description": "Core operational scheduling and coordination platform",
                        "x": 160,
                        "y": 180,
                        "attack_surface": "Admin UI, integrations, and reporting exports",
                    }
                ],
                "data_flows": [],
            }),
        },
        {
            "status": "success",
            "content": json.dumps({
                "components": [
                    {
                        "id": "comp-bhs",
                        "type": "process",
                        "name": "Baggage HMI",
                        "description": "Operator interface for baggage sortation control",
                        "x": 420,
                        "y": 200,
                        "attack_surface": "Engineering access and vendor maintenance",
                    }
                ],
                "data_flows": [],
            }),
        },
        {
            "status": "success",
            "content": json.dumps({
                "data_flows": [
                    {
                        "id": "flow-1",
                        "source": "comp-airport-operations-airport-operations-db-service",
                        "target": "comp-baggage-automation-baggage-hmi-process",
                        "label": "Sortation plans",
                        "data_classification": "internal",
                        "protocol": "HTTPS",
                        "authentication": "SSO",
                    }
                ],
            }),
        },
        {
            "status": "success",
            "content": json.dumps({
                "summary": "Airport operations depend on trusted integrations into baggage automation, making maintenance paths decisive.",
                "highest_risk_areas": ["Vendor engineering access into baggage automation"],
                "attack_surface_score": 67,
                "recommended_attack_priorities": ["Validate maintenance-path trust assumptions before deeper automation abuse"],
            }),
        },
        {
            "status": "success",
            "content": json.dumps({
                "threats": [
                    {
                        "id": "threat-1",
                        "component_id": "comp-airport-operations-airport-operations-db-service",
                        "category": "Information Disclosure",
                        "title": "Operations data extraction via admin workflows",
                        "description": "Abuse trusted admin workflows to exfiltrate airport operations data.",
                        "severity": "medium",
                        "attack_vector": "Use admin access to export schedules and routing dependencies.",
                        "prerequisites": "Compromised admin account",
                        "exploitation_complexity": "moderate",
                        "entry_surface": "Admin interface",
                        "trust_boundary": "Airport Operations",
                        "business_impact": "Exposes airport coordination data useful for subsequent disruption.",
                        "detection_notes": "Monitor large exports from admin workflows.",
                        "mitigation": "Limit export permissions and alert on unusual data volume.",
                        "likelihood": 6,
                        "impact": 5,
                    }
                ]
            }),
        },
        {
            "status": "success",
            "content": json.dumps({
                "threats": [
                    {
                        "id": "threat-1",
                        "component_id": "comp-baggage-automation-baggage-hmi-process",
                        "category": "Tampering",
                        "title": "Manipulate baggage routing logic",
                        "description": "Abuse HMI access to alter sortation behavior.",
                        "severity": "high",
                        "attack_vector": "Use maintenance access to push unauthorized route changes.",
                        "prerequisites": "Compromised engineering account",
                        "exploitation_complexity": "moderate",
                        "entry_surface": "Vendor maintenance path",
                        "trust_boundary": "Airport Operations -> Baggage Automation",
                        "business_impact": "Disrupts baggage handling and terminal operations.",
                        "detection_notes": "Alert on HMI change bursts during off-hours.",
                        "mitigation": "Enforce session recording and approval on routing changes.",
                        "likelihood": 8,
                        "impact": 7,
                        "real_world_examples": "Common OT maintenance-path abuse pattern",
                    }
                ]
            }),
        },
    ])

    async def fake_chat_completion(*args, **kwargs):
        return next(responses)

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)

    resp = await authed_client.post(f"/api/threat-models/project/{project_id}/ai-full-analysis", json={
        "system_description": "Airport operations platform linked to baggage automation and vendor maintenance paths",
        "name": "Airport Full Threat Model",
        "methodology": "stride",
        "user_guidance": "Balance operator overview with technical trust-boundary detail",
        "planning_profile": "planning_first",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["components"][0]["attack_surface"] == "Admin UI, integrations, and reporting exports"
    assert body["threats"][0]["component_name"] == "Baggage HMI"
    assert body["analysis_metadata"]["attack_surface_score"] == 67
    assert body["analysis_metadata"]["highest_risk_areas"] == ["Vendor engineering access into baggage automation"]
    assert body["analysis_metadata"]["generation_strategy"] == "chunked"
    assert body["analysis_metadata"]["chunk_count"] == 2

    resp = await authed_client.get(f"/api/analysis-runs/project/{project_id}")
    assert resp.status_code == 200, resp.text
    runs = resp.json()
    run_types = [item["run_type"] for item in runs]
    assert "dfd_generation" in run_types
    assert "threat_generation" in run_types
    assert all(item["tool"] == "threat_model" for item in runs[:2])

@pytest.mark.asyncio
async def test_infra_map_crud_for_project_and_standalone(authed_client: AsyncClient):
    resp = await authed_client.post("/api/projects", json={"name": "Infra Map Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    resp = await authed_client.post("/api/infra-maps", json={
        "project_id": project_id,
        "name": "Project Infra",
        "description": "Mapped project assets",
    })
    assert resp.status_code == 201, resp.text
    infra_map = resp.json()
    assert infra_map["project_id"] == project_id
    assert infra_map["nodes"] == []

    resp = await authed_client.get(f"/api/infra-maps/project/{project_id}")
    assert resp.status_code == 200
    assert any(item["id"] == infra_map["id"] for item in resp.json())

    resp = await authed_client.patch(f"/api/infra-maps/{infra_map['id']}", json={
        "nodes": [
            {"id": "root", "label": "Infrastructure", "category": "infrastructure", "parent_id": None}
        ]
    })
    assert resp.status_code == 200
    assert resp.json()["nodes"][0]["label"] == "Infrastructure"

    resp = await authed_client.post("/api/infra-maps", json={"name": "Standalone Infra"})
    assert resp.status_code == 201, resp.text
    standalone = resp.json()
    assert standalone["project_id"] is None

    resp = await authed_client.get("/api/infra-maps/standalone")
    assert resp.status_code == 200
    assert any(item["id"] == standalone["id"] for item in resp.json())


@pytest.mark.asyncio
async def test_infra_map_create_validates_project_and_update_normalizes_nodes(authed_client: AsyncClient):
    resp = await authed_client.post("/api/infra-maps", json={
        "project_id": "missing-project",
        "name": "Bad map",
    })
    assert resp.status_code == 404

    resp = await authed_client.post("/api/infra-maps", json={"name": "Normalization Test"})
    assert resp.status_code == 201, resp.text
    infra_map = resp.json()

    resp = await authed_client.patch(f"/api/infra-maps/{infra_map['id']}", json={
        "nodes": [
            {"id": "root", "label": "Corp Network", "category": "networking", "parent_id": None, "position_x": "120", "position_y": 84},
            {"id": "duplicate-1", "label": "VPN Gateway", "category": "networking", "parent_id": "root", "icon_hint": "router", "position_x": 260.2, "position_y": "190"},
            {"id": "duplicate-2", "label": "VPN Gateway", "category": "networking", "parent_id": "root", "icon_hint": "not-real", "position_x": "bad"},
            {"id": "orphan", "label": "Detached", "category": "mystery", "parent_id": "missing-parent", "position_x": 999999},
        ]
    })
    assert resp.status_code == 200, resp.text
    nodes = resp.json()["nodes"]
    assert len(nodes) == 3
    root = next(node for node in nodes if node["id"] == "root")
    assert root["position_x"] == 120
    assert root["position_y"] == 84
    vpn_gateway = next(node for node in nodes if node["label"] == "VPN Gateway")
    assert vpn_gateway["icon_hint"] == "router"
    assert vpn_gateway["children_loaded"] is False
    assert vpn_gateway["position_x"] == 260
    assert vpn_gateway["position_y"] == 190
    detached = next(node for node in nodes if node["label"] == "Detached")
    assert detached["category"] == "general"
    assert detached["parent_id"] is None
    assert detached["position_x"] is None


@pytest.mark.asyncio
async def test_infra_map_node_references_round_trip(authed_client: AsyncClient):
    resp = await authed_client.post("/api/infra-maps", json={"name": "Reference-backed Infra Map"})
    assert resp.status_code == 201, resp.text
    infra_map = resp.json()

    resp = await authed_client.patch(f"/api/infra-maps/{infra_map['id']}", json={
        "nodes": [
            {
                "id": "root",
                "label": "Telecom Timing Stack",
                "category": "infrastructure",
                "parent_id": None,
            },
            {
                "id": "timing",
                "label": "Timing Assurance",
                "category": "service",
                "parent_id": "root",
                "references": [
                    {
                        "framework": "environment_catalog",
                        "ref_id": "timing_assurance_pnt_monitoring",
                        "ref_name": "GNSS Jamming, Spoofing, and Timing Assurance Monitoring",
                        "confidence": 0.74,
                        "rationale": "Directly describes the timing assurance branch.",
                        "source": "manual",
                    },
                    {
                        "framework": "environment_catalog",
                        "ref_id": "timing_assurance_pnt_monitoring",
                        "ref_name": "GNSS Jamming, Spoofing, and Timing Assurance Monitoring",
                        "confidence": 0.51,
                        "rationale": "Duplicate that should be folded away.",
                        "source": "manual",
                    },
                    {
                        "framework": "infra_attack_patterns",
                        "ref_id": "IAP-019",
                        "ref_name": "GNSS Jamming and Timing Denial",
                        "confidence": 0.81,
                        "rationale": "Captures the cross-domain timing attack pattern.",
                        "source": "manual",
                    },
                ],
            },
        ]
    })
    assert resp.status_code == 200, resp.text
    updated = resp.json()
    timing_node = next(node for node in updated["nodes"] if node["id"] == "timing")
    assert len(timing_node["references"]) == 2
    timing_catalog_ref = next(item for item in timing_node["references"] if item["framework"] == "environment_catalog")
    assert timing_catalog_ref["confidence"] == 0.74
    assert {item["ref_id"] for item in timing_node["references"]} == {"timing_assurance_pnt_monitoring", "IAP-019"}

    resp = await authed_client.get(f"/api/infra-maps/{infra_map['id']}")
    assert resp.status_code == 200, resp.text
    reloaded = resp.json()
    reloaded_timing = next(node for node in reloaded["nodes"] if node["id"] == "timing")
    assert {item["ref_id"] for item in reloaded_timing["references"]} == {"timing_assurance_pnt_monitoring", "IAP-019"}


@pytest.mark.asyncio
async def test_infra_map_ai_generate_uses_multi_pass_generation_and_branch_fallback(
    authed_client: AsyncClient,
    monkeypatch,
):
    resp = await authed_client.post("/api/projects", json={"name": "Infra AI Project", "context_preset": "airport"})
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]
    await _create_active_provider(authed_client, name="Infra Multi-pass Provider")

    overview_calls = 0
    recorded_prompts: list[str] = []

    async def fake_chat_completion(*args, **kwargs):
        nonlocal overview_calls
        messages = args[1]
        joined = "\n".join(str(message.get("content", "")) for message in messages)
        recorded_prompts.append(joined)

        if "Create the top-level plan for an infrastructure mind map." in joined:
            overview_calls += 1
            if overview_calls == 1:
                return {"status": "success", "content": "{}"}
            return {
                "status": "success",
                "content": json.dumps(_infra_overview_payload("Airport Operations", [
                    ("Compute and Workloads", "hardware"),
                    ("Network and Segmentation", "networking"),
                    ("Monitoring and Security Tooling", "security"),
                ])),
            }

        if '**Branch:** "Network and Segmentation"' in joined and "Return only direct children for this branch." not in joined:
            return {"status": "success", "content": json.dumps({"nodes": []})}

        if '**Branch:** "Network and Segmentation"' in joined and "Return only direct children for this branch." in joined:
            return {
                "status": "success",
                "content": json.dumps(_infra_branch_fallback_payload("Network and Segmentation", "networking")),
            }

        if '**Branch:** "Compute and Workloads"' in joined:
            return {
                "status": "success",
                "content": json.dumps(_infra_branch_payload("BRANCH_1", "Compute and Workloads", "hardware")),
            }

        if '**Branch:** "Monitoring and Security Tooling"' in joined:
            return {
                "status": "success",
                "content": json.dumps(_infra_branch_payload("BRANCH_3", "Monitoring and Security Tooling", "security")),
            }

        return {"status": "error", "message": "Unexpected prompt"}

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)

    resp = await authed_client.post(f"/api/infra-maps/project/{project_id}/ai-generate", json={
        "root_label": "Airport Operations",
        "planning_profile": "balanced",
    })
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["analysis_metadata"]["generation_strategy"] == "multi_pass"
    assert payload["analysis_metadata"]["generation_status"] == "completed"
    assert payload["analysis_metadata"]["branch_count"] == 3
    assert payload["analysis_metadata"]["completed_branch_count"] == 3
    assert any("fell back to direct-child generation" in warning for warning in payload["analysis_metadata"]["generation_warnings"])
    labels = {node["label"] for node in payload["nodes"]}
    assert "Compute and Workloads Core" in labels
    assert "Network and Segmentation Access" in labels
    assert overview_calls == 2
    assert len(recorded_prompts) >= 5

    resp = await authed_client.get(f"/api/analysis-runs/project/{project_id}")
    assert resp.status_code == 200, resp.text
    runs = resp.json()
    assert runs[0]["tool"] == "infra_map"
    assert runs[0]["run_type"] == "map_generation"
    assert runs[0]["status"] == "completed"


@pytest.mark.asyncio
async def test_infra_map_position_updates_preserve_analysis_but_structural_changes_clear_it(
    authed_client: AsyncClient,
    monkeypatch,
):
    resp = await authed_client.post("/api/projects", json={"name": "Infra Edit Project"})
    assert resp.status_code == 201, resp.text
    project_id = resp.json()["id"]
    await _create_active_provider(authed_client, name="Infra Edit Provider")

    async def fake_chat_completion(*args, **kwargs):
        joined = "\n".join(str(message.get("content", "")) for message in args[1])
        if "Create the top-level plan for an infrastructure mind map." in joined:
            return {
                "status": "success",
                "content": json.dumps(_infra_overview_payload("Refinery", [
                    ("Compute and Workloads", "hardware"),
                    ("Network and Segmentation", "networking"),
                    ("Monitoring and Security Tooling", "security"),
                ])),
            }
        if '**Branch:** "Compute and Workloads"' in joined:
            return {"status": "success", "content": json.dumps(_infra_branch_payload("BRANCH_1", "Compute and Workloads", "hardware"))}
        if '**Branch:** "Network and Segmentation"' in joined:
            return {"status": "success", "content": json.dumps(_infra_branch_payload("BRANCH_2", "Network and Segmentation", "networking"))}
        if '**Branch:** "Monitoring and Security Tooling"' in joined:
            return {"status": "success", "content": json.dumps(_infra_branch_payload("BRANCH_3", "Monitoring and Security Tooling", "security"))}
        return {"status": "error", "message": "Unexpected prompt"}

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)

    resp = await authed_client.post(f"/api/infra-maps/project/{project_id}/ai-generate", json={"root_label": "Refinery"})
    assert resp.status_code == 200, resp.text
    infra_map = resp.json()
    assert infra_map["ai_summary"]
    assert infra_map["analysis_metadata"]["generation_strategy"] == "multi_pass"

    movable = next(node for node in infra_map["nodes"] if node["parent_id"] is not None)
    moved_nodes = [
        {
            **node,
            "position_x": 320,
            "position_y": 180,
        } if node["id"] == movable["id"] else node
        for node in infra_map["nodes"]
    ]
    resp = await authed_client.patch(f"/api/infra-maps/{infra_map['id']}", json={"nodes": moved_nodes})
    assert resp.status_code == 200, resp.text
    moved_map = resp.json()
    moved_node = next(node for node in moved_map["nodes"] if node["id"] == movable["id"])
    assert moved_node["position_x"] == 320
    assert moved_node["position_y"] == 180
    assert moved_map["ai_summary"]
    assert moved_map["analysis_metadata"]["generation_strategy"] == "multi_pass"

    root = next(node for node in moved_map["nodes"] if node["parent_id"] is None)
    structural_nodes = [
        *moved_map["nodes"],
        {
            "id": "manual-segment",
            "parent_id": root["id"],
            "label": "New Segment",
            "category": "networking",
            "description": "",
            "icon_hint": "network",
            "children_loaded": False,
            "manually_added": True,
        },
    ]
    resp = await authed_client.patch(f"/api/infra-maps/{infra_map['id']}", json={"nodes": structural_nodes})
    assert resp.status_code == 200, resp.text
    structurally_changed = resp.json()
    assert structurally_changed["ai_summary"] == ""
    assert structurally_changed["analysis_metadata"] == {}


@pytest.mark.asyncio
async def test_infra_map_ai_expand_retries_invalid_json_and_records_generation_metadata(
    authed_client: AsyncClient,
    monkeypatch,
):
    resp = await authed_client.post("/api/infra-maps", json={"name": "Expansion Test"})
    assert resp.status_code == 201, resp.text
    infra_map = resp.json()

    resp = await authed_client.patch(f"/api/infra-maps/{infra_map['id']}", json={
        "nodes": [
            {
                "id": "root",
                "label": "Data Centre",
                "category": "infrastructure",
                "parent_id": None,
                "description": "Primary operations facility.",
            },
            {
                "id": "network",
                "label": "Network and Segmentation",
                "category": "networking",
                "parent_id": "root",
                "description": "Switching, routing, and perimeter controls.",
            },
            {
                "id": "firewalls",
                "label": "Firewalls",
                "category": "security",
                "parent_id": "network",
                "description": "Perimeter and internal enforcement points.",
            },
        ],
    })
    assert resp.status_code == 200, resp.text

    await _create_active_provider(authed_client, name="Infra Expand Provider")

    expand_calls = 0
    recorded_prompts: list[str] = []

    async def fake_chat_completion(*args, **kwargs):
        nonlocal expand_calls
        expand_calls += 1
        messages = args[1]
        recorded_prompts.append("\n".join(str(message.get("content", "")) for message in messages))
        if expand_calls == 1:
            return {"status": "success", "content": "not-json"}
        return {
            "status": "success",
            "content": json.dumps({
                "children": [
                    {
                        "label": "Remote Access",
                        "category": "security",
                        "description": "Administrative remote access paths.",
                        "icon_hint": "lock",
                    },
                    {
                        "label": "Telemetry",
                        "category": "security",
                        "description": "Security monitoring and logging feeds.",
                        "icon_hint": "shield",
                    },
                ],
                "summary": "Expanded the branch with access and telemetry coverage.",
            }),
        }

    monkeypatch.setattr(llm_service, "chat_completion", fake_chat_completion)

    resp = await authed_client.post(f"/api/infra-maps/{infra_map['id']}/ai-expand", json={
        "node_id": "network",
        "planning_profile": "balanced",
    })
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert len(payload["nodes"]) == 5
    assert payload["analysis_metadata"]["last_generation_strategy"] == "branch_expand"
    assert payload["analysis_metadata"]["last_generation_status"] == "completed"
    assert expand_calls == 2
    full_prompt = "\n".join(recorded_prompts)
    assert "**Node path (root → current):** Data Centre → Network and Segmentation" in full_prompt
    assert "**Ancestor branch context:**" in full_prompt
    assert '"label": "Data Centre"' in full_prompt
    assert "**Existing child detail under this branch:**" in full_prompt
    assert "Firewalls" in full_prompt
    assert "Perimeter and internal enforcement points." in full_prompt


@pytest.mark.asyncio
async def test_environment_catalog_reference_endpoints(authed_client: AsyncClient):
    resp = await authed_client.get("/api/references/environment-catalogs")
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["total"] >= 20
    ids = {catalog["id"] for catalog in payload["catalogs"]}
    assert "data_centre" in ids
    assert "telecoms_base_station" in ids
    assert "telecoms_5g_core" in ids
    assert "electrical_substation" in ids
    assert "water_treatment_plant" in ids
    assert "manufacturing_facility" in ids
    assert "defence_manufacturing_plant" in ids
    assert "pharma_manufacturing_plant" in ids
    assert "ev_charging_network" in ids
    assert "airport" in ids
    assert "military_headquarters" in ids
    assert "oil_refinery" in ids
    assert "drilling_rig" in ids
    assert "shipyard_naval_base" in ids
    assert "lng_terminal" in ids
    assert "satellite_ground_station" in ids
    assert "port_maritime_terminal" in ids
    assert "oil_gas_pipeline" in ids
    telecom_summary = next(catalog for catalog in payload["catalogs"] if catalog["id"] == "telecoms_base_station")
    assert any(concept["label"] == "Timing / PNT" for concept in telecom_summary["shared_concepts"])

    resp = await authed_client.get("/api/references/environment-catalogs/data_centre")
    assert resp.status_code == 200, resp.text
    catalog = resp.json()
    assert catalog["name"] == "Data Centre"
    assert catalog["node_count"] >= 20
    labels = {node["label"] for node in catalog["nodes"]}
    assert "People and Trusted Roles" in labels
    assert "OT / BMS / Power / Cooling" in labels
    assert "Doors, Mantraps, Badge Readers, and PACS" in labels
    assert "CCTV Cameras, NVR/VMS, and Guard Monitoring" in labels
    assert "DCIM, Asset Telemetry, and Rack Capacity Platforms" in labels
    assert "BMS Head-End, Supervisors, and Field Controllers" in labels
    assert "CRAH/CRAC, In-Row, Rear-Door, and Chilled-Water Cooling" in labels
    assert "Automation, CMDB, ITSM, and Secrets Management" in labels
    assert "Active Directory, LDAP, SSO, and Federation Services" in labels
    assert "SIEM, Log Pipelines, and Analytics Backends" in labels

    resp = await authed_client.get("/api/references/environment-catalogs/telecoms_base_station")
    assert resp.status_code == 200, resp.text
    telecom_site_catalog = resp.json()
    assert telecom_site_catalog["name"] == "Telecoms Base Station"
    telecom_site_labels = {node["label"] for node in telecom_site_catalog["nodes"]}
    assert "Radio Units, Massive MIMO, Antennas, and RET Control" in telecom_site_labels
    assert "GNSS, PTP, SyncE, and Timing Distribution" in telecom_site_labels
    assert "PTP Grandmasters, Boundary Clocks, and SyncE Distribution" in telecom_site_labels
    assert "OSS, SON, Inventory, and Provisioning Platforms" in telecom_site_labels
    assert "PM Counters, Trace, and Service Assurance Analytics" in telecom_site_labels
    assert "GNSS Jamming, Spoofing, and Timing Assurance Monitoring" in telecom_site_labels
    timing_node = next(node for node in telecom_site_catalog["nodes"] if node["id"] == "timing_sync")
    timing_concepts = {concept["label"] for concept in timing_node["shared_concepts"]}
    timing_related = {catalog["id"] for catalog in timing_node["related_catalogs"]}
    assert "Timing / PNT" in timing_concepts
    assert "Networking / Transport" in timing_concepts
    assert "telecoms_5g_core" in timing_related
    assert "electrical_substation" in timing_related

    resp = await authed_client.get("/api/references/environment-catalogs/telecoms_5g_core")
    assert resp.status_code == 200, resp.text
    telecom_core_catalog = resp.json()
    assert telecom_core_catalog["name"] == "Telecoms 5G Core"
    telecom_core_labels = {node["label"] for node in telecom_core_catalog["nodes"]}
    assert "NSSF, PCF, CHF/OCS, and Policy or Charging Services" in telecom_core_labels
    assert "ePRTC, PTP Grandmasters, Boundary Clocks, and Time Distribution" in telecom_core_labels
    assert "SEPP, IPX, and Roaming Security Functions" in telecom_core_labels
    assert "Signalling Firewalls, Fraud, and Abuse Detection" in telecom_core_labels
    assert "Timing Assurance, Holdover, and PNT Resilience" in telecom_core_labels

    resp = await authed_client.get("/api/references/environment-catalogs/electrical_substation")
    assert resp.status_code == 200, resp.text
    substation_catalog = resp.json()
    assert substation_catalog["name"] == "Electrical Substation"
    assert substation_catalog["top_level_count"] >= 6
    assert any(node["label"] == "Protection, Control, and Automation Systems" for node in substation_catalog["nodes"])

    resp = await authed_client.get("/api/references/environment-catalogs/ev_charging_network")
    assert resp.status_code == 200, resp.text
    ev_catalog = resp.json()
    assert ev_catalog["name"] == "EV Charging Network"
    assert any(node["label"] == "Cloud Platform, Billing, and Identity Systems" for node in ev_catalog["nodes"])

    resp = await authed_client.get("/api/references/environment-catalogs/airport")
    assert resp.status_code == 200, resp.text
    airport_catalog = resp.json()
    assert airport_catalog["name"] == "Airport"
    assert any(node["label"] == "Baggage, Building, Fuel, and Airfield Systems" for node in airport_catalog["nodes"])

    resp = await authed_client.get("/api/references/environment-catalogs/drilling_rig")
    assert resp.status_code == 200, resp.text
    rig_catalog = resp.json()
    assert rig_catalog["name"] == "Drilling Rig"
    assert any(node["label"] == "Drilling Control, BOP, and Process Systems" for node in rig_catalog["nodes"])


@pytest.mark.asyncio
async def test_llm_provider_crud(authed_client: AsyncClient):
    # Create provider with minimal data (same as frontend Add Provider button)
    resp = await authed_client.post("/api/llm/providers", json={
        "name": "New Provider",
        "base_url": "http://localhost:11434/v1",
        "model": "",
    })
    assert resp.status_code == 201, f"Create failed: {resp.text}"
    provider = resp.json()
    assert provider["name"] == "New Provider"
    assert provider["base_url"] == "http://localhost:11434/v1"
    assert provider["has_api_key"] is False
    assert provider["is_active"] is True
    assert provider["tls_verify"] is True
    assert provider["ca_bundle_path"] == ""
    provider_id = provider["id"]

    # List providers
    resp = await authed_client.get("/api/llm/providers")
    assert resp.status_code == 200
    providers = resp.json()
    assert len(providers) >= 1
    assert any(p["id"] == provider_id for p in providers)

    # Update provider
    resp = await authed_client.patch(f"/api/llm/providers/{provider_id}", json={
        "name": "Updated Provider",
        "model": "llama3",
    })
    assert resp.status_code == 200, f"Update failed: {resp.text}"
    assert resp.json()["name"] == "Updated Provider"
    assert resp.json()["model"] == "llama3"

    # Update with API key
    resp = await authed_client.patch(f"/api/llm/providers/{provider_id}", json={
        "api_key": "sk-test-key-12345",
    })
    assert resp.status_code == 200, f"API key update failed: {resp.text}"
    assert resp.json()["has_api_key"] is True

    # Delete provider
    resp = await authed_client.delete(f"/api/llm/providers/{provider_id}")
    assert resp.status_code == 204

    # Verify deletion
    resp = await authed_client.get("/api/llm/providers")
    assert resp.status_code == 200
    assert not any(p["id"] == provider_id for p in resp.json())


@pytest.mark.asyncio
async def test_user_isolation_for_projects_providers_and_standalone_work(client: AsyncClient):
    headers_one = await _signup_or_login(
        client,
        name="User One",
        email="user.one@example.com",
        password="Password!123",
    )
    headers_two = await _signup_or_login(
        client,
        name="User Two",
        email="user.two@example.com",
        password="Password!123",
    )

    resp = await client.post("/api/projects", json={"name": "User One Project"}, headers=headers_one)
    assert resp.status_code == 201, resp.text
    project_one_id = resp.json()["id"]

    resp = await client.post("/api/scenarios", json={"name": "User One Standalone Scenario"}, headers=headers_one)
    assert resp.status_code == 201, resp.text
    scenario_one_id = resp.json()["id"]

    resp = await client.post("/api/llm/providers", json={
        "name": "User One Provider",
        "base_url": "http://localhost:11434/v1",
        "model": "model-one",
    }, headers=headers_one)
    assert resp.status_code == 201, resp.text

    resp = await client.get("/api/projects", headers=headers_two)
    assert resp.status_code == 200
    assert not any(project["id"] == project_one_id for project in resp.json()["projects"])

    resp = await client.get(f"/api/projects/{project_one_id}", headers=headers_two)
    assert resp.status_code == 404

    resp = await client.get("/api/scenarios?scope=standalone", headers=headers_two)
    assert resp.status_code == 200
    assert not any(scenario["id"] == scenario_one_id for scenario in resp.json())

    resp = await client.get("/api/llm/providers", headers=headers_two)
    assert resp.status_code == 200
    assert not any(provider["name"] == "User One Provider" for provider in resp.json())


@pytest.mark.asyncio
async def test_admin_user_management_and_non_admin_restrictions(client: AsyncClient, admin_client: AsyncClient, authed_client: AsyncClient):
    resp = await authed_client.get("/api/auth/users")
    assert resp.status_code == 403

    resp = await admin_client.get("/api/auth/users")
    assert resp.status_code == 200, resp.text
    assert len(resp.json()) >= 2

    resp = await admin_client.post("/api/auth/users", json={
        "name": "Managed User",
        "email": "managed.user@example.com",
        "password": "Initial!123",
        "role": "user",
    })
    assert resp.status_code == 201, resp.text
    managed_user = resp.json()

    resp = await admin_client.patch(f"/api/auth/users/{managed_user['id']}", json={
        "role": "admin",
        "is_active": True,
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["role"] == "admin"

    resp = await admin_client.post(f"/api/auth/users/{managed_user['id']}/reset-password", json={
        "new_password": "Rotated!456",
        "require_reset": True,
    })
    assert resp.status_code == 204, resp.text

    resp = await admin_client.delete(f"/api/auth/users/{managed_user['id']}")
    assert resp.status_code == 204, resp.text

    resp = await client.post("/api/auth/login", json={
        "identifier": "managed.user@example.com",
        "password": "Rotated!456",
    })
    assert resp.status_code == 401


def test_branch_prompt_uses_vulnerability_cards_for_deep_technical_guidance():
    messages = llm_service.build_branch_suggestion_prompt(
        node_data={
            "title": "Investigate parser bug",
            "node_type": "attack_step",
            "description": "Crash occurs while parsing a crafted project file before sandbox handoff.",
            "platform": "Windows desktop client",
            "attack_surface": "Imported project file",
            "extended_metadata": {
                "prompt_profile": "vulnerability_research",
                "research_domain": "file parser reversing",
                "investigation_summary": "Crash reproduced under PageHeap and ASan",
                "vulnerability_cards": [
                    {
                        "title": "Heap overflow in parser",
                        "software_family": "Desktop importer",
                        "affected_component": "Thumbnail parser",
                        "vulnerability_type": "heap overflow",
                        "primitive": "Controlled overwrite with adjacent object influence",
                        "reproduction_steps": "Open crafted file under debugger",
                    }
                ],
            },
            "project_context": {
                "name": "Research Workspace",
                "context_preset": "vulnerability_research",
                "root_objective": "Turn a parser crash into an exploit path",
                "workspace_mode": "standalone_scan",
            },
        },
        tree_context='- [attack_step] Investigate parser bug | surface=Imported project file | platform=Windows desktop client | category=Execution',
        suggestion_type="branches",
    )

    assert len(messages) == 2
    assert "vulnerability researcher" in messages[0]["content"].lower()
    assert "Deep technical requirements:" in messages[1]["content"]
    assert "Vulnerability Cards:" in messages[1]["content"]
    assert "primitive: Controlled overwrite with adjacent object influence" in messages[1]["content"]


def test_brainstorm_prompt_includes_deep_technical_context():
    req = BrainstormRequest(
        provider_id="provider-1",
        project_name="Firmware Research",
        root_objective="Find a remotely reachable exploit path",
        context_preset="embedded_firmware_research",
        workspace_mode="standalone_scan",
        planning_profile="planning_first",
        technical_depth="deep_technical",
        focus_mode="technical_research",
        tree_context="- [attack_step] Analyze update parser | surface=OTA package",
        context_packets=[
            "Top attack surfaces: OTA updater, diagnostic UART, admin web panel",
            "Research hint: parser crash happens before signature failure",
        ],
    )

    prompt = _build_brainstorm_system_prompt(req)
    seed = _build_brainstorm_seed(req)

    assert "Embedded Firmware Research" in prompt
    assert "Planning Profile: Planning-first" in prompt
    assert "Focus Mode: technical_research" in prompt
    assert "Deep technical requirements:" in prompt
    assert "Existing Tree Context:" in prompt
    assert "Top attack surfaces: OTA updater" in prompt
    assert "Attack-surface decomposition guidance:" in prompt
    assert "Open by decomposing the target into major attack-surface domains" in seed
    assert "Use deep technical detail" in seed


def test_planning_profile_helpers_cover_other_ai_workspaces():
    cases = [
        (
            _scenario_planning_context,
            "Disrupt a data centre through management plane and facilities abuse",
            "Facility with remote hands, UPS, chillers, hypervisors, BMCs, and vendor VPN access",
        ),
        (
            _kill_chain_planning_context,
            "Compromise a data centre to exfiltrate customer workloads",
            "Racks, BMC/IPMI, jump hosts, DCIM, remote hands, and supplier access",
        ),
        (
            _threat_model_planning_context,
            "Threat-model a data centre management platform",
            "Platform spans remote hands workflows, hypervisors, BMCs, UPS, cooling, and vendor support channels",
        ),
        (
            _infra_map_planning_context,
            "Map the infrastructure of a data centre",
            "Facility with physical access controls, IT management planes, OT/BMS, and third-party maintenance",
        ),
    ]

    for helper, objective, scope in cases:
        _, label, domain, guidance = helper("planning_first", objective, scope, "data_centre")
        assert label == "Planning-first"
        assert domain == "data_centre"
        assert "People and Trusted Roles" in guidance


def test_detect_domain_prefers_context_preset_and_research_aliases():
    assert llm_service._detect_domain(
        "Model a management-plane intrusion",
        "Target environment is not yet fully described",
        "data_centre",
    ) == "data_centre"
    assert llm_service._detect_domain(
        "Assess helper-service trust boundaries",
        "",
        "software_reverse_engineering",
    ) == "software_research"


def test_agent_prompt_planning_first_uses_data_centre_domain_skeleton():
    messages = llm_service.build_agent_tree_prompt(
        objective="Compromise a data centre to disrupt services and exfiltrate data",
        scope="Facility with racks, hypervisors, BMC/IPMI, remote hands, UPS, chillers, and vendor VPN access",
        depth=4,
        breadth=5,
        generation_profile="planning_first",
        context_preset="data_centre",
    )

    user_prompt = messages[1]["content"]
    assert "Planning-first" in user_prompt
    assert "People and Trusted Roles" in user_prompt
    assert "Physical Infrastructure and Facility Access" in user_prompt
    assert "Information Technology and Management Plane" in user_prompt
    assert "Operational Technology / BMS / Power / Cooling" in user_prompt
    assert "Do not use raw CWE, CAPEC, ATT&CK technique IDs, or CVE identifiers as second-level nodes." in user_prompt
    assert "Environment catalog anchor: Data Centre" in user_prompt
    assert "Doors, Mantraps, Badge Readers, and PACS" in user_prompt
    assert "DCIM, Asset Telemetry, and Rack Capacity Platforms" in user_prompt
    assert "CRAH/CRAC, In-Row, Rear-Door, and Chilled-Water Cooling" in user_prompt
    assert "Automation, CMDB, ITSM, and Secrets Management" in user_prompt
    assert "Detection, Response, and Process Weaknesses (SIEM, EDR/XDR" in user_prompt


def test_find_best_template_prefers_data_centre_context():
    template = llm_service.find_best_template_for_objective(
        objective="Disrupt colocation operations via management plane and facilities abuse",
        scope="Facility with racks, cooling, UPS, BMCs, and remote vendor access",
        context_preset="data_centre",
    )

    assert template is not None
    assert template["context_preset"] == "data_centre"


def test_environment_catalog_outline_detects_data_centre_from_physical_security_and_facility_terms():
    outline = build_environment_catalog_outline_for_context(
        "Assess data-centre facility intrusion and management-plane exposure",
        "Colocation hall with PACS, badge readers, CCTV, NVR, DCIM, CRAC units, chillers, and a BMS head-end",
        "",
    )

    assert "Environment catalog anchor: Data Centre" in outline
    assert "Doors, Mantraps, Badge Readers, and PACS" in outline
    assert "CCTV Cameras, NVR/VMS, and Guard Monitoring" in outline
    assert "DCIM, Asset Telemetry, and Rack Capacity Platforms" in outline


def test_environment_catalog_outline_detects_data_centre_from_software_platform_terms():
    outline = build_environment_catalog_outline_for_context(
        "Assess data-centre control plane compromise",
        "Platform with vCenter, Kubernetes, CyberArk PAM, Veeam backup, ServiceNow change, Ansible automation, and Splunk monitoring",
        "",
    )

    assert "Environment catalog anchor: Data Centre" in outline
    assert "Information Technology and Management Plane" in outline
    assert "Automation, CMDB, ITSM, and Secrets Management" in outline
    assert "Storage, Backup, and Recovery" in outline


@pytest.mark.parametrize(
    ("context_preset", "objective", "scope", "expected_name"),
    [
        (
            "airport",
            "Disrupt airport operations through baggage, terminal, and support-system compromise",
            "Transport hub with baggage automation, operations systems, vendor maintenance, and building services",
            "Port / Maritime Terminal Disruption",
        ),
        (
            "military_headquarters",
            "Compromise command workflows, identities, and internal coordination systems",
            "Headquarters campus with sensitive communications, secure workstations, and coalition access paths",
            "Enterprise Phishing to Domain Compromise",
        ),
        (
            "oil_refinery",
            "Manipulate process control and safety assumptions to create sustained disruption",
            "Refinery with DCS HMIs, SIS layers, contractor access, and product-quality dependencies",
            "OT Process Manipulation",
        ),
        (
            "drilling_rig",
            "Abuse well-control, remote support, and offshore operations dependencies",
            "Rig environment with drill-floor HMIs, BOP controls, satcom, and vendor support paths",
            "Oil & Gas Pipeline SCADA Compromise",
        ),
        (
            "defence_manufacturing_plant",
            "Sabotage secure production and traceability workflows without immediate detection",
            "Industrial defence plant with robotics, test rigs, MES, PLM, and quality-release records",
            "Pharmaceutical Manufacturing Sabotage",
        ),
        (
            "shipyard_naval_base",
            "Disrupt dock operations, maintenance planning, and waterside automation",
            "Dockyard with cranes, dry docks, shore power, partner access, and maintenance systems",
            "Port / Maritime Terminal Disruption",
        ),
    ],
)
def test_find_best_template_uses_environment_preference_hints(
    context_preset: str,
    objective: str,
    scope: str,
    expected_name: str,
):
    template = llm_service.find_best_template_for_objective(
        objective=objective,
        scope=scope,
        context_preset=context_preset,
    )

    assert template is not None
    assert template["name"] == expected_name


def test_environment_catalog_outline_and_prompt_anchor_for_telecoms_site():
    outline = build_environment_catalog_outline_for_context(
        "Disrupt a telecoms base station via OAM and transport compromise",
        "5G gNodeB site with microwave backhaul, DU/CU, batteries, shelter, and vendor remote support",
        "telecoms_base_station",
    )
    assert "Environment catalog anchor: Telecoms Base Station" in outline
    assert "Transport, Networking, and OAM" in outline
    assert "Radio Units, Massive MIMO, Antennas, and RET Control" in outline
    assert "GNSS, PTP, SyncE, and Timing Distribution" in outline
    assert "OSS, SON, Inventory, and Provisioning Platforms" in outline

    messages = llm_service.build_agent_tree_prompt(
        objective="Disrupt a telecoms base station via OAM and transport compromise",
        scope="5G gNodeB site with microwave backhaul, DU/CU, batteries, shelter, and vendor remote support",
        depth=4,
        breadth=5,
        generation_profile="planning_first",
        context_preset="telecoms_base_station",
    )
    assert "Environment catalog anchor: Telecoms Base Station" in messages[1]["content"]
    assert "Cloud-Native Management, OSS/BSS, OAM, and Orchestration Planes" in messages[1]["content"]
    assert "GNSS/PTP Timing" in messages[1]["content"]


def test_environment_catalog_outline_detects_telecom_site_from_ran_terms():
    outline = build_environment_catalog_outline_for_context(
        "Assess a telecom radio site for compromise",
        "Open RAN gNodeB with RU/DU/CU, cell-site gateway, ENM, SON, microwave backhaul, PTP grandmaster, boundary clock, holdover, and GNSS timing",
        "",
    )

    assert "Environment catalog anchor: Telecoms Base Station" in outline
    assert "Transport, Networking, and OAM" in outline
    assert "Radio Access Network Equipment" in outline
    assert "GNSS, PTP, SyncE, and Timing Distribution" in outline


def test_environment_catalog_outline_detects_5g_core_from_signalling_and_service_terms():
    outline = build_environment_catalog_outline_for_context(
        "Assess carrier core exposure",
        "5G core with AMF, UPF, SEPP, NEF, IMS, UDM, HSS, charging mediation, ePRTC, boundary clocks, and timing-assurance analytics",
        "",
    )

    assert "Environment catalog anchor: Telecoms 5G Core" in outline
    assert "5G Core Network Functions and Subscriber Services" in outline
    assert "ePRTC, PTP Grandmasters, Boundary Clocks, and Time Distribution" in outline
    assert "Interconnect, Signalling, and External Interfaces" in outline


@pytest.mark.parametrize(
    ("objective", "scope", "context_preset", "anchor_name", "expected_branch"),
    [
        (
            "Disrupt an electrical substation by manipulating protection and switching",
            "Control house with IEC 61850 relays, breaker panels, utility WAN backhaul, and remote engineering access",
            "electrical_substation",
            "Electrical Substation",
            "Protection, Control, and Automation Systems",
        ),
        (
            "Alter chemical dosing in a water treatment plant",
            "Plant with SCADA HMIs, dosing skids, chlorine storage, municipal remote access, and reservoir telemetry",
            "water_treatment_plant",
            "Water Treatment Plant",
            "SCADA, PLCs, and Process Control",
        ),
        (
            "Infiltrate a telecoms 5G core to access subscriber data",
            "Carrier core with AMF, SMF, UPF, UDM, lawful intercept, API gateways, and roaming interconnects",
            "telecoms_5g_core",
            "Telecoms 5G Core",
            "5G Core Network Functions and Subscriber Services",
        ),
        (
            "Disrupt a port maritime terminal through TOS and crane compromise",
            "Container terminal with TOS, gate automation, AIS/VTS links, ship-to-shore cranes, and vendor remote support",
            "port_maritime_terminal",
            "Port / Maritime Terminal",
            "Cargo-Handling OT and Automation",
        ),
        (
            "Manipulate an oil and gas pipeline compressor station",
            "Pipeline control room with SCADA HMIs, compressor PLCs, ESD systems, RTUs, and leased-line telemetry",
            "oil_gas_pipeline",
            "Oil and Gas Pipeline / Compressor Station",
            "SCADA, PLCs, and Process Control",
        ),
        (
            "Disrupt a manufacturing facility by tampering with production lines and MES workflows",
            "Factory with PLCs, robotics, MES, warehouse automation, vendor remote support, and quality holds",
            "manufacturing_facility",
            "Manufacturing Facility",
            "Industrial Control, Robotics, and Supervisory Systems",
        ),
        (
            "Sabotage pharmaceutical manufacturing by altering batch control and quality systems",
            "Plant with batch control, LIMS, cleanrooms, environmental monitoring, and release workflows",
            "pharma_manufacturing_plant",
            "Pharma Manufacturing Plant",
            "Batch Control, DCS, and Process Automation",
        ),
        (
            "Compromise an EV charging network through charger firmware and cloud platform abuse",
            "Distributed chargers using OCPP, mobile billing, roaming APIs, load balancing, and field maintenance access",
            "ev_charging_network",
            "EV Charging Network",
            "Charger Control, Firmware, and Site Management",
        ),
        (
            "Attack an LNG terminal by manipulating DCS and shutdown logic",
            "Cryogenic tanks, loading arms, DCS, SIS, jetty links, vendor support, and emergency shutdown procedures",
            "lng_terminal",
            "LNG Terminal",
            "DCS, SIS, and Process Control",
        ),
        (
            "Compromise a satellite ground station to abuse TT&C and mission control",
            "Ground segment with antennas, telemetry processors, uplink chains, mission networks, and teleport backhaul",
            "satellite_ground_station",
            "Satellite Ground Station",
            "Mission Control, TT&C, and Payload Support Systems",
        ),
        (
            "Disrupt an airport by abusing baggage automation and airport operations systems",
            "Airport with AODB, FIDS, baggage handling, building automation, airline interfaces, and airside operations",
            "airport",
            "Airport",
            "Baggage, Building, Fuel, and Airfield Systems",
        ),
        (
            "Model compromise of a military headquarters through secure comms and identity abuse",
            "Headquarters with SCIFs, command workstations, secure messaging, cross-domain transfers, and coalition links",
            "military_headquarters",
            "Military Headquarters",
            "Command, Communications, and Mission Support Systems",
        ),
        (
            "Attack an oil refinery by manipulating DCS and safety layers",
            "Refinery with process units, tank farm, DCS HMIs, SIS logic, turnaround contractors, and product-quality systems",
            "oil_refinery",
            "Oil Refinery",
            "DCS, SIS, and Process Control",
        ),
        (
            "Compromise a drilling rig by manipulating well-control and drilling automation",
            "Rig with drill-floor HMIs, BOP controls, mud logging, satcom links, and remote vendor support",
            "drilling_rig",
            "Drilling Rig",
            "Drilling Control, BOP, and Process Systems",
        ),
        (
            "Sabotage a defence manufacturing plant through secure production and traceability abuse",
            "Secure plant with robotics, PLCs, test rigs, PLM, traceability records, and program-security boundaries",
            "defence_manufacturing_plant",
            "Defence Manufacturing Plant",
            "Industrial Control, Robotics, and Test Systems",
        ),
        (
            "Disrupt a shipyard or naval base through dock automation and partner compromise",
            "Naval dockyard with dry docks, cranes, shore power, maintenance work orders, and partner remote access",
            "shipyard_naval_base",
            "Shipyard / Naval Base",
            "Industrial Control, Cranes, and Dock Systems",
        ),
    ],
)
def test_environment_catalog_outline_and_prompt_anchor_for_new_catalogs(
    objective: str,
    scope: str,
    context_preset: str,
    anchor_name: str,
    expected_branch: str,
):
    outline = build_environment_catalog_outline_for_context(objective, scope, context_preset)
    assert f"Environment catalog anchor: {anchor_name}" in outline
    assert expected_branch in outline

    messages = llm_service.build_agent_tree_prompt(
        objective=objective,
        scope=scope,
        depth=4,
        breadth=5,
        generation_profile="planning_first",
        context_preset=context_preset,
    )
    assert f"Environment catalog anchor: {anchor_name}" in messages[1]["content"]


def test_detect_domain_maps_new_environment_presets_to_expected_domains():
    assert llm_service._detect_domain(
        "Assess signalling and subscriber trust boundaries",
        "",
        "telecoms_5g_core",
    ) == "telecommunications"
    assert llm_service._detect_domain(
        "Map recovery dependencies for a transmission substation",
        "",
        "electrical_substation",
    ) == "power_energy"
    assert llm_service._detect_domain(
        "Review chemical dosing and plant safety assumptions",
        "",
        "water_treatment_plant",
    ) == "ot_ics"
    assert llm_service._detect_domain(
        "Model a robotic assembly line intrusion path",
        "",
        "manufacturing_facility",
    ) == "ot_ics"
    assert llm_service._detect_domain(
        "Map command uplink trust boundaries",
        "",
        "satellite_ground_station",
    ) == "telecommunications"
    assert llm_service._detect_domain(
        "Assess baggage and terminal operations trust boundaries",
        "",
        "airport",
    ) == "ot_ics"
    assert llm_service._detect_domain(
        "Review coalition enclave trust and secure command workflows",
        "",
        "military_headquarters",
    ) == "enterprise"
    assert llm_service._detect_domain(
        "Model process-unit and tank-farm manipulation",
        "",
        "oil_refinery",
    ) == "ot_ics"
    assert llm_service._detect_domain(
        "Review well-control and blowout-preventer trust paths",
        "",
        "drilling_rig",
    ) == "ot_ics"
    assert llm_service._detect_domain(
        "Map secure production-line and program-boundary trust paths",
        "",
        "defence_manufacturing_plant",
    ) == "ot_ics"
    assert llm_service._detect_domain(
        "Assess dry-dock and ship-support operational dependencies",
        "",
        "shipyard_naval_base",
    ) == "ot_ics"


def test_infra_map_normalization_deduplicates_and_fills_defaults():
    normalized = _normalize_nodes([
        {"id": "root", "label": "Platform", "category": "software", "parent_id": None},
        {"id": "child-1", "label": "Updater", "category": "service", "parent_id": "root"},
        {"id": "child-2", "label": "Updater", "category": "service", "parent_id": "root", "icon_hint": "not-real"},
        {"id": "child-3", "label": "Telemetry", "category": "unknown", "parent_id": "root"},
    ])

    assert len(normalized) == 3
    platform = next(node for node in normalized if node["id"] == "root")
    assert platform["icon_hint"] == "terminal"
    assert platform["children_loaded"] is True
    telemetry = next(node for node in normalized if node["label"] == "Telemetry")
    assert telemetry["category"] == "general"
    assert telemetry["icon_hint"] == "cog"
