"""Integration tests for the API endpoints."""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import backend.app.database as db_module
import backend.app.main as main_module
from backend.app.main import app
from backend.app.database import Base
from backend.app.api.ai_chat import BrainstormRequest, _build_brainstorm_system_prompt, _build_brainstorm_seed
from backend.app.api.infra_maps import _normalize_nodes
from backend.app.services import llm_service


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
    response = await client.post("/api/auth/signup", json={
        "name": name,
        "email": email,
        "password": password,
    })
    if response.status_code == 409:
        response = await client.post("/api/auth/login", json={
            "identifier": email,
            "password": password,
        })
    assert response.status_code in (200, 201), response.text
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


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
        response = await ac.post("/api/auth/login", json={
            "identifier": "administrator",
            "password": "AdminPass!234",
        })
        assert response.status_code == 200, response.text
        ac.headers.update({"Authorization": f"Bearer {response.json()['access_token']}"})
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
async def test_reference_browsing(authed_client: AsyncClient):
    resp = await authed_client.get("/api/references/browse/attack")
    assert resp.status_code == 200
    data = resp.json()
    assert data["framework"] == "attack"
    assert data["count"] > 0

    # Search
    resp = await authed_client.get("/api/references/browse/cwe?q=injection")
    assert resp.status_code == 200
    assert resp.json()["count"] > 0


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
            {"id": "root", "label": "Corp Network", "category": "networking", "parent_id": None},
            {"id": "duplicate-1", "label": "VPN Gateway", "category": "networking", "parent_id": "root", "icon_hint": "router"},
            {"id": "duplicate-2", "label": "VPN Gateway", "category": "networking", "parent_id": "root", "icon_hint": "not-real"},
            {"id": "orphan", "label": "Detached", "category": "mystery", "parent_id": "missing-parent"},
        ]
    })
    assert resp.status_code == 200, resp.text
    nodes = resp.json()["nodes"]
    assert len(nodes) == 3
    vpn_gateway = next(node for node in nodes if node["label"] == "VPN Gateway")
    assert vpn_gateway["icon_hint"] == "router"
    assert vpn_gateway["children_loaded"] is False
    detached = next(node for node in nodes if node["label"] == "Detached")
    assert detached["category"] == "general"
    assert detached["parent_id"] is None


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
    assert len(resp.json()) >= 6

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

    assert "embedded_firmware_research" in prompt
    assert "Focus Mode: technical_research" in prompt
    assert "Deep technical requirements:" in prompt
    assert "Existing Tree Context:" in prompt
    assert "Top attack surfaces: OTA updater" in prompt
    assert "Use deep technical detail" in seed


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
