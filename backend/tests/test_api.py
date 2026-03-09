"""Integration tests for the API endpoints."""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from backend.app.main import app
from backend.app.database import engine, Base


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_health(client: AsyncClient):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_project_crud(client: AsyncClient):
    # Create
    resp = await client.post("/api/projects", json={
        "name": "Test Project",
        "description": "A test",
        "context_preset": "web_application",
        "root_objective": "Test objective",
    })
    assert resp.status_code == 201
    project = resp.json()
    assert project["name"] == "Test Project"
    project_id = project["id"]

    # List
    resp = await client.get("/api/projects")
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1

    # Update
    resp = await client.patch(f"/api/projects/{project_id}", json={"name": "Updated"})
    assert resp.status_code == 200
    assert resp.json()["name"] == "Updated"

    # Delete
    resp = await client.delete(f"/api/projects/{project_id}")
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_node_crud(client: AsyncClient):
    # Create project first
    resp = await client.post("/api/projects", json={"name": "Node Test"})
    project_id = resp.json()["id"]

    # Create root node
    resp = await client.post("/api/nodes", json={
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
    resp = await client.post("/api/nodes", json={
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
    resp = await client.get(f"/api/nodes/project/{project_id}")
    assert resp.status_code == 200
    assert len(resp.json()) == 2

    # Update node
    resp = await client.patch(f"/api/nodes/{child['id']}", json={"title": "SQL Injection (Updated)"})
    assert resp.status_code == 200
    assert resp.json()["title"] == "SQL Injection (Updated)"

    # Duplicate
    resp = await client.post(f"/api/nodes/{child['id']}/duplicate")
    assert resp.status_code == 201
    assert "copy" in resp.json()["title"]


@pytest.mark.asyncio
async def test_mitigation_creation(client: AsyncClient):
    # Setup
    resp = await client.post("/api/projects", json={"name": "Mit Test"})
    project_id = resp.json()["id"]
    resp = await client.post("/api/nodes", json={
        "project_id": project_id, "title": "Step", "likelihood": 7, "impact": 8,
    })
    node_id = resp.json()["id"]

    # Create mitigation
    resp = await client.post("/api/mitigations", json={
        "node_id": node_id, "title": "WAF", "effectiveness": 0.6,
    })
    assert resp.status_code == 201
    assert resp.json()["title"] == "WAF"


@pytest.mark.asyncio
async def test_reference_browsing(client: AsyncClient):
    resp = await client.get("/api/references/browse/attack")
    assert resp.status_code == 200
    data = resp.json()
    assert data["framework"] == "attack"
    assert data["count"] > 0

    # Search
    resp = await client.get("/api/references/browse/cwe?q=injection")
    assert resp.status_code == 200
    assert resp.json()["count"] > 0


@pytest.mark.asyncio
async def test_templates(client: AsyncClient):
    resp = await client.get("/api/templates")
    assert resp.status_code == 200
    templates = resp.json()["templates"]
    assert len(templates) >= 5

    # Get specific template
    if templates:
        resp = await client.get(f"/api/templates/{templates[0]['id']}")
        assert resp.status_code == 200
        assert "nodes" in resp.json()


@pytest.mark.asyncio
async def test_snapshot_crud(client: AsyncClient):
    resp = await client.post("/api/projects", json={"name": "Snap Test"})
    project_id = resp.json()["id"]

    # Create snapshot
    resp = await client.post("/api/snapshots", json={
        "project_id": project_id, "label": "v1"
    })
    assert resp.status_code == 201
    snap_id = resp.json()["id"]

    # List snapshots
    resp = await client.get(f"/api/snapshots/project/{project_id}")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1

    # Get snapshot detail
    resp = await client.get(f"/api/snapshots/{snap_id}")
    assert resp.status_code == 200
    assert "tree_data" in resp.json()


@pytest.mark.asyncio
async def test_export_json(client: AsyncClient):
    resp = await client.post("/api/projects", json={"name": "Export Test"})
    project_id = resp.json()["id"]
    await client.post("/api/nodes", json={"project_id": project_id, "title": "Root"})

    resp = await client.post("/api/export/json", json={"project_id": project_id})
    assert resp.status_code == 200

    resp = await client.post("/api/export/markdown", json={"project_id": project_id})
    assert resp.status_code == 200

    resp = await client.post("/api/export/csv", json={"project_id": project_id})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_risk_recalculation(client: AsyncClient):
    resp = await client.post("/api/projects", json={"name": "Risk Test"})
    project_id = resp.json()["id"]
    await client.post("/api/nodes", json={
        "project_id": project_id, "title": "Root", "node_type": "goal", "logic_type": "OR",
    })

    resp = await client.get(f"/api/export/risk-engine/{project_id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"


@pytest.mark.asyncio
async def test_llm_provider_crud(client: AsyncClient):
    # Create provider with minimal data (same as frontend Add Provider button)
    resp = await client.post("/api/llm/providers", json={
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
    resp = await client.get("/api/llm/providers")
    assert resp.status_code == 200
    providers = resp.json()
    assert len(providers) >= 1
    assert any(p["id"] == provider_id for p in providers)

    # Update provider
    resp = await client.patch(f"/api/llm/providers/{provider_id}", json={
        "name": "Updated Provider",
        "model": "llama3",
    })
    assert resp.status_code == 200, f"Update failed: {resp.text}"
    assert resp.json()["name"] == "Updated Provider"
    assert resp.json()["model"] == "llama3"

    # Update with API key
    resp = await client.patch(f"/api/llm/providers/{provider_id}", json={
        "api_key": "sk-test-key-12345",
    })
    assert resp.status_code == 200, f"API key update failed: {resp.text}"
    assert resp.json()["has_api_key"] is True

    # Delete provider
    resp = await client.delete(f"/api/llm/providers/{provider_id}")
    assert resp.status_code == 204

    # Verify deletion
    resp = await client.get("/api/llm/providers")
    assert resp.status_code == 200
    assert not any(p["id"] == provider_id for p in resp.json())
