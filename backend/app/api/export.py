from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from ..database import get_db
from ..models.project import Project
from ..models.node import Node
from ..models.reference_mapping import ReferenceMapping
from ..schemas.export import ExportRequest
from ..schemas.node import NodeResponse
from ..services import export_service
from ..services.access_control import require_project_access
from ..services.auth import get_current_user_id, get_current_user_name
from ..services.tree_service import recalculate_project_tree_scores

router = APIRouter(prefix="/export", tags=["export"])


async def _get_project_and_nodes(project_id: str, db: AsyncSession):
    project = await require_project_access(project_id, db)

    nodes_result = await db.execute(
        select(Node).where(Node.project_id == project_id)
        .options(
            selectinload(Node.mitigations),
            selectinload(Node.detections),
            selectinload(Node.reference_mappings),
            selectinload(Node.tags),
        )
        .order_by(Node.sort_order)
    )
    nodes = nodes_result.scalars().all()

    project_dict = {
        "id": project.id, "name": project.name, "description": project.description,
        "context_preset": project.context_preset, "root_objective": project.root_objective,
        "owner": project.owner,
        "workspace_mode": (project.metadata_json or {}).get("workspace_mode", "project_scan"),
        "metadata_json": project.metadata_json or {},
    }
    nodes_dicts = [NodeResponse.model_validate(n).model_dump(mode="json") for n in nodes]
    return project_dict, nodes_dicts


@router.post("/json")
async def export_json(data: ExportRequest, db: AsyncSession = Depends(get_db)):
    project_dict, nodes_dicts = await _get_project_and_nodes(data.project_id, db)
    content = export_service.export_json(project_dict, nodes_dicts)
    return Response(
        content=content, media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{project_dict["name"]}.json"'},
    )


@router.post("/csv")
async def export_csv(data: ExportRequest, db: AsyncSession = Depends(get_db)):
    _, nodes_dicts = await _get_project_and_nodes(data.project_id, db)
    content = export_service.export_csv(nodes_dicts)
    return Response(
        content=content, media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="nodes.csv"'},
    )


@router.post("/markdown")
async def export_markdown(data: ExportRequest, db: AsyncSession = Depends(get_db)):
    project_dict, nodes_dicts = await _get_project_and_nodes(data.project_id, db)
    content = export_service.export_markdown(project_dict, nodes_dicts, data.report_type)
    return Response(
        content=content, media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{project_dict["name"]}_report.md"'},
    )


@router.post("/pdf")
async def export_pdf(data: ExportRequest, db: AsyncSession = Depends(get_db)):
    project_dict, nodes_dicts = await _get_project_and_nodes(data.project_id, db)
    content = export_service.export_pdf(project_dict, nodes_dicts, data.report_type)
    return Response(
        content=content, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{project_dict["name"]}_report.pdf"'},
    )


@router.post("/import")
async def import_json(data: dict, db: AsyncSession = Depends(get_db)):
    """Import a project from JSON export format."""
    project_data = data.get("project", {})
    nodes_data = data.get("nodes", [])

    if not project_data:
        raise HTTPException(400, "Invalid import format: missing 'project' key")

    import uuid
    # Create project with new ID
    project = Project(
        id=str(uuid.uuid4()),
        name=project_data.get("name", "Imported Project"),
        description=project_data.get("description", ""),
        context_preset=project_data.get("context_preset", "general"),
        root_objective=project_data.get("root_objective", ""),
        owner=get_current_user_name(),
        user_id=get_current_user_id(),
        metadata_json={
            **(project_data.get("metadata_json", {}) or {}),
            "workspace_mode": project_data.get(
                "workspace_mode",
                (project_data.get("metadata_json", {}) or {}).get("workspace_mode", "project_scan"),
            ),
        },
    )
    db.add(project)

    # Map old IDs to new IDs
    id_map = {}
    for node_data in nodes_data:
        old_id = node_data.get("id", "")
        new_id = str(uuid.uuid4())
        id_map[old_id] = new_id

    # Create nodes
    for node_data in nodes_data:
        old_id = node_data.get("id", "")
        old_parent = node_data.get("parent_id")
        node = Node(
            id=id_map.get(old_id, str(uuid.uuid4())),
            project_id=project.id,
            parent_id=id_map.get(old_parent) if old_parent else None,
            node_type=node_data.get("node_type", "attack_step"),
            title=node_data.get("title", "Imported Node"),
            description=node_data.get("description", ""),
            notes=node_data.get("notes", ""),
            logic_type=node_data.get("logic_type", "OR"),
            status=node_data.get("status", "draft"),
            sort_order=node_data.get("sort_order", 0),
            position_x=node_data.get("position_x", 0),
            position_y=node_data.get("position_y", 0),
            threat_category=node_data.get("threat_category", ""),
            attack_surface=node_data.get("attack_surface", ""),
            platform=node_data.get("platform", ""),
            required_access=node_data.get("required_access", ""),
            required_privileges=node_data.get("required_privileges", ""),
            required_tools=node_data.get("required_tools", ""),
            required_skill=node_data.get("required_skill", ""),
            likelihood=node_data.get("likelihood"),
            impact=node_data.get("impact"),
            effort=node_data.get("effort"),
            exploitability=node_data.get("exploitability"),
            detectability=node_data.get("detectability"),
            confidence=node_data.get("confidence"),
            inherent_risk=node_data.get("inherent_risk"),
            residual_risk=node_data.get("residual_risk"),
            probability=node_data.get("probability"),
            cost_to_attacker=node_data.get("cost_to_attacker"),
            time_estimate=node_data.get("time_estimate", ""),
            assumptions=node_data.get("assumptions", ""),
            analyst=node_data.get("analyst", ""),
            cve_references=node_data.get("cve_references", ""),
            extended_metadata=node_data.get("extended_metadata", {}) or {},
        )
        db.add(node)
        for mapping in node_data.get("reference_mappings", []) or []:
            if not isinstance(mapping, dict):
                continue
            db.add(ReferenceMapping(
                node_id=node.id,
                framework=mapping.get("framework", ""),
                ref_id=mapping.get("ref_id", ""),
                ref_name=mapping.get("ref_name", ""),
                confidence=mapping.get("confidence"),
                rationale=mapping.get("rationale", ""),
                source=mapping.get("source", "manual"),
            ))

    await db.flush()
    await recalculate_project_tree_scores(db, project.id)
    await db.commit()
    return {"status": "success", "project_id": project.id, "nodes_imported": len(nodes_data)}


@router.get("/risk-engine/{project_id}")
async def recalculate_risk(project_id: str, db: AsyncSession = Depends(get_db)):
    """Recalculate all risk scores for a project's tree."""
    await require_project_access(project_id, db)
    nodes_processed = await recalculate_project_tree_scores(db, project_id)
    await db.commit()
    return {"status": "success", "nodes_processed": nodes_processed}
