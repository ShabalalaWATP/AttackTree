from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, delete, or_
from sqlalchemy.orm import selectinload
from ..database import get_db
from ..models.project import Project
from ..models.node import Node
from ..schemas.project import ProjectCreate, ProjectUpdate, ProjectResponse, ProjectListResponse
from ..services.access_control import require_project_access
from ..services.auth import get_current_user_id, get_current_user_name

router = APIRouter(prefix="/projects", tags=["projects"])


def _workspace_mode(project: Project) -> str:
    return (project.metadata_json or {}).get("workspace_mode", "project_scan")


def _to_project_response(project: Project, node_count: int) -> ProjectResponse:
    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        context_preset=project.context_preset,
        root_objective=project.root_objective,
        owner=project.owner,
        workspace_mode=_workspace_mode(project),
        created_at=project.created_at,
        updated_at=project.updated_at,
        node_count=node_count,
    )


@router.get("", response_model=ProjectListResponse)
async def list_projects(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Project)
        .where(Project.user_id == get_current_user_id())
        .order_by(Project.updated_at.desc())
    )
    projects = result.scalars().all()

    responses = []
    for p in projects:
        count_result = await db.execute(select(func.count(Node.id)).where(Node.project_id == p.id))
        node_count = count_result.scalar() or 0
        responses.append(_to_project_response(p, node_count))

    return ProjectListResponse(projects=responses, total=len(responses))


@router.post("", response_model=ProjectResponse, status_code=201)
async def create_project(data: ProjectCreate, db: AsyncSession = Depends(get_db)):
    metadata = {"workspace_mode": data.workspace_mode}
    project = Project(
        name=data.name,
        description=data.description,
        context_preset=data.context_preset,
        root_objective=data.root_objective,
        owner=get_current_user_name(),
        user_id=get_current_user_id(),
        metadata_json=metadata,
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return _to_project_response(project, 0)


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: str, db: AsyncSession = Depends(get_db)):
    project = await require_project_access(project_id, db)

    count_result = await db.execute(select(func.count(Node.id)).where(Node.project_id == project_id))
    node_count = count_result.scalar() or 0

    return _to_project_response(project, node_count)


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(project_id: str, data: ProjectUpdate, db: AsyncSession = Depends(get_db)):
    project = await require_project_access(project_id, db)

    update_data = data.model_dump(exclude_unset=True)
    if "workspace_mode" in update_data:
        project.metadata_json = {
            **(project.metadata_json or {}),
            "workspace_mode": update_data.pop("workspace_mode"),
        }
    for key, value in update_data.items():
        if key == "owner":
            value = get_current_user_name()
        setattr(project, key, value)

    await db.commit()
    await db.refresh(project)

    count_result = await db.execute(select(func.count(Node.id)).where(Node.project_id == project_id))
    node_count = count_result.scalar() or 0

    return _to_project_response(project, node_count)


@router.delete("/{project_id}", status_code=204)
async def delete_project(project_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Project)
        .where(Project.id == project_id, Project.user_id == get_current_user_id())
        .options(
            selectinload(Project.nodes),
            selectinload(Project.edges),
            selectinload(Project.snapshots),
            selectinload(Project.audit_events),
            selectinload(Project.kill_chains),
            selectinload(Project.threat_models),
            selectinload(Project.scenarios),
        )
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    await db.delete(project)
    await db.commit()


@router.get("/search/nodes")
async def search_across_projects(q: str = Query(..., min_length=1), db: AsyncSession = Depends(get_db)):
    """Search nodes across all projects by title, description, threat_category, or attack_surface."""
    pattern = f"%{q}%"
    result = await db.execute(
        select(Node)
        .join(Project, Node.project_id == Project.id)
        .where(
            Project.user_id == get_current_user_id(),
            or_(
                Node.title.ilike(pattern),
                Node.description.ilike(pattern),
                Node.threat_category.ilike(pattern),
                Node.attack_surface.ilike(pattern),
            )
        )
        .limit(50)
    )
    nodes = result.scalars().all()

    # Gather project names for display
    project_ids = {n.project_id for n in nodes}
    projects_map: dict[str, str] = {}
    if project_ids:
        proj_result = await db.execute(
            select(Project).where(Project.id.in_(project_ids), Project.user_id == get_current_user_id())
        )
        for p in proj_result.scalars().all():
            projects_map[p.id] = p.name

    return {
        "count": len(nodes),
        "results": [
            {
                "node_id": n.id,
                "project_id": n.project_id,
                "project_name": projects_map.get(n.project_id, "Unknown"),
                "title": n.title,
                "node_type": n.node_type,
                "description": (n.description or "")[:200],
                "inherent_risk": n.inherent_risk,
            }
            for n in nodes
        ],
    }
