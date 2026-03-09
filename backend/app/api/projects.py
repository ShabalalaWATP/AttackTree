from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, delete
from ..database import get_db
from ..models.project import Project
from ..models.node import Node
from ..schemas.project import ProjectCreate, ProjectUpdate, ProjectResponse, ProjectListResponse

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=ProjectListResponse)
async def list_projects(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).order_by(Project.updated_at.desc()))
    projects = result.scalars().all()

    responses = []
    for p in projects:
        count_result = await db.execute(select(func.count(Node.id)).where(Node.project_id == p.id))
        node_count = count_result.scalar() or 0
        resp = ProjectResponse(
            id=p.id, name=p.name, description=p.description,
            context_preset=p.context_preset, root_objective=p.root_objective,
            owner=p.owner, created_at=p.created_at, updated_at=p.updated_at,
            node_count=node_count,
        )
        responses.append(resp)

    return ProjectListResponse(projects=responses, total=len(responses))


@router.post("", response_model=ProjectResponse, status_code=201)
async def create_project(data: ProjectCreate, db: AsyncSession = Depends(get_db)):
    project = Project(
        name=data.name,
        description=data.description,
        context_preset=data.context_preset,
        root_objective=data.root_objective,
        owner=data.owner,
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)

    return ProjectResponse(
        id=project.id, name=project.name, description=project.description,
        context_preset=project.context_preset, root_objective=project.root_objective,
        owner=project.owner, created_at=project.created_at, updated_at=project.updated_at,
        node_count=0,
    )


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    count_result = await db.execute(select(func.count(Node.id)).where(Node.project_id == project_id))
    node_count = count_result.scalar() or 0

    return ProjectResponse(
        id=project.id, name=project.name, description=project.description,
        context_preset=project.context_preset, root_objective=project.root_objective,
        owner=project.owner, created_at=project.created_at, updated_at=project.updated_at,
        node_count=node_count,
    )


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(project_id: str, data: ProjectUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(project, key, value)

    await db.commit()
    await db.refresh(project)

    count_result = await db.execute(select(func.count(Node.id)).where(Node.project_id == project_id))
    node_count = count_result.scalar() or 0

    return ProjectResponse(
        id=project.id, name=project.name, description=project.description,
        context_preset=project.context_preset, root_objective=project.root_objective,
        owner=project.owner, created_at=project.created_at, updated_at=project.updated_at,
        node_count=node_count,
    )


@router.delete("/{project_id}", status_code=204)
async def delete_project(project_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    await db.delete(project)
    await db.commit()
