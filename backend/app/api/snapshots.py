from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from ..database import get_db
from ..models.snapshot import Snapshot
from ..models.project import Project
from ..models.node import Node
from ..schemas.snapshot import SnapshotCreate, SnapshotResponse, SnapshotDetailResponse
from ..services.access_control import require_project_access, require_snapshot_access
from ..services.auth import get_current_user_name

router = APIRouter(prefix="/snapshots", tags=["snapshots"])


async def _capture_tree_data(project_id: str, db: AsyncSession) -> dict:
    """Capture full tree state as JSON."""
    result = await db.execute(
        select(Node).where(Node.project_id == project_id)
        .options(
            selectinload(Node.mitigations),
            selectinload(Node.detections),
            selectinload(Node.reference_mappings),
        )
    )
    nodes = result.scalars().all()

    from ..schemas.node import NodeResponse
    nodes_data = [NodeResponse.model_validate(n).model_dump(mode="json") for n in nodes]

    project = await require_project_access(project_id, db)

    return {
        "project": {
            "id": project.id, "name": project.name, "description": project.description,
            "context_preset": project.context_preset, "root_objective": project.root_objective,
        } if project else {},
        "nodes": nodes_data,
    }


@router.get("/project/{project_id}", response_model=list[SnapshotResponse])
async def list_snapshots(project_id: str, db: AsyncSession = Depends(get_db)):
    await require_project_access(project_id, db)
    result = await db.execute(
        select(Snapshot).where(Snapshot.project_id == project_id).order_by(Snapshot.created_at.desc())
    )
    return [SnapshotResponse.model_validate(s) for s in result.scalars().all()]


@router.post("", response_model=SnapshotResponse, status_code=201)
async def create_snapshot(data: SnapshotCreate, db: AsyncSession = Depends(get_db)):
    await require_project_access(data.project_id, db)
    tree_data = await _capture_tree_data(data.project_id, db)
    snapshot = Snapshot(
        project_id=data.project_id,
        label=data.label or f"Snapshot",
        tree_data=tree_data,
        created_by=get_current_user_name(),
    )
    db.add(snapshot)
    await db.commit()
    await db.refresh(snapshot)
    return SnapshotResponse.model_validate(snapshot)


@router.get("/{snapshot_id}", response_model=SnapshotDetailResponse)
async def get_snapshot(snapshot_id: str, db: AsyncSession = Depends(get_db)):
    snapshot = await require_snapshot_access(snapshot_id, db)
    return SnapshotDetailResponse.model_validate(snapshot)


@router.delete("/{snapshot_id}", status_code=204)
async def delete_snapshot(snapshot_id: str, db: AsyncSession = Depends(get_db)):
    snapshot = await require_snapshot_access(snapshot_id, db)
    await db.delete(snapshot)
    await db.commit()
