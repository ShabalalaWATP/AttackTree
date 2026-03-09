from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from ..database import get_db
from ..models.snapshot import Snapshot
from ..models.project import Project
from ..models.node import Node
from ..schemas.snapshot import SnapshotCreate, SnapshotResponse, SnapshotDetailResponse

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

    proj_result = await db.execute(select(Project).where(Project.id == project_id))
    project = proj_result.scalar_one_or_none()

    return {
        "project": {
            "id": project.id, "name": project.name, "description": project.description,
            "context_preset": project.context_preset, "root_objective": project.root_objective,
        } if project else {},
        "nodes": nodes_data,
    }


@router.get("/project/{project_id}", response_model=list[SnapshotResponse])
async def list_snapshots(project_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Snapshot).where(Snapshot.project_id == project_id).order_by(Snapshot.created_at.desc())
    )
    return [SnapshotResponse.model_validate(s) for s in result.scalars().all()]


@router.post("", response_model=SnapshotResponse, status_code=201)
async def create_snapshot(data: SnapshotCreate, db: AsyncSession = Depends(get_db)):
    tree_data = await _capture_tree_data(data.project_id, db)
    snapshot = Snapshot(
        project_id=data.project_id,
        label=data.label or f"Snapshot",
        tree_data=tree_data,
    )
    db.add(snapshot)
    await db.commit()
    await db.refresh(snapshot)
    return SnapshotResponse.model_validate(snapshot)


@router.get("/{snapshot_id}", response_model=SnapshotDetailResponse)
async def get_snapshot(snapshot_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Snapshot).where(Snapshot.id == snapshot_id))
    snapshot = result.scalar_one_or_none()
    if not snapshot:
        raise HTTPException(404, "Snapshot not found")
    return SnapshotDetailResponse.model_validate(snapshot)


@router.delete("/{snapshot_id}", status_code=204)
async def delete_snapshot(snapshot_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Snapshot).where(Snapshot.id == snapshot_id))
    snapshot = result.scalar_one_or_none()
    if not snapshot:
        raise HTTPException(404, "Snapshot not found")
    await db.delete(snapshot)
    await db.commit()
