from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..database import get_db
from ..models.detection import Detection
from ..models.node import Node
from ..schemas.detection import DetectionCreate, DetectionUpdate, DetectionResponse
from ..services.access_control import require_detection_access, require_node_access
from ..services.audit import log_event

router = APIRouter(prefix="/detections", tags=["detections"])


@router.get("/node/{node_id}", response_model=list[DetectionResponse])
async def list_detections(node_id: str, db: AsyncSession = Depends(get_db)):
    await require_node_access(node_id, db)
    result = await db.execute(select(Detection).where(Detection.node_id == node_id))
    return [DetectionResponse.model_validate(d) for d in result.scalars().all()]


@router.post("", response_model=DetectionResponse, status_code=201)
async def create_detection(data: DetectionCreate, db: AsyncSession = Depends(get_db)):
    node = await require_node_access(data.node_id, db)
    det = Detection(**data.model_dump())
    db.add(det)

    # Log audit event
    if node:
        await log_event(db, node.project_id, "detection_added", "detection", "", {"node_id": data.node_id, "title": data.title})

    await db.commit()
    await db.refresh(det)
    return DetectionResponse.model_validate(det)


@router.patch("/{detection_id}", response_model=DetectionResponse)
async def update_detection(detection_id: str, data: DetectionUpdate, db: AsyncSession = Depends(get_db)):
    det = await require_detection_access(detection_id, db)

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(det, key, value)

    # Log audit event
    node = await require_node_access(det.node_id, db)
    if node:
        await log_event(db, node.project_id, "detection_updated", "detection", detection_id, {"title": det.title, "fields": list(update_data.keys())})

    await db.commit()
    await db.refresh(det)
    return DetectionResponse.model_validate(det)


@router.delete("/{detection_id}", status_code=204)
async def delete_detection(detection_id: str, db: AsyncSession = Depends(get_db)):
    det = await require_detection_access(detection_id, db)

    # Log audit event
    node = await require_node_access(det.node_id, db)
    if node:
        await log_event(db, node.project_id, "detection_removed", "detection", detection_id, {"node_id": det.node_id, "title": det.title})

    await db.delete(det)
    await db.commit()
