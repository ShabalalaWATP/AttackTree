from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..database import get_db
from ..models.mitigation import Mitigation
from ..models.node import Node
from ..schemas.mitigation import MitigationCreate, MitigationUpdate, MitigationResponse
from ..services.access_control import require_mitigation_access, require_node_access
from ..services.risk_engine import compute_residual_risk
from ..services.audit import log_event

router = APIRouter(prefix="/mitigations", tags=["mitigations"])


@router.get("/node/{node_id}", response_model=list[MitigationResponse])
async def list_mitigations(node_id: str, db: AsyncSession = Depends(get_db)):
    await require_node_access(node_id, db)
    result = await db.execute(select(Mitigation).where(Mitigation.node_id == node_id))
    return [MitigationResponse.model_validate(m) for m in result.scalars().all()]


@router.post("", response_model=MitigationResponse, status_code=201)
async def create_mitigation(data: MitigationCreate, db: AsyncSession = Depends(get_db)):
    node_for_audit = await require_node_access(data.node_id, db)
    mit = Mitigation(**data.model_dump())
    db.add(mit)

    # Log audit event
    if node_for_audit:
        await log_event(db, node_for_audit.project_id, "mitigation_added", "mitigation", "", {"node_id": data.node_id, "title": data.title})

    await db.commit()
    await db.refresh(mit)

    # Update node residual risk
    node = await require_node_access(data.node_id, db)
    if node and node.inherent_risk is not None:
        all_mits = await db.execute(select(Mitigation).where(Mitigation.node_id == data.node_id))
        max_eff = max((m.effectiveness for m in all_mits.scalars().all()), default=0.0)
        node.residual_risk = compute_residual_risk(node.inherent_risk, max_eff)
        await db.commit()

    return MitigationResponse.model_validate(mit)


@router.patch("/{mitigation_id}", response_model=MitigationResponse)
async def update_mitigation(mitigation_id: str, data: MitigationUpdate, db: AsyncSession = Depends(get_db)):
    mit = await require_mitigation_access(mitigation_id, db)

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(mit, key, value)

    # Recalculate node residual risk if effectiveness changed
    node = await require_node_access(mit.node_id, db)
    if node and node.inherent_risk is not None:
        all_mits = await db.execute(select(Mitigation).where(Mitigation.node_id == mit.node_id))
        max_eff = max((m.effectiveness for m in all_mits.scalars().all()), default=0.0)
        node.residual_risk = compute_residual_risk(node.inherent_risk, max_eff)

    # Log audit event
    if node:
        await log_event(db, node.project_id, "mitigation_updated", "mitigation", mitigation_id, {"title": mit.title, "fields": list(update_data.keys())})

    await db.commit()
    await db.refresh(mit)
    return MitigationResponse.model_validate(mit)


@router.delete("/{mitigation_id}", status_code=204)
async def delete_mitigation(mitigation_id: str, db: AsyncSession = Depends(get_db)):
    mit = await require_mitigation_access(mitigation_id, db)

    # Log audit event
    node = await require_node_access(mit.node_id, db)
    if node:
        await log_event(db, node.project_id, "mitigation_removed", "mitigation", mitigation_id, {"node_id": mit.node_id})

    await db.delete(mit)
    await db.commit()
