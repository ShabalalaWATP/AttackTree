from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..database import get_db
from ..models.audit_event import AuditEvent
from ..schemas.audit_event import AuditEventResponse

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/project/{project_id}", response_model=list[AuditEventResponse])
async def list_audit_events(
    project_id: str,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AuditEvent)
        .where(AuditEvent.project_id == project_id)
        .order_by(AuditEvent.timestamp.desc())
        .offset(offset)
        .limit(limit)
    )
    return [AuditEventResponse.model_validate(e) for e in result.scalars().all()]
