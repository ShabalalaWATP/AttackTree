from sqlalchemy.ext.asyncio import AsyncSession
from ..models.audit_event import AuditEvent


async def log_event(
    db: AsyncSession,
    project_id: str,
    event_type: str,
    entity_type: str = "",
    entity_id: str = "",
    detail: dict | None = None,
    actor: str = "analyst",
):
    """Log an audit event. Caller is responsible for committing the transaction."""
    event = AuditEvent(
        project_id=project_id,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        detail=detail or {},
        actor=actor,
    )
    db.add(event)
