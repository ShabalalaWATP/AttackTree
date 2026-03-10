from sqlalchemy.ext.asyncio import AsyncSession
from ..models.audit_event import AuditEvent
from .auth import get_auth_context


async def log_event(
    db: AsyncSession,
    project_id: str,
    event_type: str,
    entity_type: str = "",
    entity_id: str = "",
    detail: dict | None = None,
    actor: str | None = None,
):
    """Log an audit event. Caller is responsible for committing the transaction."""
    context = get_auth_context(required=False)
    event = AuditEvent(
        project_id=project_id,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        detail=detail or {},
        actor=actor or (context.name if context else "analyst"),
    )
    db.add(event)
