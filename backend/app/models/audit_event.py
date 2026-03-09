import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from ..database import Base


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String(50), nullable=False)
    entity_type = Column(String(50), default="")
    entity_id = Column(String(36), default="")
    detail = Column(JSON, default=dict)
    actor = Column(String(100), default="analyst")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    project = relationship("Project", back_populates="audit_events")
