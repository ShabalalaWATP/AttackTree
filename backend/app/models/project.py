import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, JSON
from sqlalchemy.orm import relationship
from ..database import Base


class Project(Base):
    __tablename__ = "projects"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    description = Column(Text, default="")
    context_preset = Column(String(50), default="general")
    root_objective = Column(Text, default="")
    metadata_json = Column(JSON, default=dict)
    owner = Column(String(100), default="analyst")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    nodes = relationship("Node", back_populates="project", cascade="all, delete-orphan")
    edges = relationship("Edge", back_populates="project", cascade="all, delete-orphan")
    snapshots = relationship("Snapshot", back_populates="project", cascade="all, delete-orphan")
    audit_events = relationship("AuditEvent", back_populates="project", cascade="all, delete-orphan")
