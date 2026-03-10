import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from ..database import Base


class InfraMap(Base):
    """An infrastructure map (hardware/software mind-map), optionally tied to a project."""
    __tablename__ = "infra_maps"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, default="")
    # Tree structure stored as JSON: [{id, parent_id, label, category, description, icon, metadata, children_loaded}]
    nodes = Column(JSON, default=list)
    # AI summary of the infrastructure
    ai_summary = Column(Text, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="infra_maps")
    project = relationship("Project", back_populates="infra_maps")
