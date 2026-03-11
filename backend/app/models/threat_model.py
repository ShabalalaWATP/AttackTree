import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, Float, Integer, ForeignKey, JSON
from sqlalchemy.orm import relationship
from ..database import Base


class ThreatModel(Base):
    """A STRIDE/PASTA threat model tied to a project."""
    __tablename__ = "threat_models"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, default="")
    methodology = Column(String(30), default="stride")  # stride, pasta, linddun
    scope = Column(Text, default="")
    # Data Flow Diagram components
    components = Column(JSON, default=list)    # [{id, type, name, description, x, y}]
    data_flows = Column(JSON, default=list)    # [{id, source, target, label, data_classification}]
    trust_boundaries = Column(JSON, default=list)  # [{id, name, component_ids[]}]
    # AI-generated threats
    threats = Column(JSON, default=list)       # [{id, component_id, category, title, description, severity, mitigation, linked_node_id}]
    ai_summary = Column(Text, default="")
    dfd_metadata = Column(JSON, default=dict)
    analysis_metadata = Column(JSON, default=dict)
    deep_dive_cache = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    project = relationship("Project", back_populates="threat_models")
