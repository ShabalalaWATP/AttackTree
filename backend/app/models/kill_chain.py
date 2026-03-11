import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, Float, Integer, ForeignKey, JSON
from sqlalchemy.orm import relationship
from ..database import Base


class KillChain(Base):
    """A kill chain / campaign timeline tied to a project."""
    __tablename__ = "kill_chains"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, default="")
    framework = Column(String(50), default="mitre_attck")  # mitre_attck, cyber_kill_chain, unified
    # AI-generated analysis
    ai_summary = Column(Text, default="")
    phases = Column(JSON, default=list)  # [{phase, name, description, node_ids[], detection_window, dwell_time}]
    recommendations = Column(JSON, default=list)
    total_estimated_time = Column(String(100), default="")
    weakest_links = Column(JSON, default=list)
    overall_risk_rating = Column(String(20), default="")
    attack_complexity = Column(String(20), default="")
    coverage_score = Column(Float, nullable=True)
    critical_path = Column(Text, default="")
    analysis_metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    project = relationship("Project", back_populates="kill_chains")
