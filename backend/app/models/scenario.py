import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, Float, Integer, ForeignKey, JSON
from sqlalchemy.orm import relationship
from ..database import Base


class Scenario(Base):
    """A what-if scenario simulation tied to a project."""
    __tablename__ = "scenarios"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, default="")
    status = Column(String(20), default="draft")  # draft, running, completed
    # Attacker profile
    attacker_type = Column(String(50), default="opportunistic")  # script_kiddie, insider, apt, nation_state
    attacker_skill = Column(String(20), default="Medium")
    attacker_resources = Column(String(20), default="Medium")
    attacker_motivation = Column(String(100), default="")
    # Scenario parameters
    disabled_controls = Column(JSON, default=list)  # list of mitigation IDs toggled off
    modified_scores = Column(JSON, default=dict)    # node_id -> {field: value} overrides
    assumptions = Column(Text, default="")
    # AI analysis results
    ai_narrative = Column(Text, default="")
    ai_recommendations = Column(JSON, default=list)
    impact_summary = Column(JSON, default=dict)     # {original_risk, simulated_risk, delta, affected_paths}
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    project = relationship("Project", backref="scenarios")
