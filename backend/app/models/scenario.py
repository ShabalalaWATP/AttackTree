import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from ..database import Base


class Scenario(Base):
    """A planning scenario that can be standalone or linked to a project."""

    __tablename__ = "scenarios"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True)
    scope = Column(String(20), default="standalone")
    name = Column(String(255), nullable=False)
    description = Column(Text, default="")
    status = Column(String(20), default="draft")

    # Mission framing
    scenario_type = Column(String(50), default="campaign")
    operation_goal = Column(Text, default="")
    target_profile = Column(String(255), default="")
    target_environment = Column(String(255), default="")
    execution_tempo = Column(String(20), default="balanced")
    stealth_level = Column(String(20), default="balanced")
    access_level = Column(String(30), default="external")

    # Attacker profile
    attacker_type = Column(String(50), default="opportunistic")
    attacker_skill = Column(String(20), default="Medium")
    attacker_resources = Column(String(20), default="Medium")
    attacker_motivation = Column(String(100), default="")

    # Scenario parameters
    entry_vectors = Column(JSON, default=list)
    campaign_phases = Column(JSON, default=list)
    constraints = Column(JSON, default=list)
    dependencies = Column(JSON, default=list)
    intelligence_gaps = Column(JSON, default=list)
    success_criteria = Column(JSON, default=list)
    focus_node_ids = Column(JSON, default=list)
    focus_tags = Column(JSON, default=list)
    disabled_controls = Column(JSON, default=list)
    degraded_detections = Column(JSON, default=list)
    modified_scores = Column(JSON, default=dict)
    assumptions = Column(Text, default="")
    planning_notes = Column(Text, default="")
    reference_mappings = Column(JSON, default=list)

    # AI analysis results
    ai_narrative = Column(Text, default="")
    ai_recommendations = Column(JSON, default=list)
    impact_summary = Column(JSON, default=dict)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    user = relationship("User", back_populates="scenarios")
    project = relationship("Project", back_populates="scenarios")
