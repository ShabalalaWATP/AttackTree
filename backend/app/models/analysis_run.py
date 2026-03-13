import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from ..database import Base


class AnalysisRun(Base):
    """A project-scoped ledger entry for a concrete analysis run."""

    __tablename__ = "analysis_runs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    tool = Column(String(30), nullable=False, index=True)
    run_type = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False, default="completed", index=True)
    artifact_kind = Column(String(30), default="")
    artifact_id = Column(String(36), nullable=True)
    artifact_name = Column(String(255), default="")
    summary = Column(Text, default="")
    metadata_json = Column(JSON, default=dict)
    duration_ms = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    project = relationship("Project", back_populates="analysis_runs")
