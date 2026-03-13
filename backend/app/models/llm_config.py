import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from ..database import Base


class LLMProviderConfig(Base):
    __tablename__ = "llm_provider_configs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    name = Column(String(255), nullable=False, default="Local LLM")
    base_url = Column(String(1000), nullable=False, default="http://localhost:11434/v1")
    api_key_encrypted = Column(Text, default="")
    model = Column(String(200), default="")
    custom_headers = Column(JSON, default=dict)
    timeout = Column(Integer, default=120)
    stream_enabled = Column(Boolean, default=False)
    tls_verify = Column(Boolean, default=True)
    ca_bundle_path = Column(String(1000), default="")
    client_cert_path = Column(String(1000), default="")
    client_key_path = Column(String(1000), default="")
    is_active = Column(Boolean, default=True)
    last_tested_at = Column(DateTime, nullable=True)
    last_test_result = Column(String(50), default="")
    last_test_message = Column(Text, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="llm_provider_configs")


class LLMJobHistory(Base):
    __tablename__ = "llm_job_history"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    provider_id = Column(String(36), nullable=True)
    project_id = Column(String(36), nullable=True)
    node_id = Column(String(36), nullable=True)
    job_type = Column(String(50), nullable=False)  # suggest_branches, summarize, enrich, report_draft
    prompt_summary = Column(Text, default="")
    response_summary = Column(Text, default="")
    status = Column(String(20), default="pending")  # pending, success, error
    tokens_used = Column(Integer, default=0)
    duration_ms = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class LLMAgentRun(Base):
    __tablename__ = "llm_agent_runs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    provider_id = Column(String(36), nullable=True, index=True)
    project_id = Column(String(36), nullable=True, index=True)
    mode = Column(String(30), default="generate")
    status = Column(String(30), default="queued")  # queued, processing, completed, completed_with_warnings, failed
    current_stage = Column(String(50), default="structure")
    nodes_created = Column(Integer, default=0)
    passes_completed = Column(Integer, default=0)
    total_passes = Column(Integer, default=4)
    warnings = Column(JSON, default=list)
    checkpoints = Column(JSON, default=dict)
    error_message = Column(Text, default="")
    model_used = Column(String(200), default="")
    tokens_used = Column(Integer, default=0)
    duration_ms = Column(Integer, default=0)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
