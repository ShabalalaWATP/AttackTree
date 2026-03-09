import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, Float, ForeignKey
from sqlalchemy.orm import relationship
from ..database import Base


class Mitigation(Base):
    __tablename__ = "mitigations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    node_id = Column(String(36), ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, default="")
    effectiveness = Column(Float, default=0.5)  # 0.0 to 1.0
    status = Column(String(20), default="proposed")  # proposed, implemented, verified, rejected
    control_ref = Column(String(200), default="")  # e.g., NIST CSF ref
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    node = relationship("Node", back_populates="mitigations")
