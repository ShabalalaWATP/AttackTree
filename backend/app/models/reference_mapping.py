import uuid
from sqlalchemy import Column, String, ForeignKey, Float, Text
from sqlalchemy.orm import relationship
from ..database import Base


class ReferenceMapping(Base):
    __tablename__ = "reference_mappings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    node_id = Column(String(36), ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False)
    framework = Column(String(50), nullable=False)  # attack, capec, cwe, owasp, masvs, custom
    ref_id = Column(String(50), nullable=False)  # e.g., T1566
    ref_name = Column(String(500), default="")
    confidence = Column(Float, nullable=True)
    rationale = Column(Text, default="")
    source = Column(String(30), default="manual")

    node = relationship("Node", back_populates="reference_mappings")
