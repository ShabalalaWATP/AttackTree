import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, Integer, ForeignKey
from sqlalchemy.orm import relationship
from ..database import Base


class Attachment(Base):
    __tablename__ = "attachments"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    node_id = Column(String(36), ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False)
    filename = Column(String(500), nullable=False)
    mime_type = Column(String(100), default="application/octet-stream")
    file_size = Column(Integer, default=0)
    file_hash = Column(String(128), default="")
    storage_path = Column(String(1000), default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    node = relationship("Node", back_populates="attachments")
