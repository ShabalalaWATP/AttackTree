import uuid
from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.orm import relationship
from ..database import Base


class Edge(Base):
    """Edge model for explicit edge storage. Currently unused — the tree
    hierarchy is driven by Node.parent_id.  Kept for potential future use
    with cross-link / non-tree edges."""
    __tablename__ = "edges"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    source_id = Column(String(36), ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False)
    target_id = Column(String(36), ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False)
    edge_type = Column(String(20), default="parent_child")

    project = relationship("Project", back_populates="edges")
