import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, Float, Integer, ForeignKey, Table, JSON
from sqlalchemy.orm import relationship
from ..database import Base


class Tag(Base):
    __tablename__ = "tags"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False, unique=True)


class NodeTag(Base):
    __tablename__ = "node_tags"
    node_id = Column(String(36), ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True)
    tag_id = Column(String(36), ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)


class Node(Base):
    __tablename__ = "nodes"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    parent_id = Column(String(36), ForeignKey("nodes.id", ondelete="SET NULL"), nullable=True)

    # Core fields
    node_type = Column(String(30), nullable=False, default="attack_step")
    title = Column(String(500), nullable=False, default="New Node")
    description = Column(Text, default="")
    notes = Column(Text, default="")
    logic_type = Column(String(10), default="OR")  # AND, OR, SEQUENCE
    status = Column(String(20), default="draft")  # draft, validated, mitigated, accepted, archived
    sort_order = Column(Integer, default=0)

    # Position on canvas
    position_x = Column(Float, default=0.0)
    position_y = Column(Float, default=0.0)

    # Attack context
    threat_category = Column(String(100), default="")
    attack_surface = Column(String(100), default="")
    platform = Column(String(100), default="")
    required_access = Column(String(100), default="")
    required_privileges = Column(String(100), default="")
    required_tools = Column(Text, default="")
    required_skill = Column(String(50), default="")

    # Scoring - simple mode (1-10)
    likelihood = Column(Float, nullable=True)
    impact = Column(Float, nullable=True)
    effort = Column(Float, nullable=True)
    exploitability = Column(Float, nullable=True)
    detectability = Column(Float, nullable=True)
    confidence = Column(Float, nullable=True)
    inherent_risk = Column(Float, nullable=True)
    residual_risk = Column(Float, nullable=True)

    # Scoring - advanced mode
    probability = Column(Float, nullable=True)
    cost_to_attacker = Column(Float, nullable=True)
    time_estimate = Column(String(50), default="")

    # Roll-up fields (computed)
    rolled_up_risk = Column(Float, nullable=True)
    rolled_up_likelihood = Column(Float, nullable=True)

    # Analyst fields
    assumptions = Column(Text, default="")
    analyst = Column(String(100), default="")
    cve_references = Column(Text, default="")

    # Extended metadata as JSON
    extended_metadata = Column(JSON, default=dict)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    project = relationship("Project", back_populates="nodes")
    children = relationship("Node", backref="parent_node", remote_side="Node.id",
                           foreign_keys="Node.parent_id", viewonly=True)
    mitigations = relationship("Mitigation", back_populates="node", cascade="all, delete-orphan")
    detections = relationship("Detection", back_populates="node", cascade="all, delete-orphan")
    reference_mappings = relationship("ReferenceMapping", back_populates="node", cascade="all, delete-orphan")
    comments = relationship("Comment", back_populates="node", cascade="all, delete-orphan")
    attachments = relationship("Attachment", back_populates="node", cascade="all, delete-orphan")
    tags = relationship("Tag", secondary="node_tags", backref="nodes")
