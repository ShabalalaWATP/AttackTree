from pydantic import BaseModel, Field
from typing import Optional, Any
from datetime import datetime


class NodeCreate(BaseModel):
    project_id: str
    parent_id: Optional[str] = None
    node_type: str = "attack_step"
    title: str = Field(default="New Node", max_length=500)
    description: str = ""
    notes: str = ""
    logic_type: str = "OR"
    status: str = "draft"
    sort_order: int = 0
    position_x: float = 0.0
    position_y: float = 0.0
    threat_category: str = ""
    attack_surface: str = ""
    platform: str = ""
    required_access: str = ""
    required_privileges: str = ""
    required_tools: str = ""
    required_skill: str = ""
    likelihood: Optional[float] = Field(default=None, ge=0, le=10)
    impact: Optional[float] = Field(default=None, ge=0, le=10)
    effort: Optional[float] = Field(default=None, ge=0, le=10)
    exploitability: Optional[float] = Field(default=None, ge=0, le=10)
    detectability: Optional[float] = Field(default=None, ge=0, le=10)
    confidence: Optional[float] = Field(default=None, ge=0, le=10)
    probability: Optional[float] = Field(default=None, ge=0, le=1)
    cost_to_attacker: Optional[float] = Field(default=None, ge=0, le=10)
    time_estimate: str = ""
    assumptions: str = ""
    analyst: str = ""
    cve_references: str = ""
    extended_metadata: dict[str, Any] = {}


class NodeUpdate(BaseModel):
    parent_id: Optional[str] = None
    node_type: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    notes: Optional[str] = None
    logic_type: Optional[str] = None
    status: Optional[str] = None
    sort_order: Optional[int] = None
    position_x: Optional[float] = None
    position_y: Optional[float] = None
    threat_category: Optional[str] = None
    attack_surface: Optional[str] = None
    platform: Optional[str] = None
    required_access: Optional[str] = None
    required_privileges: Optional[str] = None
    required_tools: Optional[str] = None
    required_skill: Optional[str] = None
    likelihood: Optional[float] = Field(default=None, ge=0, le=10)
    impact: Optional[float] = Field(default=None, ge=0, le=10)
    effort: Optional[float] = Field(default=None, ge=0, le=10)
    exploitability: Optional[float] = Field(default=None, ge=0, le=10)
    detectability: Optional[float] = Field(default=None, ge=0, le=10)
    confidence: Optional[float] = Field(default=None, ge=0, le=10)
    inherent_risk: Optional[float] = Field(default=None, ge=0, le=10)
    residual_risk: Optional[float] = Field(default=None, ge=0, le=10)
    probability: Optional[float] = Field(default=None, ge=0, le=1)
    cost_to_attacker: Optional[float] = Field(default=None, ge=0, le=10)
    time_estimate: Optional[str] = None
    assumptions: Optional[str] = None
    analyst: Optional[str] = None
    cve_references: Optional[str] = None
    extended_metadata: Optional[dict[str, Any]] = None


class MitigationSummary(BaseModel):
    id: str
    title: str
    effectiveness: float
    status: str
    model_config = {"from_attributes": True}


class DetectionSummary(BaseModel):
    id: str
    title: str
    coverage: float
    model_config = {"from_attributes": True}


class ReferenceMappingSummary(BaseModel):
    id: str
    node_id: str
    framework: str
    ref_id: str
    ref_name: str
    confidence: Optional[float] = None
    rationale: str
    source: str
    model_config = {"from_attributes": True}


class TagSummary(BaseModel):
    id: str
    name: str
    model_config = {"from_attributes": True}


class NodeResponse(BaseModel):
    id: str
    project_id: str
    parent_id: Optional[str]
    node_type: str
    title: str
    description: str
    notes: str
    logic_type: str
    status: str
    sort_order: int
    position_x: float
    position_y: float
    threat_category: str
    attack_surface: str
    platform: str
    required_access: str
    required_privileges: str
    required_tools: str
    required_skill: str
    likelihood: Optional[float]
    impact: Optional[float]
    effort: Optional[float]
    exploitability: Optional[float]
    detectability: Optional[float]
    confidence: Optional[float]
    inherent_risk: Optional[float]
    residual_risk: Optional[float]
    probability: Optional[float]
    cost_to_attacker: Optional[float]
    time_estimate: str
    rolled_up_risk: Optional[float]
    rolled_up_likelihood: Optional[float]
    assumptions: str
    analyst: str
    cve_references: str
    extended_metadata: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    mitigations: list[MitigationSummary] = []
    detections: list[DetectionSummary] = []
    reference_mappings: list[ReferenceMappingSummary] = []
    tags: list[TagSummary] = []

    model_config = {"from_attributes": True}
