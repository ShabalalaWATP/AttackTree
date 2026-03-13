from pydantic import BaseModel
from typing import Optional


class ReferenceMappingCreate(BaseModel):
    node_id: str
    framework: str
    ref_id: str
    ref_name: str = ""
    confidence: float | None = None
    rationale: str = ""
    source: str = "manual"


class ReferenceMappingUpdate(BaseModel):
    framework: Optional[str] = None
    ref_id: Optional[str] = None
    ref_name: Optional[str] = None
    confidence: Optional[float] = None
    rationale: Optional[str] = None
    source: Optional[str] = None


class ReferenceMappingResponse(BaseModel):
    id: str
    node_id: str
    framework: str
    ref_id: str
    ref_name: str
    confidence: float | None = None
    rationale: str
    source: str

    model_config = {"from_attributes": True}
