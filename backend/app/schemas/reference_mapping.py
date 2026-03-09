from pydantic import BaseModel
from typing import Optional


class ReferenceMappingCreate(BaseModel):
    node_id: str
    framework: str
    ref_id: str
    ref_name: str = ""


class ReferenceMappingUpdate(BaseModel):
    framework: Optional[str] = None
    ref_id: Optional[str] = None
    ref_name: Optional[str] = None


class ReferenceMappingResponse(BaseModel):
    id: str
    node_id: str
    framework: str
    ref_id: str
    ref_name: str

    model_config = {"from_attributes": True}
