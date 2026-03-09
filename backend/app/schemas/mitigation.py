from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class MitigationCreate(BaseModel):
    node_id: str
    title: str
    description: str = ""
    effectiveness: float = Field(default=0.5, ge=0, le=1)
    status: str = "proposed"
    control_ref: str = ""


class MitigationUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    effectiveness: Optional[float] = Field(default=None, ge=0, le=1)
    status: Optional[str] = None
    control_ref: Optional[str] = None


class MitigationResponse(BaseModel):
    id: str
    node_id: str
    title: str
    description: str
    effectiveness: float
    status: str
    control_ref: str
    created_at: datetime

    model_config = {"from_attributes": True}
