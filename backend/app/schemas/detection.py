from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class DetectionCreate(BaseModel):
    node_id: str
    title: str
    description: str = ""
    coverage: float = Field(default=0.5, ge=0, le=1)
    data_source: str = ""


class DetectionUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    coverage: Optional[float] = Field(default=None, ge=0, le=1)
    data_source: Optional[str] = None


class DetectionResponse(BaseModel):
    id: str
    node_id: str
    title: str
    description: str
    coverage: float
    data_source: str
    created_at: datetime

    model_config = {"from_attributes": True}
