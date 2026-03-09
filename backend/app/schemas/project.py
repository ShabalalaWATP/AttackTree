from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str = ""
    context_preset: str = "general"
    root_objective: str = ""
    owner: str = "analyst"


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    context_preset: Optional[str] = None
    root_objective: Optional[str] = None
    owner: Optional[str] = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: str
    context_preset: str
    root_objective: str
    owner: str
    created_at: datetime
    updated_at: datetime
    node_count: int = 0

    model_config = {"from_attributes": True}


class ProjectListResponse(BaseModel):
    projects: list[ProjectResponse]
    total: int
