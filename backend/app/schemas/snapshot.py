from pydantic import BaseModel
from typing import Any
from datetime import datetime


class SnapshotCreate(BaseModel):
    project_id: str
    label: str = ""


class SnapshotResponse(BaseModel):
    id: str
    project_id: str
    label: str
    created_at: datetime
    created_by: str

    model_config = {"from_attributes": True}


class SnapshotDetailResponse(SnapshotResponse):
    tree_data: dict[str, Any]
