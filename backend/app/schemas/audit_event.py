from pydantic import BaseModel
from datetime import datetime
from typing import Any


class AuditEventResponse(BaseModel):
    id: str
    project_id: str
    event_type: str
    entity_type: str
    entity_id: str
    detail: dict[str, Any]
    actor: str
    timestamp: datetime

    model_config = {"from_attributes": True}
