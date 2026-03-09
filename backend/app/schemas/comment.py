from pydantic import BaseModel
from datetime import datetime


class CommentCreate(BaseModel):
    node_id: str
    author: str = "analyst"
    text: str


class CommentResponse(BaseModel):
    id: str
    node_id: str
    author: str
    text: str
    created_at: datetime

    model_config = {"from_attributes": True}
