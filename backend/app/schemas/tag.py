from pydantic import BaseModel


class TagCreate(BaseModel):
    name: str


class TagResponse(BaseModel):
    id: str
    name: str

    model_config = {"from_attributes": True}
