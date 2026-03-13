from pydantic import BaseModel, Field


class ReferenceSearchRequest(BaseModel):
    query: str = ""
    artifact_type: str = ""
    context_preset: str = ""
    objective: str = ""
    scope: str = ""
    target_kind: str = ""
    target_summary: str = ""
    allowed_frameworks: list[str] = Field(default_factory=list)
    limit: int = Field(default=10, ge=1, le=50)


class ReferenceSearchItem(BaseModel):
    framework: str
    ref_id: str
    ref_name: str
    description: str = ""
    category: str | None = None
    tactic: str | None = None
    severity: str | None = None
    score: int
    reasons: list[str] = Field(default_factory=list)


class ReferenceSearchResponse(BaseModel):
    items: list[ReferenceSearchItem]
