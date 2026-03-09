from pydantic import BaseModel
from typing import Optional, Any


class LLMSuggestRequest(BaseModel):
    node_id: str
    project_id: str
    suggestion_type: str = "branches"  # branches, mitigations, detections, mappings, prerequisites
    additional_context: str = ""


class SuggestedNode(BaseModel):
    title: str
    description: str = ""
    node_type: str = "attack_step"
    logic_type: str = "OR"
    threat_category: str = ""
    likelihood: Optional[float] = None
    impact: Optional[float] = None


class LLMSuggestResponse(BaseModel):
    suggestions: list[SuggestedNode]
    prompt_used: str = ""
    model_used: str = ""
    raw_response: str = ""


class LLMSummaryRequest(BaseModel):
    project_id: str
    summary_type: str = "technical"  # technical, executive, report_draft
    additional_context: str = ""


class LLMSummaryResponse(BaseModel):
    summary: str
    prompt_used: str = ""
    model_used: str = ""
