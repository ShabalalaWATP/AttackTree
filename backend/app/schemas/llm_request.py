from pydantic import BaseModel, Field, model_validator
from typing import Optional, Any


MAX_AGENT_DEPTH = 6
MAX_AGENT_BREADTH = 6
MAX_AGENT_NODE_BUDGET = 240


def _estimate_tree_node_budget(depth: int, breadth: int) -> int:
    total = 1
    level_size = 1
    for _ in range(1, depth):
        level_size *= breadth
        total += level_size
    return total


class LLMSuggestRequest(BaseModel):
    node_id: str
    project_id: str
    suggestion_type: str = "branches"  # branches, mitigations, detections, mappings, prerequisites
    additional_context: str = ""
    technical_depth: str = "standard"
    prompt_profile: str = ""


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


class LLMAgentRequest(BaseModel):
    project_id: str
    objective: str
    scope: str = ""
    depth: int = Field(default=4, ge=2, le=MAX_AGENT_DEPTH)
    breadth: int = Field(default=5, ge=2, le=MAX_AGENT_BREADTH)
    mode: str = "generate"  # generate | from_template | expand
    template_id: Optional[str] = None
    generation_profile: str = "balanced"  # planning_first | balanced | reference_heavy

    @model_validator(mode="after")
    def validate_agent_request(self):
        normalized_mode = (self.mode or "").strip().lower()
        if normalized_mode not in {"generate", "from_template", "expand"}:
            raise ValueError("Mode must be one of: generate, from_template, expand.")

        if normalized_mode == "from_template" and not (self.template_id or "").strip():
            raise ValueError("template_id is required for from_template mode.")

        if normalized_mode != "expand":
            objective = (self.objective or "").strip()
            if not objective:
                raise ValueError("Enter an attacker objective before generating a tree.")

            estimated_nodes = _estimate_tree_node_budget(self.depth, self.breadth)
            if estimated_nodes > MAX_AGENT_NODE_BUDGET:
                raise ValueError(
                    "Requested tree size is too large for robust generation "
                    f"({estimated_nodes} estimated nodes). Reduce depth or breadth."
                )

        return self


class LLMAgentResponse(BaseModel):
    nodes_created: int
    model_used: str = ""
    elapsed_ms: int = 0
    passes_completed: int = 1
    warnings: list[str] = Field(default_factory=list)
