from pydantic import BaseModel, Field, model_validator
from typing import Optional, Any


MAX_AGENT_DEPTH = 6
MAX_AGENT_BREADTH = 6
MAX_AGENT_NODE_BUDGET = 300


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


class SuggestedItem(BaseModel):
    kind: str = "branch"
    title: str = ""
    description: str = ""
    node_type: str = "attack_step"
    logic_type: str = "OR"
    threat_category: str = ""
    likelihood: Optional[float] = None
    impact: Optional[float] = None
    effectiveness: Optional[float] = None
    coverage: Optional[float] = None
    data_source: str = ""
    framework: str = ""
    ref_id: str = ""
    ref_name: str = ""
    confidence: Optional[float] = None
    rationale: str = ""
    source: str = "manual"


class LLMSuggestResponse(BaseModel):
    suggestions: list[SuggestedItem]
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
    total_passes: int = 4
    warnings: list[str] = Field(default_factory=list)
    agent_run_id: Optional[str] = None
    background_processing: bool = False
    current_stage: str = ""
    post_processing_status: str = ""


class LLMAgentRunStatusResponse(BaseModel):
    id: str
    project_id: str = ""
    status: str
    current_stage: str = ""
    nodes_created: int = 0
    passes_completed: int = 0
    total_passes: int = 4
    warnings: list[str] = Field(default_factory=list)
    error_message: str = ""
    model_used: str = ""
    tokens_used: int = 0
    elapsed_ms: int = 0
    checkpoints: dict[str, Any] = Field(default_factory=dict)
    background_processing: bool = False
