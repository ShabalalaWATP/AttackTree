from pydantic import BaseModel
from typing import Optional


class ExportRequest(BaseModel):
    project_id: str
    format: str = "json"  # json, csv, markdown, pdf
    include_metadata: bool = True
    include_mitigations: bool = True
    include_mappings: bool = True
    report_type: str = "technical"  # technical, executive
