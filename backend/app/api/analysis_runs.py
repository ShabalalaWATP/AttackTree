from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.analysis_run import AnalysisRun
from ..services.access_control import require_project_access

router = APIRouter(prefix="/analysis-runs", tags=["analysis-runs"])


class AnalysisRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    tool: str
    run_type: str
    status: str
    artifact_kind: str
    artifact_id: str | None = None
    artifact_name: str
    summary: str
    metadata_json: dict
    duration_ms: int
    created_at: str


def _to_response(run: AnalysisRun) -> AnalysisRunResponse:
    return AnalysisRunResponse(
        id=run.id,
        project_id=run.project_id,
        tool=run.tool,
        run_type=run.run_type,
        status=run.status,
        artifact_kind=run.artifact_kind or "",
        artifact_id=run.artifact_id,
        artifact_name=run.artifact_name or "",
        summary=run.summary or "",
        metadata_json=run.metadata_json or {},
        duration_ms=run.duration_ms or 0,
        created_at=run.created_at.isoformat() if run.created_at else "",
    )


@router.get("/project/{project_id}", response_model=list[AnalysisRunResponse])
async def list_analysis_runs(
    project_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    await require_project_access(project_id, db)
    result = await db.execute(
        select(AnalysisRun)
        .where(AnalysisRun.project_id == project_id)
        .order_by(AnalysisRun.created_at.desc())
        .limit(limit)
    )
    return [_to_response(run) for run in result.scalars().all()]
