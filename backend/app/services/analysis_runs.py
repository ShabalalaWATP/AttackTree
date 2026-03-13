from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..models.analysis_run import AnalysisRun


async def record_analysis_run(
    db: AsyncSession,
    *,
    project_id: str | None,
    tool: str,
    run_type: str,
    status: str = "completed",
    artifact_kind: str = "",
    artifact_id: str | None = None,
    artifact_name: str = "",
    summary: str = "",
    metadata: dict[str, Any] | None = None,
    duration_ms: int | None = None,
) -> AnalysisRun | None:
    if not project_id:
        return None

    run = AnalysisRun(
        project_id=project_id,
        tool=tool,
        run_type=run_type,
        status=status,
        artifact_kind=artifact_kind,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        summary=summary or "",
        metadata_json=metadata or {},
        duration_ms=max(0, int(duration_ms or 0)),
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    return run


async def update_analysis_run(
    db: AsyncSession,
    analysis_run_id: str | None,
    *,
    status: str | None = None,
    artifact_kind: str | None = None,
    artifact_id: str | None = None,
    artifact_name: str | None = None,
    summary: str | None = None,
    metadata: dict[str, Any] | None = None,
    duration_ms: int | None = None,
    commit: bool = False,
) -> AnalysisRun | None:
    if not analysis_run_id:
        return None

    run = await db.get(AnalysisRun, analysis_run_id)
    if not run:
        return None

    if status is not None:
        run.status = status
    if artifact_kind is not None:
        run.artifact_kind = artifact_kind
    if artifact_id is not None:
        run.artifact_id = artifact_id
    if artifact_name is not None:
        run.artifact_name = artifact_name
    if summary is not None:
        run.summary = summary
    if metadata:
        run.metadata_json = {
            **(run.metadata_json or {}),
            **metadata,
        }
    if duration_ms is not None:
        run.duration_ms = max(0, int(duration_ms))

    if commit:
        await db.commit()
        await db.refresh(run)
    return run
