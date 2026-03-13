from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.analysis_run import AnalysisRun
from ..models.detection import Detection
from ..models.infra_map import InfraMap
from ..models.kill_chain import KillChain
from ..models.mitigation import Mitigation
from ..models.node import Node
from ..models.project import Project
from ..models.reference_mapping import ReferenceMapping
from ..models.scenario import Scenario
from ..models.snapshot import Snapshot
from ..models.threat_model import ThreatModel
from ..schemas.project import ProjectResponse
from ..services.access_control import require_project_access
from ..services.auth import get_current_user_id

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_BATCH_SIZE = 400
_RISK_BUCKETS = (
    ("Low", 0.0, 2.0, "bg-emerald-500"),
    ("Guarded", 2.0, 4.0, "bg-blue-500"),
    ("Medium", 4.0, 6.0, "bg-amber-500"),
    ("High", 6.0, 8.0, "bg-orange-500"),
    ("Critical", 8.0, 10.1, "bg-red-500"),
)


class ArtifactCountsResponse(BaseModel):
    scenarios: int = 0
    kill_chains: int = 0
    threat_models: int = 0
    infra_maps: int = 0
    snapshots: int = 0


class DashboardNodeSummaryResponse(BaseModel):
    id: str
    title: str
    node_type: str
    inherent_risk: float | None = None
    residual_risk: float | None = None
    mitigation_count: int = 0
    detection_count: int = 0
    mapping_count: int = 0
    status: str = ""
    platform: str = ""
    attack_surface: str = ""
    required_access: str = ""
    created_at: datetime | None = None
    updated_at: datetime | None = None


class RiskBucketResponse(BaseModel):
    label: str
    count: int
    color: str


class DashboardAnalysisResponse(BaseModel):
    total_nodes: int = 0
    scored: int = 0
    avg_risk: float = 0.0
    max_risk: float = 0.0
    residual_scored: int = 0
    avg_residual_risk: float = 0.0
    residual_reduction_pct: float = 0.0
    critical_count: int = 0
    review_backlog: int = 0
    gap_count: int = 0
    no_mitigation_count: int = 0
    no_detection_count: int = 0
    no_mapping_count: int = 0
    mitigation_pct: float = 0.0
    detection_pct: float = 0.0
    mapping_pct: float = 0.0
    top_risks: list[DashboardNodeSummaryResponse] = Field(default_factory=list)
    unmitigated: list[DashboardNodeSummaryResponse] = Field(default_factory=list)
    gap_queue: list[DashboardNodeSummaryResponse] = Field(default_factory=list)
    recent_updates: list[DashboardNodeSummaryResponse] = Field(default_factory=list)
    by_type: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_surface: dict[str, int] = Field(default_factory=dict)
    by_platform: dict[str, int] = Field(default_factory=dict)
    by_access: dict[str, int] = Field(default_factory=dict)
    risk_buckets: list[RiskBucketResponse] = Field(default_factory=list)


class DashboardRunResponse(BaseModel):
    id: str
    project_id: str
    tool: str
    run_type: str
    status: str
    artifact_kind: str
    artifact_id: str | None = None
    artifact_name: str
    summary: str
    metadata_json: dict[str, Any]
    duration_ms: int
    created_at: str


class DashboardWorkspaceResponse(BaseModel):
    project: ProjectResponse
    artifacts: ArtifactCountsResponse
    analysis: DashboardAnalysisResponse
    total_artifacts: int = 0


class DashboardPortfolioResponse(BaseModel):
    workspaces: list[DashboardWorkspaceResponse] = Field(default_factory=list)
    aggregate: DashboardAnalysisResponse = Field(default_factory=DashboardAnalysisResponse)
    artifact_totals: ArtifactCountsResponse = Field(default_factory=ArtifactCountsResponse)
    project_scans: int = 0
    standalone_scans: int = 0
    contexts: dict[str, int] = Field(default_factory=dict)


class DashboardProjectResponse(BaseModel):
    project: ProjectResponse
    artifacts: ArtifactCountsResponse = Field(default_factory=ArtifactCountsResponse)
    analysis: DashboardAnalysisResponse = Field(default_factory=DashboardAnalysisResponse)
    analysis_runs: list[DashboardRunResponse] = Field(default_factory=list)


def _workspace_mode(project: Project) -> str:
    return (project.metadata_json or {}).get("workspace_mode", "project_scan")


def _batched(values: list[str], size: int = _BATCH_SIZE):
    for index in range(0, len(values), size):
        yield values[index:index + size]


def _node_card(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": record["id"],
        "title": record["title"],
        "node_type": record["node_type"],
        "inherent_risk": record["inherent_risk"],
        "residual_risk": record["residual_risk"],
        "mitigation_count": record["mitigation_count"],
        "detection_count": record["detection_count"],
        "mapping_count": record["mapping_count"],
        "status": record["status"],
        "platform": record["platform"],
        "attack_surface": record["attack_surface"],
        "required_access": record["required_access"],
        "created_at": record["created_at"],
        "updated_at": record["updated_at"],
    }


def _artifact_total(artifacts: ArtifactCountsResponse) -> int:
    return (
        artifacts.scenarios
        + artifacts.kill_chains
        + artifacts.threat_models
        + artifacts.infra_maps
        + artifacts.snapshots
    )


def _safe_timestamp(value: datetime | None) -> float:
    return value.timestamp() if value is not None else 0.0


def _coverage_gap_reasons(record: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if record["mitigation_count"] <= 0:
        reasons.append("No controls")
    if record["detection_count"] <= 0:
        reasons.append("No detections")
    if record["mapping_count"] <= 0:
        reasons.append("No references")
    return reasons


def _empty_analysis() -> DashboardAnalysisResponse:
    return DashboardAnalysisResponse(
        risk_buckets=[
            RiskBucketResponse(label=label, count=0, color=color)
            for label, _, _, color in _RISK_BUCKETS
        ]
    )


def _analyse_nodes(records: list[dict[str, Any]]) -> DashboardAnalysisResponse:
    if not records:
        return _empty_analysis()

    scored = [record for record in records if record["inherent_risk"] is not None]
    residual_scored = [record for record in records if record["residual_risk"] is not None]
    dual_scored = [
        record
        for record in records
        if record["inherent_risk"] is not None and record["residual_risk"] is not None
    ]

    by_type: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_surface: dict[str, int] = {}
    by_platform: dict[str, int] = {}
    by_access: dict[str, int] = {}

    mitigated = 0
    with_detections = 0
    with_mappings = 0

    for record in records:
        by_type[record["node_type"]] = by_type.get(record["node_type"], 0) + 1
        by_status[record["status"]] = by_status.get(record["status"], 0) + 1
        by_surface[record["attack_surface"] or "Unknown"] = by_surface.get(record["attack_surface"] or "Unknown", 0) + 1
        by_platform[record["platform"] or "Unspecified"] = by_platform.get(record["platform"] or "Unspecified", 0) + 1
        by_access[record["required_access"] or "Unspecified"] = by_access.get(record["required_access"] or "Unspecified", 0) + 1

        if record["mitigation_count"] > 0:
            mitigated += 1
        if record["detection_count"] > 0:
            with_detections += 1
        if record["mapping_count"] > 0:
            with_mappings += 1

    top_risks = sorted(
        scored,
        key=lambda record: ((record["inherent_risk"] or 0.0), _safe_timestamp(record["updated_at"])),
        reverse=True,
    )[:10]
    unmitigated = sorted(
        [record for record in scored if record["mitigation_count"] <= 0],
        key=lambda record: ((record["inherent_risk"] or 0.0), _safe_timestamp(record["updated_at"])),
        reverse=True,
    )
    gap_queue = sorted(
        [
            record
            for record in scored
            if (record["inherent_risk"] or 0.0) >= 6.0 and _coverage_gap_reasons(record)
        ],
        key=lambda record: ((record["inherent_risk"] or 0.0), _safe_timestamp(record["updated_at"])),
        reverse=True,
    )[:8]
    recent_updates = sorted(
        records,
        key=lambda record: _safe_timestamp(record["updated_at"] or record["created_at"]),
        reverse=True,
    )[:8]

    avg_risk = (
        sum(record["inherent_risk"] or 0.0 for record in scored) / len(scored)
        if scored
        else 0.0
    )
    avg_residual_risk = (
        sum(record["residual_risk"] or 0.0 for record in residual_scored) / len(residual_scored)
        if residual_scored
        else 0.0
    )
    max_risk = max((record["inherent_risk"] or 0.0 for record in scored), default=0.0)
    critical_count = sum(1 for record in scored if (record["inherent_risk"] or 0.0) >= 8.0)
    total_inherent = sum(record["inherent_risk"] or 0.0 for record in dual_scored)
    total_residual = sum(record["residual_risk"] or 0.0 for record in dual_scored)
    residual_reduction_pct = (
        ((total_inherent - total_residual) / total_inherent) * 100.0
        if total_inherent > 0
        else 0.0
    )

    risk_buckets: list[RiskBucketResponse] = []
    for label, minimum, maximum, color in _RISK_BUCKETS:
        count = sum(
            1
            for record in scored
            if (record["inherent_risk"] or 0.0) >= minimum and (record["inherent_risk"] or 0.0) < maximum
        )
        risk_buckets.append(RiskBucketResponse(label=label, count=count, color=color))

    return DashboardAnalysisResponse(
        total_nodes=len(records),
        scored=len(scored),
        avg_risk=round(avg_risk, 2),
        max_risk=round(max_risk, 2),
        residual_scored=len(residual_scored),
        avg_residual_risk=round(avg_residual_risk, 2),
        residual_reduction_pct=round(residual_reduction_pct, 2),
        critical_count=critical_count,
        review_backlog=sum(
            1 for record in records if record["status"] == "draft" or record["inherent_risk"] is None
        ),
        gap_count=sum(
            1
            for record in scored
            if (record["inherent_risk"] or 0.0) >= 6.0 and _coverage_gap_reasons(record)
        ),
        no_mitigation_count=sum(1 for record in records if record["mitigation_count"] <= 0),
        no_detection_count=sum(1 for record in records if record["detection_count"] <= 0),
        no_mapping_count=sum(1 for record in records if record["mapping_count"] <= 0),
        mitigation_pct=round((mitigated / len(records)) * 100.0, 2),
        detection_pct=round((with_detections / len(records)) * 100.0, 2),
        mapping_pct=round((with_mappings / len(records)) * 100.0, 2),
        top_risks=[DashboardNodeSummaryResponse(**_node_card(record)) for record in top_risks],
        unmitigated=[DashboardNodeSummaryResponse(**_node_card(record)) for record in unmitigated[:10]],
        gap_queue=[DashboardNodeSummaryResponse(**_node_card(record)) for record in gap_queue],
        recent_updates=[DashboardNodeSummaryResponse(**_node_card(record)) for record in recent_updates],
        by_type=by_type,
        by_status=by_status,
        by_surface=by_surface,
        by_platform=by_platform,
        by_access=by_access,
        risk_buckets=risk_buckets,
    )


def _project_response(project: Project, node_count: int) -> ProjectResponse:
    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        context_preset=project.context_preset,
        root_objective=project.root_objective,
        owner=project.owner,
        workspace_mode=_workspace_mode(project),
        created_at=project.created_at,
        updated_at=project.updated_at,
        node_count=node_count,
    )


async def _count_by_field(
    db: AsyncSession,
    field,
    values: list[str],
) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not values:
        return counts

    for batch in _batched(values):
        result = await db.execute(
            select(field, func.count())
            .where(field.in_(batch))
            .group_by(field)
        )
        for key, count in result.all():
            if key is None:
                continue
            counts[str(key)] = int(count or 0)
    return counts


async def _load_node_records(db: AsyncSession, project_ids: list[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not project_ids:
        return records

    for batch in _batched(project_ids):
        result = await db.execute(
            select(
                Node.id,
                Node.project_id,
                Node.node_type,
                Node.title,
                Node.status,
                Node.platform,
                Node.attack_surface,
                Node.required_access,
                Node.inherent_risk,
                Node.residual_risk,
                Node.created_at,
                Node.updated_at,
            ).where(Node.project_id.in_(batch))
        )
        for row in result.all():
            records.append(
                {
                    "id": row.id,
                    "project_id": row.project_id,
                    "node_type": row.node_type,
                    "title": row.title,
                    "status": row.status or "",
                    "platform": row.platform or "",
                    "attack_surface": row.attack_surface or "",
                    "required_access": row.required_access or "",
                    "inherent_risk": row.inherent_risk,
                    "residual_risk": row.residual_risk,
                    "created_at": row.created_at,
                    "updated_at": row.updated_at or row.created_at,
                }
            )
    return records


async def _attach_node_coverage_counts(
    db: AsyncSession,
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not records:
        return records

    node_ids = [record["id"] for record in records]
    mitigation_counts = await _count_by_field(db, Mitigation.node_id, node_ids)
    detection_counts = await _count_by_field(db, Detection.node_id, node_ids)
    mapping_counts = await _count_by_field(db, ReferenceMapping.node_id, node_ids)

    enriched: list[dict[str, Any]] = []
    for record in records:
        enriched.append(
            {
                **record,
                "mitigation_count": mitigation_counts.get(record["id"], 0),
                "detection_count": detection_counts.get(record["id"], 0),
                "mapping_count": mapping_counts.get(record["id"], 0),
            }
        )
    return enriched


async def _load_artifact_counts(
    db: AsyncSession,
    project_ids: list[str],
) -> dict[str, ArtifactCountsResponse]:
    counts = {project_id: ArtifactCountsResponse() for project_id in project_ids}
    if not project_ids:
        return counts

    grouped_sources = (
        ("scenarios", Scenario.project_id),
        ("kill_chains", KillChain.project_id),
        ("threat_models", ThreatModel.project_id),
        ("infra_maps", InfraMap.project_id),
        ("snapshots", Snapshot.project_id),
    )

    for field_name, project_field in grouped_sources:
        grouped = await _count_by_field(db, project_field, project_ids)
        for project_id, count in grouped.items():
            setattr(counts[project_id], field_name, count)

    return counts


def _serialise_run(run: AnalysisRun) -> DashboardRunResponse:
    return DashboardRunResponse(
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


async def _load_runs_for_project(db: AsyncSession, project_id: str, limit: int = 30) -> list[DashboardRunResponse]:
    result = await db.execute(
        select(AnalysisRun)
        .where(AnalysisRun.project_id == project_id)
        .order_by(AnalysisRun.created_at.desc())
        .limit(limit)
    )
    return [_serialise_run(run) for run in result.scalars().all()]


@router.get("/portfolio", response_model=DashboardPortfolioResponse)
async def get_portfolio_dashboard(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Project)
        .where(Project.user_id == get_current_user_id())
        .order_by(Project.updated_at.desc())
    )
    projects = result.scalars().all()
    if not projects:
        return DashboardPortfolioResponse()

    project_ids = [project.id for project in projects]
    node_records = await _attach_node_coverage_counts(db, await _load_node_records(db, project_ids))
    node_records_by_project: dict[str, list[dict[str, Any]]] = {project_id: [] for project_id in project_ids}
    for record in node_records:
        node_records_by_project.setdefault(record["project_id"], []).append(record)

    artifact_counts = await _load_artifact_counts(db, project_ids)

    workspaces: list[DashboardWorkspaceResponse] = []
    contexts: dict[str, int] = {}
    project_scans = 0
    standalone_scans = 0

    for project in projects:
        project_nodes = node_records_by_project.get(project.id, [])
        project_artifacts = artifact_counts.get(project.id, ArtifactCountsResponse())
        analysis = _analyse_nodes(project_nodes)
        workspaces.append(
            DashboardWorkspaceResponse(
                project=_project_response(project, len(project_nodes)),
                artifacts=project_artifacts,
                analysis=analysis,
                total_artifacts=_artifact_total(project_artifacts),
            )
        )

        context_key = (project.context_preset or "general").strip() or "general"
        contexts[context_key] = contexts.get(context_key, 0) + 1
        if _workspace_mode(project) == "standalone_scan":
            standalone_scans += 1
        else:
            project_scans += 1

    artifact_totals = ArtifactCountsResponse(
        scenarios=sum(workspace.artifacts.scenarios for workspace in workspaces),
        kill_chains=sum(workspace.artifacts.kill_chains for workspace in workspaces),
        threat_models=sum(workspace.artifacts.threat_models for workspace in workspaces),
        infra_maps=sum(workspace.artifacts.infra_maps for workspace in workspaces),
        snapshots=sum(workspace.artifacts.snapshots for workspace in workspaces),
    )

    return DashboardPortfolioResponse(
        workspaces=workspaces,
        aggregate=_analyse_nodes(node_records),
        artifact_totals=artifact_totals,
        project_scans=project_scans,
        standalone_scans=standalone_scans,
        contexts=contexts,
    )


@router.get("/project/{project_id}", response_model=DashboardProjectResponse)
async def get_project_dashboard(project_id: str, db: AsyncSession = Depends(get_db)):
    project = await require_project_access(project_id, db)
    node_records = await _attach_node_coverage_counts(db, await _load_node_records(db, [project.id]))
    artifacts = (await _load_artifact_counts(db, [project.id])).get(project.id, ArtifactCountsResponse())
    analysis_runs = await _load_runs_for_project(db, project.id)

    return DashboardProjectResponse(
        project=_project_response(project, len(node_records)),
        artifacts=artifacts,
        analysis=_analyse_nodes(node_records),
        analysis_runs=analysis_runs,
    )
