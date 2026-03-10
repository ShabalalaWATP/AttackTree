from fastapi import HTTPException
from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.comment import Comment
from ..models.detection import Detection
from ..models.infra_map import InfraMap
from ..models.kill_chain import KillChain
from ..models.llm_config import LLMProviderConfig
from ..models.mitigation import Mitigation
from ..models.node import Node, Tag
from ..models.project import Project
from ..models.scenario import Scenario
from ..models.snapshot import Snapshot
from ..models.threat_model import ThreatModel
from .auth import get_current_user_id


async def require_project_access(project_id: str, db: AsyncSession) -> Project:
    result = await db.execute(
        select(Project).where(Project.id == project_id, Project.user_id == get_current_user_id())
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


async def require_node_access(
    node_id: str,
    db: AsyncSession,
    *,
    options: tuple = (),
) -> Node:
    query: Select = (
        select(Node)
        .join(Project, Node.project_id == Project.id)
        .where(Node.id == node_id, Project.user_id == get_current_user_id())
    )
    if options:
        query = query.options(*options)
    result = await db.execute(query)
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    return node


async def require_provider_access(provider_id: str, db: AsyncSession) -> LLMProviderConfig:
    result = await db.execute(
        select(LLMProviderConfig).where(
            LLMProviderConfig.id == provider_id,
            LLMProviderConfig.user_id == get_current_user_id(),
        )
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    return provider


async def get_active_provider_for_user(db: AsyncSession) -> LLMProviderConfig | None:
    result = await db.execute(
        select(LLMProviderConfig)
        .where(
            LLMProviderConfig.user_id == get_current_user_id(),
            LLMProviderConfig.is_active == True,
        )
        .limit(1)
    )
    return result.scalar_one_or_none()


async def require_scenario_access(scenario_id: str, db: AsyncSession) -> Scenario:
    result = await db.execute(
        select(Scenario).where(
            Scenario.id == scenario_id,
            Scenario.user_id == get_current_user_id(),
        )
    )
    scenario = result.scalar_one_or_none()
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return scenario


async def require_infra_map_access(infra_map_id: str, db: AsyncSession) -> InfraMap:
    result = await db.execute(
        select(InfraMap).where(
            InfraMap.id == infra_map_id,
            InfraMap.user_id == get_current_user_id(),
        )
    )
    infra_map = result.scalar_one_or_none()
    if not infra_map:
        raise HTTPException(status_code=404, detail="Infrastructure map not found")
    return infra_map


async def require_kill_chain_access(kill_chain_id: str, db: AsyncSession) -> KillChain:
    result = await db.execute(
        select(KillChain)
        .join(Project, KillChain.project_id == Project.id)
        .where(KillChain.id == kill_chain_id, Project.user_id == get_current_user_id())
    )
    kill_chain = result.scalar_one_or_none()
    if not kill_chain:
        raise HTTPException(status_code=404, detail="Kill chain not found")
    return kill_chain


async def require_threat_model_access(threat_model_id: str, db: AsyncSession) -> ThreatModel:
    result = await db.execute(
        select(ThreatModel)
        .join(Project, ThreatModel.project_id == Project.id)
        .where(ThreatModel.id == threat_model_id, Project.user_id == get_current_user_id())
    )
    threat_model = result.scalar_one_or_none()
    if not threat_model:
        raise HTTPException(status_code=404, detail="Threat model not found")
    return threat_model


async def require_snapshot_access(snapshot_id: str, db: AsyncSession) -> Snapshot:
    result = await db.execute(
        select(Snapshot)
        .join(Project, Snapshot.project_id == Project.id)
        .where(Snapshot.id == snapshot_id, Project.user_id == get_current_user_id())
    )
    snapshot = result.scalar_one_or_none()
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return snapshot


async def require_mitigation_access(mitigation_id: str, db: AsyncSession) -> Mitigation:
    result = await db.execute(
        select(Mitigation)
        .join(Node, Mitigation.node_id == Node.id)
        .join(Project, Node.project_id == Project.id)
        .where(Mitigation.id == mitigation_id, Project.user_id == get_current_user_id())
    )
    mitigation = result.scalar_one_or_none()
    if not mitigation:
        raise HTTPException(status_code=404, detail="Mitigation not found")
    return mitigation


async def require_detection_access(detection_id: str, db: AsyncSession) -> Detection:
    result = await db.execute(
        select(Detection)
        .join(Node, Detection.node_id == Node.id)
        .join(Project, Node.project_id == Project.id)
        .where(Detection.id == detection_id, Project.user_id == get_current_user_id())
    )
    detection = result.scalar_one_or_none()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")
    return detection


async def require_comment_access(comment_id: str, db: AsyncSession) -> Comment:
    result = await db.execute(
        select(Comment)
        .join(Node, Comment.node_id == Node.id)
        .join(Project, Node.project_id == Project.id)
        .where(Comment.id == comment_id, Project.user_id == get_current_user_id())
    )
    comment = result.scalar_one_or_none()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    return comment


async def require_tag_access(tag_id: str, db: AsyncSession) -> Tag:
    result = await db.execute(
        select(Tag).where(Tag.id == tag_id, Tag.user_id == get_current_user_id())
    )
    tag = result.scalar_one_or_none()
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")
    return tag
