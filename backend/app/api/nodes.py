from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
from typing import Optional
from ..database import get_db
from ..models.node import Node
from ..models.mitigation import Mitigation
from ..models.detection import Detection
from ..models.reference_mapping import ReferenceMapping
from ..schemas.node import NodeCreate, NodeUpdate, NodeResponse
from ..services.auth import get_current_user_id
from ..services.risk_engine import compute_inherent_risk, compute_residual_risk, compute_advanced_risk
from ..services.access_control import require_node_access, require_project_access
from ..services.audit import log_event

router = APIRouter(prefix="/nodes", tags=["nodes"])


def _node_to_response(node: Node) -> NodeResponse:
    return NodeResponse.model_validate(node)


@router.get("/project/{project_id}", response_model=list[NodeResponse])
async def list_nodes(project_id: str, db: AsyncSession = Depends(get_db)):
    await require_project_access(project_id, db)
    result = await db.execute(
        select(Node)
        .where(Node.project_id == project_id)
        .options(
            selectinload(Node.mitigations),
            selectinload(Node.detections),
            selectinload(Node.reference_mappings),
            selectinload(Node.tags),
        )
        .order_by(Node.sort_order)
    )
    nodes = result.scalars().all()
    return [_node_to_response(n) for n in nodes]


@router.post("", response_model=NodeResponse, status_code=201)
async def create_node(data: NodeCreate, db: AsyncSession = Depends(get_db)):
    await require_project_access(data.project_id, db)
    node = Node(**data.model_dump())

    # Compute initial scores
    node.inherent_risk = compute_inherent_risk(
        node.likelihood, node.impact, node.effort,
        node.exploitability, node.detectability,
    )

    db.add(node)
    await log_event(db, node.project_id, "node_created", "node", node.id, {"title": node.title})
    await db.commit()
    await db.refresh(node)

    # Reload with relationships
    result = await db.execute(
        select(Node).where(Node.id == node.id)
        .options(selectinload(Node.mitigations), selectinload(Node.detections), selectinload(Node.reference_mappings), selectinload(Node.tags))
    )
    node = result.scalar_one()
    return _node_to_response(node)


@router.get("/{node_id}", response_model=NodeResponse)
async def get_node(node_id: str, db: AsyncSession = Depends(get_db)):
    node = await require_node_access(
        node_id,
        db,
        options=(
            selectinload(Node.mitigations),
            selectinload(Node.detections),
            selectinload(Node.reference_mappings),
            selectinload(Node.tags),
        ),
    )
    return _node_to_response(node)


@router.patch("/{node_id}", response_model=NodeResponse)
async def update_node(node_id: str, data: NodeUpdate, db: AsyncSession = Depends(get_db)):
    node = await require_node_access(
        node_id,
        db,
        options=(
            selectinload(Node.mitigations),
            selectinload(Node.detections),
            selectinload(Node.reference_mappings),
            selectinload(Node.tags),
        ),
    )

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(node, key, value)

    # Recompute scores - simple mode
    node.inherent_risk = compute_inherent_risk(
        node.likelihood, node.impact, node.effort,
        node.exploitability, node.detectability,
    )

    # Also compute advanced risk if probability is set
    if node.probability is not None:
        advanced = compute_advanced_risk(node.probability, node.impact, node.cost_to_attacker)
        if advanced is not None and node.inherent_risk is None:
            node.inherent_risk = advanced

    # Compute residual risk
    max_eff = 0.0
    if node.mitigations:
        max_eff = max((m.effectiveness for m in node.mitigations), default=0.0)
    node.residual_risk = compute_residual_risk(node.inherent_risk, max_eff)

    await log_event(db, node.project_id, "node_updated", "node", node_id, {"title": node.title, "fields": list(update_data.keys())})
    await db.commit()
    await db.refresh(node)
    return _node_to_response(node)


@router.delete("/{node_id}", status_code=204)
async def delete_node(node_id: str, db: AsyncSession = Depends(get_db)):
    node = await require_node_access(node_id, db)

    # Re-parent children to this node's parent
    children_result = await db.execute(
        select(Node).where(Node.parent_id == node_id, Node.project_id == node.project_id)
    )
    children = children_result.scalars().all()
    for child in children:
        child.parent_id = node.parent_id

    await log_event(db, node.project_id, "node_deleted", "node", node_id, {"title": node.title})
    await db.delete(node)
    await db.commit()


@router.post("/{node_id}/duplicate", response_model=NodeResponse, status_code=201)
async def duplicate_node(node_id: str, db: AsyncSession = Depends(get_db)):
    original = await require_node_access(
        node_id,
        db,
        options=(
            selectinload(Node.mitigations),
            selectinload(Node.detections),
            selectinload(Node.reference_mappings),
            selectinload(Node.tags),
        ),
    )

    import uuid
    new_node = Node(
        id=str(uuid.uuid4()),
        project_id=original.project_id,
        parent_id=original.parent_id,
        node_type=original.node_type,
        title=f"{original.title} (copy)",
        description=original.description,
        notes=original.notes,
        logic_type=original.logic_type,
        status="draft",
        sort_order=original.sort_order + 1,
        position_x=original.position_x + 50,
        position_y=original.position_y + 50,
        threat_category=original.threat_category,
        attack_surface=original.attack_surface,
        platform=original.platform,
        required_access=original.required_access,
        required_privileges=original.required_privileges,
        required_tools=original.required_tools,
        required_skill=original.required_skill,
        likelihood=original.likelihood,
        impact=original.impact,
        effort=original.effort,
        exploitability=original.exploitability,
        detectability=original.detectability,
        confidence=original.confidence,
        inherent_risk=original.inherent_risk,
        probability=original.probability,
        cost_to_attacker=original.cost_to_attacker,
        time_estimate=original.time_estimate,
        assumptions=original.assumptions,
        analyst=original.analyst,
        cve_references=original.cve_references,
        extended_metadata=dict(original.extended_metadata) if original.extended_metadata else {},
    )
    db.add(new_node)
    await db.commit()
    await db.refresh(new_node)

    result = await db.execute(
        select(Node).where(Node.id == new_node.id)
        .options(selectinload(Node.mitigations), selectinload(Node.detections), selectinload(Node.reference_mappings), selectinload(Node.tags))
    )
    new_node = result.scalar_one()
    return _node_to_response(new_node)


# --- Bulk operations ---

class BulkUpdateRequest(BaseModel):
    node_ids: list[str]
    updates: dict  # partial NodeUpdate fields


class BulkDeleteRequest(BaseModel):
    node_ids: list[str]


@router.post("/bulk/update")
async def bulk_update_nodes(data: BulkUpdateRequest, db: AsyncSession = Depends(get_db)):
    """Apply the same partial update to multiple nodes."""
    result = await db.execute(
        select(Node)
        .where(
            Node.id.in_(data.node_ids),
            Node.project.has(user_id=get_current_user_id()),
        )
    )
    nodes = result.scalars().all()
    if not nodes:
        raise HTTPException(404, "No matching nodes found")

    allowed_fields = {c.name for c in Node.__table__.columns} - {"id", "project_id", "created_at", "updated_at"}
    for node in nodes:
        for key, value in data.updates.items():
            if key in allowed_fields:
                setattr(node, key, value)
        # Recompute risk if scoring fields changed
        scoring_keys = {"likelihood", "impact", "effort", "exploitability", "detectability"}
        if scoring_keys & data.updates.keys():
            node.inherent_risk = compute_inherent_risk(
                node.likelihood,
                node.impact,
                node.effort,
                node.exploitability,
                node.detectability,
            )

    await db.commit()
    return {"updated": len(nodes)}


@router.post("/bulk/delete")
async def bulk_delete_nodes(data: BulkDeleteRequest, db: AsyncSession = Depends(get_db)):
    """Delete multiple nodes. Re-parents children to deleted node's parent."""
    ids_set = set(data.node_ids)
    result = await db.execute(
        select(Node)
        .where(
            Node.id.in_(data.node_ids),
            Node.project.has(user_id=get_current_user_id()),
        )
    )
    nodes = result.scalars().all()
    if not nodes:
        raise HTTPException(404, "No matching nodes found")

    for node in nodes:
        # Re-parent children that are not also being deleted
        children_result = await db.execute(
            select(Node).where(Node.parent_id == node.id, Node.project_id == node.project_id)
        )
        for child in children_result.scalars().all():
            if child.id not in ids_set:
                child.parent_id = node.parent_id
        await log_event(db, node.project_id, "node_deleted", "node", node.id, {"title": node.title, "bulk": True})
        await db.delete(node)

    await db.commit()
    return {"deleted": len(nodes)}


# --- Critical path analysis ---

class CriticalPathResponse(BaseModel):
    path: list[str]
    cumulative_risk: float
    path_details: list[dict]
    all_paths: list[dict]


@router.get("/project/{project_id}/critical-path", response_model=CriticalPathResponse)
async def get_critical_path(project_id: str, db: AsyncSession = Depends(get_db)):
    """Compute the highest-risk root-to-leaf path in the attack tree."""
    await require_project_access(project_id, db)
    result = await db.execute(
        select(Node)
        .where(Node.project_id == project_id)
        .options(selectinload(Node.mitigations))
    )
    nodes = result.scalars().all()
    if not nodes:
        return CriticalPathResponse(path=[], cumulative_risk=0.0, path_details=[], all_paths=[])

    # Build adjacency
    node_map = {n.id: n for n in nodes}
    children_map: dict[str, list[str]] = {}
    roots: list[str] = []
    for n in nodes:
        if not n.parent_id or n.parent_id not in node_map:
            roots.append(n.id)
        else:
            children_map.setdefault(n.parent_id, []).append(n.id)

    def node_risk(n: Node) -> float:
        return n.inherent_risk or n.rolled_up_risk or 0.0

    # DFS to enumerate all root-to-leaf paths
    all_paths: list[tuple[list[str], float]] = []

    def dfs(nid: str, path: list[str], cum_risk: float):
        node = node_map[nid]
        risk = node_risk(node)
        new_cum = cum_risk + risk
        path.append(nid)
        kids = children_map.get(nid, [])
        if not kids:
            all_paths.append((list(path), round(new_cum, 2)))
        else:
            for kid in kids:
                dfs(kid, path, new_cum)
        path.pop()

    for root in roots:
        dfs(root, [], 0.0)

    if not all_paths:
        return CriticalPathResponse(path=[], cumulative_risk=0.0, path_details=[], all_paths=[])

    # Sort by cumulative risk descending
    all_paths.sort(key=lambda x: x[1], reverse=True)
    best_path, best_risk = all_paths[0]

    path_details = []
    for nid in best_path:
        n = node_map[nid]
        mit_count = len(n.mitigations) if n.mitigations else 0
        max_eff = max((m.effectiveness for m in n.mitigations), default=0.0) if n.mitigations else 0.0
        path_details.append({
            "id": n.id,
            "title": n.title,
            "node_type": n.node_type,
            "inherent_risk": n.inherent_risk,
            "residual_risk": n.residual_risk,
            "mitigation_count": mit_count,
            "max_mitigation_effectiveness": round(max_eff, 2),
        })

    # Return top 5 paths summary
    top_paths = [
        {"path": p, "cumulative_risk": r}
        for p, r in all_paths[:5]
    ]

    return CriticalPathResponse(
        path=best_path,
        cumulative_risk=best_risk,
        path_details=path_details,
        all_paths=top_paths,
    )
