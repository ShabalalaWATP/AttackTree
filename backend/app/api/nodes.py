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
from ..services.access_control import require_node_access, require_project_access
from ..services.audit import log_event
from ..services.tree_service import (
    load_validated_project_tree,
    recalculate_project_tree_scores,
    validate_parent_assignment,
)

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
    project = await require_project_access(data.project_id, db)
    await validate_parent_assignment(db, project_id=project.id, parent_id=data.parent_id)
    node = Node(**data.model_dump())

    db.add(node)
    await log_event(db, node.project_id, "node_created", "node", node.id, {"title": node.title})
    await db.flush()
    await recalculate_project_tree_scores(db, node.project_id)
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
    if "parent_id" in update_data:
        await validate_parent_assignment(
            db,
            project_id=node.project_id,
            parent_id=update_data.get("parent_id"),
            node_id=node.id,
        )
    for key, value in update_data.items():
        setattr(node, key, value)

    await log_event(db, node.project_id, "node_updated", "node", node_id, {"title": node.title, "fields": list(update_data.keys())})
    await db.flush()
    await recalculate_project_tree_scores(db, node.project_id)
    await db.commit()
    await db.refresh(node)
    return _node_to_response(node)


@router.delete("/{node_id}", status_code=204)
async def delete_node(node_id: str, db: AsyncSession = Depends(get_db)):
    node = await require_node_access(node_id, db)
    project_id = node.project_id

    # Re-parent children to this node's parent
    children_result = await db.execute(
        select(Node).where(Node.parent_id == node_id, Node.project_id == node.project_id)
    )
    children = children_result.scalars().all()
    for child in children:
        child.parent_id = node.parent_id

    await log_event(db, node.project_id, "node_deleted", "node", node_id, {"title": node.title})
    await db.delete(node)
    await db.flush()
    await recalculate_project_tree_scores(db, project_id)
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
    await db.flush()
    await recalculate_project_tree_scores(db, new_node.project_id)
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
    if "parent_id" in data.updates:
        raise HTTPException(400, "Bulk parent changes are not supported")

    allowed_fields = {c.name for c in Node.__table__.columns} - {"id", "project_id", "created_at", "updated_at"}
    for node in nodes:
        for key, value in data.updates.items():
            if key in allowed_fields:
                setattr(node, key, value)
    await db.flush()
    for project_id in sorted({node.project_id for node in nodes}):
        await recalculate_project_tree_scores(db, project_id)
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
    touched_project_ids = {node.project_id for node in nodes}
    node_map = {node.id: node for node in nodes}

    def surviving_parent_id(node: Node) -> str | None:
        parent_id = node.parent_id
        seen: set[str] = set()
        while parent_id and parent_id in ids_set and parent_id not in seen:
            seen.add(parent_id)
            parent = node_map.get(parent_id)
            parent_id = parent.parent_id if parent else None
        return parent_id if parent_id not in ids_set else None

    surviving_parent_by_node = {
        node.id: surviving_parent_id(node)
        for node in nodes
    }

    for node in nodes:
        # Re-parent children that are not also being deleted
        children_result = await db.execute(
            select(Node).where(Node.parent_id == node.id, Node.project_id == node.project_id)
        )
        for child in children_result.scalars().all():
            if child.id not in ids_set:
                child.parent_id = surviving_parent_by_node[node.id]
        await log_event(db, node.project_id, "node_deleted", "node", node.id, {"title": node.title, "bulk": True})
        await db.delete(node)

    await db.flush()
    for project_id in sorted(touched_project_ids):
        await recalculate_project_tree_scores(db, project_id)
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
    tree = await load_validated_project_tree(db, project_id, include_mitigations=True)
    nodes = tree.nodes
    if not nodes:
        return CriticalPathResponse(path=[], cumulative_risk=0.0, path_details=[], all_paths=[])

    node_map = tree.node_map
    child_ids_by_parent = {
        parent_id: [child.id for child in children]
        for parent_id, children in tree.children_map.items()
        if parent_id is not None
    }

    def node_risk(n: Node) -> float:
        # Path scoring should use only the node's own risk so parent roll-ups are not counted twice.
        return n.inherent_risk or 0.0

    # DFS to enumerate all root-to-leaf paths
    all_paths: list[tuple[list[str], float]] = []

    def dfs(nid: str, path: list[str], cum_risk: float):
        node = node_map[nid]
        risk = node_risk(node)
        new_cum = cum_risk + risk
        path.append(nid)
        kids = child_ids_by_parent.get(nid, [])
        if not kids:
            all_paths.append((list(path), round(new_cum, 2)))
        else:
            for kid in kids:
                dfs(kid, path, new_cum)
        path.pop()

    for root in tree.roots:
        dfs(root.id, [], 0.0)

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
