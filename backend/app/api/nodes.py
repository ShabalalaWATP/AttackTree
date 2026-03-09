from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from ..database import get_db
from ..models.node import Node
from ..models.mitigation import Mitigation
from ..models.detection import Detection
from ..models.reference_mapping import ReferenceMapping
from ..schemas.node import NodeCreate, NodeUpdate, NodeResponse
from ..services.risk_engine import compute_inherent_risk, compute_residual_risk, compute_advanced_risk
from ..services.audit import log_event

router = APIRouter(prefix="/nodes", tags=["nodes"])


def _node_to_response(node: Node) -> NodeResponse:
    return NodeResponse.model_validate(node)


@router.get("/project/{project_id}", response_model=list[NodeResponse])
async def list_nodes(project_id: str, db: AsyncSession = Depends(get_db)):
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
    result = await db.execute(
        select(Node).where(Node.id == node_id)
        .options(selectinload(Node.mitigations), selectinload(Node.detections), selectinload(Node.reference_mappings), selectinload(Node.tags))
    )
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(404, "Node not found")
    return _node_to_response(node)


@router.patch("/{node_id}", response_model=NodeResponse)
async def update_node(node_id: str, data: NodeUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Node).where(Node.id == node_id)
        .options(selectinload(Node.mitigations), selectinload(Node.detections), selectinload(Node.reference_mappings), selectinload(Node.tags))
    )
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(404, "Node not found")

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
    result = await db.execute(select(Node).where(Node.id == node_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(404, "Node not found")

    # Re-parent children to this node's parent
    children_result = await db.execute(select(Node).where(Node.parent_id == node_id))
    children = children_result.scalars().all()
    for child in children:
        child.parent_id = node.parent_id

    await log_event(db, node.project_id, "node_deleted", "node", node_id, {"title": node.title})
    await db.delete(node)
    await db.commit()


@router.post("/{node_id}/duplicate", response_model=NodeResponse, status_code=201)
async def duplicate_node(node_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Node).where(Node.id == node_id)
        .options(selectinload(Node.mitigations), selectinload(Node.detections), selectinload(Node.reference_mappings), selectinload(Node.tags))
    )
    original = result.scalar_one_or_none()
    if not original:
        raise HTTPException(404, "Node not found")

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
