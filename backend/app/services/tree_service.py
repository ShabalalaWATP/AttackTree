from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..models.node import Node
from .access_control import require_node_access
from .risk_engine import (
    compute_advanced_risk,
    compute_inherent_risk,
    compute_residual_risk,
    rollup_and_likelihood,
    rollup_and_risk,
    rollup_or_likelihood,
    rollup_or_risk,
)


@dataclass
class ProjectTree:
    nodes: list[Node]
    node_map: dict[str, Node]
    children_map: dict[str | None, list[Node]]
    roots: list[Node]
    post_order: list[Node]


async def validate_parent_assignment(
    db: AsyncSession,
    *,
    project_id: str,
    parent_id: str | None,
    node_id: str | None = None,
) -> None:
    if not parent_id:
        return

    parent = await require_node_access(parent_id, db)
    if parent.project_id != project_id:
        raise HTTPException(400, "Parent node must belong to the same project")
    if node_id and parent.id == node_id:
        raise HTTPException(400, "A node cannot be its own parent")
    if not node_id:
        return

    result = await db.execute(select(Node.id, Node.parent_id).where(Node.project_id == project_id))
    children_map: dict[str, list[str]] = {}
    for row in result.all():
        children_map.setdefault(row.parent_id, []).append(row.id)

    descendants: set[str] = set()
    stack = list(children_map.get(node_id, []))
    while stack:
        current = stack.pop()
        if current in descendants:
            continue
        descendants.add(current)
        stack.extend(children_map.get(current, []))

    if parent_id in descendants:
        raise HTTPException(400, "Cannot move a node beneath one of its descendants")


async def load_validated_project_tree(
    db: AsyncSession,
    project_id: str,
    *,
    include_mitigations: bool = False,
) -> ProjectTree:
    query = select(Node).where(Node.project_id == project_id).order_by(Node.sort_order, Node.created_at)
    if include_mitigations:
        query = query.options(selectinload(Node.mitigations))

    result = await db.execute(query)
    nodes = result.scalars().all()
    node_map = {node.id: node for node in nodes}
    children_map: dict[str | None, list[Node]] = {}
    roots: list[Node] = []

    for node in nodes:
        if node.parent_id is None:
            roots.append(node)
            children_map.setdefault(None, []).append(node)
            continue
        parent = node_map.get(node.parent_id)
        if not parent:
            raise HTTPException(409, f"Attack tree is malformed: node '{node.title}' references a missing parent")
        children_map.setdefault(node.parent_id, []).append(node)

    visiting: set[str] = set()
    visited: set[str] = set()
    post_order: list[Node] = []

    def walk(node: Node) -> None:
        if node.id in visited:
            return
        if node.id in visiting:
            raise HTTPException(409, f"Attack tree is malformed: cycle detected at '{node.title}'")
        visiting.add(node.id)
        for child in children_map.get(node.id, []):
            walk(child)
        visiting.remove(node.id)
        visited.add(node.id)
        post_order.append(node)

    for root in roots:
        walk(root)
    for node in nodes:
        walk(node)

    if len(visited) != len(nodes):
        orphaned = next(node for node in nodes if node.id not in visited)
        raise HTTPException(409, f"Attack tree is malformed near '{orphaned.title}'")
    if nodes and not roots:
        raise HTTPException(409, "Attack tree is malformed: no root nodes remain after validation")

    return ProjectTree(
        nodes=nodes,
        node_map=node_map,
        children_map=children_map,
        roots=roots,
        post_order=post_order,
    )


def recompute_node_scores(node: Node) -> None:
    inherent = compute_inherent_risk(
        node.likelihood,
        node.impact,
        node.effort,
        node.exploitability,
        node.detectability,
    )
    if node.probability is not None:
        advanced = compute_advanced_risk(node.probability, node.impact, node.cost_to_attacker)
        if advanced is not None and inherent is None:
            inherent = advanced

    node.inherent_risk = inherent
    max_effectiveness = max((mit.effectiveness for mit in node.mitigations or []), default=0.0)
    node.residual_risk = compute_residual_risk(node.inherent_risk, max_effectiveness)


async def recalculate_project_tree_scores(db: AsyncSession, project_id: str) -> int:
    tree = await load_validated_project_tree(db, project_id, include_mitigations=True)

    for node in tree.post_order:
        recompute_node_scores(node)
        child_nodes = tree.children_map.get(node.id, [])
        if not child_nodes:
            node.rolled_up_risk = None
            node.rolled_up_likelihood = None
            continue

        child_risks = [
            child.inherent_risk if child.inherent_risk is not None else child.rolled_up_risk
            for child in child_nodes
            if child.inherent_risk is not None or child.rolled_up_risk is not None
        ]
        child_likelihoods = [
            child.likelihood if child.likelihood is not None else child.rolled_up_likelihood
            for child in child_nodes
            if child.likelihood is not None or child.rolled_up_likelihood is not None
        ]

        if child_risks:
            if node.logic_type in ("AND", "SEQUENCE"):
                node.rolled_up_risk = rollup_and_risk(child_risks)
            else:
                node.rolled_up_risk = rollup_or_risk(child_risks)
        else:
            node.rolled_up_risk = None

        if child_likelihoods:
            if node.logic_type in ("AND", "SEQUENCE"):
                node.rolled_up_likelihood = rollup_and_likelihood(child_likelihoods)
            else:
                node.rolled_up_likelihood = rollup_or_likelihood(child_likelihoods)
        else:
            node.rolled_up_likelihood = None

    return len(tree.nodes)
