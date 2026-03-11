from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..database import get_db
from ..models.reference_mapping import ReferenceMapping
from ..models.node import Node
from ..schemas.reference_mapping import ReferenceMappingCreate, ReferenceMappingUpdate, ReferenceMappingResponse
from ..services.access_control import require_node_access
from ..services.auth import get_current_user_id
from ..services.audit import log_event
from ..services.environment_catalog_service import (
    get_environment_catalog,
    list_environment_catalog_summaries,
)

router = APIRouter(prefix="/references", tags=["references"])


@router.get("/node/{node_id}", response_model=list[ReferenceMappingResponse])
async def list_mappings(node_id: str, db: AsyncSession = Depends(get_db)):
    await require_node_access(node_id, db)
    result = await db.execute(select(ReferenceMapping).where(ReferenceMapping.node_id == node_id))
    return [ReferenceMappingResponse.model_validate(r) for r in result.scalars().all()]


@router.post("", response_model=ReferenceMappingResponse, status_code=201)
async def create_mapping(data: ReferenceMappingCreate, db: AsyncSession = Depends(get_db)):
    node = await require_node_access(data.node_id, db)
    ref = ReferenceMapping(**data.model_dump())
    db.add(ref)

    # Log audit event
    if node:
        await log_event(db, node.project_id, "mapping_added", "reference", "", {"node_id": data.node_id, "ref_id": data.ref_id, "framework": data.framework})

    await db.commit()
    await db.refresh(ref)
    return ReferenceMappingResponse.model_validate(ref)


@router.patch("/{mapping_id}", response_model=ReferenceMappingResponse)
async def update_mapping(mapping_id: str, data: ReferenceMappingUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ReferenceMapping)
        .join(Node, ReferenceMapping.node_id == Node.id)
        .where(
            ReferenceMapping.id == mapping_id,
            Node.project.has(user_id=get_current_user_id()),
        )
    )
    ref = result.scalar_one_or_none()
    if not ref:
        raise HTTPException(404, "Mapping not found")

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(ref, key, value)

    # Log audit event
    node = await require_node_access(ref.node_id, db)
    if node:
        await log_event(db, node.project_id, "mapping_updated", "reference", mapping_id, {"ref_id": ref.ref_id, "framework": ref.framework})

    await db.commit()
    await db.refresh(ref)
    return ReferenceMappingResponse.model_validate(ref)


@router.delete("/{mapping_id}", status_code=204)
async def delete_mapping(mapping_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ReferenceMapping)
        .join(Node, ReferenceMapping.node_id == Node.id)
        .where(
            ReferenceMapping.id == mapping_id,
            Node.project.has(user_id=get_current_user_id()),
        )
    )
    ref = result.scalar_one_or_none()
    if not ref:
        raise HTTPException(404, "Mapping not found")

    # Log audit event
    node = await require_node_access(ref.node_id, db)
    if node:
        await log_event(db, node.project_id, "mapping_removed", "reference", mapping_id, {"node_id": ref.node_id, "ref_id": ref.ref_id})

    await db.delete(ref)
    await db.commit()


# --- Local reference data browser ---
import json
from pathlib import Path

REFERENCE_DIR = Path(__file__).parent.parent / "reference_data"


FILTER_FIELDS = {
    "attack": "tactic",
    "capec": "severity",
    "cwe": "severity",
    "owasp": "category",
}


def _load_framework(framework: str) -> list[dict]:
    file_path = REFERENCE_DIR / f"{framework}.json"
    if not file_path.exists():
        raise HTTPException(404, f"Reference data for '{framework}' not found")
    with open(file_path) as f:
        return json.load(f)


@router.get("/browse/{framework}")
async def browse_reference_data(framework: str, q: str = "", filter: str = ""):
    """Browse local reference data by framework (attack, capec, cwe, owasp)."""
    data = _load_framework(framework)

    # Collect filter options from the full dataset
    filter_field = FILTER_FIELDS.get(framework)
    filter_options: list[str] = []
    if filter_field:
        filter_options = sorted({item.get(filter_field, "") for item in data if item.get(filter_field)})

    total = len(data)

    if q:
        q_lower = q.lower()
        data = [item for item in data if q_lower in json.dumps(item).lower()]

    if filter and filter_field:
        data = [item for item in data if item.get(filter_field) == filter]

    return {
        "framework": framework,
        "total": total,
        "count": len(data),
        "items": data[:100],
        "filter_field": filter_field,
        "filter_options": filter_options,
    }


@router.get("/environment-catalogs")
async def list_environment_catalogs():
    """List bundled environment catalogs for planning-first references."""
    catalogs = list_environment_catalog_summaries()
    return {
        "total": len(catalogs),
        "catalogs": catalogs,
    }


@router.get("/environment-catalogs/{catalog_id}")
async def get_environment_catalog_detail(catalog_id: str):
    """Return one bundled environment catalog with its hierarchical nodes."""
    catalog = get_environment_catalog(catalog_id)
    if not catalog:
        raise HTTPException(404, "Environment catalog not found")
    return catalog
