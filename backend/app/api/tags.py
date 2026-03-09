from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..database import get_db
from ..models.node import Tag, NodeTag, Node
from ..schemas.tag import TagCreate, TagResponse

router = APIRouter(prefix="/tags", tags=["tags"])


@router.get("", response_model=list[TagResponse])
async def list_tags(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Tag).order_by(Tag.name))
    return [TagResponse.model_validate(t) for t in result.scalars().all()]


@router.post("", response_model=TagResponse, status_code=201)
async def create_tag(data: TagCreate, db: AsyncSession = Depends(get_db)):
    # Return existing tag if name matches (case-insensitive)
    result = await db.execute(select(Tag).where(Tag.name == data.name.strip()))
    existing = result.scalar_one_or_none()
    if existing:
        return TagResponse.model_validate(existing)

    tag = Tag(name=data.name.strip())
    db.add(tag)
    await db.commit()
    await db.refresh(tag)
    return TagResponse.model_validate(tag)


@router.post("/node/{node_id}/{tag_id}", status_code=204)
async def add_tag_to_node(node_id: str, tag_id: str, db: AsyncSession = Depends(get_db)):
    # Verify node exists
    node = await db.execute(select(Node).where(Node.id == node_id))
    if not node.scalar_one_or_none():
        raise HTTPException(404, "Node not found")

    # Verify tag exists
    tag = await db.execute(select(Tag).where(Tag.id == tag_id))
    if not tag.scalar_one_or_none():
        raise HTTPException(404, "Tag not found")

    # Check if already attached
    existing = await db.execute(
        select(NodeTag).where(NodeTag.node_id == node_id, NodeTag.tag_id == tag_id)
    )
    if existing.scalar_one_or_none():
        return  # Already attached, no-op

    node_tag = NodeTag(node_id=node_id, tag_id=tag_id)
    db.add(node_tag)
    await db.commit()


@router.delete("/node/{node_id}/{tag_id}", status_code=204)
async def remove_tag_from_node(node_id: str, tag_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(NodeTag).where(NodeTag.node_id == node_id, NodeTag.tag_id == tag_id)
    )
    node_tag = result.scalar_one_or_none()
    if not node_tag:
        raise HTTPException(404, "Tag not attached to this node")
    await db.delete(node_tag)
    await db.commit()


@router.delete("/{tag_id}", status_code=204)
async def delete_tag(tag_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Tag).where(Tag.id == tag_id))
    tag = result.scalar_one_or_none()
    if not tag:
        raise HTTPException(404, "Tag not found")
    await db.delete(tag)
    await db.commit()
