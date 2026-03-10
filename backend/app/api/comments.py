from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..database import get_db
from ..models.comment import Comment
from ..models.node import Node
from ..schemas.comment import CommentCreate, CommentResponse
from ..services.access_control import require_comment_access, require_node_access
from ..services.auth import get_current_user_name
from ..services.audit import log_event

router = APIRouter(prefix="/comments", tags=["comments"])


@router.get("/node/{node_id}", response_model=list[CommentResponse])
async def list_comments(node_id: str, db: AsyncSession = Depends(get_db)):
    await require_node_access(node_id, db)
    result = await db.execute(
        select(Comment).where(Comment.node_id == node_id).order_by(Comment.created_at)
    )
    return [CommentResponse.model_validate(c) for c in result.scalars().all()]


@router.post("", response_model=CommentResponse, status_code=201)
async def create_comment(data: CommentCreate, db: AsyncSession = Depends(get_db)):
    node = await require_node_access(data.node_id, db)
    comment = Comment(**{**data.model_dump(), "author": get_current_user_name()})
    db.add(comment)

    # Log audit event
    project_id = node.project_id
    if project_id:
        await log_event(db, project_id, "comment_added", "comment", "", {"node_id": data.node_id, "author": comment.author})

    await db.commit()
    await db.refresh(comment)
    return CommentResponse.model_validate(comment)


@router.delete("/{comment_id}", status_code=204)
async def delete_comment(comment_id: str, db: AsyncSession = Depends(get_db)):
    comment = await require_comment_access(comment_id, db)

    # Log audit event
    node = await require_node_access(comment.node_id, db)
    project_id = node.project_id
    if project_id:
        await log_event(db, project_id, "comment_deleted", "comment", comment_id, {"node_id": comment.node_id})

    await db.delete(comment)
    await db.commit()
