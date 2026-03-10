from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.user import User
from ..schemas.user import (
    AdminPasswordResetRequest,
    AdminUserCreate,
    AdminUserUpdate,
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    SignupRequest,
    UserResponse,
)
from ..services.auth import (
    create_access_token,
    get_current_user_id,
    hash_password,
    require_admin,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/signup", response_model=LoginResponse, status_code=201)
async def signup(data: SignupRequest, db: AsyncSession = Depends(get_db)):
    user = await _create_user(
        db,
        name=data.name,
        email=data.email,
        username=data.username,
        password=data.password,
        role="user",
    )
    await db.commit()
    await db.refresh(user)
    return _login_response(user)


@router.post("/login", response_model=LoginResponse)
async def login(data: LoginRequest, db: AsyncSession = Depends(get_db)):
    identifier = data.identifier.strip().lower()
    result = await db.execute(
        select(User).where(
            or_(
                func.lower(User.email) == identifier,
                func.lower(User.username) == identifier,
            )
        )
    )
    user = result.scalar_one_or_none()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username/email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is disabled")
    return _login_response(user)


@router.get("/me", response_model=UserResponse)
async def me(db: AsyncSession = Depends(get_db)):
    return UserResponse.model_validate(await _current_user(db))


@router.post("/change-password", status_code=204)
async def change_password(data: ChangePasswordRequest, db: AsyncSession = Depends(get_db)):
    user = await _current_user(db)
    if not verify_password(data.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    user.password_hash = hash_password(data.new_password)
    user.password_reset_required = False
    await db.commit()


@router.get("/users", response_model=list[UserResponse])
async def list_users(db: AsyncSession = Depends(get_db)):
    require_admin()
    result = await db.execute(select(User).order_by(User.role.desc(), User.name.asc()))
    return [UserResponse.model_validate(user) for user in result.scalars().all()]


@router.post("/users", response_model=UserResponse, status_code=201)
async def admin_create_user(data: AdminUserCreate, db: AsyncSession = Depends(get_db)):
    require_admin()
    user = await _create_user(
        db,
        name=data.name,
        email=data.email,
        username=data.username,
        password=data.password,
        role=data.role,
    )
    await db.commit()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserResponse)
async def admin_update_user(user_id: str, data: AdminUserUpdate, db: AsyncSession = Depends(get_db)):
    require_admin()
    user = await _user_or_404(user_id, db)
    update_data = data.model_dump(exclude_unset=True)
    if "email" in update_data:
        update_data["email"] = update_data["email"].lower()
        if "@" not in update_data["email"] or update_data["email"].startswith("@") or update_data["email"].endswith("@"):
            raise HTTPException(status_code=400, detail="Enter a valid email address")
        await _ensure_unique_email(db, update_data["email"], exclude_user_id=user.id)
    if "username" in update_data and update_data["username"] is not None:
        update_data["username"] = _normalize_username(update_data["username"])
        await _ensure_unique_username(db, update_data["username"], exclude_user_id=user.id)
    for key, value in update_data.items():
        setattr(user, key, value)
    await db.commit()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.post("/users/{user_id}/reset-password", status_code=204)
async def admin_reset_password(user_id: str, data: AdminPasswordResetRequest, db: AsyncSession = Depends(get_db)):
    require_admin()
    user = await _user_or_404(user_id, db)
    user.password_hash = hash_password(data.new_password)
    user.password_reset_required = data.require_reset
    await db.commit()


@router.delete("/users/{user_id}", status_code=204)
async def admin_delete_user(user_id: str, db: AsyncSession = Depends(get_db)):
    current = require_admin()
    if current.user_id == user_id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    user = await _user_or_404(user_id, db)
    await db.delete(user)
    await db.commit()


async def _current_user(db: AsyncSession) -> User:
    return await _user_or_404(get_current_user_id(), db)


async def _user_or_404(user_id: str, db: AsyncSession) -> User:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def _create_user(
    db: AsyncSession,
    *,
    name: str,
    email: str,
    username: str | None,
    password: str,
    role: str,
) -> User:
    normalized_email = email.lower()
    if "@" not in normalized_email or normalized_email.startswith("@") or normalized_email.endswith("@"):
        raise HTTPException(status_code=400, detail="Enter a valid email address")
    normalized_username = _normalize_username(username or email.split("@", 1)[0] or name)
    await _ensure_unique_email(db, normalized_email)
    await _ensure_unique_username(db, normalized_username)
    user = User(
        name=name.strip(),
        username=normalized_username,
        email=normalized_email,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
        password_reset_required=False,
    )
    db.add(user)
    await db.flush()
    return user


async def _ensure_unique_email(db: AsyncSession, email: str, *, exclude_user_id: str | None = None) -> None:
    query = select(User.id).where(func.lower(User.email) == email.lower())
    if exclude_user_id:
        query = query.where(User.id != exclude_user_id)
    result = await db.execute(query)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A user with that email already exists")


async def _ensure_unique_username(db: AsyncSession, username: str, *, exclude_user_id: str | None = None) -> None:
    query = select(User.id).where(func.lower(User.username) == username.lower())
    if exclude_user_id:
        query = query.where(User.id != exclude_user_id)
    result = await db.execute(query)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A user with that username already exists")


def _normalize_username(username: str) -> str:
    normalized = username.strip().lower()
    if len(normalized) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._-")
    if any(char not in allowed for char in normalized):
        raise HTTPException(status_code=400, detail="Username can use letters, numbers, dot, dash, and underscore only")
    return normalized


def _login_response(user: User) -> LoginResponse:
    return LoginResponse(
        access_token=create_access_token(user_id=user.id, email=user.email, role=user.role),
        user=UserResponse.model_validate(user),
    )
