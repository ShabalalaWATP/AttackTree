from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class UserResponse(BaseModel):
    id: str
    name: str
    username: str
    email: str
    role: str
    is_active: bool
    approval_status: str
    password_reset_required: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class LoginRequest(BaseModel):
    identifier: str
    password: str = Field(..., min_length=8, max_length=128)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class SignupResponse(BaseModel):
    message: str
    approval_required: bool = True
    user: UserResponse


class SignupRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    email: str
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=8, max_length=128)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=8, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)


class AdminUserCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    email: str
    username: Optional[str] = Field(default=None, min_length=3, max_length=100)
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(default="user", pattern="^(admin|user)$")


class AdminUserUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    email: Optional[str] = None
    username: Optional[str] = Field(default=None, min_length=3, max_length=100)
    role: Optional[str] = Field(default=None, pattern="^(admin|user)$")
    is_active: Optional[bool] = None


class AdminPasswordResetRequest(BaseModel):
    new_password: str = Field(..., min_length=8, max_length=128)
    require_reset: bool = False
