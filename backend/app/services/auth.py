import base64
import hashlib
import hmac
import json
import os
from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException

from ..config import settings


TOKEN_TTL_HOURS = 12
PBKDF2_ITERATIONS = 390000


@dataclass(frozen=True)
class AuthContext:
    user_id: str
    name: str
    email: str
    role: str
    is_active: bool


_auth_context: ContextVar[AuthContext | None] = ContextVar("auth_context", default=None)


def set_auth_context(context: AuthContext | None) -> Token:
    return _auth_context.set(context)


def reset_auth_context(token: Token) -> None:
    _auth_context.reset(token)


def get_auth_context(required: bool = True) -> AuthContext | None:
    context = _auth_context.get()
    if context is None and required:
        raise HTTPException(status_code=401, detail="Authentication required")
    return context


def get_current_user_id() -> str:
    return get_auth_context().user_id


def get_current_user_name() -> str:
    return get_auth_context().name


def require_admin() -> AuthContext:
    context = get_auth_context()
    if context.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return context


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return "pbkdf2_sha256${iterations}${salt}${digest}".format(
        iterations=PBKDF2_ITERATIONS,
        salt=base64.urlsafe_b64encode(salt).decode("ascii"),
        digest=base64.urlsafe_b64encode(derived).decode("ascii"),
    )


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iteration_text, salt_text, digest_text = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iteration_text)
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
    except (TypeError, ValueError):
        return False

    actual = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(actual, expected)


def create_access_token(*, user_id: str, email: str, role: str, expires_in_hours: int = TOKEN_TTL_HOURS) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)).timestamp()),
    }
    encoded_payload = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = _sign(encoded_payload.encode("ascii"))
    return f"{encoded_payload}.{signature}"


def decode_access_token(token: str) -> dict[str, str | int]:
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid authentication token") from exc

    expected_signature = _sign(encoded_payload.encode("ascii"))
    if not hmac.compare_digest(expected_signature, encoded_signature):
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    try:
        payload = json.loads(_b64url_decode(encoded_payload).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid authentication token") from exc

    if int(payload.get("exp", 0)) < int(datetime.now(timezone.utc).timestamp()):
        raise HTTPException(status_code=401, detail="Authentication token expired")

    return payload


def _sign(payload: bytes) -> str:
    secret = settings.SECRET_KEY.encode("utf-8")
    digest = hmac.new(secret, payload, hashlib.sha256).digest()
    return _b64url_encode(digest)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))
