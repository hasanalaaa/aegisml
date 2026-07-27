import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from jwt.exceptions import InvalidTokenError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from auth.models import User

logger = logging.getLogger("aegisml.auth")

SECRET_KEY = os.getenv("SECRET_KEY", "")
if not SECRET_KEY:
    # SECURITY: never fall back to a publicly-known constant — that would let
    # anyone forge valid JWTs. Generate an ephemeral per-process secret instead
    # (tokens won't survive restarts until SECRET_KEY is configured).
    SECRET_KEY = secrets.token_urlsafe(64)
    logger.critical(
        "SECRET_KEY is not set! Using an ephemeral random secret — sessions "
        "will not survive restarts. Set SECRET_KEY in the environment."
    )
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 30

security = HTTPBearer(auto_error=False)

def create_access_token(user_id: UUID | str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": str(user_id), "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(user_id: UUID | str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = {"sub": str(user_id), "exp": expire, "type": "refresh"}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Dependency for getting the current authenticated user."""
    if not credentials:
        return None
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
        # SECURITY: refresh tokens must never be usable as access tokens.
        if payload.get("type") == "refresh":
            return None
        user_id_str = payload.get("sub")
        if user_id_str is None:
            return None
    except InvalidTokenError:
        return None

    result = await db.execute(select(User).where(User.id == user_id_str))
    user = result.scalar_one_or_none()
    if user is not None and not user.is_active:
        return None
    return user


async def require_user(
    current_user: Optional[User] = Depends(get_current_user),
) -> User:
    """Dependency that enforces authentication (401 instead of None)."""
    if current_user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return current_user
