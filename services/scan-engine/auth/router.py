import logging
import os
import secrets
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import RedirectResponse
import jwt
from jwt.exceptions import InvalidTokenError
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from auth.models import User
from auth.schemas import TokenResponse, UserRead
from auth.sync_security import (
    InvalidSyncSecret,
    SyncSecretUnavailable,
    verify_sync_secret,
)
from auth.utils import create_access_token, create_refresh_token, get_current_user
from auth.oauth import get_github_user_info, get_google_user_info, GITHUB_CLIENT_ID, GOOGLE_CLIENT_ID, GOOGLE_REDIRECT_URI

router = APIRouter()

async def sync_user(db: AsyncSession, provider: str, user_info: dict[str, Any]) -> User:
    email = user_info["email"]
    provider_id = user_info["provider_id"]
    
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    
    if user:
        user.display_name = user_info.get("display_name") or user.display_name
        user.avatar_url = user_info.get("avatar_url") or user.avatar_url
        user.provider_id = provider_id
    else:
        user = User(
            email=email,
            username=user_info.get("username") or email.split("@")[0],
            display_name=user_info.get("display_name"),
            avatar_url=user_info.get("avatar_url"),
            provider=provider,
            provider_id=provider_id,
            api_key=secrets.token_hex(16),
            plan="free",
        )
        db.add(user)
    
    await db.commit()
    await db.refresh(user)
    return user

@router.get("/github")
async def github_login():
    return RedirectResponse(f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&scope=user:email")

@router.get("/github/callback")
async def github_callback(code: str, db: AsyncSession = Depends(get_db)):
    user_info = await get_github_user_info(code)
    if not user_info:
        raise HTTPException(status_code=400, detail="Failed to authenticate with GitHub")
        
    user = await sync_user(db, "github", user_info)
    return {
        "access_token": create_access_token(user.id),
        "refresh_token": create_refresh_token(user.id),
        "token_type": "bearer",
    }

@router.get("/google")
async def google_login():
    return RedirectResponse(
        f"https://accounts.google.com/o/oauth2/v2/auth?client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&response_type=code&scope=email profile"
    )

@router.get("/google/callback")
async def google_callback(code: str, db: AsyncSession = Depends(get_db)):
    user_info = await get_google_user_info(code)
    if not user_info:
        raise HTTPException(status_code=400, detail="Failed to authenticate with Google")
        
    user = await sync_user(db, "google", user_info)
    return {
        "access_token": create_access_token(user.id),
        "refresh_token": create_refresh_token(user.id),
        "token_type": "bearer",
    }

_logger = logging.getLogger("aegisml.auth")

AUTH_SYNC_SECRET = os.getenv("AUTH_SYNC_SECRET", "")
if not AUTH_SYNC_SECRET:
    _logger.critical(
        "AUTH_SYNC_SECRET is not set; /auth/sync is disabled until configured."
    )

class NextAuthSyncRequest(BaseModel):
    email: EmailStr
    name: str
    image: str
    provider: str
    providerAccountId: str

@router.post("/sync", response_model=TokenResponse)
async def nextauth_sync(
    data: NextAuthSyncRequest,
    db: AsyncSession = Depends(get_db),
    x_auth_sync_secret: str | None = Header(None),
):
    """Server-to-server endpoint for NextAuth to sync a user and mint a backend JWT.

    SECURITY: this endpoint issues tokens for an arbitrary email, so it MUST
    only be callable by the trusted frontend server. It is protected by a
    shared secret (AUTH_SYNC_SECRET) sent in the X-Auth-Sync-Secret header.
    """
    try:
        verify_sync_secret(AUTH_SYNC_SECRET, x_auth_sync_secret)
    except SyncSecretUnavailable:
        raise HTTPException(
            status_code=503,
            detail="Authentication sync is not configured",
        ) from None
    except InvalidSyncSecret:
        raise HTTPException(status_code=401, detail="Invalid sync secret") from None
    user_info = {
        "email": data.email,
        "username": data.email.split("@")[0],
        "display_name": data.name,
        "avatar_url": data.image,
        "provider_id": data.providerAccountId,
    }
    user = await sync_user(db, data.provider, user_info)
    return {
        "access_token": create_access_token(user.id),
        "refresh_token": create_refresh_token(user.id),
        "token_type": "bearer",
    }

class RefreshRequest(BaseModel):
    refresh_token: str

@router.post("/refresh")
async def refresh_token(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """Exchange a valid refresh token for a new access token."""
    from auth.utils import SECRET_KEY, ALGORITHM

    try:
        payload = jwt.decode(
            body.refresh_token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=401, detail="Invalid or expired refresh token"
        ) from None

    if payload.get("type") != "refresh" or not payload.get("sub"):
        raise HTTPException(status_code=401, detail="Not a refresh token")

    result = await db.execute(select(User).where(User.id == payload["sub"]))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    return {"access_token": create_access_token(user.id), "token_type": "bearer"}

@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # Delete refresh token from DB if it exists
    return {"status": "logged_out"}

@router.get("/me", response_model=UserRead)
async def get_me(current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return current_user

class UserUpdate(BaseModel):
    display_name: str | None = None
    avatar_url: str | None = None

@router.put("/me", response_model=UserRead)
async def update_me(data: UserUpdate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if data.display_name is not None:
        current_user.display_name = data.display_name
    if data.avatar_url is not None:
        current_user.avatar_url = data.avatar_url
    await db.commit()
    await db.refresh(current_user)
    return current_user

@router.post("/me/regenerate-key")
async def regenerate_key(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    current_user.api_key = secrets.token_hex(16)
    await db.commit()
    await db.refresh(current_user)
    return {"api_key": current_user.api_key}
