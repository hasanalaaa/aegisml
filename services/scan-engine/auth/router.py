import os
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from auth.models import User, RefreshToken
from auth.schemas import TokenResponse, UserRead
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

from pydantic import BaseModel
class NextAuthSyncRequest(BaseModel):
    email: str
    name: str
    image: str
    provider: str
    providerAccountId: str

@router.post("/sync", response_model=TokenResponse)
async def nextauth_sync(data: NextAuthSyncRequest, db: AsyncSession = Depends(get_db)):
    """Endpoint for NextAuth to sync user and get backend JWT."""
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

@router.get("/me", response_model=UserRead)
async def get_me(current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return current_user

@router.post("/me/regenerate-key")
async def regenerate_key(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    current_user.api_key = secrets.token_hex(16)
    await db.commit()
    await db.refresh(current_user)
    return {"api_key": current_user.api_key}
