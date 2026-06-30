import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from auth.models import User, UserAPIKey
from auth.utils import get_current_user
from auth.crypto import encrypt_key
from database import get_db

router = APIRouter(prefix="/api/v1", tags=["API Keys"])

class AIProviderResponse(BaseModel):
    id: str
    name: str
    models: List[str]

class AddKeyRequest(BaseModel):
    provider: str
    plain_key: str

class KeyResponse(BaseModel):
    id: uuid.UUID
    provider: str
    is_active: bool

@router.get("/ai/providers", response_model=List[AIProviderResponse])
async def get_providers():
    return [
        {"id": "openai", "name": "OpenAI", "models": ["gpt-4o", "gpt-4o-mini"]},
        {"id": "anthropic", "name": "Anthropic", "models": ["claude-3-5-sonnet-20240620", "claude-3-haiku-20240307"]},
        {"id": "google", "name": "Google Gemini", "models": ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash"]},
        {"id": "ollama", "name": "Ollama (Local)", "models": ["llama3", "mistral", "gemma"]},
    ]

@router.get("/user/api-keys", response_model=List[KeyResponse])
async def get_user_keys(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(UserAPIKey).where(UserAPIKey.user_id == current_user.id)
    result = await db.execute(stmt)
    keys = result.scalars().all()
    return [{"id": k.id, "provider": k.provider, "is_active": k.is_active} for k in keys]

@router.post("/user/api-keys", response_model=KeyResponse)
async def add_user_key(
    req: AddKeyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Encrypt the key
    try:
        enc_key = encrypt_key(req.plain_key)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Encryption system is not properly configured on server.")

    # Check if a key for this provider already exists
    stmt = select(UserAPIKey).where(UserAPIKey.user_id == current_user.id, UserAPIKey.provider == req.provider)
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()

    if existing:
        existing.encrypted_key = enc_key
        existing.is_active = True
        key_obj = existing
    else:
        key_obj = UserAPIKey(
            user_id=current_user.id,
            provider=req.provider,
            encrypted_key=enc_key,
            is_active=True
        )
        db.add(key_obj)

    await db.commit()
    await db.refresh(key_obj)
    
    return {"id": key_obj.id, "provider": key_obj.provider, "is_active": key_obj.is_active}

@router.delete("/user/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_key(
    key_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    stmt = delete(UserAPIKey).where(UserAPIKey.id == key_id, UserAPIKey.user_id == current_user.id)
    result = await db.execute(stmt)
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="API Key not found")
    await db.commit()
