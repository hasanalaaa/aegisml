import json
import hmac
import hashlib
import logging
from typing import Any
import httpx
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel, HttpUrl
import uuid
import secrets

from database import get_db, WebhookSubscription, WebhookLog
from auth.models import User
from auth.utils import get_current_user

logger = logging.getLogger("aegisml.webhooks")
router = APIRouter(prefix="/api/v1/developer", tags=["developer"])

class WebhookCreate(BaseModel):
    url: HttpUrl
    events: list[str]

class WebhookResponse(BaseModel):
    id: int
    url: str
    events: list[str]
    secret_token: str
    is_active: bool
    created_at: str

@router.post("/webhooks", response_model=WebhookResponse)
async def create_webhook(
    webhook: WebhookCreate, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    """Register a new webhook subscription for the current developer."""
    secret_token = secrets.token_hex(32)
    
    new_sub = WebhookSubscription(
        user_id=current_user.id,
        url=str(webhook.url),
        secret_token=secret_token,
        events=webhook.events,
        is_active=True
    )
    
    db.add(new_sub)
    await db.commit()
    await db.refresh(new_sub)
    
    return {
        "id": new_sub.id,
        "url": new_sub.url,
        "events": new_sub.events,
        "secret_token": new_sub.secret_token,
        "is_active": new_sub.is_active,
        "created_at": new_sub.created_at.isoformat()
    }

@router.get("/webhooks", response_model=list[WebhookResponse])
async def list_webhooks(
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    """List all webhook subscriptions for the current developer."""
    stmt = select(WebhookSubscription).where(WebhookSubscription.user_id == current_user.id)
    result = await db.execute(stmt)
    subs = result.scalars().all()
    
    return [
        {
            "id": s.id,
            "url": s.url,
            "events": s.events,
            "secret_token": "********",  # Do not return token again for security
            "is_active": s.is_active,
            "created_at": s.created_at.isoformat()
        } for s in subs
    ]

@router.get("/webhooks/logs")
async def get_webhook_logs(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get the recent delivery logs for the user's webhooks."""
    # Join with WebhookSubscription to ensure user owns the log
    stmt = (
        select(WebhookLog, WebhookSubscription.url)
        .join(WebhookSubscription, WebhookLog.subscription_id == WebhookSubscription.id)
        .where(WebhookSubscription.user_id == current_user.id)
        .order_by(desc(WebhookLog.triggered_at))
        .limit(limit)
    )
    result = await db.execute(stmt)
    logs = result.all()
    
    return [
        {
            "id": log[0].id,
            "url": log[1],
            "event_type": log[0].event_type,
            "response_status": log[0].response_status,
            "response_body": log[0].response_body,
            "triggered_at": log[0].triggered_at.isoformat()
        } for log in logs
    ]

async def trigger_webhook(user_id: uuid.UUID, event_type: str, payload: dict[str, Any], db: AsyncSession):
    """
    Background engine to dispatch webhooks.
    Calculates HMAC-SHA256 signature using secret_token.
    """
    stmt = select(WebhookSubscription).where(
        WebhookSubscription.user_id == user_id,
        WebhookSubscription.is_active == True
    )
    result = await db.execute(stmt)
    subs = result.scalars().all()
    
    # Filter subs that listen to this event
    listening_subs = [s for s in subs if event_type in s.events or "all" in s.events]
    if not listening_subs:
        return
        
    payload_bytes = json.dumps(payload).encode('utf-8')
    
    async with httpx.AsyncClient(timeout=15.0) as client:
        for sub in listening_subs:
            # Cryptographic Signing
            signature = hmac.new(
                key=sub.secret_token.encode('utf-8'),
                msg=payload_bytes,
                digestmod=hashlib.sha256
            ).hexdigest()
            
            headers = {
                "Content-Type": "application/json",
                "X-Aegis-Signature": signature,
                "X-Aegis-Event": event_type
            }
            
            log_entry = WebhookLog(
                subscription_id=sub.id,
                event_type=event_type,
                payload=payload
            )
            
            try:
                response = await client.post(sub.url, content=payload_bytes, headers=headers)
                log_entry.response_status = response.status_code
                log_entry.response_body = response.text[:1000] # Cap body length
            except httpx.RequestError as e:
                logger.error(f"Webhook delivery failed for sub {sub.id}: {e}")
                log_entry.response_status = 500
                log_entry.response_body = f"Network Error: {str(e)}"
            
            db.add(log_entry)
            
    await db.commit()
