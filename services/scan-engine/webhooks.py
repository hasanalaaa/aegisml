import hmac
import hashlib
import json
import httpx
from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
import uuid

# Models for the router
class WebhookRegisterRequest(BaseModel):
    url: str
    events: list[str]

class WebhookResponse(BaseModel):
    id: int
    url: str
    secret_token: str
    events: list[str]

webhooks_router = APIRouter()

# HMAC Signing
def sign_payload(secret: str, payload: dict) -> str:
    payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    signature = hmac.new(secret.encode('utf-8'), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={signature}"

async def trigger_webhook(url: str, secret: str, event: str, payload: dict):
    headers = {
        "Content-Type": "application/json",
        "X-AegisML-Event": event,
        "X-AegisML-Signature": sign_payload(secret, payload)
    }
    
    async with httpx.AsyncClient() as client:
        try:
            await client.post(url, json=payload, headers=headers, timeout=5.0)
        except Exception as e:
            print(f"Webhook delivery failed to {url}: {str(e)}")

# Endpoints
@webhooks_router.post("/register", response_model=WebhookResponse)
async def register_webhook(req: WebhookRegisterRequest):
    # In a real app, this interacts with the DB (from database import get_db, WebhookSubscription)
    # We mock it for the Phase 7 integration structure test
    secret_token = "whsec_" + uuid.uuid4().hex
    return WebhookResponse(
        id=1,
        url=req.url,
        secret_token=secret_token,
        events=req.events
    )

@webhooks_router.get("", response_model=list[WebhookResponse])
async def list_webhooks():
    return []

@webhooks_router.delete("/{hook_id}")
async def delete_webhook(hook_id: int):
    return {"status": "success", "deleted": hook_id}

@webhooks_router.post("/test/{hook_id}")
async def test_webhook(hook_id: int):
    # Mock finding hook and firing
    mock_url = "https://httpbin.org/post"
    mock_secret = "whsec_mock"
    await trigger_webhook(mock_url, mock_secret, "ping", {"message": "AegisML Webhook Test"})
    return {"status": "success", "message": "Test webhook fired"}
