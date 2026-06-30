from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List
from hf_monitor.scheduler import get_scheduler_status
import datetime

router = APIRouter(tags=["HF Monitor"])

class SubscribeRequest(BaseModel):
    author: str

# Mock data for recent models and subscriptions
_recent_models = [
    {"name": "test/model1", "author": "test", "risk": "safe", "time": datetime.datetime.now().isoformat(), "scan_id": "uuid-123"},
    {"name": "hacker/malware_agent", "author": "hacker", "risk": "critical", "time": datetime.datetime.now().isoformat(), "scan_id": "uuid-456"}
]
_subscriptions = ["meta-llama", "mistralai"]

@router.get("/recent")
async def get_recent():
    return {"models": _recent_models}

@router.get("/status")
async def get_status():
    return get_scheduler_status()

@router.post("/subscribe")
async def subscribe(req: SubscribeRequest):
    if req.author not in _subscriptions:
        _subscriptions.append(req.author)
    return {"status": "subscribed", "author": req.author}

@router.delete("/subscribe/{author}")
async def unsubscribe(author: str):
    if author in _subscriptions:
        _subscriptions.remove(author)
    return {"status": "unsubscribed", "author": author}

@router.get("/subscriptions")
async def get_subscriptions():
    return {"subscriptions": _subscriptions}
