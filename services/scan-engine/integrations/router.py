from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

from .github_action import handle_github_scan, GitHubScanError

router = APIRouter(tags=["Integrations"])

# A dedicated limiter instance for the CI/CD-facing endpoint. This is kept
# separate from the main app's limiter (defined in main.py) specifically to
# avoid a circular import — main.py imports this router, so this module
# cannot import back from main.py. slowapi's @limiter.limit decorator binds
# to whichever Limiter instance decorates the route, so this still enforces
# real per-IP rate limiting independent of the rest of the app.
gh_limiter = Limiter(key_func=get_remote_address)


class GithubScanRequest(BaseModel):
    model_url: str = Field(..., max_length=2048)
    fail_on: str = "CRITICAL"


@router.post("/slack/events")
async def slack_events(request: Request):
    # Mock endpoint for Slack event subscription
    # In production, dispatch to slack_bolt adapter
    payload = await request.json()
    if "challenge" in payload:
        return {"challenge": payload["challenge"]}
    return {"status": "ok"}


@router.post("/discord/webhook")
async def discord_webhook(request: Request):
    # Mock endpoint for Discord Interactions/Webhooks
    return {"type": 4, "data": {"content": "Scan queued!"}}


@router.post("/github/scan")
@gh_limiter.limit("20/hour")
async def github_scan(request: Request, req: GithubScanRequest):
    """Real CI/CD scan gate: downloads the referenced HuggingFace model,
    runs it through the full AegisML scan engine, and returns pass/fail
    relative to `fail_on` so a GitHub Actions workflow can gate merges on
    the result. See integrations/github_action.py for the implementation —
    this used to return a hardcoded mock verdict regardless of input."""
    try:
        result = await handle_github_scan(req.model_url, req.fail_on)
    except GitHubScanError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    return result
