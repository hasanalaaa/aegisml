"""
AegisML Scan Engine - FastAPI Backend v2.0.0

Self-hostable API for static security inspection of AI model artifacts.
PostgreSQL and Redis are supported; local inline mode can use SQLite alone.
"""


import hashlib
import json
import logging
import os
import secrets
import subprocess
import tempfile
import uuid
import asyncio
from contextlib import asynccontextmanager

from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import unquote, urlparse

from dotenv import load_dotenv
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cache import (
    PREFIX_SCAN,
    get_cached_scan,
    get_cached_stats,
    get_cached_threats,
    invalidate_scan,
    set_cache,
    set_cached_scan,
    set_cached_stats,
    set_cached_threats,
)
from auth.models import User
from auth.router import router as auth_router
from growth.router import router as growth_router
import growth.models
from community.router import router as community_router
from enterprise.router import router as enterprise_router
from integrations.router import router as integrations_router
from research.router import router as research_router
from routers.threat_intel import router as threat_intel_router
from routers.ai_features import router as ai_features_router
from routers.analytics import router as analytics_router
from routers.developer import router as developer_router, trigger_webhook
from auth.utils import get_current_user
from threat_intel.scheduler import start_scheduler, shutdown_scheduler
from threat_intel.ioc_database import check_hash
from input_security import (
    InputSecurityError,
    sanitize_filename,
    secure_hf_stream,
    validate_hf_download_url,
    validate_model_header,
)
from database import (
    APIKey,
    AsyncSessionLocal,
    DATABASE_BACKEND,
    ScanRecord,
    ThreatPattern,
    check_db_health,
    check_redis_health,
    close_redis,
    get_db,
    init_db,
    init_redis,
    seed_threat_patterns,
)

load_dotenv()

# -- Logging ----------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("aegisml.api")

# -- Constants --------------------------------------------------------

VERSION = "2.0.0"
SUPPORTED_EXTENSIONS: frozenset[str] = frozenset(
    {".gguf", ".safetensors", ".pkl", ".pickle", ".pt", ".pth"}
)
MAX_FILE_SIZE: int = 100 * 1024 * 1024 * 1024  # 100 GB absolute maximum — no tier limits

ALLOWED_SCAN_HOSTS: frozenset[str] = frozenset(
    {
        "huggingface.co",
        "hf.co",
        "cdn-lfs.huggingface.co",
        "cdn-lfs-us-1.huggingface.co",
    }
)

# Fallback patterns used when DB has none
BUILTIN_THREAT_PATTERNS: list[dict[str, str]] = [
    {
        "pattern": "os.system",
        "severity": "critical",
        "category": "code_execution",
        "description_en": "System command execution",
        "description_ar": "تنفيذ أوامر النظام",
    },
    {
        "pattern": "subprocess",
        "severity": "high",
        "category": "code_execution",
        "description_en": "External process execution",
        "description_ar": "تشغيل عمليات خارجية",
    },
    {
        "pattern": "eval",
        "severity": "critical",
        "category": "code_execution",
        "description_en": "Dynamic code evaluation",
        "description_ar": "تنفيذ كود ديناميكي",
    },
    {
        "pattern": "exec",
        "severity": "critical",
        "category": "code_execution",
        "description_en": "Code execution function",
        "description_ar": "دالة تنفيذ الكود",
    },
    {
        "pattern": "pickle.loads",
        "severity": "high",
        "category": "deserialization",
        "description_en": "Unsafe pickle deserialization",
        "description_ar": "تحميل pickle غير آمن",
    },
    {
        "pattern": "__reduce__",
        "severity": "critical",
        "category": "deserialization",
        "description_en": "Pickle execution hook",
        "description_ar": "خطاف تنفيذ pickle",
    },
    {
        "pattern": "import os",
        "severity": "high",
        "category": "system_access",
        "description_en": "OS module import",
        "description_ar": "استيراد وحدة النظام",
    },
    {
        "pattern": "shutil",
        "severity": "medium",
        "category": "file_operations",
        "description_en": "File system operations",
        "description_ar": "عمليات نظام الملفات",
    },
    {
        "pattern": "base64",
        "severity": "medium",
        "category": "obfuscation",
        "description_en": "Potential code obfuscation",
        "description_ar": "إخفاء الكود المحتمل",
    },
    {
        "pattern": "socket",
        "severity": "high",
        "category": "network",
        "description_en": "Network socket access",
        "description_ar": "الوصول للشبكة",
    },
    {
        "pattern": "requests",
        "severity": "medium",
        "category": "network",
        "description_en": "HTTP request capability",
        "description_ar": "قدرة طلب HTTP",
    },
    {
        "pattern": "urllib",
        "severity": "medium",
        "category": "network",
        "description_en": "URL access capability",
        "description_ar": "قدرة الوصول للروابط",
    },
    {
        "pattern": "__import__",
        "severity": "high",
        "category": "code_execution",
        "description_en": "Dynamic import",
        "description_ar": "استيراد ديناميكي",
    },
    {
        "pattern": "ctypes",
        "severity": "critical",
        "category": "system_access",
        "description_en": "Low-level system access",
        "description_ar": "وصول منخفض للنظام",
    },
]

# -- Rate Limiter -----------------------------------------------------

limiter = Limiter(key_func=get_remote_address)

# -- Connection Manager -----------------------------------------------

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, list[Any]] = {}

    async def connect(self, scan_id: str, websocket: Any):
        # We type hint websocket as Any to allow MockWS for SSE
        if hasattr(websocket, "accept"):
            await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)

    def disconnect(self, scan_id: str, websocket: Any):
        if scan_id in self.active_connections:
            if websocket in self.active_connections[scan_id]:
                self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def send_progress(self, scan_id: str, data: dict[str, Any]):
        if scan_id in self.active_connections:
            for connection in list(self.active_connections[scan_id]):
                try:
                    await connection.send_json(data)
                except Exception:
                    pass

manager = ConnectionManager()

# -- Lifespan ---------------------------------------------------------


from fastapi.middleware.gzip import GZipMiddleware
from arq import create_pool
from arq.connections import RedisSettings

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Application startup initiated.")
    try:
        await init_db()
        redis_ok = await init_redis()
        logger.info("Redis status: %s", "connected" if redis_ok else "disabled")

        async with AsyncSessionLocal() as session:
            await seed_threat_patterns(session)
    except Exception as exc:
        logger.error(f"Startup error: {exc}")

    start_scheduler()

    # Redis/arq is optional: large-file async scans use it, but the API (and
    # inline scans) must still boot without it.
    try:
        app.state.arq_pool = await create_pool(RedisSettings.from_dsn(os.getenv("REDIS_URL", "redis://localhost:6379/0")))
    except Exception as exc:
        logger.warning("ARQ/Redis pool unavailable (%s) - large-file async scans disabled; inline scans still work.", exc)
        app.state.arq_pool = None

    logger.info("AegisML v%s started", VERSION)
    yield

    # Shutdown
    shutdown_scheduler()
    if getattr(app.state, "arq_pool", None):
        await app.state.arq_pool.close()
    await close_redis()
    logger.info("AegisML shutdown complete")

# -- App --------------------------------------------------------------

app = FastAPI(
    title="AegisML API",
    description="Static, no-execution security inspection for AI model artifacts.",
    version=VERSION,
    lifespan=lifespan,
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

app.include_router(auth_router, prefix="/auth", tags=["Auth"])
app.include_router(community_router, prefix="/api/v1/community", tags=["Community"])
app.include_router(enterprise_router, prefix="/api/v1/enterprise", tags=["Enterprise"])
app.include_router(integrations_router, prefix="/api/v1/integrations")
app.include_router(research_router)
app.include_router(threat_intel_router)
app.include_router(ai_features_router)
app.include_router(analytics_router)
app.include_router(developer_router)
app.include_router(growth_router, prefix="/api/v1", tags=["Growth"])

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Dynamic CORS to support Vercel preview URLs
FRONTEND_URL = os.getenv("FRONTEND_URL", "")
ALLOWED_ORIGINS: list[str] = [
    "http://localhost:4001",
    "https://aegisml.vercel.app",
]
if FRONTEND_URL:
    ALLOWED_ORIGINS.append(FRONTEND_URL)
for k, v in os.environ.items():
    if "VERCEL_URL" in k and v:
        if not v.startswith("http"):
            v = f"https://{v}"
        if v not in ALLOWED_ORIGINS:
            ALLOWED_ORIGINS.append(v)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    max_age=86400,
)


# ======================================================================
# SECURITY MIDDLEWARE & RATE LIMITING
# ======================================================================
import jwt
from auth.utils import SECRET_KEY, ALGORITHM
from datetime import datetime, timedelta

@app.middleware("http")
async def plan_rate_limit_middleware(request: Request, call_next):
    if not request.url.path.startswith("/api/v1/scan"):
        return await call_next(request)

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        plan = "free"
        user_id = request.client.host if request.client else "unknown_ip"
    else:
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id = str(payload.get("sub"))
            async with AsyncSessionLocal() as session:
                from auth.models import User
                user = await session.get(User, user_id)
                if user:
                    if getattr(user, "role", None) == "researcher":
                        plan = "enterprise"
                    else:
                        plan = user.plan
                else:
                    plan = "free"
        except Exception:
            plan = "free"
            user_id = request.client.host if request.client else "unknown_ip"

    if plan in ["enterprise", "researcher"]:
        return await call_next(request)

    limits = {
        "free": {"min": 10, "hour": 100, "day": 1000},
        "pro": {"min": 60, "hour": 1000, "day": 5000}
    }
    p = limits.get(plan, limits["free"])

    from database import redis_client
    if redis_client:
        try:
            now = int(datetime.now().timestamp())
            min_key = f"ratelimit:{user_id}:min:{now // 60}"
            hour_key = f"ratelimit:{user_id}:hour:{now // 3600}"
            day_key = f"ratelimit:{user_id}:day:{now // 86400}"

            pipe = redis_client.pipeline()
            pipe.incr(min_key)
            pipe.expire(min_key, 60)
            pipe.incr(hour_key)
            pipe.expire(hour_key, 3600)
            pipe.incr(day_key)
            pipe.expire(day_key, 86400)

            results = await pipe.execute()
            c_min, c_hour, c_day = results[0], results[2], results[4]

            if c_min > p["min"] or c_hour > p["hour"] or c_day > p["day"]:
                return JSONResponse(status_code=429, content={"error": "Scan limit reached", "upgrade_url": "/scan"})
        except Exception as e:
            logger.error(f"Rate limit error: {e}")

    return await call_next(request)



@app.middleware("http")
async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Inject security headers into every response."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


# ======================================================================
# ENDPOINTS
# ======================================================================


@app.get("/health")
async def health() -> dict[str, Any]:
    """Report required database health and optional queue availability."""
    db_ok = await check_db_health()
    redis_ok = await check_redis_health()

    # Redis accelerates queued large-file work, but the documented local mode
    # deliberately supports inline scans without it.  Do not make container
    # health checks restart an otherwise usable local API.
    status = "healthy" if db_ok else "unhealthy"

    return {
        "status": status,
        "database": DATABASE_BACKEND,
        "redis": "connected" if redis_ok else "disconnected",
        "queue": "enabled" if redis_ok else "inline-only",
        "version": VERSION,
    }


@app.get("/api/v1/stats")
async def get_stats(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Platform-wide scan statistics.  Cached for 60 s."""
    cached = await get_cached_stats()
    if cached is not None:
        return cached

    # Single aggregated query (was 6 sequential round-trips). FILTER-ed
    # aggregates let Postgres compute every bucket in one table scan, which
    # keeps p99 latency flat under load even before the 60s cache kicks in.
    row = (
        await db.execute(
            select(
                func.count(ScanRecord.id),
                func.count(ScanRecord.id).filter(ScanRecord.risk_level == "clean"),
                func.count(ScanRecord.id).filter(ScanRecord.risk_level == "suspicious"),
                func.count(ScanRecord.id).filter(ScanRecord.risk_level == "malicious"),
                func.count(ScanRecord.id).filter(ScanRecord.risk_level == "critical"),
                func.avg(ScanRecord.risk_score),
            )
        )
    ).one()
    total, clean, suspicious, malicious, critical, avg_score = row

    result: dict[str, Any] = {
        "total": total or 0,
        "clean": clean or 0,
        "suspicious": suspicious or 0,
        "malicious": malicious or 0,
        "critical": critical or 0,
        "avg_risk_score": round(float(avg_score or 0.0), 1),
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }
    await set_cached_stats(result)
    return result


@app.get("/api/v1/scans/recent")
async def get_recent_scans(
    _limit: int = Query(10, ge=1, le=50, alias="limit"),
) -> list[dict[str, Any]]:
    """Do not enumerate user scans through the unauthenticated public API."""
    return []


# -- WebSockets & Streaming -------------------------------------------

@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan_endpoint(websocket: WebSocket, scan_id: str):
    await manager.connect(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)


@app.get("/api/v1/scan/{scan_id}/stream")
async def scan_stream(scan_id: str, db: AsyncSession = Depends(get_db)):
    """SSE Fallback for streaming progress.

    Fixes vs. previous version: if the scan already finished before the
    client subscribed, emit a 'complete' event immediately instead of
    hanging forever; idle keepalives + an absolute deadline prevent
    orphaned connections from leaking queue subscribers.
    """
    # If the scan already reached a terminal state, don't subscribe — reply
    # and end. The cache now also holds *in-progress* snapshots (so the HTTP
    # polling fallback returns 200 instead of 404); those must NOT be treated
    # as finished here, or we'd wrongly tell the SSE client the scan is done.
    existing = await get_cached_scan(scan_id)
    if isinstance(existing, dict) and existing.get("status") == "processing":
        existing = None  # still running — fall through and stream live updates

    if existing is None:
        r = await db.execute(select(ScanRecord).where(ScanRecord.scan_id == scan_id))
        rec = r.scalar_one_or_none()
        if rec is not None:
            existing = {"stage": "complete", "progress": 100}

    if existing is not None:
        if isinstance(existing, dict) and existing.get("status") == "error":
            done = {
                "stage": "error",
                "progress": existing.get("progress", 0),
                "message": existing.get("message", "Scan error."),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        else:
            done = {
                "stage": "complete",
                "progress": 100,
                "message": "اكتمل الفحص",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        return StreamingResponse(
            iter([f"data: {json.dumps(done, ensure_ascii=False)}\n\n"]),
            media_type="text/event-stream",
        )

    q: asyncio.Queue = asyncio.Queue()

    class MockWS:
        async def send_json(self, data: dict[str, Any]):
            await q.put(data)

    mock_ws = MockWS()
    await manager.connect(scan_id, mock_ws)

    MAX_STREAM_SECONDS = 30 * 60  # absolute deadline
    KEEPALIVE_SECONDS = 25

    async def event_stream():
        deadline = asyncio.get_event_loop().time() + MAX_STREAM_SECONDS
        try:
            while asyncio.get_event_loop().time() < deadline:
                try:
                    data = await asyncio.wait_for(q.get(), timeout=KEEPALIVE_SECONDS)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
                if data.get("stage") in ("complete", "error"):
                    break
        finally:
            manager.disconnect(scan_id, mock_ws)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.websocket("/ws/stats")
async def websocket_stats_endpoint(websocket: WebSocket, db: AsyncSession = Depends(get_db)):
    """Live stats feed.

    Uses its OWN cache key ('aegisml:livestats'). Previously it shared the
    /api/v1/stats key while writing a different JSON shape, so each endpoint
    could poison the other's cache.
    """
    from cache import get_cache, set_cache

    LIVE_STATS_KEY = "aegisml:livestats"
    await websocket.accept()
    try:
        while True:
            cached = await get_cache(LIVE_STATS_KEY)
            if cached is not None:
                cached["activeScans"] = len(manager.active_connections)
                await websocket.send_json(cached)
            else:
                result = await db.execute(select(func.count(ScanRecord.id)))
                total_scans = result.scalar() or 0

                result = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.risk_level.in_(["malicious", "critical"])))
                threats_found = result.scalar() or 0

                stats = {"totalScans": total_scans, "threatsFound": threats_found, "activeScans": len(manager.active_connections)}
                await set_cache(LIVE_STATS_KEY, stats, ttl=15)
                await websocket.send_json(stats)
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        pass


# -- Background Process -----------------------------------------------

# In-progress and error snapshots live longer than a completed result (30s,
# TTL_SCAN). A single stage — notably a large-file download — can easily exceed
# 30s, and an error state has NO database row to fall back on, so if either
# expired the polling endpoint would return 404 again and the frontend would
# re-freeze. 15 minutes comfortably covers the longest single stage while still
# self-cleaning abandoned scans.
PROGRESS_STATE_TTL: int = 15 * 60


async def _persist_scan_state(scan_id: str, state: dict[str, Any]) -> None:
    """Persist an intermediate progress / error snapshot to the scan cache.

    This is what lets the HTTP polling fallback (GET /api/v1/scan/{scan_id})
    return 200 with live status while a background scan is still running,
    instead of 404-ing until the scan finishes. Failures here must never abort
    the scan itself, so all errors are swallowed (and logged).
    """
    try:
        await set_cache(f"{PREFIX_SCAN}{scan_id}", state, ttl=PROGRESS_STATE_TTL)
    except Exception as exc:  # pragma: no cover - cache is best-effort
        logger.warning("Failed to persist scan state for %s: %s", scan_id, exc)


async def _emit_progress(
    scan_id: str,
    stage: str,
    progress: int,
    message: str,
    *,
    threat_count: int = 0,
    filename: Optional[str] = None,
    status: str = "processing",
    persist: bool = True,
) -> None:
    """Broadcast a progress event over WebSocket AND (optionally) persist it.

    The WebSocket payload keeps its historical shape (stage/progress/message/
    threat_count/timestamp) so existing WS + SSE clients are unaffected. The
    persisted cache snapshot additionally carries ``scan_id``/``status`` so the
    polling endpoint can report live progress and terminate the loading state
    on error.

    ``persist`` is set False for the terminal "complete" event: by that point
    the full scan result has already been written to the cache, and we must not
    clobber it with a lightweight progress dict.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {
        "stage": stage,
        "progress": progress,
        "message": message,
        "threat_count": threat_count,
        "timestamp": timestamp,
    }
    await manager.send_progress(scan_id, payload)

    if not persist:
        return

    state: dict[str, Any] = {
        "scan_id": scan_id,
        "status": status,
        "stage": stage,
        "progress": progress,
        "message": message,
        "threat_count": threat_count,
        "timestamp": timestamp,
    }
    if filename is not None:
        state["filename"] = filename
    await _persist_scan_state(scan_id, state)


async def _process_scan(
    temp_path: Optional[str],
    filename: str,
    ext: str,
    scan_id: str,
    content_size: int,
    source_type: str,
    source_url: str,
    ip_address: Optional[str],
    user_agent: str,
    ai_provider: Optional[str] = None,
    ai_model: Optional[str] = None,
    user_id: Optional[str] = None,
    api_key: Optional[str] = None,
):
    try:
        # Persist an immediate snapshot so the polling fallback returns 200 the
        # instant the background task starts, instead of 404 until stage 1.
        await _emit_progress(
            scan_id, "initializing", 2, "بدء الفحص...",
            threat_count=0, filename=filename,
        )

        await _emit_progress(
            scan_id, "header_check", 10, "فحص الهيكل الأساسي...",
            threat_count=0, filename=filename,
        )
        await asyncio.sleep(0.5)

        if not temp_path:
            raise ValueError("No file provided for scanning.")

        file_size = os.path.getsize(temp_path)
        # The trusted local adapter owns the only full-byte evidence pass,
        # including SHA-256. IOC enrichment runs afterwards and can only raise
        # the static verdict; it never skips local analysis.
        await _emit_progress(
            scan_id, "parallel_analysis", 40, "تحليل محلي شامل للملف...",
            threat_count=0, filename=filename,
        )
        from scanner import engine as scanner_engine
        scan_result = await scanner_engine.scan(
            file_path=temp_path,
            scan_id=scan_id,
            manager_ws=manager,
        )
        file_hash = scan_result["file_hash"]
        ioc_hit = await check_hash(file_hash)

        threats = list(scan_result["threats"])
        highest_cvss = float(scan_result["highest_cvss"])
        engine_verdict = scan_result["verdict"]
        if ioc_hit:
            threats.insert(0, {
                "id": "IOC-BLACKLIST",
                "pattern": "IOC-BLACKLIST",
                "name": "Known Malicious File (IOC Match)",
                "severity": "critical",
                "cvss": 10.0,
                "description": "This file is known to be malicious according to the global IOC database.",
                "location": filename,
                "category": "known_malware",
                "byte_offsets": [],
                "occurrences": 1,
                "remediation": "Quarantine the artifact and verify its source.",
                "references": [],
            })
            highest_cvss = 10.0
            engine_verdict = "critical"

        verdict_to_risk_level = {
            "safe": "clean",
            "suspicious": "suspicious",
            "dangerous": "malicious",
            "critical": "critical",
        }
        risk_level = verdict_to_risk_level.get(engine_verdict, "suspicious")
        threat_count = len(threats)
        result: dict[str, Any] = {
            "scan_id": scan_id,
            "filename": filename,
            "risk_score": round(highest_cvss * 10, 1),
            "risk_level": risk_level,
            "verdict": engine_verdict.upper(),
            "threats": threats,
            "entropy": scan_result["entropy_analysis"],
            "cvss": highest_cvss,
            "format_detected": scan_result["format_detected"],
            "metadata": {
                "file_size": file_size,
                "extension": ext,
                "threats_found": threat_count,
                "ioc_hit": bool(ioc_hit),
                "file_hash": file_hash,
                "format_detected": scan_result["format_detected"],
                "entropy_analysis": scan_result["entropy_analysis"],
                "patterns_checked": scan_result.get("patterns_checked", 0),
                "scan_passes": scan_result.get("scan_passes", []),
                "highest_cvss": highest_cvss,
                "format_specific": scan_result.get("format_specific", {}),
                "coverage": scan_result["coverage"],
            },
        }

        ai_enabled = bool(api_key and api_key.strip()) or (
            os.getenv("AEGISML_ENABLE_AI_ANALYSIS", "").strip().lower() == "true"
        )
        progress_stage = "ai_analysis" if ai_enabled else "finalizing"
        progress_message = (
            "تحليل اختياري بالذكاء الاصطناعي..."
            if ai_enabled
            else "جارٍ حفظ تقرير الفحص المحلي..."
        )
        await _emit_progress(
            scan_id, progress_stage, 90, progress_message,
            threat_count=threat_count, filename=filename,
        )

        if ai_enabled:
            from ai_providers.manager import manager as ai_manager

            try:
                ai_res_obj = await ai_manager.analyze(
                    file_info={"filename": filename, "size": content_size},
                    scan_results=result,
                    provider=ai_provider or "anthropic",
                    model=ai_model,
                    user_api_key=api_key,
                    fallback=True,
                )
                ai_result = {
                    "verdict": ai_res_obj.verdict,
                    "confidence": ai_res_obj.confidence,
                    "summary_en": ai_res_obj.explanation,
                    "summary_ar": ai_res_obj.explanation,
                    "key_risks": ai_res_obj.recommendations,
                    "recommendation": ai_res_obj.explanation,
                    "recommendation_ar": ai_res_obj.explanation,
                    "technical_details": "Optional AI enrichment; static verdict remains authoritative.",
                    "provider": ai_res_obj.provider,
                    "model": ai_res_obj.model,
                    "static_only": False,
                }
            except Exception as exc:
                logger.warning("Optional AI enrichment failed (%s)", type(exc).__name__)
                ai_result = {
                    "verdict": result["verdict"],
                    "confidence": 0,
                    "summary_en": "AI enrichment was unavailable; the static local verdict is unchanged.",
                    "summary_ar": "تعذر إثراء الذكاء الاصطناعي؛ نتيجة الفحص المحلي لم تتغير.",
                    "key_risks": [],
                    "recommendation": "Use the deterministic static findings in this report.",
                    "recommendation_ar": "اعتمد نتائج الفحص المحلي الحتمية في هذا التقرير.",
                    "provider": "static",
                    "model": None,
                    "static_only": True,
                }
        else:
            ai_result = {
                "verdict": result["verdict"],
                "confidence": 0,
                "summary_en": "Static local analysis only; AI enrichment was not requested.",
                "summary_ar": "تحليل محلي ثابت فقط؛ لم يُطلب إثراء بالذكاء الاصطناعي.",
                "key_risks": [],
                "recommendation": "Review the deterministic static findings in this report.",
                "recommendation_ar": "راجع نتائج الفحص المحلي الحتمية في هذا التقرير.",
                "technical_details": "No model-provider network call was made.",
                "provider": "static",
                "model": None,
                "static_only": True,
            }

        result["ai_analysis"] = ai_result
        if source_type == "url":
            result["source_url"] = source_url
        result["created_at"] = datetime.now(timezone.utc).isoformat()

        await set_cached_scan(scan_id, result)

        async with AsyncSessionLocal() as db:
            record = ScanRecord(
                scan_id=scan_id,
                filename=filename,
                file_size=file_size,
                file_extension=ext,
                file_hash=file_hash,
                risk_score=result.get("risk_score", 0),
                risk_level=result.get("risk_level", "clean"),
                threats=result.get("threats", []),
                metadata_info=result.get("metadata", {}),
                ai_verdict=result.get("ai_analysis", {}).get("verdict"),
                ai_confidence=result.get("ai_analysis", {}).get("confidence"),
                ai_summary_en=result.get("ai_analysis", {}).get("summary_en"),
                ai_summary_ar=result.get("ai_analysis", {}).get("summary_ar"),
                ai_key_risks=result.get("ai_analysis", {}).get("key_risks", []),
                ai_recommendation_en=result.get("ai_analysis", {}).get("recommendation"),
                ai_recommendation_ar=result.get("ai_analysis", {}).get("recommendation_ar"),
                source_type=source_type,
                source_url=source_url,
                ip_address=ip_address,
                user_agent=user_agent,
                is_public=False,
            )
            db.add(record)
            await db.commit()

            if user_id:
                try:
                    user_uuid = uuid.UUID(user_id)
                    await trigger_webhook(
                        user_id=user_uuid,
                        event_type="scan.completed",
                        payload={"scan_id": scan_id, "risk_level": result.get("risk_level", "clean")},
                        db=db
                    )
                    if result.get("risk_level") == "critical":
                        await trigger_webhook(
                            user_id=user_uuid,
                            event_type="threat.critical",
                            payload={"scan_id": scan_id, "threats": result.get("threats", [])},
                            db=db
                        )
                except Exception as wh_exc:
                    logger.error(f"Failed to trigger webhooks: {wh_exc}")

        # Bust the aggregate stats cache (a new scan changes the totals) but
        # KEEP the fresh per-scan cache entry we just wrote above — the old
        # invalidate_scan() call deleted it immediately after setting it.
        from cache import PREFIX_STATS, delete_cache
        await delete_cache(PREFIX_STATS)

        # persist=False: the full result dict is already in the cache (written
        # above via set_cached_scan). Broadcast completion without overwriting it
        # with a lightweight progress snapshot.
        await _emit_progress(
            scan_id, "complete", 100, "اكتمل الفحص بنجاح",
            threat_count=threat_count, filename=filename,
            status="complete", persist=False,
        )

    except Exception as exc:
        logger.error("Scan failed for %s: %s", filename, exc, exc_info=True)
        # Persist the error state so the polling fallback returns a terminal
        # error (HTTP 200) and the frontend can kill its loading spinner,
        # instead of hanging on 404. Message stays generic — no internal
        # exception detail is leaked to API consumers.
        await _emit_progress(
            scan_id, "error", 0, "Internal scan error.",
            threat_count=0, filename=filename, status="error",
        )
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError as exc:
                logger.warning("Failed to remove temp file %s: %s", temp_path, exc)


async def _process_url_scan(
    url: str,
    filename: str,
    ext: str,
    scan_id: str,
    max_size: int,
    ip_address: Optional[str],
    user_agent: str,
    ai_provider: Optional[str] = None,
    ai_model: Optional[str] = None,
    user_id: Optional[str] = None,
    api_key: Optional[str] = None,
):
    temp_path: Optional[str] = None
    try:
        await _emit_progress(
            scan_id, "downloading", 5, "جارٍ تحميل النموذج من الرابط...",
            threat_count=0, filename=filename,
        )
        import httpx
        # 4-hour timeout: massive (70 GB+) model downloads must not drop mid-stream.
        # Redirects are followed manually so every destination is validated.
        async with httpx.AsyncClient(timeout=14400.0, follow_redirects=False) as client:
            headers: dict[str, str] = {}
            hf_token = os.getenv("HF_TOKEN")
            if hf_token:
                headers["Authorization"] = f"Bearer {hf_token}"
            async with secure_hf_stream(client, url, headers=headers) as response:
                if response.status_code != 200:
                    raise Exception(f"Failed to download from URL: HTTP {response.status_code}")
                content_length_raw = response.headers.get("content-length")
                if content_length_raw:
                    try:
                        declared_size = int(content_length_raw)
                    except ValueError:
                        pass
                    else:
                        if declared_size < 0:
                            raise InputSecurityError("Invalid download size")
                        if declared_size > max_size:
                            raise Exception(f"File too large. Maximum supported size is {max_size // (1024**3)} GB.")

                with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                    # Record the path BEFORE streaming so the finally-block can
                    # clean up if the download aborts midway (temp-file leak fix).
                    temp_path = tmp.name
                    # Stream straight to disk in 4 MB chunks — constant, tiny RAM
                    # footprint regardless of file size (zero RAM bloat at 100 GB).
                    downloaded = 0
                    head = b""
                    async for chunk in response.aiter_bytes(chunk_size=4 * 1024 * 1024):
                        if len(head) < 16:
                            head += chunk[: 16 - len(head)]
                        downloaded += len(chunk)
                        if downloaded > max_size:
                            raise Exception("File too large. Size limit exceeded.")
                        tmp.write(chunk)

                validate_model_header(ext, downloaded, head)

        await _process_scan(temp_path, filename, ext, scan_id, downloaded, "url", url, ip_address, user_agent, ai_provider, ai_model, user_id, api_key)
        temp_path = None # Prevents deleting it twice since _process_scan handles cleanup
    except Exception as exc:
        # Do not echo user-controlled URLs, signed query strings, DNS details,
        # or internal exception text into logs or the public progress feed.
        logger.warning("URL scan %s failed during download (%s)", scan_id, type(exc).__name__)
        # Persist the error state (download timeout, HTTP error, size limit, …)
        # so the polling fallback terminates the frontend loading state instead
        # of hanging at 404 forever.
        await _emit_progress(
            scan_id, "error", 0, "تعذر تنزيل الملف بأمان.",
            threat_count=0, filename=filename, status="error",
        )
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


# -- File Scan --------------------------------------------------------


def _validate_filename(name: str) -> str:
    """Sanitize and validate an uploaded filename."""
    return sanitize_filename(name)


def _validate_extension(filename: str) -> str:
    """Extract and validate file extension.  Raises HTTPException on invalid."""
    ext = os.path.splitext(filename)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format '{ext}'. Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}",
        )
    return ext


@app.post("/api/v1/scan/file", response_model=None)
@limiter.limit("10/minute")
async def scan_file(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    ai_provider: Optional[str] = Form(None),
    ai_model: Optional[str] = Form(None),
    api_key: Optional[str] = Form(None),
    x_ai_provider: Optional[str] = Header(None),
    x_ai_model: Optional[str] = Header(None),
    x_ai_key: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
) -> dict[str, Any]:
    """Upload and scan a model file for security threats.

    BYOK: the user's third-party AI key is supplied per-request via the
    X-AI-Key header (with optional X-AI-Provider / X-AI-Model). The key
    is used in-memory for this scan only and never persisted server-side.
    Legacy multipart form fields are still accepted as a fallback.
    """
    filename = _validate_filename(file.filename or "unknown")
    ext = _validate_extension(filename)

    # BYOK headers take precedence over legacy form fields. Nothing is stored.
    ai_provider = x_ai_provider or ai_provider
    ai_model = x_ai_model or ai_model
    api_key = x_ai_key or api_key

    # Strip and ignore unexpected metadata
    ai_provider = ai_provider[:50] if ai_provider else None
    ai_model = ai_model[:50] if ai_model else None

    # Check size limit before reading body.
    # Tier-based limits removed: every user gets the 100 GB absolute maximum.
    content_length_raw = request.headers.get("content-length")
    max_size = MAX_FILE_SIZE

    if content_length_raw:
        try:
            if int(content_length_raw) > max_size:
                raise HTTPException(status_code=413, detail=f"File too large. Maximum supported size is {max_size // (1024**3)} GB.")
        except ValueError:
            pass

    # Stream the upload to disk in 1 MB chunks. The previous implementation
    # buffered the ENTIRE file in memory (up to 5 GB for pro users), which
    # could OOM the process under a handful of concurrent large uploads.
    scan_id = str(uuid.uuid4())
    CHUNK = 1024 * 1024
    content_size = 0
    head = b""

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    temp_path = tmp.name
    try:
        while True:
            chunk = await file.read(CHUNK)
            if not chunk:
                break
            if len(head) < 16:
                head += chunk[: 16 - len(head)]
            content_size += len(chunk)
            if content_size > max_size:
                raise HTTPException(
                    status_code=413,
                    detail=f"File too large. Maximum supported size is {int(max_size // (1024**3))} GB.",
                )
            tmp.write(chunk)
    except BaseException:
        tmp.close()
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise
    tmp.close()

    if content_size == 0:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise HTTPException(status_code=400, detail="Empty file uploaded")

    # Magic byte validation (on the first bytes captured during streaming)
    def _reject(detail: str):
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise HTTPException(status_code=400, detail=detail)

    try:
        validate_model_header(ext, content_size, head)
    except InputSecurityError as exc:
        _reject(str(exc))

    ip_address = request.client.host if request.client else None
    user_agent = (request.headers.get("user-agent") or "")[:500]

    try:
        # ARQ serializes job arguments into Redis. A caller-supplied BYOK key
        # must remain in process memory, so scans carrying one use the local
        # background-task path even when a queue is available.
        if (
            content_size > 50 * 1024 * 1024
            and not api_key
            and getattr(request.app.state, "arq_pool", None)
        ):
            job = await request.app.state.arq_pool.enqueue_job(
                "scan_job",
                temp_path, filename, ext, scan_id, content_size, "upload", "", ip_address, user_agent, ai_provider, ai_model, str(current_user.id) if current_user else None, api_key
            )
            return {"scan_id": scan_id, "status": "processing", "job_id": job.job_id}

        background_tasks.add_task(
            _process_scan,
            temp_path, filename, ext, scan_id, content_size, "upload", "", ip_address, user_agent, ai_provider, ai_model, str(current_user.id) if current_user else None, api_key
        )
    except BaseException:
        # Ownership of the temporary file transfers only after successful job
        # dispatch. Queue outages must not accumulate complete uploads on disk.
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise

    return {"scan_id": scan_id, "status": "processing"}

@app.get("/api/v1/scan/{job_id}/status")
async def get_scan_job_status(job_id: str, request: Request):
    pool = getattr(request.app.state, "arq_pool", None)
    if pool is None:
        # Previously this only checked hasattr(), so a None pool crashed with
        # an AttributeError (HTTP 500) instead of a clean 503.
        raise HTTPException(status_code=503, detail="Background worker not available")
    from arq.jobs import Job
    job = Job(job_id, pool)
    status = await job.status()
    return {"job_id": job_id, "status": status.value}


# -- URL Scan ---------------------------------------------------------


def _validate_scan_url(url: str) -> tuple[str, str, str]:
    """Validate and parse a model-download URL.

    Returns (url, filename, extension).
    Raises HTTPException on invalid input.
    """
    url = url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    if len(url) > 2048:
        raise HTTPException(status_code=400, detail="URL too long (max 2048 chars)")

    try:
        url = validate_hf_download_url(url, initial=True)
    except InputSecurityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Extract filename from URL path
    parsed = urlparse(url)
    path_parts = parsed.path.rstrip("/").split("/")
    raw_filename = unquote(path_parts[-1]) if path_parts else ""
    filename = _validate_filename(raw_filename) if raw_filename else "model_from_url"

    ext = _validate_extension(filename)
    return url, filename, ext


@app.post("/api/v1/scan/url", response_model=None)
@limiter.limit("5/minute")
async def scan_url(
    request: Request,
    body: dict[str, Any],
    background_tasks: BackgroundTasks,
    x_ai_provider: Optional[str] = Header(None),
    x_ai_model: Optional[str] = Header(None),
    x_ai_key: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
) -> dict[str, Any]:
    """Download a model from a URL and scan it for security threats.

    BYOK: AI key supplied via the X-AI-Key header is used for this scan
    only and never persisted. Legacy body fields are accepted as fallback.
    """
    raw_url = body.get("url")
    if not isinstance(raw_url, str):
        raise HTTPException(status_code=400, detail="URL must be a string")

    # BYOK headers take precedence over legacy body fields. Nothing is stored.
    ai_provider = x_ai_provider or body.get("ai_provider")
    ai_model = x_ai_model or body.get("ai_model")
    api_key = x_ai_key or body.get("api_key")

    url, filename, ext = _validate_scan_url(raw_url)
    scan_id = str(uuid.uuid4())
    temp_path: Optional[str] = None

    # Tier-based limits removed: every user gets the 100 GB absolute maximum.
    max_size = MAX_FILE_SIZE

    ip_address = request.client.host if request.client else None
    user_agent = (request.headers.get("user-agent") or "")[:500]

    background_tasks.add_task(
        _process_url_scan,
        url,
        filename,
        ext,
        scan_id,
        max_size,
        ip_address,
        user_agent,
        ai_provider,
        ai_model,
        str(current_user.id) if current_user else None,
        api_key
    )

    return {"scan_id": scan_id, "status": "processing"}


# -- Get Scan Result --------------------------------------------------


@app.get("/api/v1/scan/{scan_id}")
async def get_scan(
    scan_id: str, db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    """Retrieve a scan result by its ID."""
    if not scan_id or len(scan_id) > 36:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    # Check cache first
    cached = await get_cached_scan(scan_id)
    if cached is not None:
        return cached

    # scan_id is an unguessable capability returned only to the caller that
    # submitted the scan. Public discovery and publication endpoints enforce
    # is_public separately.
    result = await db.execute(
        select(ScanRecord).where(ScanRecord.scan_id == scan_id)
    )
    record = result.scalar_one_or_none()

    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    response: dict[str, Any] = {
        "scan_id": record.scan_id,
        "filename": record.filename,
        "risk_score": record.risk_score,
        "risk_level": record.risk_level,
        "threats": record.threats or [],
        "metadata": record.metadata_info or {},
        "source_url": record.source_url,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "ai_analysis": {
            "verdict": record.ai_verdict or "UNKNOWN",
            "confidence": record.ai_confidence or 0,
            "summary_en": record.ai_summary_en or "",
            "summary_ar": record.ai_summary_ar or "",
            "key_risks": record.ai_key_risks or [],
            "recommendation": record.ai_recommendation_en or "",
            "recommendation_ar": record.ai_recommendation_ar or "",
        },
    }
    await set_cached_scan(scan_id, response)
    return response


# -- Threat Patterns --------------------------------------------------


@app.get("/api/v1/threats/patterns")
async def get_threat_patterns(
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """List all active threat patterns.  Cached for 300 s."""
    cached = await get_cached_threats()
    if cached is not None:
        return cached

    result = await db.execute(
        select(ThreatPattern)
        .where(ThreatPattern.is_active.is_(True))
        .order_by(desc(ThreatPattern.times_detected))
    )
    patterns = result.scalars().all()

    if not patterns:
        response: dict[str, Any] = {
            "patterns": BUILTIN_THREAT_PATTERNS,
            "source": "builtin",
        }
    else:
        response = {
            "patterns": [
                {
                    "pattern": p.pattern,
                    "severity": p.severity,
                    "category": p.category,
                    "description_en": p.description_en,
                    "description_ar": p.description_ar,
                    "times_detected": p.times_detected,
                }
                for p in patterns
            ],
            "source": "database",
        }

    await set_cached_threats(response)
    return response


# -- Badge ------------------------------------------------------------


@app.get("/api/v1/badge/{scan_id}")
async def get_badge(
    scan_id: str, db: AsyncSession = Depends(get_db)
) -> Response:
    """Generate an SVG badge for a scan result."""
    if not scan_id or len(scan_id) > 36:
        raise HTTPException(status_code=400, detail="Invalid scan ID")

    result = await db.execute(
        select(ScanRecord)
        .where(ScanRecord.scan_id == scan_id)
        .where(ScanRecord.is_public.is_(True))
    )
    record = result.scalar_one_or_none()

    if not record:
        color, label = "#9f9f9f", "unknown"
    elif record.risk_score < 30:
        color, label = "#2ECC71", "clean"
    elif record.risk_score < 60:
        color, label = "#E67E22", "suspicious"
    elif record.risk_score < 85:
        color, label = "#E74C3C", "dangerous"
    else:
        color, label = "#C0392B", "critical"

    left_w, right_w = 60, 70
    total_w = left_w + right_w
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20" role="img">
  <title>AegisML: {label}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="{total_w}" height="20" rx="3"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{left_w}" height="20" fill="#555"/>
    <rect x="{left_w}" width="{right_w}" height="20" fill="{color}"/>
    <rect width="{total_w}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle"
     font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{left_w // 2}" y="15" fill="#010101" fill-opacity=".3">AegisML</text>
    <text x="{left_w // 2}" y="14">AegisML</text>
    <text x="{left_w + right_w // 2}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{left_w + right_w // 2}" y="14">{label}</text>
  </g>
</svg>"""
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={"Cache-Control": "max-age=3600", "ETag": scan_id[:8]},
    )


@app.get("/api/v1/badge/{scan_id}/json")
async def get_badge_json(
    scan_id: str, db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    """Shields.io-compatible JSON badge endpoint."""
    if not scan_id or len(scan_id) > 36:
        raise HTTPException(status_code=400, detail="Invalid scan ID")

    result = await db.execute(
        select(ScanRecord)
        .where(ScanRecord.scan_id == scan_id)
        .where(ScanRecord.is_public.is_(True))
    )
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    color_map: dict[str, str] = {
        "clean": "brightgreen",
        "suspicious": "yellow",
        "malicious": "orange",
        "critical": "red",
    }
    return {
        "schemaVersion": 1,
        "label": "AegisML",
        "message": record.risk_level,
        "color": color_map.get(record.risk_level, "lightgrey"),
        "namedLogo": "shield",
    }


# -- Compare ----------------------------------------------------------


@app.get("/api/v1/compare")
async def compare_scans(
    scan_a: str,
    scan_b: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Compare two scan results side by side."""
    if not scan_a or not scan_b or len(scan_a) > 36 or len(scan_b) > 36:
        raise HTTPException(status_code=400, detail="Invalid scan ID(s)")

    async def _get_record(sid: str) -> Optional[dict[str, Any]]:
        # Comparison is a public publication feature. Do not use the private
        # scan cache here because it contains owner-facing results regardless
        # of publication status.
        r = await db.execute(
            select(ScanRecord)
            .where(ScanRecord.scan_id == sid)
            .where(ScanRecord.is_public.is_(True))
        )
        rec = r.scalar_one_or_none()
        if not rec:
            return None
        return {
            "scan_id": rec.scan_id,
            "filename": rec.filename,
            "risk_score": rec.risk_score,
            "risk_level": rec.risk_level,
            "threats": rec.threats or [],
            "ai_analysis": {
                "verdict": rec.ai_verdict or "UNKNOWN",
                "confidence": rec.ai_confidence or 0,
            },
        }

    a = await _get_record(scan_a)
    b = await _get_record(scan_b)

    if not a or not b:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    a_score: float = a.get("risk_score", 100.0)
    b_score: float = b.get("risk_score", 100.0)
    safer = scan_a if a_score <= b_score else scan_b
    return {
        "scan_a": a,
        "scan_b": b,
        "comparison": {
            "safer": safer,
            "risk_difference": abs(a_score - b_score),
            "a_threat_count": len(a.get("threats", [])),
            "b_threat_count": len(b.get("threats", [])),
        },
    }


# -- API Keys (AegisML platform keys, not third-party AI keys) ---------


def _hash_key(key: str) -> str:
    """SHA-256 hash of an API key for storage (never store plaintext)."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


@app.post("/api/v1/keys/generate")
@limiter.limit("3/hour")
async def generate_api_key(
    request: Request,
    body: dict[str, Any],
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Generate a new API key.  The raw key is shown only once."""
    name = str(body.get("name", "")).strip()
    email = str(body.get("email", "")).strip()

    if not name or len(name) < 3:
        raise HTTPException(
            status_code=400, detail="Name must be at least 3 characters"
        )
    if len(name) > 200:
        raise HTTPException(status_code=400, detail="Name too long (max 200 chars)")
    if email and len(email) > 200:
        raise HTTPException(status_code=400, detail="Email too long (max 200 chars)")

    raw_key = "aml_" + secrets.token_urlsafe(32)
    api_key_obj = APIKey(
        key_hash=_hash_key(raw_key),
        key_prefix=raw_key[:12],
        name=name,
        email=email or None,
        scans_limit=500,
    )
    db.add(api_key_obj)
    await db.commit()

    return {
        "api_key": raw_key,
        "prefix": raw_key[:12],
        "name": name,
        "scans_limit": 500,
        "warning": "Save this key securely - it will not be shown again.",
    }


@app.get("/api/v1/keys/validate")
async def validate_platform_key(
    request: Request, db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    """Validate an API key from the Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing API key")

    raw_key = auth[7:].strip()  # len("Bearer ") == 7
    if not raw_key:
        raise HTTPException(status_code=401, detail="Empty API key")

    result = await db.execute(
        select(APIKey).where(
            APIKey.key_hash == _hash_key(raw_key),
            APIKey.is_active.is_(True),
        )
    )
    api_key_obj = result.scalar_one_or_none()
    if not api_key_obj:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")

    return {
        "valid": True,
        "name": api_key_obj.name,
        "scans_used": api_key_obj.scans_used,
        "scans_limit": api_key_obj.scans_limit,
        "scans_remaining": api_key_obj.scans_limit - api_key_obj.scans_used,
    }



# -- AI Provider Endpoints --------------------------------------------

from ai_providers.manager import manager as ai_manager
from pydantic import BaseModel

class ValidateKeyRequest(BaseModel):
    provider: str
    api_key: str

@app.get("/api/v1/ai/providers")
async def list_providers():
    return {"providers": ai_manager.get_available_providers()}

@app.post("/api/v1/ai/validate-key")
async def validate_ai_key(req: ValidateKeyRequest):
    is_valid = await ai_manager.validate_key(req.provider, req.api_key)
    return {"valid": is_valid}

@app.get("/api/v1/ai/providers/{name}/models")
async def list_provider_models(name: str):
    providers = ai_manager.get_available_providers()
    for p in providers:
        if p["name"] == name:
            return {"models": p["models"]}
    raise HTTPException(status_code=404, detail="Provider not found")


# -- Operational Resilience (Phase 2) ---------------------------------

@app.get("/api/v1/ops/resilience")
async def ops_resilience() -> dict[str, Any]:
    """Real-time fault-tolerance telemetry for the ops dashboard.

    Surfaces two independent subsystems introduced in Phase 2:

    * **AI provider circuit breakers** — per-provider state (closed / open /
      half_open) plus lifetime success/failure counters, so a degraded
      upstream is visible before it starts costing every scan its full
      timeout. Reported in fallback order.
    * **Size-class admission control** — how many scans are in flight and
      waiting per file-size class, and the configured concurrency permits,
      so operators can see head-of-line pressure from large uploads.

    Read-only and side-effect free (breaker ``snapshot()`` never mutates
    state), so it is safe to poll at a few-second cadence from the UI.
    """
    from scanner.admission import get_admission_controller

    try:
        circuits = ai_manager.circuit_snapshots()
    except Exception as exc:  # never let telemetry take the endpoint down
        logger.warning("circuit snapshot failed: %s", exc)
        circuits = []

    try:
        admission = get_admission_controller().stats()
    except Exception as exc:
        logger.warning("admission stats failed: %s", exc)
        admission = {}

    open_circuits = sum(1 for c in circuits if c.get("state") == "open")
    degraded = sum(1 for c in circuits if c.get("state") in ("open", "half_open"))
    total_in_flight = sum((admission.get("in_flight") or {}).values())
    total_waiting = sum((admission.get("waiting") or {}).values())

    if open_circuits or total_waiting:
        posture = "degraded" if open_circuits < max(1, len(circuits)) else "critical"
    else:
        posture = "nominal"

    return {
        "posture": posture,
        "circuits": circuits,
        "admission": admission,
        "summary": {
            "providers": len(circuits),
            "open_circuits": open_circuits,
            "degraded_circuits": degraded,
            "scans_in_flight": total_in_flight,
            "scans_waiting": total_waiting,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# -- BYOK (Bring Your Own Key) ----------------------------------------
# AegisML is stateless with respect to third-party AI provider keys. Keys
# are supplied by the browser per-request via the X-AI-Key header (see
# the scan endpoints) and are NEVER persisted server-side. There is
# deliberately no endpoint to store, list, or retrieve user AI keys.
