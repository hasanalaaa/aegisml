"""
AegisML Scan Engine — FastAPI Backend v2.0.0

Production-grade API for scanning AI model files for malware, backdoors,
and security vulnerabilities.  Backed by PostgreSQL + Redis.
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

from scanner import ScanEngine
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    Form,
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
    get_cached_scan,
    get_cached_stats,
    get_cached_threats,
    invalidate_scan,
    set_cached_scan,
    set_cached_stats,
    set_cached_threats,
)
from auth.models import User
from auth.router import router as auth_router
from graphql_schema import graphql_router
from webhooks import webhooks_router
from growth.router import router as growth_router
import growth.models
from community.router import router as community_router
from enterprise.router import router as enterprise_router
from integrations.router import router as integrations_router
from hf_monitor.router import router as hf_monitor_router
from research.router import router as research_router
from billing.router import router as billing_router
from routers.user_keys import router as keys_router
from routers.threat_intel import router as threat_intel_router
from routers.ai_features import router as ai_features_router
from routers.analytics import router as analytics_router
from routers.developer import router as developer_router, trigger_webhook
from graphql_gateway.schema import schema
from strawberry.fastapi import GraphQLRouter
from auth.utils import get_current_user
from threat_intel.scheduler import start_scheduler, shutdown_scheduler
from hf_monitor.scheduler import start_scheduler as start_hf_scheduler, shutdown_scheduler as shutdown_hf_scheduler
from threat_intel.ioc_database import check_hash
from ai_providers.manager import AIProviderManager
from database import (
    APIKey,
    AsyncSessionLocal,
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

# ── Logging ──────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("aegisml.api")

# ── Constants ────────────────────────────────────────────────────────

VERSION = "2.0.0"
SUPPORTED_EXTENSIONS: frozenset[str] = frozenset(
    {".gguf", ".safetensors", ".pkl", ".pickle", ".pt", ".pth"}
)
MAX_FILE_SIZE: int = 500 * 1024 * 1024  # 500 MB

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

# ── Rate Limiter ─────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)

# ── Connection Manager ───────────────────────────────────────────────

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

# ── Lifespan ─────────────────────────────────────────────────────────


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
    start_hf_scheduler()
    
    app.state.arq_pool = await create_pool(RedisSettings.from_dsn(os.getenv("REDIS_URL", "redis://localhost:6379/0")))
    
    logger.info("AegisML v%s started", VERSION)
    yield

    # Shutdown
    shutdown_hf_scheduler()
    shutdown_scheduler()
    if hasattr(app.state, "arq_pool"):
        await app.state.arq_pool.close()
    await close_redis()
    logger.info("AegisML shutdown complete")

# ── App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="AegisML API",
    description="AI Model Security Scanner API — Detect backdoors, trojans & malicious code in AI models.",
    version=VERSION,
    lifespan=lifespan,
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

app.include_router(auth_router, prefix="/auth", tags=["Auth"])
app.include_router(graphql_router, prefix="/graphql", tags=["GraphQL"])
app.include_router(webhooks_router, prefix="/api/v1/webhooks", tags=["Webhooks"])
app.include_router(community_router, prefix="/api/v1/community", tags=["Community"])
app.include_router(enterprise_router, prefix="/api/v1/enterprise", tags=["Enterprise"])
app.include_router(integrations_router, prefix="/api/v1/integrations")
app.include_router(hf_monitor_router, prefix="/api/v1/monitor")
app.include_router(research_router)
app.include_router(billing_router, prefix="/api/v1/billing")
app.include_router(keys_router)
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


# ══════════════════════════════════════════════════════════════════════
# SECURITY MIDDLEWARE & RATE LIMITING
# ══════════════════════════════════════════════════════════════════════
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
                return JSONResponse(status_code=429, content={"error": "Scan limit reached", "upgrade_url": "/pricing"})
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


# ══════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════════════


@app.get("/health")
async def health() -> dict[str, Any]:
    """Health check with database and Redis status."""
    db_ok = await check_db_health()
    redis_ok = await check_redis_health()

    status = "healthy" if db_ok and redis_ok else "unhealthy"

    return {
        "status": status,
        "database": "postgresql",
        "redis": "connected" if redis_ok else "disconnected",
        "version": VERSION,
    }


@app.get("/api/v1/stats")
async def get_stats(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Platform-wide scan statistics.  Cached for 60 s."""
    cached = await get_cached_stats()
    if cached is not None:
        return cached

    total: int = await db.scalar(select(func.count(ScanRecord.id))) or 0
    if total == 0:
        empty: dict[str, Any] = {
            "total": 0,
            "clean": 0,
            "suspicious": 0,
            "malicious": 0,
            "critical": 0,
            "avg_risk_score": 0.0,
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
        await set_cached_stats(empty)
        return empty

    clean: int = (
        await db.scalar(
            select(func.count(ScanRecord.id)).where(ScanRecord.risk_level == "clean")
        )
        or 0
    )
    suspicious: int = (
        await db.scalar(
            select(func.count(ScanRecord.id)).where(
                ScanRecord.risk_level == "suspicious"
            )
        )
        or 0
    )
    malicious: int = (
        await db.scalar(
            select(func.count(ScanRecord.id)).where(
                ScanRecord.risk_level == "malicious"
            )
        )
        or 0
    )
    critical: int = (
        await db.scalar(
            select(func.count(ScanRecord.id)).where(
                ScanRecord.risk_level == "critical"
            )
        )
        or 0
    )
    avg_score: float = (
        await db.scalar(select(func.avg(ScanRecord.risk_score))) or 0.0
    )

    result: dict[str, Any] = {
        "total": total,
        "clean": clean,
        "suspicious": suspicious,
        "malicious": malicious,
        "critical": critical,
        "avg_risk_score": round(float(avg_score), 1),
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }
    await set_cached_stats(result)
    return result


@app.get("/api/v1/scans/recent")
async def get_recent_scans(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    """Return the N most recent public scans."""
    result = await db.execute(
        select(ScanRecord)
        .where(ScanRecord.is_public.is_(True))
        .order_by(desc(ScanRecord.created_at))
        .limit(limit)
    )
    scans = result.scalars().all()
    return [
        {
            "scan_id": s.scan_id,
            "filename": s.filename,
            "risk_score": s.risk_score,
            "risk_level": s.risk_level,
            "verdict": s.ai_verdict or "UNKNOWN",
            "threats_count": len(s.threats) if s.threats else 0,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in scans
    ]


# ── WebSockets & Streaming ───────────────────────────────────────────

@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan_endpoint(websocket: WebSocket, scan_id: str):
    await manager.connect(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)


@app.get("/api/v1/scan/{scan_id}/stream")
async def scan_stream(scan_id: str):
    """SSE Fallback for streaming progress"""
    q = asyncio.Queue()
    class MockWS:
        async def send_json(self, data: dict[str, Any]):
            await q.put(data)
            
    mock_ws = MockWS()
    await manager.connect(scan_id, mock_ws)

    async def event_stream():
        try:
            while True:
                data = await q.get()
                yield f"data: {json.dumps(data)}\n\n"
                if data.get("stage") in ("complete", "error"):
                    break
        finally:
            manager.disconnect(scan_id, mock_ws)
            
    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.websocket("/ws/stats")
async def websocket_stats_endpoint(websocket: WebSocket, db: AsyncSession = Depends(get_db)):
    await websocket.accept()
    try:
        while True:
            cached = await get_cached_stats()
            if cached is not None:
                await websocket.send_json(cached)
            else:
                result = await db.execute(select(func.count(ScanRecord.id)))
                total_scans = result.scalar() or 0

                result = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.risk_level.in_(["malicious", "critical"])))
                threats_found = result.scalar() or 0

                stats = {"totalScans": total_scans, "threatsFound": threats_found, "activeScans": len(manager.active_connections)}
                await set_cached_stats(stats)
                await websocket.send_json(stats)
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        pass


# ── Background Process ───────────────────────────────────────────────

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
        await manager.send_progress(scan_id, {
            "stage": "header_check", "progress": 10, "message": "فحص الهيكل الأساسي...", "threat_count": 0, "timestamp": datetime.now(timezone.utc).isoformat()
        })
        await asyncio.sleep(0.5)

        if not temp_path:
            raise ValueError("No file provided for scanning.")

        # Compute hash early for IOC check
        file_size = os.path.getsize(temp_path)
        sha = hashlib.sha256()
        with open(temp_path, "rb") as fh:
            while True:
                block = fh.read(8192)
                if not block:
                    break
                sha.update(block)
        file_hash = sha.hexdigest()

        # Check IOC database
        ioc_hit = await check_hash(file_hash)

        # NOTE: `result` is initialized here, unconditionally, before either
        # branch runs. Previously this dict was only ever assigned inside the
        # `if ioc_hit:` branch, while the `else:` branch (the path taken for
        # every scan that ISN'T an exact known-malware hash match — i.e. the
        # overwhelming majority of real scans) did `result["verdict"] = ...`
        # against a name that was never bound, raising UnboundLocalError on
        # every single normal scan. The broad `except Exception` below caught
        # it silently and reported a generic "Internal scan error.", which is
        # why the scan pipeline never actually produced usable results and
        # the frontend had to ship hardcoded mock data instead.
        result: dict[str, Any] = {
            "scan_id": scan_id,
            "filename": filename,
        }

        if ioc_hit:
            result.update({
                "risk_score": 100,
                "risk_level": "critical",
                "verdict": "CRITICAL",
                "threats": [{
                    "id": "IOC-BLACKLIST",
                    "pattern": "IOC-BLACKLIST",
                    "name": "Known Malicious File (IOC Match)",
                    "severity": "critical",
                    "cvss": 10.0,
                    "description": "This file is known to be malicious according to the global IOC database.",
                    "location": filename,
                    "category": "known_malware"
                }],
                "metadata": {
                    "file_size": file_size,
                    "extension": ext,
                    "threats_found": 1,
                    "ioc_hit": True
                }
            })
            threat_count = 1
        else:
            from scanner import engine as scanner_engine
            scan_result = await scanner_engine.scan(file_path=temp_path, scan_id=scan_id, manager_ws=manager)

            threat_count = scan_result["threat_count"]
            highest_cvss = scan_result["highest_cvss"]

            # The scanner engine speaks in `verdict` terms (safe / suspicious /
            # dangerous / critical) which is what the frontend's VerdictBadge
            # expects. The database column + analytics dashboards speak in
            # `risk_level` terms (clean / suspicious / malicious / critical).
            # Map between the two vocabularies explicitly rather than letting
            # them silently diverge — analytics.py groups scans by exactly
            # the four risk_level values below.
            verdict_to_risk_level = {
                "safe": "clean",
                "suspicious": "suspicious",
                "dangerous": "malicious",
                "critical": "critical",
            }
            engine_verdict = scan_result["verdict"]
            risk_level = verdict_to_risk_level.get(engine_verdict, "suspicious")

            result.update({
                "risk_score": round(highest_cvss * 10, 1),  # CVSS 0-10 -> risk_score 0-100
                "risk_level": risk_level,
                "verdict": engine_verdict.upper(),
                "threats": scan_result["threats"],
                "entropy": scan_result["entropy_analysis"],
                "cvss": highest_cvss,
                "format_detected": scan_result["format_detected"],
                "metadata": {
                    "file_size": file_size,
                    "extension": ext,
                    "threats_found": threat_count,
                    "ioc_hit": False,
                    "file_hash": file_hash,
                    "format_detected": scan_result["format_detected"],
                    "entropy_analysis": scan_result["entropy_analysis"],
                    "patterns_checked": scan_result.get("patterns_checked", 0),
                    "scan_passes": scan_result.get("scan_passes", []),
                    "highest_cvss": highest_cvss,
                },
            })

        await manager.send_progress(scan_id, {
            "stage": "ai_analysis", "progress": 70, "message": "تحليل الذكاء الاصطناعي...", "threat_count": threat_count, "timestamp": datetime.now(timezone.utc).isoformat()
        })

        from ai_providers.manager import manager as ai_manager
        
        try:
            ai_res_obj = await ai_manager.analyze(
                file_info={"filename": filename, "size": content_size},
                scan_results=result,
                provider=ai_provider or "anthropic",
                model=ai_model,
                user_api_key=api_key,
                fallback=True
            )
            ai_result = {
                "verdict": ai_res_obj.verdict,
                "confidence": ai_res_obj.confidence,
                "summary_en": ai_res_obj.explanation,
                "summary_ar": ai_res_obj.explanation,
                "key_risks": ai_res_obj.recommendations,
                "recommendation": ai_res_obj.explanation,
                "recommendation_ar": ai_res_obj.explanation,
                "technical_details": "Provided by AI",
                "provider": ai_res_obj.provider,
                "model": ai_res_obj.model
            }
        except Exception as e:
            logger.error(f"AI Provider error: {e}")
            ai_result = {
                "verdict": "UNKNOWN",
                "confidence": 0,
                "summary_en": f"AI analysis failed: {e}",
                "summary_ar": "فشل التحليل الذكي بسبب خطأ",
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
                is_public=True,
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

        await invalidate_scan(scan_id)

        await manager.send_progress(scan_id, {
            "stage": "complete", "progress": 100, "message": "اكتمل الفحص بنجاح", "threat_count": threat_count, "timestamp": datetime.now(timezone.utc).isoformat()
        })

    except Exception as exc:
        logger.error("Scan failed for %s: %s", filename, exc, exc_info=True)
        await manager.send_progress(scan_id, {
            "stage": "error", "progress": 0, "message": "Internal scan error.", "threat_count": 0, "timestamp": datetime.now(timezone.utc).isoformat()
        })
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
        await manager.send_progress(scan_id, {
            "stage": "downloading", "progress": 5, "message": "جارٍ تحميل النموذج من الرابط...", "threat_count": 0, "timestamp": datetime.now(timezone.utc).isoformat()
        })
        import httpx
        async with httpx.AsyncClient(timeout=300.0, follow_redirects=True, max_redirects=5) as client:
            headers: dict[str, str] = {}
            hf_token = os.getenv("HF_TOKEN")
            if hf_token:
                headers["Authorization"] = f"Bearer {hf_token}"
            async with client.stream("GET", url, headers=headers) as response:
                if response.status_code != 200:
                    raise Exception(f"Failed to download from URL: HTTP {response.status_code}")
                content_length_raw = response.headers.get("content-length")
                if content_length_raw:
                    try:
                        if int(content_length_raw) > max_size:
                            raise Exception(f"File too large. Maximum size for your tier is {max_size // (1024*1024)} MB.")
                    except ValueError:
                        pass
                
                with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                    downloaded = 0
                    async for chunk in response.aiter_bytes(chunk_size=1024 * 1024):
                        downloaded += len(chunk)
                        if downloaded > max_size:
                            raise Exception("File too large. Size limit exceeded.")
                        tmp.write(chunk)
                    temp_path = tmp.name
        
        await _process_scan(temp_path, filename, ext, scan_id, downloaded, "url", url, ip_address, user_agent, ai_provider, ai_model, user_id, api_key)
        temp_path = None # Prevents deleting it twice since _process_scan handles cleanup
    except Exception as exc:
        logger.error("URL scan failed for %s: %s", url, exc, exc_info=True)
        await manager.send_progress(scan_id, {
            "stage": "error", "progress": 0, "message": f"خطأ في التحميل: {str(exc)}", "threat_count": 0, "timestamp": datetime.now(timezone.utc).isoformat()
        })
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


# ── File Scan ────────────────────────────────────────────────────────


def _validate_filename(name: str) -> str:
    """Sanitize and validate an uploaded filename."""
    # Strip path separators that could allow directory traversal
    sanitized = os.path.basename(name).strip()
    if not sanitized:
        return "unknown"
    # Remove null bytes and control characters
    sanitized = "".join(c for c in sanitized if c.isprintable() and c != "\x00")
    # Truncate to 500 chars
    return sanitized[:500] if sanitized else "unknown"


def _validate_extension(filename: str) -> str:
    """Extract and validate file extension.  Raises HTTPException on invalid."""
    ext = os.path.splitext(filename)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format '{ext}'. Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}",
        )
    return ext


def _compute_file_hash(content: bytes) -> str:
    """SHA-256 hash of file content."""
    return hashlib.sha256(content).hexdigest()


@app.post("/api/v1/scan/file", response_model=None)
@limiter.limit("10/minute")
async def scan_file(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    ai_provider: Optional[str] = Form(None),
    ai_model: Optional[str] = Form(None),
    api_key: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
) -> dict[str, Any]:
    """Upload and scan a model file for security threats."""
    filename = _validate_filename(file.filename or "unknown")
    ext = _validate_extension(filename)

    # Strip and ignore unexpected metadata
    ai_provider = ai_provider[:50] if ai_provider else None
    ai_model = ai_model[:50] if ai_model else None

    # Check size limit before reading body
    content_length_raw = request.headers.get("content-length")
    max_size = 500 * 1024 * 1024  # Free: 500MB
    if current_user:
        if current_user.plan == "pro":
            max_size = 5 * 1024 * 1024 * 1024  # Pro: 5GB
        elif current_user.plan in ["enterprise", "researcher"]:
            max_size = float('inf')

    if content_length_raw:
        try:
            if int(content_length_raw) > max_size:
                raise HTTPException(status_code=413, detail=f"File too large. Maximum size for your tier is {max_size // (1024*1024)} MB.")
        except ValueError:
            pass

    content = await file.read()
    content_size = len(content)

    if content_size == 0:
        raise HTTPException(status_code=400, detail="Empty file uploaded")
        
    if content_size > max_size:
        raise HTTPException(status_code=413, detail=f"File too large. Maximum size for your tier is {max_size // (1024*1024)} MB.")

    # Magic byte validation
    if content_size >= 4:
        magic = content[:4]
        if ext == ".safetensors" and content_size > 8:
            if content[8:9] != b'{':
                raise HTTPException(status_code=400, detail="Magic bytes mismatch for safetensors")
        elif ext == ".gguf" and magic != b'GGUF':
            raise HTTPException(status_code=400, detail="Magic bytes mismatch for GGUF")

    scan_id = str(uuid.uuid4())

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    tmp.write(content)
    tmp.close()
    temp_path = tmp.name

    ip_address = request.client.host if request.client else None
    user_agent = (request.headers.get("user-agent") or "")[:500]

    if content_size > 50 * 1024 * 1024 and hasattr(request.app.state, "arq_pool"):
        job = await request.app.state.arq_pool.enqueue_job(
            "scan_job",
            temp_path, filename, ext, scan_id, content_size, "upload", "", ip_address, user_agent, ai_provider, ai_model, str(current_user.id) if current_user else None, api_key
        )
        return {"scan_id": scan_id, "status": "processing", "job_id": job.job_id}
    else:
        background_tasks.add_task(
            _process_scan,
            temp_path, filename, ext, scan_id, content_size, "upload", "", ip_address, user_agent, ai_provider, ai_model, str(current_user.id) if current_user else None, api_key
        )

    return {"scan_id": scan_id, "status": "processing"}

@app.get("/api/v1/scan/{job_id}/status")
async def get_scan_job_status(job_id: str, request: Request):
    if not hasattr(request.app.state, "arq_pool"):
        raise HTTPException(status_code=500, detail="Background worker not enabled")
    from arq.jobs import Job
    job = Job(job_id, request.app.state.arq_pool)
    status = await job.status()
    return {"job_id": job_id, "status": status.value}


# ── URL Scan ─────────────────────────────────────────────────────────


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

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Only HTTP/HTTPS URLs are allowed")

    hostname = (parsed.hostname or "").lower()
    if hostname not in ["huggingface.co", "www.huggingface.co"]:
        raise HTTPException(
            status_code=400,
            detail="Only HuggingFace URLs are allowed",
        )

    # Extract filename from URL path
    path_parts = parsed.path.rstrip("/").split("/")
    raw_filename = path_parts[-1].split("?")[0] if path_parts else ""
    filename = _validate_filename(raw_filename) if raw_filename else "model_from_url"

    ext = _validate_extension(filename)
    return url, filename, ext


@app.post("/api/v1/scan/url", response_model=None)
@limiter.limit("5/minute")
async def scan_url(
    request: Request,
    body: dict[str, Any],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
) -> dict[str, Any]:
    """Download a model from a URL and scan it for security threats."""
    raw_url = body.get("url")
    if not isinstance(raw_url, str):
        raise HTTPException(status_code=400, detail="URL must be a string")

    url, filename, ext = _validate_scan_url(raw_url)
    scan_id = str(uuid.uuid4())
    temp_path: Optional[str] = None
    
    # Tier-based file size limits
    max_size = 50 * 1024 * 1024  # Guest: 50MB
    if current_user:
        if current_user.plan == "pro":
            max_size = 2 * 1024 * 1024 * 1024  # Pro: 2GB
        else:
            max_size = 200 * 1024 * 1024  # Free: 200MB

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
        body.get("ai_provider"),
        body.get("ai_model"),
        str(current_user.id) if current_user else None,
        body.get("api_key")
    )

    return {"scan_id": scan_id, "status": "processing"}


# ── Get Scan Result ──────────────────────────────────────────────────


@app.get("/api/v1/threats/patterns")
async def get_threat_patterns(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
) -> dict[str, Any]:
    """List all active threat patterns from the 200+ pattern library."""
    from scanner.patterns import THREAT_PATTERNS
    
    filtered = THREAT_PATTERNS
    
    if category:
        filtered = [p for p in filtered if p["category"] == category]
    if severity:
        filtered = [p for p in filtered if p["severity"] == severity]
    if search:
        search_lower = search.lower()
        filtered = [p for p in filtered if search_lower in p["name"].lower() or search_lower in p["description"].lower() or search_lower in p["id"].lower()]
        
    total = len(filtered)
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    
    paginated = filtered[start_idx:end_idx]
    
    # To avoid JSON serialization issues with bytes pattern
    clean_paginated = []
    for p in paginated:
        p_copy = dict(p)
        if "pattern" in p_copy and isinstance(p_copy["pattern"], bytes):
            p_copy["pattern"] = str(p_copy["pattern"])
        clean_paginated.append(p_copy)
    
    return {
        "data": clean_paginated,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit
    }


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


# ── Threat Patterns ──────────────────────────────────────────────────


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


# ── Badge ────────────────────────────────────────────────────────────


@app.get("/api/v1/badge/{scan_id}")
async def get_badge(
    scan_id: str, db: AsyncSession = Depends(get_db)
) -> Response:
    """Generate an SVG badge for a scan result."""
    if not scan_id or len(scan_id) > 36:
        raise HTTPException(status_code=400, detail="Invalid scan ID")

    result = await db.execute(
        select(ScanRecord).where(ScanRecord.scan_id == scan_id)
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
        select(ScanRecord).where(ScanRecord.scan_id == scan_id)
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


# ── Compare ──────────────────────────────────────────────────────────


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
        cached = await get_cached_scan(sid)
        if cached is not None:
            return cached
        r = await db.execute(select(ScanRecord).where(ScanRecord.scan_id == sid))
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


# ── API Keys ─────────────────────────────────────────────────────────


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
        "warning": "Save this key securely — it will not be shown again.",
    }


@app.get("/api/v1/keys/validate")
async def validate_key(
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



# ── AI Provider Endpoints ──────────────────────────────────────────────

from ai_providers.manager import manager as ai_manager
from pydantic import BaseModel

class ValidateKeyRequest(BaseModel):
    provider: str
    api_key: str

@app.get("/api/v1/ai/providers")
async def list_providers():
    return {"providers": ai_manager.get_available_providers()}

@app.post("/api/v1/ai/validate-key")
async def validate_key(req: ValidateKeyRequest):
    is_valid = await ai_manager.validate_key(req.provider, req.api_key)
    return {"valid": is_valid}

@app.get("/api/v1/ai/providers/{name}/models")
async def list_provider_models(name: str):
    providers = ai_manager.get_available_providers()
    for p in providers:
        if p["name"] == name:
            return {"models": p["models"]}
    raise HTTPException(status_code=404, detail="Provider not found")

# ── User API Keys ──────────────────────────────────────────────────────

from auth.models import UserAPIKey
from auth.encryption import encrypt_key
from sqlalchemy import select

class SaveAPIKeyRequest(BaseModel):
    provider: str
    api_key: str

@app.post("/api/v1/user/api-keys")
async def save_api_key(req: SaveAPIKeyRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Check if provider already has a key
    result = await db.execute(select(UserAPIKey).where(UserAPIKey.user_id == current_user.id, UserAPIKey.provider == req.provider))
    existing = result.scalar_one_or_none()
    
    enc_key = encrypt_key(req.api_key)
    
    if existing:
        existing.encrypted_key = enc_key
        existing.is_active = True
    else:
        new_key = UserAPIKey(user_id=current_user.id, provider=req.provider, encrypted_key=enc_key)
        db.add(new_key)
        
    await db.commit()
    return {"status": "saved"}

@app.get("/api/v1/user/api-keys")
async def get_api_keys(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
        
    result = await db.execute(select(UserAPIKey).where(UserAPIKey.user_id == current_user.id))
    keys = result.scalars().all()
    
    return {
        "keys": [{"id": str(k.id), "provider": k.provider, "is_active": k.is_active} for k in keys]
    }

@app.delete("/api/v1/user/api-keys/{key_id}")
async def delete_api_key(key_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
        
    result = await db.execute(select(UserAPIKey).where(UserAPIKey.id == key_id, UserAPIKey.user_id == current_user.id))
    key = result.scalar_one_or_none()
    
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
        
    await db.delete(key)
    await db.commit()
    return {"status": "deleted"}
