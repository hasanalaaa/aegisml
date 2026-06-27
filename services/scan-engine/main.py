"""
AegisML Scan Engine — FastAPI Backend v2.0.0

Production-grade API for scanning AI model files for malware, backdoors,
and security vulnerabilities.  Backed by PostgreSQL + Redis.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import subprocess
import tempfile
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import anthropic
from dotenv import load_dotenv
from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
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

# ── Lifespan ─────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    """Startup: init DB + Redis + seed patterns.  Shutdown: close Redis."""
    logger.info("Application startup initiated.")
    try:
        await init_db()
        redis_ok = await init_redis()
        logger.info("Redis status: %s", "connected" if redis_ok else "disabled")

        async with AsyncSessionLocal() as session:
            await seed_threat_patterns(session)
    except Exception as exc:
        logger.error(f"Non-blocking startup database initialization warning: {exc}")

    logger.info("AegisML v%s started", VERSION)
    yield

    # Shutdown
    await close_redis()
    logger.info("AegisML shutdown complete")


# ── App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="AegisML API",
    description="AI Model Security Scanner API — Detect backdoors, trojans & malicious code in AI models.",
    version=VERSION,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

ALLOWED_ORIGINS: list[str] = [
    o
    for o in [
        "http://localhost:3000",
        "https://aegisml.vercel.app",
        os.getenv("FRONTEND_URL", ""),
    ]
    if o
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    max_age=86400,
)


# ══════════════════════════════════════════════════════════════════════
# SECURITY MIDDLEWARE
# ══════════════════════════════════════════════════════════════════════


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

    status = "healthy" if db_ok else "degraded"
    if not db_ok:
        status = "unhealthy"

    return {
        "status": status,
        "version": VERSION,
        "database": "connected" if db_ok else "disconnected",
        "database_type": "postgresql",
        "redis": "connected" if redis_ok else "disconnected",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "features": [
            "file_scan",
            "url_scan",
            "claude_judge",
            "postgresql",
            "redis_cache",
            "rate_limiting",
            "api_keys",
            "badge_generator",
            "model_comparison",
        ],
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
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Upload and scan a model file for security threats."""
    filename = _validate_filename(file.filename or "unknown")
    ext = _validate_extension(filename)

    # Read content with size guard
    content = await file.read()
    content_size = len(content)

    if content_size == 0:
        raise HTTPException(status_code=400, detail="Empty file uploaded")
    if content_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413, detail="File too large. Maximum size is 500 MB."
        )

    scan_id = str(uuid.uuid4())
    file_hash = _compute_file_hash(content)

    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        tmp.write(content)
        temp_path = tmp.name

    try:
        result = await _run_inspector(temp_path, filename, scan_id)
        result["ai_analysis"] = await _claude_judge(result)

        # Cache the scan result
        await set_cached_scan(scan_id, result)

        record = ScanRecord(
            scan_id=scan_id,
            filename=filename,
            file_size=content_size,
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
            ai_recommendation_ar=result.get("ai_analysis", {}).get(
                "recommendation_ar"
            ),
            source_type="upload",
            ip_address=request.client.host if request.client else None,
            user_agent=(request.headers.get("user-agent") or "")[:500],
            is_public=True,
        )
        db.add(record)
        await db.commit()

        # Bust stats cache after new scan
        await invalidate_scan(scan_id)

        return {"scan_id": scan_id, "status": "complete", "result": result}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Scan failed for %s: %s", filename, exc, exc_info=True)
        raise HTTPException(
            status_code=500, detail="Internal scan error. Please try again."
        ) from exc
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError as exc:
                logger.warning("Failed to remove temp file %s: %s", temp_path, exc)


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
    if hostname not in ALLOWED_SCAN_HOSTS:
        raise HTTPException(
            status_code=400,
            detail="Only HuggingFace URLs are supported for URL scanning",
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
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Download a model from a URL and scan it for security threats."""
    raw_url = body.get("url")
    if not isinstance(raw_url, str):
        raise HTTPException(status_code=400, detail="URL must be a string")

    url, filename, ext = _validate_scan_url(raw_url)
    scan_id = str(uuid.uuid4())
    temp_path: Optional[str] = None

    try:
        import httpx

        async with httpx.AsyncClient(
            timeout=300.0, follow_redirects=True, max_redirects=5
        ) as client:
            headers: dict[str, str] = {}
            hf_token = os.getenv("HF_TOKEN")
            if hf_token:
                headers["Authorization"] = f"Bearer {hf_token}"

            async with client.stream("GET", url, headers=headers) as response:
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Failed to download from URL: HTTP {response.status_code}",
                    )
                content_length_raw = response.headers.get("content-length")
                if content_length_raw:
                    try:
                        content_length = int(content_length_raw)
                        if content_length > MAX_FILE_SIZE:
                            raise HTTPException(
                                status_code=413,
                                detail="File too large. Maximum size is 500 MB.",
                            )
                    except ValueError:
                        pass  # Invalid header — rely on streaming check below

                with tempfile.NamedTemporaryFile(
                    delete=False, suffix=ext
                ) as tmp:
                    downloaded = 0
                    async for chunk in response.aiter_bytes(
                        chunk_size=1024 * 1024
                    ):
                        downloaded += len(chunk)
                        if downloaded > MAX_FILE_SIZE:
                            raise HTTPException(
                                status_code=413,
                                detail="File too large. Maximum size is 500 MB.",
                            )
                        tmp.write(chunk)
                    temp_path = tmp.name

        result = await _run_inspector(temp_path, filename, scan_id)
        result["ai_analysis"] = await _claude_judge(result)
        result["source_url"] = url

        await set_cached_scan(scan_id, result)

        file_size = os.path.getsize(temp_path) if temp_path else 0
        file_hash = ""
        if temp_path:
            sha = hashlib.sha256()
            with open(temp_path, "rb") as fh:
                while True:
                    block = fh.read(8192)
                    if not block:
                        break
                    sha.update(block)
            file_hash = sha.hexdigest()

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
            ai_recommendation_ar=result.get("ai_analysis", {}).get(
                "recommendation_ar"
            ),
            source_type="url",
            source_url=url,
            ip_address=request.client.host if request.client else None,
            user_agent=(request.headers.get("user-agent") or "")[:500],
            is_public=True,
        )
        db.add(record)
        await db.commit()

        await invalidate_scan(scan_id)

        return {"scan_id": scan_id, "status": "complete", "result": result}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("URL scan failed for %s: %s", url, exc, exc_info=True)
        raise HTTPException(
            status_code=500, detail="Internal scan error. Please try again."
        ) from exc
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError as exc:
                logger.warning("Failed to remove temp file %s: %s", temp_path, exc)


# ── Get Scan Result ──────────────────────────────────────────────────


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


# ══════════════════════════════════════════════════════════════════════
# CORE SCAN HELPERS
# ══════════════════════════════════════════════════════════════════════


async def _run_inspector(
    file_path: str, filename: str, scan_id: str
) -> dict[str, Any]:
    """Run the aegisml CLI scanner, falling back to built-in pattern matching."""
    try:
        proc = subprocess.run(
            ["python", "-m", "aegisml", "scan", file_path, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=os.path.join(os.path.dirname(__file__), "..", ".."),
        )
        if proc.returncode == 0 and proc.stdout.strip():
            data: dict[str, Any] = json.loads(proc.stdout)
            data["scan_id"] = scan_id
            data["filename"] = filename
            return data
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as exc:
        logger.debug("aegisml CLI unavailable, using fallback scanner: %s", exc)
    except Exception as exc:
        logger.debug("aegisml CLI error: %s", exc)

    # ── Fallback: built-in pattern scanner ───────────────────────
    ext = os.path.splitext(filename)[1].lower()
    file_size = os.path.getsize(file_path)
    threats: list[dict[str, str]] = []

    try:
        read_limit = min(file_size, 10 * 1024 * 1024)  # 10 MB max
        with open(file_path, "rb") as f:
            content = f.read(read_limit)
        text_content = content.decode("utf-8", errors="ignore")

        for p in BUILTIN_THREAT_PATTERNS:
            pattern = p["pattern"]
            if pattern.encode("utf-8") in content or pattern in text_content:
                threats.append(
                    {
                        "pattern": pattern,
                        "severity": p["severity"],
                        "description": p["description_en"],
                        "location": filename,
                        "category": p["category"],
                    }
                )
    except OSError as exc:
        logger.error("Failed to read file %s: %s", file_path, exc)

    severity_scores: dict[str, int] = {
        "critical": 35,
        "high": 20,
        "medium": 10,
        "low": 5,
    }
    base_risk: int = {
        "pkl": 30,
        "pickle": 30,
        "pt": 25,
        "pth": 25,
        "gguf": 5,
        "safetensors": 3,
    }.get(ext.lstrip("."), 15)
    threat_score = sum(
        severity_scores.get(t["severity"], 5) for t in threats
    )
    risk = min(100, base_risk + threat_score)

    risk_level: str
    if risk < 30:
        risk_level = "clean"
    elif risk < 60:
        risk_level = "suspicious"
    elif risk < 85:
        risk_level = "malicious"
    else:
        risk_level = "critical"

    return {
        "scan_id": scan_id,
        "filename": filename,
        "risk_score": risk,
        "risk_level": risk_level,
        "threats": threats,
        "metadata": {
            "file_size": file_size,
            "extension": ext,
            "threats_found": len(threats),
        },
    }


# ── Claude AI Judge ──────────────────────────────────────────────────

_CLAUDE_MODEL = "claude-sonnet-4-20250514"
_CLAUDE_MAX_THREATS_IN_PROMPT = 10
_CLAUDE_MAX_TOKENS = 1500


async def _claude_judge(scan_data: dict[str, Any]) -> dict[str, Any]:
    """Ask Claude to render a security verdict on the scan results."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return {
            "verdict": "UNKNOWN",
            "confidence": 0,
            "summary_en": "Claude API key not configured. Static analysis results only.",
            "summary_ar": "مفتاح Claude API غير مضبوط. نتائج التحليل الثابت فقط.",
            "key_risks": [],
            "recommendation": "Configure ANTHROPIC_API_KEY to enable AI analysis.",
            "recommendation_ar": "اضبط ANTHROPIC_API_KEY لتفعيل التحليل الذكي.",
        }

    try:
        client = anthropic.Anthropic(api_key=api_key)
        threat_list = scan_data.get("threats", [])[:_CLAUDE_MAX_THREATS_IN_PROMPT]
        threat_summary = json.dumps(threat_list, indent=2, ensure_ascii=False)

        prompt = f"""You are AegisML's expert AI security analyst specializing in AI model security.

SCAN DATA:
- File: {scan_data.get('filename', 'unknown')}
- Extension: {scan_data.get('metadata', {}).get('extension', 'unknown')}
- File Size: {scan_data.get('metadata', {}).get('file_size', 0)} bytes
- Risk Score: {scan_data.get('risk_score', 0)}/100
- Risk Level: {scan_data.get('risk_level', 'unknown')}
- Threats Found: {len(scan_data.get('threats', []))}
- Threat Details:
{threat_summary}

Respond ONLY with valid JSON (no markdown):

{{
  "verdict": "SAFE or SUSPICIOUS or DANGEROUS or CRITICAL",
  "confidence": <integer 0-100>,
  "summary_en": "<3-4 sentences in English>",
  "summary_ar": "<3-4 جمل بالعربية>",
  "key_risks": ["<risk 1>", "<risk 2>", "<risk 3>"],
  "recommendation": "<actionable steps in English>",
  "recommendation_ar": "<خطوات محددة بالعربية>",
  "technical_details": "<brief technical explanation>"
}}"""

        message = client.messages.create(
            model=_CLAUDE_MODEL,
            max_tokens=_CLAUDE_MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}],
        )
        text = (
            message.content[0].text.replace("```json", "").replace("```", "").strip()
        )
        return json.loads(text)

    except json.JSONDecodeError:
        return {
            "verdict": "UNKNOWN",
            "confidence": 50,
            "summary_en": "AI analysis completed but response format was unexpected.",
            "summary_ar": "اكتمل التحليل الذكي لكن تنسيق الاستجابة كان غير متوقع.",
            "key_risks": [],
            "recommendation": "Review static analysis results manually.",
            "recommendation_ar": "راجع نتائج التحليل الثابت يدوياً.",
        }
    except anthropic.APIConnectionError as exc:
        logger.warning("Claude API connection error: %s", exc)
        return {
            "verdict": "UNKNOWN",
            "confidence": 0,
            "summary_en": "AI analysis temporarily unavailable (connection error).",
            "summary_ar": "التحليل الذكي غير متاح مؤقتاً (خطأ اتصال).",
            "key_risks": [],
            "recommendation": "Static analysis results are still valid.",
            "recommendation_ar": "نتائج التحليل الثابت لا تزال صحيحة.",
        }
    except anthropic.RateLimitError:
        logger.warning("Claude API rate limit reached")
        return {
            "verdict": "UNKNOWN",
            "confidence": 0,
            "summary_en": "AI analysis temporarily unavailable (rate limit).",
            "summary_ar": "التحليل الذكي غير متاح مؤقتاً (حد الاستخدام).",
            "key_risks": [],
            "recommendation": "Static analysis results are still valid. Try again later.",
            "recommendation_ar": "نتائج التحليل الثابت صحيحة. حاول لاحقاً.",
        }
    except Exception as exc:
        logger.error("Claude AI judge error: %s", exc, exc_info=True)
        return {
            "verdict": "UNKNOWN",
            "confidence": 0,
            "summary_en": f"AI analysis temporarily unavailable: {str(exc)[:100]}",
            "summary_ar": "التحليل الذكي غير متاح مؤقتاً.",
            "key_risks": [],
            "recommendation": "Static analysis results are still valid.",
            "recommendation_ar": "نتائج التحليل الثابت لا تزال صحيحة.",
        }
