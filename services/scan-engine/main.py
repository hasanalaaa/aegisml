"""
AegisML Scan Engine — FastAPI Backend
"""
import anthropic
import uuid
import json
import os
import hashlib
import secrets
import subprocess
import tempfile
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from urllib.parse import urlparse
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from database import (
    init_db, get_db, seed_threat_patterns,
    ScanRecord, ThreatPattern, APIKey, AsyncSessionLocal
)
from dotenv import load_dotenv

load_dotenv()

# ── Constants ────────────────────────────────────────────────
SUPPORTED_EXTENSIONS = {".gguf", ".safetensors", ".pkl", ".pickle", ".pt", ".pth"}
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB
MAX_CACHE_SIZE = 500               # حدّ أقصى للـ cache
ALLOWED_SCAN_HOSTS = {
    "huggingface.co", "hf.co",
    "cdn-lfs.huggingface.co", "cdn-lfs-us-1.huggingface.co",
}

# ── In-memory cache (مع حدّ أقصى لتفادي تسريب الذاكرة) ─────
scan_results_cache: dict = {}


def cache_set(scan_id: str, result: dict) -> None:
    """أضف إلى الـ cache مع طرد أقدم عنصر إذا امتلأ."""
    if len(scan_results_cache) >= MAX_CACHE_SIZE:
        oldest = next(iter(scan_results_cache))
        del scan_results_cache[oldest]
    scan_results_cache[scan_id] = result


# ── Rate Limiter ─────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    async with AsyncSessionLocal() as session:
        try:
            await seed_threat_patterns(session)
        except Exception as e:
            print(f"Warning: Could not seed threat patterns: {e}")
    yield


app = FastAPI(
    title="AegisML API",
    description="AI Model Security Scanner API",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

ALLOWED_ORIGINS = [
    o for o in [
        "http://localhost:3000",
        "https://aegisml.vercel.app",
        os.getenv("FRONTEND_URL", ""),
    ] if o
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Threat Patterns (Fallback) ───────────────────────────────
BUILTIN_THREAT_PATTERNS = [
    {"pattern": "os.system",    "severity": "critical", "category": "code_execution",
     "description_en": "System command execution",           "description_ar": "تنفيذ أوامر النظام"},
    {"pattern": "subprocess",   "severity": "high",     "category": "code_execution",
     "description_en": "External process execution",         "description_ar": "تشغيل عمليات خارجية"},
    {"pattern": "eval",         "severity": "critical", "category": "code_execution",
     "description_en": "Dynamic code evaluation",            "description_ar": "تنفيذ كود ديناميكي"},
    {"pattern": "exec",         "severity": "critical", "category": "code_execution",
     "description_en": "Code execution function",            "description_ar": "دالة تنفيذ الكود"},
    {"pattern": "pickle.loads", "severity": "high",     "category": "deserialization",
     "description_en": "Unsafe pickle deserialization",      "description_ar": "تحميل pickle غير آمن"},
    {"pattern": "__reduce__",   "severity": "critical", "category": "deserialization",
     "description_en": "Pickle execution hook",              "description_ar": "خطاف تنفيذ pickle"},
    {"pattern": "import os",    "severity": "high",     "category": "system_access",
     "description_en": "OS module import",                   "description_ar": "استيراد وحدة النظام"},
    {"pattern": "shutil",       "severity": "medium",   "category": "file_operations",
     "description_en": "File system operations",             "description_ar": "عمليات نظام الملفات"},
    {"pattern": "base64",       "severity": "medium",   "category": "obfuscation",
     "description_en": "Potential code obfuscation",         "description_ar": "إخفاء الكود المحتمل"},
    {"pattern": "socket",       "severity": "high",     "category": "network",
     "description_en": "Network socket access",              "description_ar": "الوصول للشبكة"},
    {"pattern": "requests",     "severity": "medium",   "category": "network",
     "description_en": "HTTP request capability",            "description_ar": "قدرة طلب HTTP"},
    {"pattern": "urllib",       "severity": "medium",   "category": "network",
     "description_en": "URL access capability",              "description_ar": "قدرة الوصول للروابط"},
    {"pattern": "__import__",   "severity": "high",     "category": "code_execution",
     "description_en": "Dynamic import",                     "description_ar": "استيراد ديناميكي"},
    {"pattern": "ctypes",       "severity": "critical", "category": "system_access",
     "description_en": "Low-level system access",            "description_ar": "وصول منخفض للنظام"},
]


# ════════════════════════════════════════════════════════════
# ENDPOINTS
# ════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "features": [
            "file_scan", "url_scan", "claude_judge",
            "database", "rate_limiting", "api_keys",
            "badge_generator", "model_comparison",
        ],
    }


@app.get("/api/v1/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    total = await db.scalar(select(func.count(ScanRecord.id))) or 0
    if not total:
        return {
            "total": 0, "clean": 0, "suspicious": 0,
            "malicious": 0, "critical": 0, "avg_risk_score": 0,
        }
    clean      = await db.scalar(select(func.count(ScanRecord.id)).where(ScanRecord.risk_level == "clean")) or 0
    suspicious = await db.scalar(select(func.count(ScanRecord.id)).where(ScanRecord.risk_level == "suspicious")) or 0
    malicious  = await db.scalar(select(func.count(ScanRecord.id)).where(ScanRecord.risk_level == "malicious")) or 0
    critical   = await db.scalar(select(func.count(ScanRecord.id)).where(ScanRecord.risk_level == "critical")) or 0
    avg_score  = await db.scalar(select(func.avg(ScanRecord.risk_score))) or 0.0
    return {
        "total": total, "clean": clean, "suspicious": suspicious,
        "malicious": malicious, "critical": critical,
        "avg_risk_score": round(float(avg_score), 1),
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v1/scans/recent")
async def get_recent_scans(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanRecord)
        .where(ScanRecord.is_public == True)
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


@app.post("/api/v1/scan/file")
@limiter.limit("10/minute")
async def scan_file(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    content = await file.read()

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large. Maximum size is 500MB.")

    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format. Supported: {', '.join(SUPPORTED_EXTENSIONS)}",
        )

    scan_id = str(uuid.uuid4())

    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        tmp.write(content)
        temp_path = tmp.name

    try:
        result = await run_inspector(temp_path, file.filename or "unknown", scan_id)
        result["ai_analysis"] = await claude_judge(result)
        cache_set(scan_id, result)

        record = ScanRecord(
            scan_id=scan_id,
            filename=file.filename or "unknown",
            file_size=len(content),
            file_extension=ext,
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
            source_type="upload",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            is_public=True,
        )
        db.add(record)
        await db.commit()

        return {"scan_id": scan_id, "status": "complete", "result": result}
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@app.post("/api/v1/scan/url")
@limiter.limit("5/minute")
async def scan_url(
    request: Request,
    body: dict,
    db: AsyncSession = Depends(get_db),
):
    url = body.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_SCAN_HOSTS:
        raise HTTPException(
            status_code=400,
            detail="Only HuggingFace URLs are supported for URL scanning",
        )

    filename = url.split("/")[-1].split("?")[0] or "model_from_url"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format. Supported: {', '.join(SUPPORTED_EXTENSIONS)}",
        )

    scan_id = str(uuid.uuid4())
    temp_path: Optional[str] = None

    try:
        import httpx
        async with httpx.AsyncClient(timeout=300.0, follow_redirects=True) as client:
            headers = {}
            hf_token = os.getenv("HF_TOKEN")
            if hf_token:
                headers["Authorization"] = f"Bearer {hf_token}"

            async with client.stream("GET", url, headers=headers) as response:
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Failed to download from URL: HTTP {response.status_code}",
                    )
                content_length = int(response.headers.get("content-length", 0))
                if content_length > MAX_FILE_SIZE:
                    raise HTTPException(status_code=413, detail="File too large. Maximum size is 500MB.")

                with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                    downloaded = 0
                    async for chunk in response.aiter_bytes(chunk_size=1024 * 1024):
                        tmp.write(chunk)
                        downloaded += len(chunk)
                        if downloaded > MAX_FILE_SIZE:
                            raise HTTPException(status_code=413, detail="File too large.")
                    temp_path = tmp.name

        result = await run_inspector(temp_path, filename, scan_id)
        result["ai_analysis"] = await claude_judge(result)
        result["source_url"] = url
        cache_set(scan_id, result)

        record = ScanRecord(
            scan_id=scan_id,
            filename=filename,
            file_size=os.path.getsize(temp_path),
            file_extension=ext,
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
            source_type="url",
            source_url=url,
            ip_address=request.client.host if request.client else None,
            is_public=True,
        )
        db.add(record)
        await db.commit()

        return {"scan_id": scan_id, "status": "complete", "result": result}
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


@app.get("/api/v1/scan/{scan_id}")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    if scan_id in scan_results_cache:
        return scan_results_cache[scan_id]

    result = await db.execute(select(ScanRecord).where(ScanRecord.scan_id == scan_id))
    record = result.scalar_one_or_none()

    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
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


@app.get("/api/v1/threats/patterns")
async def get_threat_patterns(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ThreatPattern)
        .where(ThreatPattern.is_active == True)
        .order_by(desc(ThreatPattern.times_detected))
    )
    patterns = result.scalars().all()
    if not patterns:
        return {"patterns": BUILTIN_THREAT_PATTERNS, "source": "builtin"}
    return {
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


# ── Badge Endpoint (SVG generated inline — no external dependency) ──
@app.get("/api/v1/badge/{scan_id}")
async def get_badge(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanRecord).where(ScanRecord.scan_id == scan_id))
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
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20" role="img">
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
</svg>'''
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={"Cache-Control": "max-age=3600", "ETag": scan_id[:8]},
    )


@app.get("/api/v1/badge/{scan_id}/json")
async def get_badge_json(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanRecord).where(ScanRecord.scan_id == scan_id))
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    color_map = {
        "clean": "brightgreen", "suspicious": "yellow",
        "malicious": "orange", "critical": "red"
    }
    return {
        "schemaVersion": 1,
        "label": "AegisML",
        "message": record.risk_level,
        "color": color_map.get(record.risk_level, "lightgrey"),
        "namedLogo": "shield",
    }


@app.get("/api/v1/compare")
async def compare_scans(
    scan_a: str, scan_b: str, db: AsyncSession = Depends(get_db)
):
    async def get_record(sid: str) -> Optional[dict]:
        if sid in scan_results_cache:
            return scan_results_cache[sid]
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

    a = await get_record(scan_a)
    b = await get_record(scan_b)

    if not a or not b:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    safer = scan_a if (a.get("risk_score", 100) <= b.get("risk_score", 100)) else scan_b
    return {
        "scan_a": a,
        "scan_b": b,
        "comparison": {
            "safer": safer,
            "risk_difference": abs(a.get("risk_score", 0) - b.get("risk_score", 0)),
            "a_threat_count": len(a.get("threats", [])),
            "b_threat_count": len(b.get("threats", [])),
        },
    }


# ── API Keys ─────────────────────────────────────────────────

def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


@app.post("/api/v1/keys/generate")
@limiter.limit("3/hour")
async def generate_api_key(
    request: Request, body: dict, db: AsyncSession = Depends(get_db)
):
    name = body.get("name", "").strip()
    email = body.get("email", "").strip()
    if not name or len(name) < 3:
        raise HTTPException(status_code=400, detail="Name must be at least 3 characters")

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
async def validate_key(request: Request, db: AsyncSession = Depends(get_db)):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing API key")

    raw_key = auth.replace("Bearer ", "").strip()
    result = await db.execute(
        select(APIKey).where(
            APIKey.key_hash == _hash_key(raw_key),
            APIKey.is_active == True,
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


# ════════════════════════════════════════════════════════════
# CORE SCAN HELPERS
# ════════════════════════════════════════════════════════════

async def run_inspector(file_path: str, filename: str, scan_id: str) -> dict:
    """يشغل المحرك الحقيقي أولاً ثم يرجع للـ fallback الذكي."""
    try:
        proc = subprocess.run(
            ["python", "-m", "aegisml", "scan", file_path, "--format", "json"],
            capture_output=True, text=True, timeout=120,
            cwd=os.path.join(os.path.dirname(__file__), "..", ".."),
        )
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout)
            data["scan_id"] = scan_id
            data["filename"] = filename
            return data
    except Exception:
        pass

    # Fallback: فحص ذكي بالأنماط
    ext = os.path.splitext(filename)[1].lower()
    file_size = os.path.getsize(file_path)
    threats = []

    try:
        with open(file_path, "rb") as f:
            content = f.read(min(file_size, 10 * 1024 * 1024))
        text_content = content.decode("utf-8", errors="ignore")

        for p in BUILTIN_THREAT_PATTERNS:
            pattern = p["pattern"]
            if pattern.encode() in content or pattern in text_content:
                threats.append({
                    "pattern": pattern,
                    "severity": p["severity"],
                    "description": p["description_en"],
                    "location": filename,
                    "category": p["category"],
                })
    except Exception:
        pass

    severity_scores = {"critical": 35, "high": 20, "medium": 10, "low": 5}
    base_risk = {
        "pkl": 30, "pickle": 30, "pt": 25, "pth": 25,
        "gguf": 5, "safetensors": 3,
    }.get(ext.lstrip("."), 15)
    threat_score = sum(severity_scores.get(t["severity"], 5) for t in threats)
    risk = min(100, base_risk + threat_score)

    risk_level = (
        "clean" if risk < 30 else
        "suspicious" if risk < 60 else
        "malicious" if risk < 85 else
        "critical"
    )

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


async def claude_judge(scan_data: dict) -> dict:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return {
            "verdict": "UNKNOWN", "confidence": 0,
            "summary_en": "Claude API key not configured. Static analysis results only.",
            "summary_ar": "مفتاح Claude API غير مضبوط. نتائج التحليل الثابت فقط.",
            "key_risks": [],
            "recommendation": "Configure ANTHROPIC_API_KEY to enable AI analysis.",
            "recommendation_ar": "اضبط ANTHROPIC_API_KEY لتفعيل التحليل الذكي.",
        }

    try:
        client = anthropic.Anthropic(api_key=api_key)
        threat_summary = json.dumps(scan_data.get("threats", [])[:10], indent=2)

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
            model="claude-3-5-sonnet-20241022",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}],
        )
        text = message.content[0].text.replace("```json", "").replace("```", "").strip()
        return json.loads(text)

    except json.JSONDecodeError:
        return {
            "verdict": "UNKNOWN", "confidence": 50,
            "summary_en": "AI analysis completed but response format was unexpected.",
            "summary_ar": "اكتمل التحليل الذكي لكن تنسيق الاستجابة كان غير متوقع.",
            "key_risks": [],
            "recommendation": "Review static analysis results manually.",
            "recommendation_ar": "راجع نتائج التحليل الثابت يدوياً.",
        }
    except Exception as e:
        return {
            "verdict": "UNKNOWN", "confidence": 0,
            "summary_en": f"AI analysis temporarily unavailable: {str(e)[:100]}",
            "summary_ar": "التحليل الذكي غير متاح مؤقتاً.",
            "key_risks": [],
            "recommendation": "Static analysis results are still valid.",
            "recommendation_ar": "نتائج التحليل الثابت لا تزال صحيحة.",
        }
