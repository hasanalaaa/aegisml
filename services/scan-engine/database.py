"""
AegisML Database Module — PostgreSQL (asyncpg) + Redis

Provides:
  - Async SQLAlchemy engine (AsyncAdaptedQueuePool or NullPool)
  - Redis client with graceful fallback
  - ORM models for scans, threat patterns, and API keys
  - Session management and DB initialization utilities
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    JSON,
    String,
    Text,
    func,
    select,
)
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.pool import AsyncAdaptedQueuePool, NullPool

logger = logging.getLogger("aegisml.database")

# ── Environment ──────────────────────────────────────────────────────

_raw_db_url: str = os.getenv(
    "DATABASE_URL", "sqlite+aiosqlite:///./aegisml.db"
)
REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Auto-convert prefixes for SQLAlchemy + asyncpg
if _raw_db_url.startswith("postgres://"):
    _DB_URL = _raw_db_url.replace("postgres://", "postgresql+asyncpg://", 1)
elif _raw_db_url.startswith("postgresql://") and "+asyncpg" not in _raw_db_url:
    _DB_URL = _raw_db_url.replace("postgresql://", "postgresql+asyncpg://", 1)
else:
    _DB_URL = _raw_db_url

DATABASE_URL: str = _DB_URL

# Detect if we're using SQLite (for local development fallback)
_IS_SQLITE: bool = DATABASE_URL.startswith("sqlite")

# ── Engine ───────────────────────────────────────────────────────────

if _IS_SQLITE:
    engine = create_async_engine(
        DATABASE_URL,
        echo=False,
        poolclass=NullPool
    )
else:
    engine = create_async_engine(
        DATABASE_URL,
        echo=False,
        pool_pre_ping=True,
        poolclass=AsyncAdaptedQueuePool,
        pool_size=10,
        max_overflow=20,
        pool_recycle=1800,
        connect_args={
            "server_settings": {"application_name": "aegisml"},
            "command_timeout": 30,
        }
    )

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# ── Redis Client ─────────────────────────────────────────────────────

try:
    import redis.asyncio as aioredis
    _HAS_REDIS = True
except ImportError:
    aioredis = None  # type: ignore
    _HAS_REDIS = False

redis_client: Optional[object] = None


async def init_redis() -> bool:
    """Initialise the Redis connection. Returns True on success, False if unavailable."""
    global redis_client

    if not _HAS_REDIS:
        logger.warning("redis package not installed — caching disabled")
        return False

    try:
        redis_client = aioredis.from_url(
            REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
            max_connections=20,
        )
        await redis_client.ping()  # type: ignore
        logger.info("Redis connected successfully")
        return True
    except Exception as exc:
        logger.warning("Redis connection failed (%s) — caching disabled", exc)
        redis_client = None
        return False


async def close_redis() -> None:
    """Gracefully close the Redis connection pool."""
    global redis_client
    if redis_client is not None:
        try:
            await redis_client.aclose()  # type: ignore
        except Exception as exc:
            logger.debug("Redis close error: %s", exc)
        finally:
            redis_client = None


async def check_redis_health() -> bool:
    """Non-throwing health-check for Redis."""
    if redis_client is None:
        return False
    try:
        await redis_client.ping()  # type: ignore
        return True
    except Exception:
        return False


async def check_db_health() -> bool:
    """Non-throwing health-check for the database."""
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(select(func.now()))
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════
# ORM MODELS
# ══════════════════════════════════════════════════════════════════════

class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    file_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    file_extension: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(20), default="clean")
    threats: Mapped[Optional[dict]] = mapped_column(JSON, default=list)
    metadata_info: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)

    ai_verdict: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    ai_confidence: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    ai_summary_en: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_summary_ar: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_key_risks: Mapped[Optional[dict]] = mapped_column(JSON, default=list)
    ai_recommendation_en: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_recommendation_ar: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    source_type: Mapped[str] = mapped_column(String(20), default="upload")
    source_url: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    is_public: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class ThreatPattern(Base):
    __tablename__ = "threat_patterns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    pattern: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    category: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    description_en: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    description_ar: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    times_detected: Mapped[int] = mapped_column(Integer, default=0)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    scans_used: Mapped[int] = mapped_column(Integer, default=0)
    scans_limit: Mapped[int] = mapped_column(Integer, default=500)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_used: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


# ══════════════════════════════════════════════════════════════════════
# INITIALISATION
# ══════════════════════════════════════════════════════════════════════

async def init_db() -> None:
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables verified / created")
    except Exception as exc:
        logger.error("Failed to initialise database: %s", exc)
        raise


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def seed_threat_patterns(session: AsyncSession) -> None:
    existing = await session.scalar(select(func.count(ThreatPattern.id)))
    if existing and existing > 0:
        return

    defaults = [
        ThreatPattern(pattern="os.system", severity="critical", category="code_execution", description_en="Executes arbitrary OS commands — highest risk", description_ar="ينفذ أوامر نظام التشغيل — أعلى درجات الخطر"),
        ThreatPattern(pattern="subprocess.run", severity="critical", category="code_execution", description_en="Spawns external processes with potential privilege escalation", description_ar="يشغل عمليات خارجية مع احتمال رفع الصلاحيات"),
        ThreatPattern(pattern="eval", severity="critical", category="code_execution", description_en="Dynamic code evaluation — can execute any Python code", description_ar="تقييم ديناميكي للكود — يمكنه تنفيذ أي كود Python"),
        ThreatPattern(pattern="exec", severity="critical", category="code_execution", description_en="Executes compiled Python code objects", description_ar="يُنفِّذ كائنات كود Python المُجمَّعة"),
        ThreatPattern(pattern="__reduce__", severity="critical", category="deserialization", description_en="Pickle hook that executes code during deserialization", description_ar="خطاف Pickle يُنفِّذ كوداً أثناء إلغاء التسلسل"),
        ThreatPattern(pattern="pickle.loads", severity="high", category="deserialization", description_en="Loads arbitrary Python objects — can trigger code execution", description_ar="يحمّل كائنات Python عشوائية — يمكنه تشغيل الكود"),
        ThreatPattern(pattern="ctypes", severity="critical", category="system_access", description_en="Low-level C library access — bypasses Python safety", description_ar="وصول مستوى منخفض لمكتبات C — يتجاوز أمان Python"),
        ThreatPattern(pattern="socket", severity="high", category="network", description_en="Network socket creation — enables data exfiltration", description_ar="إنشاء مقبس شبكي — يُمكِّن تسريب البيانات"),
        ThreatPattern(pattern="import os", severity="high", category="system_access", description_en="Imports OS module for system operations access", description_ar="استيراد وحدة النظام للوصول لعمليات النظام"),
        ThreatPattern(pattern="base64", severity="medium", category="obfuscation", description_en="Often used to encode and hide malicious payloads", description_ar="يُستخدم غالباً لتشفير وإخفاء الحمولات الخبيثة"),
        ThreatPattern(pattern="requests", severity="medium", category="network", description_en="HTTP library — can send data to external servers", description_ar="مكتبة HTTP — يمكنها إرسال بيانات لخوادم خارجية"),
        ThreatPattern(pattern="shutil", severity="medium", category="file_operations", description_en="File system operations including copy, move, delete", description_ar="عمليات نظام الملفات شاملة النسخ والنقل والحذف"),
        ThreatPattern(pattern="__import__", severity="high", category="code_execution", description_en="Dynamic module importing — can load any installed package", description_ar="استيراد ديناميكي للوحدات — يمكنه تحميل أي حزمة مثبتة"),
        ThreatPattern(pattern="urllib", severity="medium", category="network", description_en="URL handling library with HTTP request capabilities", description_ar="مكتبة معالجة الروابط مع قدرات طلب HTTP"),
    ]

    for p in defaults:
        session.add(p)
    await session.commit()
    logger.info("Seeded %d default threat patterns", len(defaults))
