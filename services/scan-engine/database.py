from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, Float, DateTime, Text, Boolean, JSON, select, func
from datetime import datetime, timezone
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./aegisml.db")

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=True)
    file_extension: Mapped[str] = mapped_column(String(20), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(20), default="clean")
    threats: Mapped[dict] = mapped_column(JSON, default=list)
    metadata_info: Mapped[dict] = mapped_column(JSON, default=dict)
    ai_verdict: Mapped[str] = mapped_column(String(20), nullable=True)
    ai_confidence: Mapped[int] = mapped_column(Integer, nullable=True)
    ai_summary_en: Mapped[str] = mapped_column(Text, nullable=True)
    ai_summary_ar: Mapped[str] = mapped_column(Text, nullable=True)
    ai_key_risks: Mapped[dict] = mapped_column(JSON, default=list)
    ai_recommendation_en: Mapped[str] = mapped_column(Text, nullable=True)
    ai_recommendation_ar: Mapped[str] = mapped_column(Text, nullable=True)
    source_type: Mapped[str] = mapped_column(String(20), default="upload")
    source_url: Mapped[str] = mapped_column(String(1000), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str] = mapped_column(String(500), nullable=True)
    is_public: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )


class ThreatPattern(Base):
    __tablename__ = "threat_patterns"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    pattern: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=True)
    description_en: Mapped[str] = mapped_column(Text, nullable=True)
    description_ar: Mapped[str] = mapped_column(Text, nullable=True)
    times_detected: Mapped[int] = mapped_column(Integer, default=0)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )


class APIKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[str] = mapped_column(String(200), nullable=True)
    scans_used: Mapped[int] = mapped_column(Integer, default=0)
    scans_limit: Mapped[int] = mapped_column(Integer, default=500)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    last_used: Mapped[datetime] = mapped_column(DateTime, nullable=True)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def seed_threat_patterns(session: AsyncSession):
    """تعبئة أنماط التهديد الأولية إذا لم تكن موجودة."""
    existing = await session.scalar(select(func.count(ThreatPattern.id)))
    if existing and existing > 0:
        return

    patterns = [
        ThreatPattern(
            pattern="os.system", severity="critical", category="code_execution",
            description_en="Executes arbitrary OS commands — highest risk",
            description_ar="ينفذ أوامر نظام التشغيل — أعلى درجات الخطر",
        ),
        ThreatPattern(
            pattern="subprocess.run", severity="critical", category="code_execution",
            description_en="Spawns external processes with potential privilege escalation",
            description_ar="يشغل عمليات خارجية مع احتمال رفع الصلاحيات",
        ),
        ThreatPattern(
            pattern="eval", severity="critical", category="code_execution",
            description_en="Dynamic code evaluation — can execute any Python code",
            description_ar="تقييم ديناميكي للكود — يمكنه تنفيذ أي كود Python",
        ),
        ThreatPattern(
            pattern="exec", severity="critical", category="code_execution",
            description_en="Executes compiled Python code objects",
            description_ar="يُنفِّذ كائنات كود Python المُجمَّعة",
        ),
        ThreatPattern(
            pattern="__reduce__", severity="critical", category="deserialization",
            description_en="Pickle hook that executes code during deserialization",
            description_ar="خطاف Pickle يُنفِّذ كوداً أثناء إلغاء التسلسل",
        ),
        ThreatPattern(
            pattern="pickle.loads", severity="high", category="deserialization",
            description_en="Loads arbitrary Python objects — can trigger code execution",
            description_ar="يحمّل كائنات Python عشوائية — يمكنه تشغيل الكود",
        ),
        ThreatPattern(
            pattern="ctypes", severity="critical", category="system_access",
            description_en="Low-level C library access — bypasses Python safety",
            description_ar="وصول مستوى منخفض لمكتبات C — يتجاوز أمان Python",
        ),
        ThreatPattern(
            pattern="socket", severity="high", category="network",
            description_en="Network socket creation — enables data exfiltration",
            description_ar="إنشاء مقبس شبكي — يُمكِّن تسريب البيانات",
        ),
        ThreatPattern(
            pattern="import os", severity="high", category="system_access",
            description_en="Imports OS module for system operations access",
            description_ar="استيراد وحدة النظام للوصول لعمليات النظام",
        ),
        ThreatPattern(
            pattern="base64", severity="medium", category="obfuscation",
            description_en="Often used to encode and hide malicious payloads",
            description_ar="يُستخدم غالباً لتشفير وإخفاء الحمولات الخبيثة",
        ),
        ThreatPattern(
            pattern="requests", severity="medium", category="network",
            description_en="HTTP library — can send data to external servers",
            description_ar="مكتبة HTTP — يمكنها إرسال بيانات لخوادم خارجية",
        ),
        ThreatPattern(
            pattern="shutil", severity="medium", category="file_operations",
            description_en="File system operations including copy, move, delete",
            description_ar="عمليات نظام الملفات شاملة النسخ والنقل والحذف",
        ),
        ThreatPattern(
            pattern="__import__", severity="high", category="code_execution",
            description_en="Dynamic module importing — can load any installed package",
            description_ar="استيراد ديناميكي للوحدات — يمكنه تحميل أي حزمة مثبتة",
        ),
        ThreatPattern(
            pattern="urllib", severity="medium", category="network",
            description_en="URL handling library with HTTP request capabilities",
            description_ar="مكتبة معالجة الروابط مع قدرات طلب HTTP",
        ),
    ]

    for p in patterns:
        session.add(p)
    await session.commit()
