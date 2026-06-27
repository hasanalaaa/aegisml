from sqlalchemy import select
from database import AsyncSessionLocal, IOCRecord

async def check_hash(file_hash: str) -> dict | None:
    """Check if a file hash exists in the IOC database."""
    async with AsyncSessionLocal() as session:
        stmt = select(IOCRecord).where(IOCRecord.file_hash == file_hash)
        record = await session.scalar(stmt)
        
        if record:
            return {
                "file_hash": record.file_hash,
                "severity": record.severity,
                "is_verified": record.is_verified,
                "reported_at": record.reported_at.isoformat() if record.reported_at else None
            }
    return None

async def report_ioc(file_hash: str, severity: str = "malicious", reporter_id: str | None = None) -> bool:
    """Report a new malicious hash to the database."""
    async with AsyncSessionLocal() as session:
        stmt = select(IOCRecord).where(IOCRecord.file_hash == file_hash)
        existing = await session.scalar(stmt)
        
        if not existing:
            new_record = IOCRecord(
                file_hash=file_hash,
                severity=severity,
                reporter_id=reporter_id,
                is_verified=False # Requires manual verification for community reports
            )
            session.add(new_record)
            await session.commit()
            return True
    return False
