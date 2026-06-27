from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from pydantic import BaseModel

from database import get_db, CVERecord, IOCRecord, ScanRecord, ThreatPattern
from threat_intel.ioc_database import check_hash, report_ioc
from threat_intel.cve_fetcher import fetch_and_store_ai_cves

router = APIRouter(prefix="/api/v1", tags=["threat-intel"])

class IOCReportRequest(BaseModel):
    file_hash: str
    severity: str = "malicious"
    reporter_id: str | None = None

@router.get("/cve/recent")
async def get_recent_cves(limit: int = 50, db: AsyncSession = Depends(get_db)):
    """Fetch the most recent AI-related CVEs."""
    stmt = select(CVERecord).order_by(desc(CVERecord.published_date)).limit(limit)
    result = await db.execute(stmt)
    cves = result.scalars().all()
    return {"cves": cves}

@router.get("/cve/{cve_id}")
async def get_cve_details(cve_id: str, db: AsyncSession = Depends(get_db)):
    """Fetch details of a specific CVE by its ID."""
    stmt = select(CVERecord).where(CVERecord.cve_id == cve_id)
    cve = await db.scalar(stmt)
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return {"cve": cve}

@router.get("/ioc/check/{file_hash}")
async def check_ioc_hash(file_hash: str):
    """Fast check to see if a SHA256 hash is in the malicious IOC database."""
    result = await check_hash(file_hash)
    if result:
        return {"status": "found", "details": result}
    return {"status": "clean"}

@router.post("/ioc/report")
async def report_malicious_ioc(request: IOCReportRequest):
    """Report a malicious hash to the IOC database."""
    success = await report_ioc(request.file_hash, request.severity, request.reporter_id)
    if success:
        return {"status": "success", "message": "IOC reported successfully and is pending verification."}
    return {"status": "ignored", "message": "IOC already exists in the database."}

@router.get("/threats/statistics")
async def get_threat_statistics(db: AsyncSession = Depends(get_db)):
    """Get aggregated statistics about threats and scans."""
    # Total Scans
    total_scans_result = await db.execute(select(func.count(ScanRecord.id)))
    total_scans = total_scans_result.scalar() or 0
    
    # Threats Found
    threats_found_result = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.risk_level.in_(["malicious", "critical"])))
    threats_found = threats_found_result.scalar() or 0
    
    # Total CVEs
    total_cves_result = await db.execute(select(func.count(CVERecord.id)))
    total_cves = total_cves_result.scalar() or 0
    
    # Total IOCs
    total_iocs_result = await db.execute(select(func.count(IOCRecord.id)))
    total_iocs = total_iocs_result.scalar() or 0
    
    return {
        "total_scans": total_scans,
        "malicious_scans": threats_found,
        "clean_scans": total_scans - threats_found,
        "total_cves": total_cves,
        "total_iocs": total_iocs
    }

@router.post("/cve/trigger-sync")
async def trigger_cve_sync(background_tasks: BackgroundTasks):
    """Manually trigger a CVE sync (for admin/testing)."""
    background_tasks.add_task(fetch_and_store_ai_cves)
    return {"status": "sync_started", "message": "CVE fetcher started in the background."}

@router.get("/threats/patterns")
async def get_threat_patterns(db: AsyncSession = Depends(get_db)):
    """Fetch active threat patterns."""
    stmt = select(ThreatPattern).where(ThreatPattern.is_active == True)
    result = await db.execute(stmt)
    patterns = result.scalars().all()
    return {"patterns": patterns}
