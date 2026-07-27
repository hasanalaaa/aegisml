from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from database import get_db, ScanRecord
from export_utils import daily_trends, render_csv

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])

THREAT_CSV_FIELDS = (
    "scan_id",
    "filename",
    "threat_id",
    "threat_name",
    "category",
    "severity",
    "cvss",
    "description",
    "remediation",
)
SCAN_CSV_FIELDS = (
    "scan_id",
    "filename",
    "file_extension",
    "file_size",
    "risk_level",
    "risk_score",
    "threat_count",
    "source_type",
    "created_at",
)


@router.get("/export/{scan_id}.csv")
async def export_scan_csv(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Export a single scan's threat findings as a flat CSV — one row per
    threat finding, suitable for spreadsheet tools or security ticketing
    system import."""
    result = await db.execute(
        select(ScanRecord)
        .where(ScanRecord.scan_id == scan_id)
        .where(ScanRecord.is_public.is_(True))
    )
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    threats = record.threats or []
    if threats:
        rows = []
        for t in threats:
            rows.append({
                "scan_id": record.scan_id,
                "filename": record.filename,
                "threat_id": t.get("id", ""),
                "threat_name": t.get("name", t.get("pattern", "")),
                "category": t.get("category", ""),
                "severity": t.get("severity", ""),
                "cvss": t.get("cvss", ""),
                "description": t.get("description", ""),
                "remediation": t.get("remediation", ""),
            })
    else:
        rows = [{
            "scan_id": record.scan_id,
            "filename": record.filename,
            "threat_id": "",
            "threat_name": "No threats detected",
            "category": "",
            "severity": "",
            "cvss": "",
            "description": "",
            "remediation": "",
        }]

    headers = {
        "Content-Disposition": f'attachment; filename="AegisML_{scan_id}_threats.csv"'
    }
    return Response(
        content=render_csv(THREAT_CSV_FIELDS, rows),
        media_type="text/csv",
        headers=headers,
    )


@router.get("/export/scans.csv")
async def export_all_scans_csv(
    limit: int = 1000,
    db: AsyncSession = Depends(get_db),
):
    """Export a summary CSV across recent scans (one row per scan, not per
    threat) — useful for bulk auditing or feeding into a SIEM."""
    limit = max(1, min(limit, 5000))
    result = await db.execute(
        select(ScanRecord)
        .where(ScanRecord.is_public.is_(True))
        .order_by(ScanRecord.created_at.desc())
        .limit(limit)
    )
    records = result.scalars().all()

    rows = [{
        "scan_id": r.scan_id,
        "filename": r.filename,
        "file_extension": r.file_extension,
        "file_size": r.file_size,
        "risk_level": r.risk_level,
        "risk_score": r.risk_score,
        "threat_count": len(r.threats or []),
        "source_type": r.source_type,
        "created_at": r.created_at.isoformat() if r.created_at else "",
    } for r in records]

    headers = {
        "Content-Disposition": 'attachment; filename="AegisML_scans_export.csv"'
    }
    return Response(
        content=render_csv(SCAN_CSV_FIELDS, rows),
        media_type="text/csv",
        headers=headers,
    )


@router.get("/overview")
async def get_overview(db: AsyncSession = Depends(get_db)):
    """General overview statistics for the dashboard."""
    total_scans_result = await db.execute(select(func.count(ScanRecord.id)))
    total_scans = total_scans_result.scalar() or 0
    
    threats_result = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.risk_level.in_(["malicious", "critical"])))
    threats = threats_result.scalar() or 0
    
    clean_result = await db.execute(select(func.count(ScanRecord.id)).where(ScanRecord.risk_level == "clean"))
    clean = clean_result.scalar() or 0
    
    return {
        "totalScans": total_scans,
        "threatsFound": threats,
        "cleanModels": clean,
    }

@router.get("/trends")
async def get_trends(period: str = "7d", db: AsyncSession = Depends(get_db)):
    """Scan trends grouped by date."""
    days = 7
    if period == "1d": days = 1
    elif period == "30d": days = 30
    elif period == "90d": days = 90
    elif period == "1y": days = 365
        
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)
    
    stmt = select(ScanRecord.created_at, ScanRecord.risk_level).where(ScanRecord.created_at >= start_date)
    result = await db.execute(stmt)
    records = result.all()
    
    if not records:
        return {"data": []}
        
    return {"data": daily_trends(records, start_date.date(), end_date.date())}

@router.get("/threats")
async def get_threat_distribution(db: AsyncSession = Depends(get_db)):
    """Threats distribution by file extension and severity levels."""
    
    # File Extension Pie Chart
    ext_stmt = select(ScanRecord.file_extension, func.count(ScanRecord.id)).where(ScanRecord.risk_level.in_(["malicious", "critical"])).group_by(ScanRecord.file_extension)
    ext_res = await db.execute(ext_stmt)
    file_types = [{"name": r[0] or "unknown", "value": r[1]} for r in ext_res.all()]
    
    # Severity Bar Chart
    sev_stmt = select(ScanRecord.risk_level, func.count(ScanRecord.id)).group_by(ScanRecord.risk_level)
    sev_res = await db.execute(sev_stmt)
    severity_map = {r[0]: r[1] for r in sev_res.all()}
    
    severity_data = [
        {"name": "Critical", "count": severity_map.get("critical", 0), "fill": "#E74C3C"},
        {"name": "High/Malicious", "count": severity_map.get("malicious", 0), "fill": "#E67E22"},
        {"name": "Medium/Suspicious", "count": severity_map.get("suspicious", 0), "fill": "#F1C40F"},
        {"name": "Low/Clean", "count": severity_map.get("clean", 0), "fill": "#2ECC71"}
    ]
    
    return {
        "fileTypes": file_types,
        "severities": severity_data
    }

@router.get("/geography")
async def get_geography():
    """Return an honest empty capability until GeoIP is configured."""
    return {
        "points": [],
        "available": False,
        "reason": "GeoIP mapping is not configured; synthetic locations are never returned.",
    }
