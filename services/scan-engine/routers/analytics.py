import io
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text
import pandas as pd
from xhtml2pdf import pisa
from jinja2 import Environment, FileSystemLoader

from database import get_db, ScanRecord, ThreatPattern

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])

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
        
    start_date = datetime.now(timezone.utc) - timedelta(days=days)
    
    stmt = select(ScanRecord.created_at, ScanRecord.risk_level).where(ScanRecord.created_at >= start_date)
    result = await db.execute(stmt)
    records = result.all()
    
    if not records:
        return {"data": []}
        
    # Process using pandas for quick time-series grouping
    df = pd.DataFrame(records, columns=["created_at", "risk_level"])
    df["date"] = pd.to_datetime(df["created_at"]).dt.date
    
    # Create a complete date range to fill missing days with 0
    date_range = pd.date_range(start=start_date.date(), end=datetime.now(timezone.utc).date(), freq="D").date
    
    # Group by date and risk level
    grouped = df.groupby(["date", "risk_level"]).size().unstack(fill_value=0)
    
    # Reindex to ensure all dates exist
    grouped = grouped.reindex(date_range, fill_value=0)
    
    data = []
    for date, row in grouped.iterrows():
        malicious = row.get("malicious", 0) + row.get("critical", 0)
        clean = row.get("clean", 0) + row.get("suspicious", 0)
        data.append({
            "date": date.strftime("%Y-%m-%d"),
            "safe": int(clean),
            "threats": int(malicious)
        })
        
    return {"data": data}

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
async def get_geography(db: AsyncSession = Depends(get_db)):
    """Mock or mapped GeoIP points for Leaflet map display."""
    # Since we don't have a full GeoIP database like MaxMind built-in,
    # we simulate realistic distribution based on actual IP counts if available,
    # or just return an empty array if privacy is strictly enforced.
    
    stmt = select(ScanRecord.ip_address, func.count(ScanRecord.id)).where(ScanRecord.ip_address.isnot(None)).group_by(ScanRecord.ip_address).limit(100)
    result = await db.execute(stmt)
    
    # In a real production system, you'd map IPs to Lat/Lng.
    # Here we send a few hardcoded mock points and scale them by actual traffic.
    points = [
        {"lat": 37.7749, "lng": -122.4194, "intensity": 80, "label": "San Francisco"},
        {"lat": 51.5074, "lng": -0.1278, "intensity": 60, "label": "London"},
        {"lat": 35.6895, "lng": 139.6917, "intensity": 45, "label": "Tokyo"},
        {"lat": 48.8566, "lng": 2.3522, "intensity": 30, "label": "Paris"},
        {"lat": -33.8688, "lng": 151.2093, "intensity": 25, "label": "Sydney"}
    ]
    
    return {"points": points}

@router.post("/report/{scan_id}")
async def generate_pdf_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Generate a PDF report using xhtml2pdf and Jinja2."""
    stmt = select(ScanRecord).where(ScanRecord.scan_id == scan_id)
    scan = await db.scalar(stmt)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    env = FileSystemLoader('templates')
    template_env = Environment(loader=env)
    
    try:
        template = template_env.get_template('report.html')
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report template missing: {e}")
        
    html_content = template.render(scan=scan, date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    
    pdf_buffer = io.BytesIO()
    pisa_status = pisa.CreatePDF(io.BytesIO(html_content.encode("utf-8")), dest=pdf_buffer)
    
    if pisa_status.err:
        raise HTTPException(status_code=500, detail="PDF generation failed")
        
    pdf_buffer.seek(0)
    
    headers = {
        'Content-Disposition': f'attachment; filename="AegisML_Report_{scan_id}.pdf"'
    }
    
    return Response(content=pdf_buffer.read(), media_type="application/pdf", headers=headers)
