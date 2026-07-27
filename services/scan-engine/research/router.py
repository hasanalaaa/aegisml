import uuid
from collections import Counter, defaultdict

from fastapi import APIRouter, Query, Response, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from database import get_db, ScanRecord
from export_utils import render_csv
from .models import ResearchKeyRequest

router = APIRouter(tags=["Research API"])

DATASET_CSV_FIELDS = (
    "file_type",
    "verdict",
    "threat_categories",
    "cvss_score",
    "entropy_score",
    "timestamp",
)


class ResearchKeyRequestPayload(BaseModel):
    name: str
    institution: str
    use_case: str
    email: str


@router.post("/api/v1/research/api-key")
async def request_research_key(req: ResearchKeyRequestPayload, db: AsyncSession = Depends(get_db)):
    """Persist a research-key application to the real ResearchKeyRequest
    table (previously this just returned success without storing anything)."""
    request_id = str(uuid.uuid4())
    record = ResearchKeyRequest(
        id=request_id,
        name=req.name,
        institution=req.institution,
        use_case=req.use_case,
        email=req.email,
        status="pending",
    )
    db.add(record)
    await db.commit()
    return {
        "status": "success",
        "message": "Research key requested. You will be notified via email upon approval.",
        "request_id": request_id,
    }


def _anonymized_rows(records: list[ScanRecord]) -> list[dict]:
    """Strip all PII (no user IDs, IPs, filenames, source URLs, hashes) —
    keep only research-relevant, non-identifying fields."""
    rows = []
    for r in records:
        meta = r.metadata_info or {}
        entropy = (meta.get("entropy_analysis") or {}).get("overall_entropy")
        categories = sorted({t.get("category", "unknown") for t in (r.threats or [])})
        rows.append({
            "file_type": r.file_extension or "",
            "verdict": r.risk_level,
            "threat_categories": categories,
            "cvss_score": round((r.risk_score or 0) / 10.0, 1),
            "entropy_score": entropy if entropy is not None else "",
            "timestamp": r.created_at.isoformat() if r.created_at else "",
        })
    return rows


@router.get("/api/v1/research/dataset")
async def get_dataset(
    format: str = Query("json"),
    limit: int = Query(1000, ge=1, le=50000),
    db: AsyncSession = Depends(get_db),
):
    """Return row-level research data from explicitly public scans only."""
    result = await db.execute(
        select(ScanRecord)
        .where(ScanRecord.is_public.is_(True))
        .order_by(ScanRecord.created_at.desc())
        .limit(limit)
    )
    records = result.scalars().all()
    data = _anonymized_rows(records)

    if format == "json":
        return {"dataset": data, "count": len(data)}

    if format == "csv":
        flat = [
            {**row, "threat_categories": ";".join(row["threat_categories"])}
            for row in data
        ]
        return Response(
            content=render_csv(DATASET_CSV_FIELDS, flat),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=aegisml_dataset.csv"},
        )

    raise HTTPException(status_code=400, detail="Invalid format. Use json or csv.")


@router.get("/api/v1/research/stats/aggregate")
async def get_aggregate_stats(db: AsyncSession = Depends(get_db)):
    """Compute real aggregate statistics from the scan history table."""
    total = (await db.execute(select(func.count(ScanRecord.id)))).scalar() or 0

    # Verdict distribution
    verdict_rows = (await db.execute(
        select(ScanRecord.risk_level, func.count(ScanRecord.id)).group_by(ScanRecord.risk_level)
    )).all()
    verdict_distribution = {level: count for level, count in verdict_rows}

    # Average CVSS-equivalent (risk_score/10) by file type
    type_rows = (await db.execute(
        select(ScanRecord.file_extension, func.avg(ScanRecord.risk_score)).group_by(ScanRecord.file_extension)
    )).all()
    avg_cvss_by_type = {ext or "unknown": round((avg or 0) / 10.0, 2) for ext, avg in type_rows}

    # Top threat patterns + monthly trend require row-level scan: bounded pull
    recent = (await db.execute(
        select(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(5000)
    )).scalars().all()

    pattern_counter: Counter = Counter()
    monthly: defaultdict = defaultdict(int)
    for r in recent:
        for t in (r.threats or []):
            if t.get("id"):
                pattern_counter[t["id"]] += 1
        if r.created_at:
            monthly[r.created_at.strftime("%Y-%m")] += 1

    top_threat_patterns = [pid for pid, _ in pattern_counter.most_common(10)]
    monthly_trend = [{"month": m, "count": c} for m, c in sorted(monthly.items())]

    return {
        "total_scans": total,
        "verdict_distribution": verdict_distribution,
        "top_threat_patterns": top_threat_patterns,
        "avg_cvss_by_type": avg_cvss_by_type,
        "monthly_trend": monthly_trend,
    }


@router.get("/api/v1/research/citation")
async def get_citation():
    apa = "AegisML Team. (2026). AegisML: A Global Registry of AI Model Vulnerabilities and Anomalies. Retrieved from https://aegisml.com/research"
    bibtex = "@misc{aegisml2026,\n  author = {AegisML Team},\n  title = {AegisML: A Global Registry of AI Model Vulnerabilities and Anomalies},\n  year = {2026},\n  url = {https://aegisml.com/research}\n}"
    return {"apa": apa, "bibtex": bibtex}
