from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, case
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from database import get_db, ScanRecord
from auth.models import User
from auth.utils import get_current_user
from .models import ModelReview, ModelBookmark, CommunityThreatReport

router = APIRouter(tags=["Community"])

# --- Schemas ---
class ReviewCreate(BaseModel):
    model_url: str
    rating: int
    comment: Optional[str] = None

class ReviewResponse(BaseModel):
    id: int
    model_url: str
    rating: int
    comment: Optional[str]
    created_at: datetime

class BookmarkCreate(BaseModel):
    model_url: str

class BookmarkResponse(BaseModel):
    id: int
    model_url: str
    created_at: datetime

class ThreatReportCreate(BaseModel):
    pattern: str
    category: str
    description: str
    evidence: dict = {}

class ThreatReportResponse(BaseModel):
    id: int
    pattern: str
    category: str
    status: str
    created_at: datetime


# --- Endpoints ---
# Previously every endpoint here ignored the real ModelReview / ModelBookmark
# / CommunityThreatReport SQLAlchemy models entirely and returned the exact
# same hardcoded literal regardless of input (explicit comment: "Mocking DB
# insertion for now"). The models were already correctly defined — they were
# just never actually queried or written to.

@router.post("/reviews", response_model=ReviewResponse)
async def submit_review(
    req: ReviewCreate,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
):
    if not (1 <= req.rating <= 5):
        raise HTTPException(status_code=400, detail="rating must be between 1 and 5")
    review = ModelReview(
        model_url=req.model_url,
        user_id=current_user.id if current_user else None,
        rating=req.rating,
        comment=req.comment,
    )
    db.add(review)
    await db.commit()
    await db.refresh(review)
    return ReviewResponse(
        id=review.id, model_url=review.model_url, rating=review.rating,
        comment=review.comment, created_at=review.created_at,
    )


@router.get("/reviews/{model_url:path}", response_model=List[ReviewResponse])
async def get_reviews(model_url: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ModelReview)
        .where(ModelReview.model_url == model_url)
        .order_by(desc(ModelReview.created_at))
        .limit(100)
    )
    reviews = result.scalars().all()
    return [
        ReviewResponse(id=r.id, model_url=r.model_url, rating=r.rating, comment=r.comment, created_at=r.created_at)
        for r in reviews
    ]


@router.get("/leaderboard")
async def get_leaderboard(limit: int = Query(20, ge=1, le=100), db: AsyncSession = Depends(get_db)):
    """Real leaderboard computed from actual scan history: models scanned
    via URL (i.e. identifiable public HuggingFace repos, as opposed to
    anonymous file uploads) ranked by a safety score derived from their
    average risk_score across all submitted scans."""
    stmt = (
        select(
            ScanRecord.source_url,
            func.avg(ScanRecord.risk_score).label("avg_risk_score"),
            func.count(ScanRecord.id).label("scan_count"),
        )
        .where(ScanRecord.source_type == "url")
        .where(ScanRecord.source_url.is_not(None))
        .group_by(ScanRecord.source_url)
        .order_by(func.avg(ScanRecord.risk_score).asc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    rows = result.all()

    if not rows:
        return []

    leaderboard = []
    for source_url, avg_risk_score, scan_count in rows:
        safety_score = round(max(0.0, 100.0 - float(avg_risk_score or 0)), 1)
        leaderboard.append({
            "model_url": source_url,
            "safety_score": safety_score,
            "scan_count": scan_count,
        })
    return leaderboard


@router.post("/bookmark", response_model=BookmarkResponse)
async def bookmark_model(
    req: BookmarkCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Login required to bookmark models")
    bookmark = ModelBookmark(model_url=req.model_url, user_id=current_user.id)
    db.add(bookmark)
    await db.commit()
    await db.refresh(bookmark)
    return BookmarkResponse(id=bookmark.id, model_url=bookmark.model_url, created_at=bookmark.created_at)


@router.get("/bookmarks", response_model=List[BookmarkResponse])
async def get_bookmarks(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Login required")
    result = await db.execute(
        select(ModelBookmark)
        .where(ModelBookmark.user_id == current_user.id)
        .order_by(desc(ModelBookmark.created_at))
    )
    bookmarks = result.scalars().all()
    return [
        BookmarkResponse(id=b.id, model_url=b.model_url, created_at=b.created_at)
        for b in bookmarks
    ]


@router.post("/threat-reports", response_model=ThreatReportResponse)
async def report_threat(
    req: ThreatReportCreate,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
):
    report = CommunityThreatReport(
        reporter_id=current_user.id if current_user else None,
        pattern=req.pattern,
        category=req.category,
        description=req.description,
        evidence=req.evidence,
        status="pending",
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return ThreatReportResponse(
        id=report.id, pattern=report.pattern, category=report.category,
        status=report.status, created_at=report.created_at,
    )


@router.get("/threat-reports", response_model=List[ThreatReportResponse])
async def list_threat_reports(
    status_filter: Optional[str] = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(CommunityThreatReport).order_by(desc(CommunityThreatReport.created_at)).limit(100)
    if status_filter:
        stmt = stmt.where(CommunityThreatReport.status == status_filter)
    result = await db.execute(stmt)
    reports = result.scalars().all()
    return [
        ThreatReportResponse(id=r.id, pattern=r.pattern, category=r.category, status=r.status, created_at=r.created_at)
        for r in reports
    ]
