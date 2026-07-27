from sqlalchemy import Integer, String, Boolean, DateTime, Float, Text, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column
from database import Base
from datetime import datetime, timezone
import uuid
from sqlalchemy.dialects.postgresql import UUID

class ModelReview(Base):
    __tablename__ = "model_reviews"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    model_url: Mapped[str] = mapped_column(String(1000), index=True, nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True, nullable=True) # Optional for anon reviews
    rating: Mapped[int] = mapped_column(Integer, nullable=False) # 1 to 5
    comment: Mapped[str] = mapped_column(Text, nullable=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class ModelBookmark(Base):
    __tablename__ = "model_bookmarks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    model_url: Mapped[str] = mapped_column(String(1000), index=True, nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class CommunityThreatReport(Base):
    __tablename__ = "community_threat_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    reporter_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True, nullable=True)
    pattern: Mapped[str] = mapped_column(String(500), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="pending") # pending, verified, rejected
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
