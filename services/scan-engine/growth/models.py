from sqlalchemy import Column, String, Integer, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
import datetime
from database import Base

class ReferralCode(Base):
    __tablename__ = "referral_codes"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    # users.id is UUID(as_uuid=True). This FK column MUST be the same type or
    # Postgres rejects the constraint at CREATE time:
    #   DatatypeMismatchError: foreign key ... incompatible types: varchar and uuid
    # which aborts the whole create_all() transaction and leaves the DB empty.
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    code = Column(String, unique=True, nullable=False, index=True)
    referred_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User", backref="referral_code")

class NewsletterSubscriber(Base):
    __tablename__ = "newsletter_subscribers"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
