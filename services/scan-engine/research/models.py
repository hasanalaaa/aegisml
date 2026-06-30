from sqlalchemy import Column, String, DateTime, Text, Integer, ForeignKey
from database import Base
import datetime

class ResearchKeyRequest(Base):
    __tablename__ = "research_key_requests"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    institution = Column(String, nullable=False)
    use_case = Column(Text, nullable=False)
    email = Column(String, nullable=False)
    status = Column(String, default="pending") # pending, approved, rejected
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
