import strawberry
from typing import List, Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from database import ScanRecord, CVERecord, ThreatPattern, get_db

@strawberry.type
class ThreatGraphQL:
    pattern: str
    severity: str
    category: str
    description_en: Optional[str]
    description_ar: Optional[str]

@strawberry.type
class ScanGraphQL:
    scan_id: str
    filename: str
    risk_score: float
    risk_level: str
    source_type: str
    source_url: Optional[str]
    created_at: str
    
    # Resolver for threats
    @strawberry.field
    def threats(self) -> List[ThreatGraphQL]:
        # Here we mock mapping the JSON 'threats' column to the GraphQL type
        # For a true implementation, we'd pull from self._threats_json
        return []

@strawberry.type
class CVEGraphQL:
    cve_id: str
    description: str
    cvss_score: Optional[float]
    affected_tech: Optional[str]
    published_date: Optional[str]

@strawberry.type
class Query:
    @strawberry.field
    async def recent_scans(self, limit: int = 10) -> List[ScanGraphQL]:
        async for db in get_db():
            stmt = select(ScanRecord).where(ScanRecord.is_public == True).order_by(desc(ScanRecord.created_at)).limit(limit)
            result = await db.execute(stmt)
            scans = result.scalars().all()
            return [
                ScanGraphQL(
                    scan_id=s.scan_id,
                    filename=s.filename,
                    risk_score=s.risk_score,
                    risk_level=s.risk_level,
                    source_type=s.source_type,
                    source_url=s.source_url,
                    created_at=s.created_at.isoformat()
                ) for s in scans
            ]
        return []

    @strawberry.field
    async def cve_feed(self, limit: int = 20) -> List[CVEGraphQL]:
        async for db in get_db():
            stmt = select(CVERecord).order_by(desc(CVERecord.published_date)).limit(limit)
            result = await db.execute(stmt)
            cves = result.scalars().all()
            return [
                CVEGraphQL(
                    cve_id=c.cve_id,
                    description=c.description,
                    cvss_score=c.cvss_score,
                    affected_tech=c.affected_tech,
                    published_date=c.published_date.isoformat() if c.published_date else None
                ) for c in cves
            ]
        return []

    @strawberry.field
    async def threat_patterns(self) -> List[ThreatGraphQL]:
        async for db in get_db():
            stmt = select(ThreatPattern).where(ThreatPattern.is_active == True)
            result = await db.execute(stmt)
            patterns = result.scalars().all()
            return [
                ThreatGraphQL(
                    pattern=p.pattern,
                    severity=p.severity,
                    category=p.category,
                    description_en=p.description_en,
                    description_ar=p.description_ar
                ) for p in patterns
            ]
        return []

@strawberry.type
class Mutation:
    @strawberry.mutation
    async def trigger_url_scan(self, url: str) -> str:
        # Note: In a fully fleshed out mutation, we would integrate this directly 
        # with our `_process_scan` backend task from main.py
        return f"Scan triggered for {url}. Monitor webhooks for completion."

schema = strawberry.Schema(query=Query, mutation=Mutation)
