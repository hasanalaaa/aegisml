import strawberry
from typing import List, Optional
from strawberry.fastapi import GraphQLRouter
from pydantic import BaseModel

# --- Strawberry Types ---

@strawberry.type
class ThreatPatternType:
    id: str
    name: str
    severity: str
    category: str
    description: str

@strawberry.type
class EntropyAnalysisType:
    overall_entropy: float
    risk_level: str

@strawberry.type
class ScanResultType:
    scan_id: str
    filename: str
    verdict: str
    threat_count: int
    threats: List[ThreatPatternType]
    entropy: Optional[EntropyAnalysisType]
    format_detected: str

@strawberry.type
class StatsType:
    total_scans: int
    threats_detected: int
    active_patterns: int

# --- Mock Data Providers (Replace with DB calls in production) ---
# For this phase, we mock the responses to satisfy the schema

def get_recent_scans() -> List[ScanResultType]:
    return [
        ScanResultType(
            scan_id="mock-123", filename="model.gguf", verdict="SAFE", 
            threat_count=0, threats=[], entropy=EntropyAnalysisType(overall_entropy=4.2, risk_level="low"), format_detected="gguf"
        )
    ]

def get_stats() -> StatsType:
    return StatsType(total_scans=15420, threats_detected=342, active_patterns=250)

# --- Queries ---

@strawberry.type
class Query:
    @strawberry.field
    def scan(self, scan_id: str) -> Optional[ScanResultType]:
        # Return mock for now or fetch from DB
        if scan_id == "mock-123":
            return get_recent_scans()[0]
        return None

    @strawberry.field
    def recent_scans(self, limit: int = 10) -> List[ScanResultType]:
        return get_recent_scans()[:limit]

    @strawberry.field
    def stats(self) -> StatsType:
        return get_stats()

# --- Mutations ---

@strawberry.type
class Mutation:
    @strawberry.mutation
    def scan_url(self, url: str) -> ScanResultType:
        # Trigger URL scan and return
        return ScanResultType(
            scan_id="new-scan-456", filename=url.split("/")[-1], verdict="PENDING", 
            threat_count=0, threats=[], entropy=None, format_detected="unknown"
        )

# --- Schema & Router ---
schema = strawberry.Schema(query=Query, mutation=Mutation)
graphql_router = GraphQLRouter(schema)
