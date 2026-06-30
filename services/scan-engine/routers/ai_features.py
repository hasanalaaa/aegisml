from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional
from ai_providers.manager import manager
from ai_providers.nlp_query import natural_language_query

router = APIRouter(tags=["AI Features"])

class FixSuggestionRequest(BaseModel):
    scan_id: str
    findings: List[dict]
    file_type: str

class NLPQueryRequest(BaseModel):
    question: str
    patterns: Optional[List[dict]] = None

@router.post("/api/v1/ai/fix-suggestions")
async def get_fix_suggestions(req: FixSuggestionRequest):
    suggestions = await manager.get_fix_suggestions(req.findings, req.file_type)
    return {"scan_id": req.scan_id, "suggestions": suggestions}

@router.post("/api/v1/threats/query")
async def query_threats(req: NLPQueryRequest):
    result = await natural_language_query(req.question, req.patterns)
    return result
