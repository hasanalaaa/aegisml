from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod

@dataclass
class AIAnalysisResult:
    verdict: str  # "SAFE", "SUSPICIOUS", "DANGEROUS", "CRITICAL"
    confidence: int  # 0 to 100
    summary_en: str
    summary_ar: str
    key_risks: List[str] = field(default_factory=list)
    recommendation: str = ""
    recommendation_ar: str = ""
    technical_details: str = ""
    provider: str = ""
    model: str = ""

class AIProvider(ABC):
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model

    @abstractmethod
    async def analyze(self, scan_data: Dict[str, Any]) -> AIAnalysisResult:
        """Analyze the static scan results and return an AI verdict."""
        pass

    @abstractmethod
    async def validate_key(self) -> bool:
        """Validate if the provided API key is functional."""
        pass
