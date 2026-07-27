from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class AIAnalysisResult:
    verdict: str        # safe | suspicious | dangerous | critical
    confidence: float   # 0.0 - 1.0
    explanation: str
    threats: list[dict]
    recommendations: list[str]
    provider: str
    model: str

class AIProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...
    
    @property
    @abstractmethod
    def available_models(self) -> list[str]: ...
    
    @abstractmethod
    async def analyze(self, file_info: dict, scan_results: dict,
                      model: str, api_key: str | None) -> AIAnalysisResult: ...
    
    @abstractmethod
    async def validate_key(self, api_key: str) -> bool: ...
