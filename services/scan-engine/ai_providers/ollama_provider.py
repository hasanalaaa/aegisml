from typing import Dict, Any
import json
import logging
import httpx
from .base import AIProvider, AIAnalysisResult

logger = logging.getLogger("aegisml.ai.ollama")

PROMPT_TEMPLATE = """You are AegisML's expert AI security analyst specializing in AI model security.

SCAN DATA:
- File: {filename}
- File Size: {file_size} bytes
- Risk Score: {risk_score}/100
- Risk Level: {risk_level}
- Threats Found: {threat_count}
- Threat Details:
{threat_summary}

Respond ONLY with valid JSON (no markdown):
{{
  "verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "CRITICAL",
  "confidence": <integer 0-100>,
  "summary_en": "<3-4 sentences in English>",
  "summary_ar": "<3-4 جمل بالعربية>",
  "key_risks": ["<risk 1>", "<risk 2>", "<risk 3>"],
  "recommendation": "<actionable steps in English>",
  "recommendation_ar": "<خطوات محددة بالعربية>",
  "technical_details": "<brief technical explanation>"
}}"""

class OllamaProvider(AIProvider):
    def __init__(self, api_key: str, model: str = "llama3"):
        super().__init__(api_key, model)
        self.base_url = api_key if api_key.startswith("http") else "http://localhost:11434"

    async def analyze(self, scan_data: Dict[str, Any]) -> AIAnalysisResult:
        try:
            threat_list = scan_data.get("threats", [])[:50]
            threat_summary = json.dumps(threat_list, indent=2, ensure_ascii=False)
            
            prompt = PROMPT_TEMPLATE.format(
                filename=scan_data.get('filename', 'unknown'),
                file_size=scan_data.get('metadata', {}).get('file_size', 0),
                risk_score=scan_data.get('risk_score', 0),
                risk_level=scan_data.get('risk_level', 'unknown'),
                threat_count=len(scan_data.get('threats', [])),
                threat_summary=threat_summary
            )
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json"
                    },
                    timeout=120.0
                )
                response.raise_for_status()
                data = response.json()
            
            raw_text = data.get("response", "{}")
            result_data = json.loads(raw_text)
            
            return AIAnalysisResult(
                verdict=result_data.get("verdict", "SUSPICIOUS"),
                confidence=result_data.get("confidence", 50),
                summary_en=result_data.get("summary_en", ""),
                summary_ar=result_data.get("summary_ar", ""),
                key_risks=result_data.get("key_risks", []),
                recommendation=result_data.get("recommendation", ""),
                recommendation_ar=result_data.get("recommendation_ar", ""),
                technical_details=result_data.get("technical_details", ""),
                provider="ollama",
                model=self.model
            )
        except Exception as e:
            logger.error(f"Ollama analysis failed: {e}")
            raise e

    async def validate_key(self) -> bool:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.base_url}/api/tags", timeout=5.0)
                return response.status_code == 200
        except Exception:
            return False
