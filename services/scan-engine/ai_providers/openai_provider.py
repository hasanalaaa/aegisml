from typing import Dict, Any
import json
import logging
from openai import AsyncOpenAI
from .base import AIProvider, AIAnalysisResult

logger = logging.getLogger("aegisml.ai.openai")

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

class OpenAIProvider(AIProvider):
    def __init__(self, api_key: str, model: str = "gpt-4o"):
        super().__init__(api_key, model)
        self.client = AsyncOpenAI(api_key=api_key)

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

            response = await self.client.chat.completions.create(
                model=self.model,
                response_format={ "type": "json_object" },
                temperature=0.0,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert. Output valid JSON only."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            raw_text = response.choices[0].message.content or "{}"
            data = json.loads(raw_text)
            
            return AIAnalysisResult(
                verdict=data.get("verdict", "SUSPICIOUS"),
                confidence=data.get("confidence", 50),
                summary_en=data.get("summary_en", ""),
                summary_ar=data.get("summary_ar", ""),
                key_risks=data.get("key_risks", []),
                recommendation=data.get("recommendation", ""),
                recommendation_ar=data.get("recommendation_ar", ""),
                technical_details=data.get("technical_details", ""),
                provider="openai",
                model=self.model
            )
        except Exception as e:
            logger.error(f"OpenAI analysis failed: {e}")
            raise e

    async def validate_key(self) -> bool:
        try:
            await self.client.models.list()
            return True
        except Exception:
            return False
