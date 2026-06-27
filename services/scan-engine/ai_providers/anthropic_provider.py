from typing import Dict, Any
import json
import logging
from anthropic import AsyncAnthropic
from .base import AIProvider, AIAnalysisResult

logger = logging.getLogger("aegisml.ai.anthropic")

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

class AnthropicProvider(AIProvider):
    def __init__(self, api_key: str, model: str = "claude-3-5-sonnet-20240620"):
        super().__init__(api_key, model)
        self.client = AsyncAnthropic(api_key=api_key)

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

            response = await self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                temperature=0.0,
                messages=[{"role": "user", "content": prompt}]
            )
            
            raw_text = response.content[0].text
            if "```json" in raw_text:
                raw_text = raw_text.split("```json")[1].split("```")[0].strip()
            elif "```" in raw_text:
                raw_text = raw_text.split("```")[1].strip()
                
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
                provider="anthropic",
                model=self.model
            )
        except Exception as e:
            logger.error(f"Anthropic analysis failed: {e}")
            raise e

    async def validate_key(self) -> bool:
        try:
            await self.client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=1,
                messages=[{"role": "user", "content": "hello"}]
            )
            return True
        except Exception:
            return False
