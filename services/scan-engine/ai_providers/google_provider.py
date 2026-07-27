from urllib.parse import quote

import httpx

from .base import AIProvider, AIAnalysisResult
from .prompt_utils import build_analysis_prompt, parse_ai_json_response


GOOGLE_API_BASE = "https://generativelanguage.googleapis.com/v1beta"


class GoogleProvider(AIProvider):
    @property
    def name(self) -> str:
        return "google"

    @property
    def available_models(self) -> list[str]:
        return ["gemini-1.5-pro", "gemini-1.5-flash"]

    async def analyze(self, file_info: dict, scan_results: dict, model: str, api_key: str | None) -> AIAnalysisResult:
        if not api_key:
            raise ValueError("Google API key is required")

        prompt = build_analysis_prompt(file_info, scan_results)
        resolved_model = (model or "gemini-1.5-pro").removeprefix("models/")
        model_path = quote(resolved_model, safe="")

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{GOOGLE_API_BASE}/models/{model_path}:generateContent",
                headers={"x-goog-api-key": api_key},
                json={
                    "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                    "generationConfig": {"responseMimeType": "application/json"},
                },
            )
            response.raise_for_status()
            data = response.json()

        try:
            parts = data["candidates"][0]["content"]["parts"]
            raw_text = "".join(part.get("text", "") for part in parts)
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("Google response did not contain generated text") from exc
        return parse_ai_json_response(raw_text, self.name, resolved_model)

    async def validate_key(self, api_key: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{GOOGLE_API_BASE}/models",
                    headers={"x-goog-api-key": api_key},
                )
                return resp.status_code == 200
        except Exception:
            return False
