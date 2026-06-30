import httpx
import google.generativeai as genai
from .base import AIProvider, AIAnalysisResult
from .prompt_utils import build_analysis_prompt, parse_ai_json_response


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
        resolved_model = model or "gemini-1.5-pro"

        genai.configure(api_key=api_key)
        model_obj = genai.GenerativeModel(
            resolved_model,
            generation_config={"response_mime_type": "application/json"},
        )
        response = await model_obj.generate_content_async(prompt)
        raw_text = response.text or ""
        return parse_ai_json_response(raw_text, self.name, resolved_model)

    async def validate_key(self, api_key: str) -> bool:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}")
                return resp.status_code == 200
        except Exception:
            return False
