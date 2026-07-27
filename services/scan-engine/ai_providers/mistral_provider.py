import httpx

from .base import AIProvider, AIAnalysisResult
from .prompt_utils import build_analysis_prompt, parse_ai_json_response


MISTRAL_API_BASE = "https://api.mistral.ai/v1"


class MistralProvider(AIProvider):
    @property
    def name(self) -> str:
        return "mistral"

    @property
    def available_models(self) -> list[str]:
        return ["mistral-large-latest", "mistral-small-latest", "open-mistral-nemo"]

    async def analyze(self, file_info: dict, scan_results: dict, model: str, api_key: str | None) -> AIAnalysisResult:
        if not api_key:
            raise ValueError("Mistral API key is required")

        prompt = build_analysis_prompt(file_info, scan_results)
        resolved_model = model or "mistral-large-latest"

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{MISTRAL_API_BASE}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": resolved_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "response_format": {"type": "json_object"},
                    "max_tokens": 1024,
                },
            )
            response.raise_for_status()
            data = response.json()

        try:
            raw_text = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("Mistral response did not contain generated text") from exc
        if not isinstance(raw_text, str):
            raise ValueError("Mistral response content was not text")
        return parse_ai_json_response(raw_text, self.name, resolved_model)

    async def validate_key(self, api_key: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{MISTRAL_API_BASE}/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                return response.status_code == 200
        except Exception:
            return False
