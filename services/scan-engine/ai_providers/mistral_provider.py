import httpx
import mistralai
from .base import AIProvider, AIAnalysisResult
from .prompt_utils import build_analysis_prompt, parse_ai_json_response


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
        client = mistralai.Mistral(api_key=api_key)
        resolved_model = model or "mistral-large-latest"

        response = await client.chat.complete_async(
            model=resolved_model,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
        )
        raw_text = response.choices[0].message.content or ""
        return parse_ai_json_response(raw_text, self.name, resolved_model)

    async def validate_key(self, api_key: str) -> bool:
        try:
            client = mistralai.Mistral(api_key=api_key)
            await client.models.list_async()
            return True
        except Exception:
            return False
