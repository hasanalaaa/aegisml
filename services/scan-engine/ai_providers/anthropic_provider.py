import anthropic
import httpx
from .base import AIProvider, AIAnalysisResult
from .prompt_utils import build_analysis_prompt, parse_ai_json_response


class AnthropicProvider(AIProvider):
    @property
    def name(self) -> str:
        return "anthropic"

    @property
    def available_models(self) -> list[str]:
        return ["claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-haiku-20240307"]

    async def analyze(self, file_info: dict, scan_results: dict, model: str, api_key: str | None) -> AIAnalysisResult:
        if not api_key:
            raise ValueError("Anthropic API key is required")

        prompt = build_analysis_prompt(file_info, scan_results)
        client = anthropic.AsyncAnthropic(api_key=api_key)
        resolved_model = model or "claude-3-5-sonnet-20241022"

        response = await client.messages.create(
            model=resolved_model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        raw_text = "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        )
        return parse_ai_json_response(raw_text, self.name, resolved_model)

    async def validate_key(self, api_key: str) -> bool:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://api.anthropic.com/v1/models",
                    headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"}
                )
                return resp.status_code == 200
        except Exception:
            return False
