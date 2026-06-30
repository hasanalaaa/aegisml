import httpx
import openai
from .base import AIProvider, AIAnalysisResult
from .prompt_utils import build_analysis_prompt, parse_ai_json_response


class OpenAIProvider(AIProvider):
    @property
    def name(self) -> str:
        return "openai"

    @property
    def available_models(self) -> list[str]:
        return ["gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"]

    async def analyze(self, file_info: dict, scan_results: dict, model: str, api_key: str | None) -> AIAnalysisResult:
        if not api_key:
            raise ValueError("OpenAI API key is required")

        prompt = build_analysis_prompt(file_info, scan_results)
        client = openai.AsyncOpenAI(api_key=api_key)
        resolved_model = model or "gpt-4o"

        # JSON mode is supported on gpt-4o / gpt-4-turbo / gpt-3.5-turbo-1106+;
        # older snapshots ignore response_format gracefully rather than erroring.
        try:
            completion = await client.chat.completions.create(
                model=resolved_model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                max_tokens=1024,
            )
        except openai.BadRequestError:
            # Fallback for models that reject response_format
            completion = await client.chat.completions.create(
                model=resolved_model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024,
            )

        raw_text = completion.choices[0].message.content or ""
        return parse_ai_json_response(raw_text, self.name, resolved_model)

    async def validate_key(self, api_key: str) -> bool:
        try:
            client = openai.AsyncOpenAI(api_key=api_key)
            await client.models.list()
            return True
        except Exception:
            return False
