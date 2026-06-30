import httpx
import groq
from .base import AIProvider, AIAnalysisResult
from .prompt_utils import build_analysis_prompt, parse_ai_json_response


class GroqProvider(AIProvider):
    @property
    def name(self) -> str:
        return "groq"

    @property
    def available_models(self) -> list[str]:
        return ["llama3-70b-8192", "llama3-8b-8192", "mixtral-8x7b-32768"]

    async def analyze(self, file_info: dict, scan_results: dict, model: str, api_key: str | None) -> AIAnalysisResult:
        if not api_key:
            raise ValueError("Groq API key is required")

        prompt = build_analysis_prompt(file_info, scan_results)
        client = groq.AsyncGroq(api_key=api_key)
        resolved_model = model or "llama3-70b-8192"

        try:
            completion = await client.chat.completions.create(
                model=resolved_model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                max_tokens=1024,
            )
        except groq.BadRequestError:
            # Not every Groq-hosted model supports JSON mode
            completion = await client.chat.completions.create(
                model=resolved_model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024,
            )

        raw_text = completion.choices[0].message.content or ""
        return parse_ai_json_response(raw_text, self.name, resolved_model)

    async def validate_key(self, api_key: str) -> bool:
        try:
            client = groq.AsyncGroq(api_key=api_key)
            await client.models.list()
            return True
        except Exception:
            return False
