import json
import httpx
from .base import AIProvider, AIAnalysisResult
from .prompt_utils import build_analysis_prompt, parse_ai_json_response

OLLAMA_BASE_URL = "http://127.0.0.1:11434"


class OllamaProvider(AIProvider):
    @property
    def name(self) -> str:
        return "ollama"

    @property
    def available_models(self) -> list[str]:
        return ["llama3", "mistral", "phi3"]

    async def analyze(self, file_info: dict, scan_results: dict, model: str, api_key: str | None) -> AIAnalysisResult:
        # No API key required for local Ollama — it's expected to be running
        # on the same host/network as the scan-engine service.
        prompt = build_analysis_prompt(file_info, scan_results)
        resolved_model = model or "llama3"

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={
                    "model": resolved_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "format": "json",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        raw_text = data.get("message", {}).get("content", "")
        return parse_ai_json_response(raw_text, self.name, resolved_model)

    async def validate_key(self, api_key: str) -> bool:
        # Local Ollama doesn't require a key — ping the local service instead.
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
                return resp.status_code == 200
        except Exception:
            return False
