from .base import AIProvider, AIAnalysisResult
from .anthropic_provider import AnthropicProvider
from .openai_provider import OpenAIProvider
from .google_provider import GoogleProvider
from .mistral_provider import MistralProvider
from .groq_provider import GroqProvider
from .ollama_provider import OllamaProvider

class AIProviderManager:
    fallback_order = ["anthropic", "openai", "google", "mistral", "groq", "ollama"]

    def __init__(self):
        self.providers: dict[str, AIProvider] = {
            "anthropic": AnthropicProvider(),
            "openai": OpenAIProvider(),
            "google": GoogleProvider(),
            "mistral": MistralProvider(),
            "groq": GroqProvider(),
            "ollama": OllamaProvider()
        }

    async def analyze(self, file_info: dict, scan_results: dict,
                      provider: str = "anthropic", model: str | None = None,
                      user_api_key: str | None = None, fallback: bool = True) -> AIAnalysisResult:
        
        target_provider = provider if provider in self.providers else "anthropic"
        
        # Try requested provider first
        try:
            return await self.providers[target_provider].analyze(file_info, scan_results, model, user_api_key)
        except Exception as e:
            if not fallback:
                raise e
            
            # Fallback logic
            for p_name in self.fallback_order:
                if p_name == target_provider:
                    continue
                # In a real scenario, we would retrieve system API keys from env or DB here
                # if user_api_key was not provided for the fallback provider.
                # For this mock implementation, we just attempt it:
                try:
                    return await self.providers[p_name].analyze(file_info, scan_results, None, "system_fallback_key")
                except Exception:
                    continue
            
            # If all fail -> return basic rule-based analysis (no AI)
            return AIAnalysisResult(
                verdict="suspicious" if scan_results.get("threat_count", 0) > 0 else "safe",
                confidence=1.0,
                explanation="AI Analysis unavailable. Results based solely on static signatures.",
                threats=[],
                recommendations=["Manual review recommended"],
                provider="static-engine",
                model="rule-based"
            )

    def get_available_providers(self) -> list[dict]:
        results = []
        for p_name, provider_inst in self.providers.items():
            results.append({
                "name": p_name,
                "models": provider_inst.available_models,
                "requires_key": p_name != "ollama",
                "description": f"Integration with {p_name.capitalize()}"
            })
        return results

    async def validate_key(self, provider: str, api_key: str) -> bool:
        if provider not in self.providers:
            return False
        return await self.providers[provider].validate_key(api_key)

    async def get_fix_suggestions(self, findings: list[dict], file_type: str) -> list[dict]:
        """Ask Claude for real, finding-specific remediation guidance. Falls
        back to a transparent rule-based suggestion (clearly not claiming to
        be AI-generated) if no system API key is configured or the call
        fails, rather than silently returning the same canned text either
        way."""
        if not findings:
            return []

        import os
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if api_key:
            try:
                return await self._ai_fix_suggestions(findings, file_type, api_key)
            except Exception:
                pass  # fall through to rule-based suggestions below

        return self._rule_based_fix_suggestions(findings, file_type)

    async def _ai_fix_suggestions(self, findings: list[dict], file_type: str, api_key: str) -> list[dict]:
        import json
        import re
        import anthropic as anthropic_sdk

        findings_block = "\n".join(
            f"- id={f.get('id')} name=\"{f.get('name', f.get('pattern', '?'))}\" "
            f"severity={f.get('severity')} category={f.get('category')}: {f.get('description', '')}"
            for f in findings[:20]
        )
        prompt = (
            f"You are a security engineer giving remediation advice for an AI "
            f"model file of type '{file_type}' with these scanner findings:\n"
            f"{findings_block}\n\n"
            "For each finding, give ONE concrete fix. Respond with ONLY a JSON "
            'array, each item: {"finding_id": "<id>", "title": "<short title>", '
            '"explanation": "<2-3 sentences>", "code_snippet": "<short code '
            'example, or empty string if not applicable>"}'
        )

        client = anthropic_sdk.AsyncAnthropic(api_key=api_key)
        response = await client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}],
        )
        raw_text = "".join(b.text for b in response.content if getattr(b, "type", None) == "text")

        fence_match = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", raw_text, re.DOTALL)
        json_text = fence_match.group(1) if fence_match else raw_text
        bracket_match = re.search(r"\[.*\]", json_text, re.DOTALL)
        if bracket_match:
            json_text = bracket_match.group(0)

        suggestions = json.loads(json_text)
        if not isinstance(suggestions, list):
            raise ValueError("AI did not return a JSON array")
        return suggestions

    def _rule_based_fix_suggestions(self, findings: list[dict], file_type: str) -> list[dict]:
        """Deterministic, non-AI fallback. Clearly distinguishable from the
        AI path via the absence of nuanced per-finding reasoning."""
        suggestions = []
        for finding in findings:
            category = str(finding.get("category", "")).lower()
            if "code_execution" in category or "pickle" in str(finding.get("pattern", "")).lower():
                suggestions.append({
                    "finding_id": finding.get("id"),
                    "title": "Migrate from Pickle to SafeTensors",
                    "explanation": "Pickle is inherently unsafe. An attacker can construct a payload that executes arbitrary code upon unpickling. You should convert these weights.",
                    "code_snippet": "import torch\nfrom safetensors.torch import save_file\n\n# Instead of torch.save(model.state_dict(), 'model.pkl')\nsave_file(model.state_dict(), 'model.safetensors')"
                })
            else:
                suggestions.append({
                    "finding_id": finding.get("id"),
                    "title": "Review and Quarantine",
                    "explanation": f"The detected pattern ({finding.get('name', finding.get('pattern', 'unknown'))}) requires manual review. Configure ANTHROPIC_API_KEY for AI-generated, finding-specific remediation steps.",
                    "code_snippet": ""
                })
        return suggestions

manager = AIProviderManager()
