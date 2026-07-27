import logging
import os

from .base import AIProvider, AIAnalysisResult
from .circuit_breaker import CircuitBreaker, CircuitOpenError
from .anthropic_provider import AnthropicProvider
from .openai_provider import OpenAIProvider
from .google_provider import GoogleProvider
from .mistral_provider import MistralProvider
from .groq_provider import GroqProvider
from .ollama_provider import OllamaProvider

logger = logging.getLogger("aegisml.ai_providers")

# Environment variables holding system-level API keys, per provider.
# Ollama is local and keyless — it is always "configured" as a last resort.
SYSTEM_KEY_ENV: dict[str, tuple[str, ...]] = {
    "anthropic": ("ANTHROPIC_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
    "google": ("GOOGLE_API_KEY", "GEMINI_API_KEY"),
    "mistral": ("MISTRAL_API_KEY",),
    "groq": ("GROQ_API_KEY",),
    "ollama": (),
}

# Substrings that identify a rate-limit / quota error across provider SDKs.
_RATE_LIMIT_MARKERS = ("rate limit", "rate_limit", "429", "quota", "overloaded", "too many requests")


def _is_rate_limited(exc: Exception) -> bool:
    """Best-effort detection of rate-limit/quota errors across SDKs.

    Checks the HTTP status attribute used by anthropic/openai/groq/mistral
    SDK exceptions first, then falls back to message inspection.
    """
    status = getattr(exc, "status_code", None)
    if status == 429:
        return True
    text = str(exc).lower()
    return any(marker in text for marker in _RATE_LIMIT_MARKERS)


# Substrings that identify an auth/credential error: the provider is healthy,
# the key is not. These must NOT count against the provider's circuit —
# a caller-supplied invalid BYOK key would otherwise trip the breaker and
# blind every other user to a perfectly healthy provider.
_AUTH_MARKERS = ("invalid api key", "invalid x-api-key", "incorrect api key",
                 "invalid_api_key", "authentication", "unauthorized",
                 "permission denied", "permission_denied")


def _is_auth_error(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None)
    if status in (401, 403):
        return True
    text = str(exc).lower()
    return any(marker in text for marker in _AUTH_MARKERS)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        logger.warning("Invalid int in env %s; using default %s", name, default)
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        logger.warning("Invalid float in env %s; using default %s", name, default)
        return default


class AIProviderManager:
    fallback_order = ["anthropic", "openai", "google", "mistral", "groq", "ollama"]

    def __init__(self):
        self.providers: dict[str, AIProvider] = {
            "anthropic": AnthropicProvider(),
            "openai": OpenAIProvider(),
            "google": GoogleProvider(),
            "mistral": MistralProvider(),
            "groq": GroqProvider(),
            "ollama": OllamaProvider(),
        }
        # Phase 2: one circuit breaker per provider. A degraded provider
        # otherwise adds its full HTTP timeout to *every* scan while the
        # fallback chain walks past it; an OPEN breaker is skipped instantly
        # and re-probed only after a cooldown (see circuit_breaker.py).
        failure_threshold = _env_int("AI_CB_FAILURE_THRESHOLD", 5)
        reset_timeout = _env_float("AI_CB_RESET_TIMEOUT_SECONDS", 60.0)
        half_open_max = _env_int("AI_CB_HALF_OPEN_MAX_CALLS", 1)
        self.breakers: dict[str, CircuitBreaker] = {
            name: CircuitBreaker(
                name=f"ai:{name}",
                failure_threshold=failure_threshold,
                reset_timeout=reset_timeout,
                half_open_max_calls=half_open_max,
            )
            for name in self.providers
        }

    @staticmethod
    def _system_key(provider_name: str) -> str | None:
        """Return the configured system API key for a provider, or None."""
        for env_name in SYSTEM_KEY_ENV.get(provider_name, ()):
            value = os.getenv(env_name)
            if value:
                return value
        return None

    def _key_for(self, provider_name: str) -> str | None:
        """Key to use for a provider, or None if the provider is unusable.

        Ollama needs no key; every other provider needs a system key.
        """
        if provider_name == "ollama":
            return None  # keyless, but usable
        return self._system_key(provider_name)

    def _is_configured(self, provider_name: str) -> bool:
        if provider_name == "ollama":
            return True
        return self._system_key(provider_name) is not None

    async def analyze(self, file_info: dict, scan_results: dict,
                      provider: str = "anthropic", model: str | None = None,
                      user_api_key: str | None = None, fallback: bool = True) -> AIAnalysisResult:
        """Run AI analysis with graceful degradation.

        Order of attempts:
          1. The requested provider, with the user's BYOK key if given,
             otherwise with the system key from the environment.
          2. Each remaining provider in fallback_order that actually has a
             configured key (keyless providers are skipped outright instead
             of burning latency on calls guaranteed to fail). Providers whose
             circuit breaker is OPEN are skipped instantly for the same
             reason — no timeout is paid for a provider known to be degraded.
          3. A deterministic static-engine verdict derived from the scanner
             results — never raises, so a scan is never interrupted by a
             missing key or a rate-limited provider.

        The requested model is only forwarded to the requested provider;
        fallback providers pick their own defaults (model names are not
        portable across vendors).
        """
        target_provider = provider if provider in self.providers else "anthropic"

        attempts: list[tuple[str, str | None, str | None]] = []
        primary_key = user_api_key or self._key_for(target_provider)
        if user_api_key or self._is_configured(target_provider):
            attempts.append((target_provider, model, primary_key))

        if fallback:
            for p_name in self.fallback_order:
                if p_name == target_provider:
                    continue
                if not self._is_configured(p_name):
                    logger.debug("Skipping fallback provider %s: no API key configured", p_name)
                    continue
                attempts.append((p_name, None, self._key_for(p_name)))

        last_error: Exception | None = None
        skipped_open: list[str] = []
        for p_name, p_model, p_key in attempts:
            breaker = self.breakers[p_name]
            if not breaker.allow():
                skipped_open.append(p_name)
                logger.warning("AI provider %s circuit is %s; skipping",
                               p_name, breaker.state.value)
                continue
            # Contract: this allow() == True is paired with exactly one
            # record_*() below, so HALF_OPEN trial slots are always returned.
            try:
                result = await self.providers[p_name].analyze(file_info, scan_results, p_model, p_key)
            except Exception as exc:
                if _is_auth_error(exc):
                    # Bad credential (e.g. caller-supplied BYOK key): says
                    # nothing about provider health — return the slot only.
                    breaker.record_neutral()
                else:
                    breaker.record_failure()
                last_error = exc
                if not fallback:
                    raise
                if _is_rate_limited(exc):
                    logger.warning("AI provider %s rate-limited; trying next provider", p_name)
                else:
                    logger.warning("AI provider %s failed (%s); trying next provider",
                                   p_name, type(exc).__name__)
            else:
                breaker.record_success()
                return result

        if not fallback:
            if last_error is not None:
                raise last_error
            if skipped_open:
                raise CircuitOpenError(
                    "circuit open for provider(s): " + ", ".join(skipped_open)
                )

        # Static fallback: no configured/working provider. Degrade gracefully
        # to a rule-based verdict instead of erroring the scan.
        if last_error is None and skipped_open:
            logger.info("All usable AI providers have open circuits (%s); "
                        "using static analysis verdict", ", ".join(skipped_open))
        elif last_error is None:
            logger.info("No AI provider configured; using static analysis verdict")
        else:
            logger.info("All AI providers failed; using static analysis verdict")

        threat_count = scan_results.get("threat_count", 0) or len(scan_results.get("threats", []) or [])
        return AIAnalysisResult(
            verdict="suspicious" if threat_count > 0 else "safe",
            confidence=1.0,
            explanation="AI analysis unavailable (no provider configured or all providers failed). "
                        "Verdict is based solely on static signature analysis.",
            threats=[],
            recommendations=["Manual review recommended",
                             "Configure an AI provider API key for deeper analysis"],
            provider="static-engine",
            model="rule-based",
        )

    def get_available_providers(self) -> list[dict]:
        results = []
        for p_name, provider_inst in self.providers.items():
            results.append({
                "name": p_name,
                "models": provider_inst.available_models,
                "requires_key": p_name != "ollama",
                "configured": self._is_configured(p_name),
                "circuit": self.breakers[p_name].state.value,
                "description": f"Integration with {p_name.capitalize()}"
            })
        return results

    def circuit_snapshots(self) -> list[dict]:
        """Per-provider breaker state, in fallback order (for ops/health)."""
        return [self.breakers[name].snapshot() for name in self.fallback_order]

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

        api_key = os.getenv("ANTHROPIC_API_KEY")
        breaker = self.breakers["anthropic"]
        if api_key and breaker.allow():
            try:
                suggestions = await self._ai_fix_suggestions(findings, file_type, api_key)
            except Exception as exc:
                if _is_auth_error(exc) or isinstance(exc, ValueError):
                    # Bad key, or a healthy response we failed to parse
                    # (json/shape ValueError): not a provider-health signal.
                    breaker.record_neutral()
                else:
                    breaker.record_failure()
                # fall through to rule-based suggestions below
            else:
                breaker.record_success()
                return suggestions

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
