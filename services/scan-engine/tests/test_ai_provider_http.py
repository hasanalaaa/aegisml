"""Contract tests for SDK-free Google and Mistral provider adapters."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest
from unittest.mock import patch


ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))

from ai_providers.google_provider import GoogleProvider  # noqa: E402
from ai_providers.mistral_provider import MistralProvider  # noqa: E402


AI_RESPONSE = {
    "verdict": "safe",
    "confidence": 97,
    "explanation": "No actionable threat was found.",
    "recommendations": ["Keep signatures current."],
}


class _Response:
    def __init__(self, payload: dict, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        return None


class _Client:
    def __init__(self, response: _Response):
        self.response = response
        self.requests: list[tuple[str, str, dict]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def post(self, url: str, **kwargs):
        self.requests.append(("POST", url, kwargs))
        return self.response


class ProviderHttpTests(unittest.IsolatedAsyncioTestCase):
    async def test_google_analyze_uses_authenticated_json_rest_request(self) -> None:
        response = _Response(
            {"candidates": [{"content": {"parts": [{"text": _json_text()}]}}]}
        )
        client = _Client(response)

        with patch("ai_providers.google_provider.httpx.AsyncClient", return_value=client):
            result = await GoogleProvider().analyze(
                {"filename": "model.bin", "size": 10},
                {"threats": [], "verdict": "safe"},
                "gemini-1.5-flash",
                "google-secret",
            )

        method, url, request = client.requests[0]
        self.assertEqual(method, "POST")
        self.assertEqual(
            url,
            "https://generativelanguage.googleapis.com/v1beta/models/"
            "gemini-1.5-flash:generateContent",
        )
        self.assertEqual(request["headers"], {"x-goog-api-key": "google-secret"})
        self.assertEqual(
            request["json"]["generationConfig"],
            {"responseMimeType": "application/json"},
        )
        self.assertEqual(result.provider, "google")
        self.assertEqual(result.verdict, "safe")

    async def test_mistral_analyze_uses_authenticated_json_rest_request(self) -> None:
        response = _Response(
            {"choices": [{"message": {"content": _json_text()}}]}
        )
        client = _Client(response)

        with patch("ai_providers.mistral_provider.httpx.AsyncClient", return_value=client):
            result = await MistralProvider().analyze(
                {"filename": "model.bin", "size": 10},
                {"threats": [], "verdict": "safe"},
                "mistral-small-latest",
                "mistral-secret",
            )

        method, url, request = client.requests[0]
        self.assertEqual(method, "POST")
        self.assertEqual(url, "https://api.mistral.ai/v1/chat/completions")
        self.assertEqual(
            request["headers"],
            {"Authorization": "Bearer mistral-secret"},
        )
        self.assertEqual(request["json"]["response_format"], {"type": "json_object"})
        self.assertEqual(result.provider, "mistral")
        self.assertEqual(result.verdict, "safe")


def _json_text() -> str:
    import json

    return json.dumps(AI_RESPONSE)


if __name__ == "__main__":
    unittest.main()
