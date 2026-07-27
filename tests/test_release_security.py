"""Release guards for high-impact trust and supply-chain contracts."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


class ReleaseSecurityTests(unittest.TestCase):
    def text(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_scans_are_private_and_not_enumerated_anonymously(self) -> None:
        main = self.text("services/scan-engine/main.py")
        database = self.text("services/scan-engine/database.py")

        self.assertIn("is_public=False", main)
        self.assertIn("mapped_column(Boolean, default=False)", database)
        self.assertNotIn('"filename": s.filename', main)

    def test_byok_never_falls_back_to_plaintext_storage(self) -> None:
        byok = self.text("apps/web/lib/byok.ts")

        self.assertNotIn("setItem(KEYS_STORAGE, json)", byok)
        self.assertNotIn("fall through to plaintext", byok)

    def test_unverified_assurance_claims_are_absent(self) -> None:
        app = self.text("apps/web/components/aegis/AegisApp.tsx").lower()
        forbidden = (
            "absolute certainty",
            "zero-retention",
            "zero retention",
            "soc2",
            "soc 2",
            "cryptographically wiped",
            "يقين مطلق",
            "عدم الاحتفاظ بالبيانات",
            "تُمحى تشفيريًا",
        )
        for claim in forbidden:
            with self.subTest(claim=claim):
                self.assertNotIn(claim, app)

    def test_actions_never_install_the_foreign_aegisml_distribution(self) -> None:
        action_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in ROOT.rglob("*action.y*ml")
            if "node_modules" not in path.parts
        )
        self.assertNotIn("pip install aegisml", action_text)
        self.assertIn('distribution("aegisml-scanner")', self.text("action.yml"))

    def test_migration_bootstrap_contains_no_schema_drop(self) -> None:
        migration = self.text("services/scan-engine/migrations/env.py").upper()
        self.assertNotIn("DROP SCHEMA", migration)

    def test_distribution_identity_cannot_collide_with_foreign_package(self) -> None:
        project = self.text("pyproject.toml")

        self.assertIn('name = "aegisml-scanner"', project)
        self.assertIn('aegisml = "aegisml_scanner.cli:main"', project)
        self.assertFalse((ROOT / "aegisml").exists())

    def test_auth_sync_and_dependency_set_fail_closed(self) -> None:
        auth = self.text("services/scan-engine/auth/router.py")
        requirements = self.text("services/scan-engine/requirements.txt").lower()

        self.assertIn("if not AUTH_SYNC_SECRET", auth)
        self.assertIn("status_code=503", auth)
        self.assertNotIn("from jose", auth)
        self.assertNotIn("python-jose", requirements)
        self.assertNotIn("xhtml2pdf", requirements)

    def test_deployment_has_one_canonical_docker_build(self) -> None:
        railway = json.loads(self.text("railway.json"))

        self.assertEqual(railway["build"]["builder"], "DOCKERFILE")
        self.assertEqual(railway["build"]["dockerfilePath"], "Dockerfile")
        self.assertFalse((ROOT / "railway.toml").exists())
        self.assertFalse((ROOT / "nixpacks.toml").exists())
        self.assertFalse((ROOT / "Procfile").exists())
        self.assertFalse((ROOT / "services/scan-engine/Dockerfile").exists())
        self.assertFalse((ROOT / "k8s").exists())

    def test_example_environment_is_local_and_ai_opt_in(self) -> None:
        example = self.text("services/scan-engine/.env.example")

        self.assertIn("DATABASE_URL=sqlite+aiosqlite:////data/aegisml.db", example)
        self.assertIn("AEGISML_ENABLE_AI_ANALYSIS=false", example)
        self.assertIn("ANTHROPIC_API_KEY=\n", example)
        self.assertNotIn("sk-ant-your-key-here", example)
        self.assertNotIn("ENVIRONMENT=production", example)

    def test_duplicate_service_scanner_cannot_return(self) -> None:
        scanner_dir = ROOT / "services/scan-engine/scanner"
        self.assertEqual(
            {path.name for path in scanner_dir.glob("*.py")},
            {"__init__.py", "admission.py", "engine.py"},
        )

        scanner_init = self.text("services/scan-engine/scanner/__init__.py")
        self.assertIn('__all__ = ["engine", "ScanEngine"]', scanner_init)
        self.assertNotIn("THREAT_PATTERNS", scanner_init)
        self.assertNotIn("calculate_cvss_v3", scanner_init)
        self.assertNotIn(
            "pyahocorasick",
            self.text("services/scan-engine/requirements.txt").lower(),
        )

    def test_nlp_query_uses_public_rules_inventory(self) -> None:
        nlp_query = self.text("services/scan-engine/ai_providers/nlp_query.py")

        self.assertIn("AegisML.rules()", nlp_query)
        self.assertNotIn("scanner.patterns", nlp_query)

    def test_nlp_query_does_not_expose_provider_exception_text(self) -> None:
        secret = "provider-secret-that-must-not-leak"

        class FailingMessages:
            async def create(self, **_kwargs):
                raise RuntimeError(secret)

        class FailingClient:
            def __init__(self, **_kwargs):
                self.messages = FailingMessages()

        fake_anthropic = SimpleNamespace(AsyncAnthropic=FailingClient)
        with (
            patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}),
            patch.dict(sys.modules, {"anthropic": fake_anthropic}),
        ):
            from ai_providers.nlp_query import natural_language_query

            result = asyncio.run(
                natural_language_query(
                    "Can this execute code?",
                    [{"id": "AML.TEST", "name": "Test rule"}],
                )
            )

        self.assertNotIn(secret, result["answer"])

    def test_ci_enforces_dependency_and_static_security_gates(self) -> None:
        workflow = self.text(".github/workflows/ci.yml")

        self.assertIn("pip-audit -r services/scan-engine/requirements.txt", workflow)
        self.assertIn("bandit -q -r aegisml_scanner services/scan-engine", workflow)
        self.assertIn("--select E9,F63,F7,F82", workflow)
        self.assertIn("pnpm audit --prod --audit-level=high", workflow)


if __name__ == "__main__":
    unittest.main()
