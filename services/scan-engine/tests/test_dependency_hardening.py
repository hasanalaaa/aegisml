"""Regression contracts for the dependency-hardening pass.

These tests intentionally use only the Python standard library so dependency
policy and the fail-closed primitives remain testable in a minimal checkout.
"""

from __future__ import annotations

import csv
from datetime import date, datetime, timezone
import importlib.util
import io
from pathlib import Path
import unittest


ENGINE = Path(__file__).resolve().parents[1]


def _load_module(name: str, relative_path: str):
    path = ENGINE / relative_path
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load module: {relative_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DependencyPolicyTests(unittest.TestCase):
    def test_security_pins_and_removed_dependencies(self) -> None:
        requirements = (ENGINE / "requirements.txt").read_text(encoding="utf-8").splitlines()
        pins = dict(
            line.split("==", 1)
            for line in requirements
            if line and not line.startswith("#") and "==" in line
        )

        self.assertEqual(pins["fastapi"], "0.140.0")
        self.assertEqual(pins["python-multipart"], "0.0.32")
        self.assertEqual(pins["PyJWT"], "2.13.0")
        self.assertEqual(pins["python-dotenv"], "1.2.2")
        self.assertEqual(pins["pydantic"], "2.9.0")
        for removed in (
            "python-jose[cryptography]",
            "pandas",
            "xhtml2pdf",
            "Jinja2",
            "google-generativeai",
            "mistralai",
            "passlib[bcrypt]",
            "cryptography",
            "pydantic-settings",
            "pytz",
            "discord.py",
            "slack-bolt",
        ):
            self.assertNotIn(removed, pins)

    def test_service_code_no_longer_imports_removed_libraries(self) -> None:
        files = (
            ENGINE / "auth" / "utils.py",
            ENGINE / "auth" / "router.py",
            ENGINE / "routers" / "analytics.py",
            ENGINE / "research" / "router.py",
            ENGINE / "ai_providers" / "google_provider.py",
            ENGINE / "ai_providers" / "mistral_provider.py",
        )
        source = "\n".join(path.read_text(encoding="utf-8") for path in files)
        for forbidden in (
            "from jose",
            "import pandas",
            "xhtml2pdf",
            "from jinja2",
            "import google.generativeai",
            "import mistralai",
        ):
            self.assertNotIn(forbidden, source)

    def test_pdf_and_parquet_surfaces_are_removed(self) -> None:
        analytics = (ENGINE / "routers" / "analytics.py").read_text(encoding="utf-8")
        research = (ENGINE / "research" / "router.py").read_text(encoding="utf-8")

        self.assertNotIn('@router.post("/report/{scan_id}")', analytics)
        self.assertNotIn("parquet", research.lower())

    def test_optional_redis_does_not_make_local_api_unhealthy(self) -> None:
        main = (ENGINE / "main.py").read_text(encoding="utf-8")

        self.assertIn('status = "healthy" if db_ok else "unhealthy"', main)
        self.assertIn('"database": DATABASE_BACKEND', main)
        self.assertIn('"queue": "enabled" if redis_ok else "inline-only"', main)

    def test_model_url_schemas_do_not_emit_pydantic_namespace_warnings(self) -> None:
        for relative_path in ("community/router.py", "integrations/router.py"):
            source = (ENGINE / relative_path).read_text(encoding="utf-8")
            self.assertIn("protected_namespaces=()", source)

    def test_nonfunctional_mock_surfaces_are_not_shipped(self) -> None:
        main = (ENGINE / "main.py").read_text(encoding="utf-8")
        analytics = (ENGINE / "routers" / "analytics.py").read_text(encoding="utf-8")

        self.assertFalse((ENGINE / "webhooks.py").exists())
        for filename in ("monitor.py", "notifications.py", "router.py", "scheduler.py"):
            self.assertFalse((ENGINE / "hf_monitor" / filename).exists())
        self.assertNotIn("hf_monitor", main)
        self.assertNotIn("San Francisco", analytics)
        self.assertIn('"points": []', analytics)

    def test_openapi_routes_have_one_threat_patterns_owner(self) -> None:
        main = (ENGINE / "main.py").read_text(encoding="utf-8")
        threat_router = (ENGINE / "routers" / "threat_intel.py").read_text(
            encoding="utf-8"
        )

        self.assertEqual(
            (main + threat_router).count('@app.get("/api/v1/threats/patterns")')
            + (main + threat_router).count('@router.get("/threats/patterns")'),
            1,
        )


class SyncSecretTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.security = _load_module("sync_security", "auth/sync_security.py")

    def test_missing_configuration_fails_closed(self) -> None:
        self.assertIsNotNone(self.security, "auth/sync_security.py is missing")
        with self.assertRaises(self.security.SyncSecretUnavailable):
            self.security.verify_sync_secret("", None)

    def test_missing_or_wrong_header_is_rejected(self) -> None:
        self.assertIsNotNone(self.security, "auth/sync_security.py is missing")
        with self.assertRaises(self.security.InvalidSyncSecret):
            self.security.verify_sync_secret("configured", None)
        with self.assertRaises(self.security.InvalidSyncSecret):
            self.security.verify_sync_secret("configured", "wrong")

    def test_matching_header_is_accepted(self) -> None:
        self.assertIsNotNone(self.security, "auth/sync_security.py is missing")
        self.assertIsNone(self.security.verify_sync_secret("configured", "configured"))

    def test_router_maps_unconfigured_secret_to_503(self) -> None:
        router = (ENGINE / "auth" / "router.py").read_text(encoding="utf-8")
        self.assertIn("except SyncSecretUnavailable", router)
        self.assertIn("status_code=503", router)


class ExportUtilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.exports = _load_module("export_utils", "export_utils.py")

    def test_csv_preserves_commas_newlines_and_column_order(self) -> None:
        self.assertIsNotNone(self.exports, "export_utils.py is missing")
        text = self.exports.render_csv(
            ["filename", "description"],
            [{"description": "line one\nline two", "filename": "model,one"}],
        )

        rows = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual(rows, [{"filename": "model,one", "description": "line one\nline two"}])
        self.assertEqual(text.splitlines()[0], "filename,description")

    def test_daily_trends_fills_missing_dates(self) -> None:
        self.assertIsNotNone(self.exports, "export_utils.py is missing")
        records = [
            (datetime(2026, 7, 24, 8, tzinfo=timezone.utc), "clean"),
            (datetime(2026, 7, 24, 9, tzinfo=timezone.utc), "suspicious"),
            (datetime(2026, 7, 26, 10, tzinfo=timezone.utc), "critical"),
            (datetime(2026, 7, 26, 11, tzinfo=timezone.utc), "malicious"),
        ]

        self.assertEqual(
            self.exports.daily_trends(records, date(2026, 7, 24), date(2026, 7, 26)),
            [
                {"date": "2026-07-24", "safe": 2, "threats": 0},
                {"date": "2026-07-25", "safe": 0, "threats": 0},
                {"date": "2026-07-26", "safe": 0, "threats": 2},
            ],
        )


if __name__ == "__main__":
    unittest.main()
