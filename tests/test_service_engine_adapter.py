"""Contracts for the service adapter over the trusted local scanner."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hashlib
import importlib
import inspect
import os
from pathlib import Path
import pickle
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "services" / "scan-engine"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SERVICE))

from scanner.engine import ScanEngine  # noqa: E402
engine_module = importlib.import_module("scanner.engine")


class _ProgressManager:
    def __init__(self) -> None:
        self.events: list[tuple[int, dict]] = []

    async def send_progress(self, _scan_id: str, payload: dict) -> None:
        self.events.append((threading.get_ident(), payload))


class _RecordingAdmission:
    def __init__(self) -> None:
        self.calls: list[tuple[int, str]] = []

    @asynccontextmanager
    async def admit(self, size: int, scan_id: str):
        self.calls.append((size, scan_id))
        yield "small"


class ServiceEngineAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_adapter_preserves_evidence_schema_and_single_full_byte_read(self) -> None:
        offset = 31
        data = b"A" * offset + b"os.system('id')" + b"B" * 41
        path = self.write("weights.future", data)
        manager = _ProgressManager()
        admission = _RecordingAdmission()
        loop_thread = threading.get_ident()
        actual_os_open = os.open
        opens = 0

        def counted_open(*args, **kwargs):
            nonlocal opens
            opens += 1
            return actual_os_open(*args, **kwargs)

        async def run():
            with (
                patch.object(engine_module, "get_admission_controller", return_value=admission),
                patch("aegisml_scanner.scanner.os.open", side_effect=counted_open),
            ):
                return await ScanEngine().scan(
                    str(path), "adapter-contract", manager_ws=manager, chunk_size=16
                )

        result = asyncio.run(run())

        required = {
            "verdict",
            "threat_count",
            "threats",
            "entropy_analysis",
            "format_detected",
            "highest_cvss",
            "file_hash",
            "patterns_checked",
            "format_specific",
            "coverage",
            "scan_passes",
        }
        self.assertTrue(required.issubset(result), required - set(result))
        self.assertEqual(result["file_hash"], hashlib.sha256(data).hexdigest())
        self.assertTrue(result["coverage"]["complete"])
        self.assertEqual(result["coverage"]["byte_scan"], "full")
        self.assertEqual(result["format_detected"], "generic")
        self.assertEqual(admission.calls, [(len(data), "adapter-contract")])
        self.assertEqual(opens, 1, "generic full-byte evidence must open the file once")

        finding = next(item for item in result["threats"] if item["id"] == "AML.RCE.OS_SYSTEM")
        self.assertEqual(finding["byte_offsets"], [offset])
        self.assertFalse(any(item["id"].startswith("ENT-") for item in result["threats"]))

        self.assertTrue(manager.events)
        self.assertTrue(all(thread_id == loop_thread for thread_id, _ in manager.events))
        self.assertNotIn("complete", [payload["stage"] for _, payload in manager.events])
        self.assertLessEqual(max(payload["progress"] for _, payload in manager.events), 85)
        byte_events = [payload for _, payload in manager.events if "bytes_scanned" in payload]
        self.assertTrue(byte_events, manager.events)
        self.assertEqual(byte_events[-1]["bytes_scanned"], len(data))

    def test_default_chunk_is_eight_mib(self) -> None:
        parameter = inspect.signature(ScanEngine.scan).parameters["chunk_size"]
        self.assertEqual(parameter.default, 8 * 1024 * 1024)

    def test_incomplete_local_coverage_raises_operational_failure(self) -> None:
        path = self.write("bounded.pkl", pickle.dumps({"tensor": [1, 2, 3]}, protocol=4))

        async def run():
            with patch("aegisml_scanner.formats.MAX_PICKLE_BYTES", 1):
                return await ScanEngine().scan(str(path), "incomplete-contract")

        with self.assertRaises(RuntimeError) as caught:
            asyncio.run(run())
        self.assertEqual(type(caught.exception).__name__, "IncompleteScanError")


class ServiceConsumptionPolicyTests(unittest.TestCase):
    def test_main_reuses_engine_hash_and_ai_is_explicit_opt_in(self) -> None:
        source = (SERVICE / "main.py").read_text(encoding="utf-8")
        process = source[source.index("async def _process_scan("):source.index("async def _process_url_scan(")]

        self.assertNotIn('open(temp_path, "rb")', process)
        self.assertNotIn("hashlib.sha256()", process)
        self.assertIn('file_hash = scan_result["file_hash"]', process)
        self.assertLess(process.index("scanner_engine.scan"), process.index("check_hash(file_hash)"))
        self.assertIn("AEGISML_ENABLE_AI_ANALYSIS", process)
        self.assertIn("static_only", process)
        self.assertNotIn('"ai_analysis", 70', process)
        self.assertLess(process.index("await set_cached_scan"), process.rindex('"complete", 100'))

    def test_github_and_api_image_consume_installed_local_engine(self) -> None:
        github = (SERVICE / "integrations" / "github_action.py").read_text(encoding="utf-8")
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

        self.assertNotIn("sha256 = hashlib.sha256()", github)
        self.assertIn('file_hash = scan_result["file_hash"]', github)
        api_stage = dockerfile[dockerfile.index("FROM python:3.11-slim AS api"):]
        self.assertIn("aegisml_scanner", api_stage)


if __name__ == "__main__":
    unittest.main()
