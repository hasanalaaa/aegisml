"""Black-box command contract for the installed ``aegisml`` CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT)
        environment.pop("AEGISML_API_URL", None)
        return subprocess.run(
            [sys.executable, "-m", "aegisml_scanner", *arguments],
            cwd=self.root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_json_stdout_is_machine_readable(self) -> None:
        path = self.root / "clean.custom"
        path.write_bytes(b"tensor bytes")

        completed = self.run_cli("scan", str(path), "--format", "json", "--chunk-size", "64")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["verdict"], "SAFE")
        self.assertEqual(payload["metadata"]["bytes_scanned"], len(b"tensor bytes"))
        self.assertNotIn("Scanning", completed.stdout)

    def test_missing_input_is_operational_exit_two(self) -> None:
        completed = self.run_cli("scan", "missing.gguf", "--format", "json")

        self.assertEqual(completed.returncode, 2)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["error"]["code"], "scan_error")
        self.assertNotIn("Traceback", completed.stderr)

    def test_critical_policy_exit_one_and_never_can_disable_policy(self) -> None:
        path = self.root / "evil.bin"
        path.write_bytes(b"prefix os.system('id') suffix")

        blocked = self.run_cli("scan", str(path), "--format", "json")
        allowed = self.run_cli(
            "scan", str(path), "--format", "json", "--fail-on", "never"
        )

        self.assertEqual(blocked.returncode, 1)
        self.assertEqual(allowed.returncode, 0)
        self.assertEqual(json.loads(allowed.stdout)["verdict"], "CRITICAL")

    def test_empty_directory_is_operational_failure_not_a_false_pass(self) -> None:
        completed = self.run_cli("scan", str(self.root), "--format", "json")

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("no regular files", json.loads(completed.stdout)["error"]["message"])

    def test_doctor_json_is_offline_ready_and_names_distribution(self) -> None:
        completed = self.run_cli("doctor", "--json")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["offline_ready"])
        self.assertEqual(payload["distribution"], "aegisml-scanner")
        self.assertEqual(payload["command"], "aegisml")


if __name__ == "__main__":
    unittest.main()
