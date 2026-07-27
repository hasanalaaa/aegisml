"""Regression tests for the offline, resource-bounded scanner."""

from __future__ import annotations

import hashlib
import os
import pickle
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from aegisml_scanner.scanner import AegisML


class _EvilPickle:
    def __reduce__(self):
        return (os.system, ("echo never-execute",))


class LocalScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    @staticmethod
    def threat(result, rule_id: str):
        return next((item for item in result.threats if item.id == rule_id), None)

    def test_scans_beyond_legacy_ten_megabyte_limit(self) -> None:
        prefix = b"\x00" * (10 * 1024 * 1024 + 17)
        payload = b"os.system('id')"
        path = self.write("late.custom", prefix + payload)

        result = AegisML(api_url="", chunk_size=64 * 1024).scan(path)

        finding = self.threat(result, "AML.RCE.OS_SYSTEM")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.byte_offsets, [len(prefix)])
        self.assertEqual(result.metadata["coverage"]["byte_scan"], "full")
        self.assertEqual(result.metadata["bytes_scanned"], path.stat().st_size)

    def test_finds_signature_spanning_chunk_boundary(self) -> None:
        pattern = b"os.system"
        offset = 13
        path = self.write("boundary.bin", b"A" * offset + pattern + b"B" * 31)

        result = AegisML(api_url="", chunk_size=16).scan(path)

        finding = self.threat(result, "AML.RCE.OS_SYSTEM")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.byte_offsets, [offset])
        self.assertEqual(finding.occurrences, 1)

    def test_unknown_extension_receives_generic_full_scan(self) -> None:
        path = self.write("weights.futureformat", b"harmless model bytes")

        result = AegisML(api_url="", chunk_size=7).scan(path)

        self.assertTrue(result.is_safe)
        self.assertEqual(result.metadata["format_detected"], "generic")
        self.assertTrue(result.metadata["coverage"]["complete"])

    def test_environment_cannot_silently_enable_network_or_ai(self) -> None:
        with patch.dict(
            os.environ,
            {
                "AEGISML_API_URL": "https://unexpected.invalid",
                "ANTHROPIC_API_KEY": "secret-that-must-not-be-used",
            },
        ):
            scanner = AegisML()

        self.assertEqual(scanner.api_url, "")
        self.assertEqual(scanner.anthropic_api_key, "")

    def test_disguised_executable_is_critical(self) -> None:
        path = self.write("weights.safetensors", b"\x7fELF" + b"\x00" * 64)

        result = AegisML(api_url="", chunk_size=32).scan(path)

        finding = self.threat(result, "AML.FORMAT.DISGUISED_EXECUTABLE")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(result.verdict, "CRITICAL")

    def test_report_does_not_leak_the_local_absolute_path(self) -> None:
        path = self.write("private-location.bin", b"os.system('id')")

        result = AegisML(api_url="").scan(path)

        self.assertTrue(result.threats)
        self.assertTrue(all(item.location == path.name for item in result.threats))
        self.assertNotIn(str(self.root), result.to_json())

    def test_evidence_contains_full_sha256_and_ruleset_identity(self) -> None:
        data = (b"tensor" * 1000) + b"\x00\xff"
        path = self.write("model.bin", data)

        result = AegisML(api_url="", chunk_size=127).scan(path)

        self.assertEqual(result.metadata["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result.metadata["total_bytes"], len(data))
        self.assertEqual(result.metadata["bytes_scanned"], len(data))
        self.assertRegex(result.metadata["ruleset_version"], r"^\d{4}\.\d{2}")
        self.assertGreaterEqual(result.metadata["entropy"], 0.0)
        self.assertLessEqual(result.metadata["entropy"], 8.0)

    def test_same_size_mutation_during_scan_fails_closed(self) -> None:
        path = self.write("moving.bin", b"A" * 256)
        changed = False

        def mutate_after_first_chunk(scanned: int, _total: int) -> None:
            nonlocal changed
            if changed or scanned < 64:
                return
            changed = True
            with path.open("r+b") as stream:
                stream.seek(192)
                stream.write(b"B")

        result = AegisML(
            api_url="", chunk_size=64, progress=mutate_after_first_chunk
        ).scan(path)

        self.assertIn("file_changed_during_scan", result.metadata["errors"])
        self.assertFalse(result.metadata["coverage"]["complete"])
        self.assertEqual(result.metadata["coverage"]["byte_scan"], "incomplete")

    def test_format_cap_does_not_falsely_downgrade_full_byte_evidence(self) -> None:
        path = self.write("large.pkl", pickle.dumps({"payload": "A" * 128}, protocol=4))

        with patch("aegisml_scanner.formats.MAX_PICKLE_BYTES", 16):
            result = AegisML(api_url="", chunk_size=11).scan(path)

        self.assertFalse(result.metadata["coverage"]["complete"])
        self.assertEqual(result.metadata["coverage"]["byte_scan"], "full")
        self.assertEqual(result.metadata["coverage"]["sha256"], "full")
        self.assertEqual(result.metadata["coverage"]["format_specific"], "capped")

    def test_empty_file_is_scanned_completely(self) -> None:
        result = AegisML(api_url="", chunk_size=64).scan(self.write("empty.bin", b""))

        self.assertTrue(result.is_safe)
        self.assertEqual(result.metadata["bytes_scanned"], 0)
        self.assertTrue(result.metadata["coverage"]["complete"])

    def safetensors(self, offsets: list[int], data: bytes = b"\x00" * 4) -> bytes:
        header = json_bytes(
            {
                "weight": {
                    "dtype": "F32",
                    "shape": [1],
                    "data_offsets": offsets,
                }
            }
        )
        return struct.pack("<Q", len(header)) + header + data

    def test_valid_safetensors_header_has_complete_format_coverage(self) -> None:
        result = AegisML(api_url="", chunk_size=11).scan(
            self.write("valid.safetensors", self.safetensors([0, 4]))
        )

        self.assertEqual(result.metadata["format_detected"], "safetensors")
        self.assertEqual(result.metadata["coverage"]["format_specific"], "complete")
        self.assertEqual(result.metadata["format"]["tensor_count"], 1)
        self.assertFalse(any(t.category == "format_anomaly" for t in result.threats))

    def test_safetensors_out_of_bounds_offset_is_critical(self) -> None:
        result = AegisML(api_url="").scan(
            self.write("invalid.safetensors", self.safetensors([0, 8]))
        )

        finding = self.threat(result, "AML.SAFETENSORS.OFFSET")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "critical")

    def test_gguf_absurd_counts_are_rejected_without_allocation(self) -> None:
        header = b"GGUF" + struct.pack("<IQQ", 3, 1, 2_000_000)
        result = AegisML(api_url="", chunk_size=9).scan(self.write("bad.gguf", header))

        finding = self.threat(result, "AML.COVERAGE.LIMIT")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "high")
        self.assertEqual(result.metadata["format"]["metadata_count"], 2_000_000)
        self.assertEqual(result.metadata["coverage"]["format_specific"], "capped")

    def test_valid_gguf_metadata_and_tensor_directory_are_fully_parsed(self) -> None:
        metadata = (
            gguf_string("general.alignment")
            + struct.pack("<I", 4)  # UINT32
            + struct.pack("<I", 32)
        )
        tensor_info = (
            gguf_string("weight")
            + struct.pack("<I", 1)
            + struct.pack("<Q", 1)
            + struct.pack("<I", 0)  # GGML_TYPE_F32
            + struct.pack("<Q", 0)
        )
        prefix = b"GGUF" + struct.pack("<IQQ", 3, 1, 1) + metadata + tensor_info
        padding = b"\x00" * ((-len(prefix)) % 32)
        artifact = prefix + padding + struct.pack("<f", 1.0)

        result = AegisML(api_url="", chunk_size=13).scan(
            self.write("valid.gguf", artifact)
        )

        self.assertEqual(result.metadata["coverage"]["format_specific"], "complete")
        self.assertTrue(result.metadata["coverage"]["complete"])
        self.assertEqual(result.metadata["format"]["tensor_info_parsed"], 1)
        self.assertEqual(result.metadata["format"]["metadata_parsed"], 1)
        self.assertEqual(result.metadata["format"]["alignment"], 32)

    def test_gguf_tensor_offset_outside_data_region_is_rejected(self) -> None:
        tensor_info = (
            gguf_string("weight")
            + struct.pack("<I", 1)
            + struct.pack("<Q", 1)
            + struct.pack("<I", 0)
            + struct.pack("<Q", 64)
        )
        prefix = b"GGUF" + struct.pack("<IQQ", 3, 1, 0) + tensor_info
        artifact = prefix + (b"\x00" * ((-len(prefix)) % 32)) + b"\x00\x00\x00\x00"

        result = AegisML(api_url="").scan(self.write("offset.gguf", artifact))

        self.assertIsNotNone(self.threat(result, "AML.GGUF.TENSOR_OFFSET"))

    def test_compressed_pytorch_pickle_is_analyzed_without_loading_it(self) -> None:
        path = self.root / "evil.pt"
        payload = pickle.dumps(_EvilPickle(), protocol=5)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("archive/data.pkl", payload)
            archive.writestr("archive/data/0", b"\x00" * 32)

        result = AegisML(api_url="", chunk_size=17).scan(path)

        finding = self.threat(result, "AML.PICKLE.GLOBAL.EXEC")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "critical")
        self.assertIn("data.pkl", finding.location)
        self.assertEqual(result.metadata["coverage"]["format_specific"], "complete")

    def test_raw_protocol_five_rce_pickle_is_not_safe(self) -> None:
        path = self.write("evil.pkl", pickle.dumps(_EvilPickle(), protocol=5))

        result = AegisML(api_url="", chunk_size=19).scan(path)

        self.assertIsNotNone(self.threat(result, "AML.PICKLE.GLOBAL.EXEC"))
        self.assertIsNotNone(self.threat(result, "AML.PICKLE.EXEC_CALL"))
        self.assertEqual(result.verdict, "CRITICAL")

    def test_pickle_stack_global_reconstructed_through_memo_gets(self) -> None:
        # PROTO4; memoize+pop module/name; BINGET both; STACK_GLOBAL; REDUCE.
        payload = (
            b"\x80\x04"
            b"\x8c\x05posix\x940"
            b"\x8c\x06system\x940"
            b"h\x00h\x01\x93)R."
        )

        result = AegisML(api_url="").scan(self.write("memo.pkl", payload))

        self.assertIsNotNone(self.threat(result, "AML.PICKLE.GLOBAL.EXEC"))

    def test_every_concatenated_pickle_stream_is_analyzed(self) -> None:
        payload = pickle.dumps({"safe": True}, protocol=4) + pickle.dumps(
            _EvilPickle(), protocol=5
        )

        result = AegisML(api_url="").scan(self.write("streams.pkl", payload))

        self.assertIsNotNone(self.threat(result, "AML.PICKLE.GLOBAL.EXEC"))
        self.assertIsNotNone(self.threat(result, "AML.PICKLE.MULTI_STREAM"))
        self.assertEqual(result.metadata["format"]["streams"], 2)

    def test_safetensors_rejects_invalid_utf8_and_duplicate_keys(self) -> None:
        invalid_utf8 = b'{"tensor\xff":{}}'
        first = struct.pack("<Q", len(invalid_utf8)) + invalid_utf8
        duplicate = (
            b'{"x":{"dtype":"F32","shape":[0],"data_offsets":[0,0]},'
            b'"x":{"dtype":"F32","shape":[0],"data_offsets":[0,0]}}'
        )
        second = struct.pack("<Q", len(duplicate)) + duplicate

        for name, artifact in (("utf8.safetensors", first), ("dup.safetensors", second)):
            with self.subTest(name=name):
                result = AegisML(api_url="").scan(self.write(name, artifact))
                self.assertIsNotNone(self.threat(result, "AML.SAFETENSORS.JSON"))
                self.assertFalse(result.is_safe)

    def test_safetensors_requires_tensor_schema(self) -> None:
        header = json_bytes({"tensor": {}})
        artifact = struct.pack("<Q", len(header)) + header

        result = AegisML(api_url="").scan(self.write("schema.safetensors", artifact))

        self.assertIsNotNone(
            self.threat(result, "AML.SAFETENSORS.TENSOR_SCHEMA")
        )

    def test_auto_entropy_sampling_is_explicit_and_bounded(self) -> None:
        path = self.write("large.custom", bytes(range(256)) * 8)

        result = AegisML(api_url="", chunk_size=64, entropy_mode="auto").scan(path)

        # In v3 "auto" always means block sampling: the histogram is derived from
        # a bounded window per block, so the cost per byte is constant.
        self.assertEqual(result.metadata["coverage"]["entropy"], "sampled")
        self.assertLessEqual(
            result.metadata["entropy_bytes_analyzed"], result.metadata["file_size"]
        )
        self.assertGreater(result.metadata["profile"]["blocks_measured"], 0)
        self.assertIn("atom-prefilter", result.metadata["matcher_backend"])


def json_bytes(value: dict) -> bytes:
    import json

    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def gguf_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack("<Q", len(encoded)) + encoded


if __name__ == "__main__":
    unittest.main()
