"""SafeTensors Model File Inspector.

Inspects .safetensors files for:
- Header JSON validation and size checks
- Suspicious URLs embedded in metadata
- Base64-encoded blobs hidden in metadata values
- Unusual or oversized metadata fields
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any

from aegisml.inspectors.base import InspectorResult


# SafeTensors header: first 8 bytes are a little-endian uint64
# representing the length of the JSON header that follows.
# Maximum sane header size: 100 MB
MAX_HEADER_SIZE = 100 * 1024 * 1024

# Patterns that are suspicious in metadata (not necessarily dangerous
# by themselves, but unusual for a model weights file)
SUSPICIOUS_PATTERNS: list[dict[str, Any]] = [
    {
        "pattern": r"https?://[^\s\"'\\]+",
        "label": "URL",
        "description": "Embedded URL found in metadata — could be a data exfiltration or C2 endpoint",
        "weight": 10.0,
    },
    {
        "pattern": r"(?:[A-Za-z0-9+/]{40,}={0,2})",
        "label": "base64 blob",
        "description": "Possible base64-encoded payload hidden in metadata",
        "weight": 10.0,
    },
    {
        "pattern": r"<script[^>]*>",
        "label": "<script> tag",
        "description": "HTML script tag found in metadata — possible XSS or injection vector",
        "weight": 15.0,
    },
    {
        "pattern": r"os\.system|subprocess\.|eval\s*\(|exec\s*\(",
        "label": "code execution",
        "description": "Code execution pattern found in metadata",
        "weight": 20.0,
    },
    {
        "pattern": r"__import__\s*\(",
        "label": "__import__",
        "description": "Dynamic module import in metadata",
        "weight": 20.0,
    },
]

# Keys that are expected in SafeTensors metadata (allowlist for anomaly detection)
EXPECTED_META_KEYS = {
    "format", "dtype", "shape", "data_offsets",
    "__metadata__", "framework", "model_type",
}


class SafeTensorsInspector:
    """Inspector for SafeTensors model files (.safetensors).

    SafeTensors is designed to be a safer alternative to Pickle — it
    stores only tensor data and JSON metadata, with no arbitrary code
    execution path. However, metadata fields can still carry suspicious
    content (URLs, obfuscated payloads, etc.).

    Default risk score is low (5) because the format is inherently safer.
    """

    SUPPORTED_EXTENSIONS = {".safetensors"}

    def inspect(self, file_path: str | Path) -> InspectorResult:
        """Inspect a SafeTensors model file and return risk assessment.

        Args:
            file_path: Path to the SafeTensors file to inspect.

        Returns:
            An InspectorResult with risk score, findings, and severity.
        """
        file_path = Path(file_path)
        findings: list[dict[str, Any]] = []
        risk_score: float = 0.0

        # ── 1. File existence check ──────────────────────────────────
        if not file_path.exists():
            findings.append({
                "type": "file_error",
                "detail": f"File not found: {file_path}",
                "severity": "critical",
            })
            return InspectorResult(risk_score=0.0, findings=findings, severity="clean")

        try:
            with open(file_path, "rb") as f:
                # ── 2. Read header length ────────────────────────────
                header_len_bytes = f.read(8)
                if len(header_len_bytes) < 8:
                    findings.append({
                        "type": "invalid_header",
                        "detail": "File too small to contain SafeTensors header length.",
                        "severity": "malicious",
                    })
                    risk_score += 25.0
                    return self._build_result(risk_score, findings)

                header_length = struct.unpack("<Q", header_len_bytes)[0]

                # ── 3. Header size sanity check ──────────────────────
                if header_length > MAX_HEADER_SIZE:
                    findings.append({
                        "type": "oversized_header",
                        "detail": (
                            f"Header length ({header_length:,} bytes) exceeds "
                            f"maximum safe size ({MAX_HEADER_SIZE:,} bytes). "
                            f"File may be malformed or malicious."
                        ),
                        "severity": "malicious",
                    })
                    risk_score += 30.0
                    return self._build_result(risk_score, findings)

                if header_length == 0:
                    findings.append({
                        "type": "empty_header",
                        "detail": "Header length is 0 — file contains no tensor metadata.",
                        "severity": "suspicious",
                    })
                    risk_score += 5.0
                    return self._build_result(risk_score, findings)

                # ── 4. Read and parse JSON header ────────────────────
                header_bytes = f.read(header_length)
                if len(header_bytes) < header_length:
                    findings.append({
                        "type": "truncated_header",
                        "detail": (
                            f"Expected {header_length:,} header bytes, "
                            f"got {len(header_bytes):,}. File is truncated."
                        ),
                        "severity": "malicious",
                    })
                    risk_score += 20.0
                    return self._build_result(risk_score, findings)

                try:
                    header = json.loads(header_bytes.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    findings.append({
                        "type": "invalid_json",
                        "detail": f"Failed to parse header JSON: {e}",
                        "severity": "malicious",
                    })
                    risk_score += 25.0
                    return self._build_result(risk_score, findings)

                if not isinstance(header, dict):
                    findings.append({
                        "type": "invalid_header_type",
                        "detail": (
                            f"Header JSON root is {type(header).__name__}, "
                            f"expected dict."
                        ),
                        "severity": "malicious",
                    })
                    risk_score += 20.0
                    return self._build_result(risk_score, findings)

                # Count tensors (entries that are not __metadata__)
                tensor_keys = [k for k in header if k != "__metadata__"]
                findings.append({
                    "type": "header_info",
                    "detail": (
                        f"SafeTensors header parsed successfully — "
                        f"{len(tensor_keys)} tensor(s), "
                        f"header size: {header_length:,} bytes."
                    ),
                    "severity": "clean",
                })

                # ── 5. Inspect __metadata__ ──────────────────────────
                metadata = header.get("__metadata__")
                if metadata is not None:
                    if not isinstance(metadata, dict):
                        findings.append({
                            "type": "invalid_metadata_type",
                            "detail": (
                                f"__metadata__ is {type(metadata).__name__}, "
                                f"expected dict."
                            ),
                            "severity": "suspicious",
                        })
                        risk_score += 10.0
                    else:
                        findings.append({
                            "type": "metadata_info",
                            "detail": (
                                f"__metadata__ contains {len(metadata)} key(s): "
                                f"{', '.join(sorted(metadata.keys())[:10])}"
                                f"{'…' if len(metadata) > 10 else ''}"
                            ),
                            "severity": "clean",
                        })

                        # Scan metadata values for suspicious content
                        self._scan_metadata(metadata, findings, risk_score_ref=[risk_score])
                        risk_score = self._scan_metadata(metadata, findings, risk_score_ref=[risk_score])

                # ── 6. Scan full header text for patterns ────────────
                header_text = header_bytes.decode("utf-8", errors="replace")
                for patt in SUSPICIOUS_PATTERNS:
                    matches = re.findall(patt["pattern"], header_text, re.IGNORECASE)
                    if matches:
                        # Deduplicate with metadata-level findings
                        findings.append({
                            "type": "header_pattern",
                            "detail": (
                                f"Pattern '{patt['label']}' found in raw header: "
                                f"{patt['description']}. "
                                f"({len(matches)} occurrence(s))"
                            ),
                            "severity": "suspicious" if patt["weight"] < 20 else "malicious",
                            "pattern": patt["label"],
                            "count": len(matches),
                        })
                        risk_score += patt["weight"]

                # ── 7. SafeTensors format safety bonus ───────────────
                # If no issues found, assign a low baseline score
                dangerous_findings = [
                    f for f in findings
                    if f["severity"] in ("malicious", "critical")
                ]
                if not dangerous_findings:
                    findings.append({
                        "type": "format_safety",
                        "detail": (
                            "SafeTensors format does not support arbitrary code "
                            "execution. This is inherently safer than Pickle."
                        ),
                        "severity": "clean",
                    })
                    # Cap risk at baseline for clean SafeTensors
                    if risk_score < 5.0:
                        risk_score = 5.0

        except PermissionError:
            findings.append({
                "type": "file_error",
                "detail": f"Permission denied: cannot read {file_path}",
                "severity": "suspicious",
            })
        except OSError as e:
            findings.append({
                "type": "file_error",
                "detail": f"OS error reading file: {e}",
                "severity": "suspicious",
            })

        return self._build_result(risk_score, findings)

    # ── Private helpers ──────────────────────────────────────────────

    def _build_result(
        self, risk_score: float, findings: list[dict]
    ) -> InspectorResult:
        """Construct an InspectorResult with auto-derived severity."""
        clamped = max(0.0, min(100.0, risk_score))
        return InspectorResult(
            risk_score=clamped,
            findings=findings,
            severity=InspectorResult.severity_from_score(clamped),
        )

    def _scan_metadata(
        self,
        metadata: dict[str, Any],
        findings: list[dict],
        risk_score_ref: list[float],
    ) -> float:
        """Scan metadata dict values for suspicious content.

        Args:
            metadata: The __metadata__ dictionary from the header.
            findings: List to append findings to.
            risk_score_ref: Single-element list holding current risk score.

        Returns:
            Updated risk score.
        """
        risk = risk_score_ref[0]

        for key, value in metadata.items():
            if not isinstance(value, str):
                continue

            # Check for very long values (possible hidden payload)
            if len(value) > 10_000:
                findings.append({
                    "type": "large_metadata_value",
                    "detail": (
                        f"Metadata key '{key}' has unusually large value "
                        f"({len(value):,} chars). May contain hidden payload."
                    ),
                    "severity": "suspicious",
                })
                risk += 5.0

        return risk
