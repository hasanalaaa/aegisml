"""GGUF Model File Inspector.

Inspects GGUF (GPT-Generated Unified Format) model files for:
- Magic bytes validation
- Metadata extraction and analysis
- Chat template injection detection
- Dangerous function call patterns
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

from aegisml.inspectors.base import InspectorResult


# GGUF magic number: "GGUF" in little-endian = 0x46554747
GGUF_MAGIC = 0x46554747

# GGUF metadata value types
GGUF_TYPE_UINT8 = 0
GGUF_TYPE_INT8 = 1
GGUF_TYPE_UINT16 = 2
GGUF_TYPE_INT16 = 3
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_INT32 = 5
GGUF_TYPE_FLOAT32 = 6
GGUF_TYPE_BOOL = 7
GGUF_TYPE_STRING = 8
GGUF_TYPE_ARRAY = 9
GGUF_TYPE_UINT64 = 10
GGUF_TYPE_INT64 = 11
GGUF_TYPE_FLOAT64 = 12

# Patterns that indicate potentially dangerous code execution
DANGEROUS_PATTERNS: list[dict[str, str]] = [
    {"pattern": r"os\.system\s*\(", "label": "os.system()", "description": "System command execution via os.system"},
    {"pattern": r"\bexec\s*\(", "label": "exec()", "description": "Dynamic code execution via exec()"},
    {"pattern": r"\beval\s*\(", "label": "eval()", "description": "Dynamic expression evaluation via eval()"},
    {"pattern": r"subprocess\.", "label": "subprocess", "description": "Process spawning via subprocess module"},
    {"pattern": r"__import__\s*\(", "label": "__import__()", "description": "Dynamic module import via __import__()"},
    {"pattern": r"\bopen\s*\(", "label": "open()", "description": "File system access via open()"},
    {"pattern": r"os\.popen\s*\(", "label": "os.popen()", "description": "Command execution via os.popen"},
    {"pattern": r"os\.exec", "label": "os.exec*()", "description": "Process replacement via os.exec family"},
    {"pattern": r"shutil\.", "label": "shutil", "description": "File operations via shutil module"},
    {"pattern": r"socket\.", "label": "socket", "description": "Network socket operations"},
    {"pattern": r"requests\.", "label": "requests", "description": "HTTP requests via requests library"},
    {"pattern": r"urllib\.", "label": "urllib", "description": "URL operations via urllib"},
    {"pattern": r"ctypes\.", "label": "ctypes", "description": "C foreign function interface via ctypes"},
    {"pattern": r"<script", "label": "<script>", "description": "Embedded HTML/JavaScript script tag"},
]

# Risk weight per finding type
RISK_WEIGHTS: dict[str, float] = {
    "invalid_magic": 30.0,
    "dangerous_pattern": 25.0,
    "suspicious_metadata_key": 10.0,
    "chat_template_injection": 20.0,
    "read_error": 5.0,
}


class GGUFInspector:
    """Inspector for GGUF model files.

    Validates file structure, reads metadata, and scans for malicious
    content embedded in model metadata and chat templates.
    """

    def inspect(self, file_path: str | Path) -> InspectorResult:
        """Inspect a GGUF model file and return risk assessment.

        Args:
            file_path: Path to the GGUF model file to inspect.

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
            return InspectorResult(
                risk_score=0.0,
                findings=findings,
                severity="clean",
            )

        try:
            with open(file_path, "rb") as f:
                # ── 2. Magic bytes validation ────────────────────────
                magic_bytes = f.read(4)
                if len(magic_bytes) < 4:
                    findings.append({
                        "type": "invalid_magic",
                        "detail": "File too small to contain GGUF magic bytes.",
                        "severity": "malicious",
                    })
                    risk_score += RISK_WEIGHTS["invalid_magic"]
                else:
                    magic = struct.unpack("<I", magic_bytes)[0]
                    if magic != GGUF_MAGIC:
                        findings.append({
                            "type": "invalid_magic",
                            "detail": (
                                f"Invalid GGUF magic bytes: expected 0x{GGUF_MAGIC:08X}, "
                                f"got 0x{magic:08X}. File may be corrupted or not a GGUF model."
                            ),
                            "severity": "malicious",
                        })
                        risk_score += RISK_WEIGHTS["invalid_magic"]
                    else:
                        findings.append({
                            "type": "valid_magic",
                            "detail": "GGUF magic bytes validated successfully.",
                            "severity": "clean",
                        })

                # ── 3. Version and counts ────────────────────────────
                header_rest = f.read(12)
                if len(header_rest) < 12:
                    findings.append({
                        "type": "read_error",
                        "detail": "File too small to read GGUF header (version + counts).",
                        "severity": "suspicious",
                    })
                    risk_score += RISK_WEIGHTS["read_error"]
                    return self._build_result(risk_score, findings)

                version, tensor_count, metadata_kv_count = struct.unpack("<III", header_rest)

                findings.append({
                    "type": "header_info",
                    "detail": (
                        f"GGUF v{version} — "
                        f"{tensor_count} tensor(s), "
                        f"{metadata_kv_count} metadata key-value pair(s)."
                    ),
                    "severity": "clean",
                })

                # ── 4. Metadata parsing ──────────────────────────────
                metadata = self._read_metadata(f, metadata_kv_count, version)

                # ── 5. Chat template inspection ──────────────────────
                chat_template_value: str | None = None
                for key, value in metadata.items():
                    if "chat_template" in key.lower():
                        chat_template_value = str(value)
                        findings.append({
                            "type": "chat_template_found",
                            "detail": f"Chat template found in key '{key}' ({len(chat_template_value)} chars).",
                            "severity": "clean",
                        })
                        break

                # ── 6. Dangerous pattern scanning ────────────────────
                scan_targets: list[tuple[str, str]] = []

                # Scan all string metadata values
                for key, value in metadata.items():
                    if isinstance(value, str):
                        scan_targets.append((f"metadata[{key}]", value))

                # Scan chat template specifically
                if chat_template_value:
                    scan_targets.append(("chat_template", chat_template_value))

                for source_label, text in scan_targets:
                    for pattern_info in DANGEROUS_PATTERNS:
                        matches = re.findall(pattern_info["pattern"], text, re.IGNORECASE)
                        if matches:
                            finding_type = (
                                "chat_template_injection"
                                if "chat_template" in source_label
                                else "dangerous_pattern"
                            )
                            findings.append({
                                "type": finding_type,
                                "detail": (
                                    f"Dangerous pattern '{pattern_info['label']}' found in "
                                    f"{source_label}: {pattern_info['description']}. "
                                    f"({len(matches)} occurrence(s))"
                                ),
                                "severity": "malicious",
                                "pattern": pattern_info["label"],
                                "source": source_label,
                                "count": len(matches),
                            })
                            risk_score += RISK_WEIGHTS.get(finding_type, 15.0)

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
        clamped_score = max(0.0, min(100.0, risk_score))
        return InspectorResult(
            risk_score=clamped_score,
            findings=findings,
            severity=InspectorResult.severity_from_score(clamped_score),
        )

    def _read_gguf_string(self, f, version: int) -> str:
        """Read a GGUF string (uint64 length + UTF-8 bytes)."""
        length_data = f.read(8)
        if len(length_data) < 8:
            return ""
        length = struct.unpack("<Q", length_data)[0]
        # Safety: cap string read at 10 MB to avoid OOM on malformed files
        if length > 10 * 1024 * 1024:
            f.seek(length, 1)
            return "<string too large to read>"
        raw = f.read(length)
        return raw.decode("utf-8", errors="replace")

    def _read_metadata_value(self, f, value_type: int, version: int) -> Any:
        """Read a single GGUF metadata value based on its type tag."""
        type_formats: dict[int, tuple[str, int]] = {
            GGUF_TYPE_UINT8:   ("<B", 1),
            GGUF_TYPE_INT8:    ("<b", 1),
            GGUF_TYPE_UINT16:  ("<H", 2),
            GGUF_TYPE_INT16:   ("<h", 2),
            GGUF_TYPE_UINT32:  ("<I", 4),
            GGUF_TYPE_INT32:   ("<i", 4),
            GGUF_TYPE_FLOAT32: ("<f", 4),
            GGUF_TYPE_UINT64:  ("<Q", 8),
            GGUF_TYPE_INT64:   ("<q", 8),
            GGUF_TYPE_FLOAT64: ("<d", 8),
        }

        if value_type == GGUF_TYPE_STRING:
            return self._read_gguf_string(f, version)

        if value_type == GGUF_TYPE_BOOL:
            raw = f.read(1)
            return bool(raw[0]) if raw else False

        if value_type == GGUF_TYPE_ARRAY:
            arr_type_data = f.read(4)
            arr_len_data = f.read(8)
            if len(arr_type_data) < 4 or len(arr_len_data) < 8:
                return []
            arr_type = struct.unpack("<I", arr_type_data)[0]
            arr_len = struct.unpack("<Q", arr_len_data)[0]
            # Safety: cap array length
            arr_len = min(arr_len, 10_000)
            return [self._read_metadata_value(f, arr_type, version) for _ in range(arr_len)]

        if value_type in type_formats:
            fmt, size = type_formats[value_type]
            raw = f.read(size)
            if len(raw) < size:
                return 0
            return struct.unpack(fmt, raw)[0]

        # Unknown type — cannot proceed safely
        return None

    def _read_metadata(self, f, count: int, version: int) -> dict[str, Any]:
        """Read *count* key-value pairs from the GGUF metadata section.

        Args:
            f: Open binary file handle positioned right after the header.
            count: Number of metadata key-value pairs to read.
            version: GGUF format version.

        Returns:
            Dictionary mapping metadata key names to their values.
        """
        metadata: dict[str, Any] = {}

        # Safety: cap metadata count to prevent infinite loop on malformed files
        count = min(count, 50_000)

        for _ in range(count):
            try:
                key = self._read_gguf_string(f, version)
                if not key:
                    break

                value_type_data = f.read(4)
                if len(value_type_data) < 4:
                    break
                value_type = struct.unpack("<I", value_type_data)[0]

                value = self._read_metadata_value(f, value_type, version)
                metadata[key] = value
            except (struct.error, EOFError):
                break

        return metadata
