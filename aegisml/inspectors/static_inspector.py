"""Static Analysis Inspector for Pickle-based Model Files.

Inspects .pkl, .pickle, .pt, and .pth files for:
- Magic bytes validation (Pickle/PyTorch/ZIP signatures)
- Dangerous deserialization patterns (__reduce__, __reduce_ex__)
- Embedded malicious code patterns (os.system, exec, eval, etc.)
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

from aegisml.inspectors.base import InspectorResult


# Known magic bytes for pickle-based formats
PICKLE_MAGIC_V2 = b"\x80\x02"       # Pickle protocol 2
PICKLE_MAGIC_V3 = b"\x80\x03"       # Pickle protocol 3
PICKLE_MAGIC_V4 = b"\x80\x04"       # Pickle protocol 4
PICKLE_MAGIC_V5 = b"\x80\x05"       # Pickle protocol 5
ZIP_MAGIC = b"PK\x03\x04"           # ZIP archive (PyTorch .pt uses ZIP)

VALID_MAGICS: dict[bytes, str] = {
    PICKLE_MAGIC_V2: "Pickle protocol 2",
    PICKLE_MAGIC_V3: "Pickle protocol 3",
    PICKLE_MAGIC_V4: "Pickle protocol 4",
    PICKLE_MAGIC_V5: "Pickle protocol 5",
    ZIP_MAGIC: "ZIP archive (PyTorch)",
}

# Dangerous patterns found in binary content
# Each entry: (regex_pattern, label, description, risk_weight)
DANGEROUS_PATTERNS: list[dict[str, Any]] = [
    {
        "pattern": r"os\.system",
        "label": "os.system",
        "description": "System command execution via os.system",
        "weight": 15.0,
    },
    {
        "pattern": r"subprocess",
        "label": "subprocess",
        "description": "Process spawning via subprocess module",
        "weight": 15.0,
    },
    {
        "pattern": r"\bexec\b",
        "label": "exec",
        "description": "Dynamic code execution via exec()",
        "weight": 15.0,
    },
    {
        "pattern": r"\beval\b",
        "label": "eval",
        "description": "Dynamic expression evaluation via eval()",
        "weight": 15.0,
    },
    {
        "pattern": r"__reduce_ex__",
        "label": "__reduce_ex__",
        "description": "Custom deserialization hook — allows arbitrary code execution on unpickle",
        "weight": 40.0,
    },
    {
        "pattern": r"__reduce__",
        "label": "__reduce__",
        "description": "Custom deserialization hook — allows arbitrary code execution on unpickle",
        "weight": 40.0,
    },
    {
        "pattern": r"\bsocket\b",
        "label": "socket",
        "description": "Network socket operations",
        "weight": 15.0,
    },
    {
        "pattern": r"\brequests\b",
        "label": "requests",
        "description": "HTTP requests via requests library",
        "weight": 15.0,
    },
    {
        "pattern": r"\burllib\b",
        "label": "urllib",
        "description": "URL operations via urllib",
        "weight": 15.0,
    },
    {
        "pattern": r"\bbase64\b",
        "label": "base64",
        "description": "Base64 encoding/decoding — may hide obfuscated payloads",
        "weight": 15.0,
    },
]

# Maximum file size to fully scan (100 MB). Larger files are sampled.
MAX_FULL_SCAN_SIZE = 100 * 1024 * 1024
# Read chunk size for streaming scan
CHUNK_SIZE = 1024 * 1024  # 1 MB


class StaticInspector:
    """Inspector for Pickle-based model files (.pkl, .pickle, .pt, .pth).

    Pickle files are inherently dangerous because deserialization can
    trigger arbitrary code execution via __reduce__ / __reduce_ex__.
    This inspector scans the raw binary content for known malicious
    patterns without actually unpickling the file.
    """

    SUPPORTED_EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth"}

    def inspect(self, file_path: str | Path) -> InspectorResult:
        """Inspect a pickle-based model file and return risk assessment.

        Args:
            file_path: Path to the model file to inspect.

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

        # ── 2. Extension check ───────────────────────────────────────
        suffix = file_path.suffix.lower()
        if suffix not in self.SUPPORTED_EXTENSIONS:
            findings.append({
                "type": "extension_warning",
                "detail": (
                    f"File extension '{suffix}' is not a standard pickle format. "
                    f"Expected one of: {', '.join(sorted(self.SUPPORTED_EXTENSIONS))}"
                ),
                "severity": "suspicious",
            })

        file_size = file_path.stat().st_size

        try:
            with open(file_path, "rb") as f:
                # ── 3. Magic bytes validation ────────────────────────
                magic_bytes = f.read(4)
                if len(magic_bytes) < 4:
                    findings.append({
                        "type": "invalid_magic",
                        "detail": "File too small to contain valid magic bytes.",
                        "severity": "malicious",
                    })
                    risk_score += 20.0
                else:
                    identified = False

                    # Check 4-byte magics first (ZIP)
                    if magic_bytes[:4] in VALID_MAGICS:
                        fmt_name = VALID_MAGICS[magic_bytes[:4]]
                        identified = True
                    # Then check 2-byte magics (Pickle protocols)
                    elif magic_bytes[:2] in VALID_MAGICS:
                        fmt_name = VALID_MAGICS[magic_bytes[:2]]
                        identified = True

                    if identified:
                        findings.append({
                            "type": "valid_magic",
                            "detail": f"Magic bytes match: {fmt_name}.",
                            "severity": "clean",
                        })
                    else:
                        hex_str = magic_bytes.hex().upper()
                        findings.append({
                            "type": "unknown_magic",
                            "detail": (
                                f"Unrecognized magic bytes: 0x{hex_str}. "
                                f"File may not be a valid pickle/PyTorch model."
                            ),
                            "severity": "suspicious",
                        })
                        risk_score += 10.0

                # ── 4. Inherent pickle risk warning ──────────────────
                if suffix in {".pkl", ".pickle"}:
                    findings.append({
                        "type": "format_risk",
                        "detail": (
                            "Pickle format is inherently unsafe — deserialization "
                            "can execute arbitrary code. Consider using SafeTensors instead."
                        ),
                        "severity": "suspicious",
                    })

                # ── 5. Content scanning ──────────────────────────────
                f.seek(0)
                found_patterns: dict[str, int] = {}

                bytes_read = 0
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    bytes_read += len(chunk)

                    # Decode chunk as latin-1 (lossless byte→str mapping)
                    text = chunk.decode("latin-1")

                    for pattern_info in DANGEROUS_PATTERNS:
                        matches = re.findall(pattern_info["pattern"], text)
                        if matches:
                            label = pattern_info["label"]
                            found_patterns[label] = found_patterns.get(label, 0) + len(matches)

                    if bytes_read >= MAX_FULL_SCAN_SIZE:
                        findings.append({
                            "type": "scan_limit",
                            "detail": (
                                f"File is {file_size:,} bytes. "
                                f"Scanned first {MAX_FULL_SCAN_SIZE:,} bytes."
                            ),
                            "severity": "clean",
                        })
                        break

                # ── 6. Build findings from detected patterns ─────────
                for pattern_info in DANGEROUS_PATTERNS:
                    label = pattern_info["label"]
                    count = found_patterns.get(label, 0)
                    if count > 0:
                        # __reduce_ex__ also matches __reduce__, so skip
                        # duplicate __reduce__ if __reduce_ex__ was found
                        if label == "__reduce__" and "__reduce_ex__" in found_patterns:
                            # Subtract the __reduce_ex__ matches from __reduce__
                            adjusted = count - found_patterns.get("__reduce_ex__", 0)
                            if adjusted <= 0:
                                continue
                            count = adjusted

                        severity = (
                            "malicious" if pattern_info["weight"] >= 40.0
                            else "suspicious"
                        )
                        findings.append({
                            "type": "dangerous_pattern",
                            "detail": (
                                f"Pattern '{label}' found {count} time(s): "
                                f"{pattern_info['description']}."
                            ),
                            "severity": severity,
                            "pattern": label,
                            "count": count,
                        })
                        risk_score += pattern_info["weight"]

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

        clamped = max(0.0, min(100.0, risk_score))
        return InspectorResult(
            risk_score=clamped,
            findings=findings,
            severity=InspectorResult.severity_from_score(clamped),
        )
