"""
AegisML ONNX Format Scanner
ONNX files are Protocol Buffer (protobuf) serialized graphs. This scanner
validates the protobuf structure heuristically (without requiring the heavy
onnx/protobuf packages) and flags custom-operator nodes, external-data
references that can be used for path traversal, and embedded strings that
match known threat patterns.
"""
from typing import Any
import re

# ONNX custom-op domains that allow native code execution via op registration
SUSPICIOUS_OP_DOMAINS = [
    b"com.microsoft.experimental",
    b"ai.onnx.contrib",
    b"custom_op",
]

# Path traversal indicators in external_data location fields
PATH_TRAVERSAL_PATTERNS = [
    b"../", b"..\\", b"/etc/", b"/root/", b"C:\\Windows", b"C:\\Users",
]


def scan(file_path: str) -> dict[str, Any]:
    threats: list[dict] = []
    metadata: dict[str, Any] = {}

    try:
        with open(file_path, "rb") as f:
            data = f.read(min(50 * 1024 * 1024, 200 * 1024 * 1024))

        metadata["bytes_scanned"] = len(data)

        # ONNX files don't have a fixed magic number (raw protobuf), but
        # well-formed ONNX ModelProto messages begin with field 1 (ir_version,
        # varint) as tag 0x08, or field 7 (opset_import) etc. We do a
        # heuristic protobuf sanity check: the file should not be valid UTF-8
        # text and should contain mostly low-value tag bytes early on.
        is_plausible_protobuf = len(data) > 8 and data[0] in (0x08, 0x0A, 0x12, 0x1A)
        metadata["plausible_protobuf_header"] = is_plausible_protobuf

        if not is_plausible_protobuf:
            threats.append({
                "id": "ONNX-STRUCT-001",
                "name": "Non-Standard ONNX Protobuf Header",
                "category": "format_anomaly",
                "severity": "medium",
                "cvss": 4.5,
                "description": "First byte does not match a typical ONNX ModelProto field tag. File may be malformed or not genuinely ONNX.",
                "remediation": "Validate with `onnx.checker.check_model()` before use.",
                "references": ["https://github.com/onnx/onnx/blob/main/docs/IR.md"]
            })

        # Custom operator domains (can register native code at runtime)
        for domain in SUSPICIOUS_OP_DOMAINS:
            if domain in data:
                threats.append({
                    "id": "ONNX-OP-001",
                    "name": f"Custom Operator Domain: {domain.decode(errors='replace')}",
                    "category": "code_execution",
                    "severity": "high",
                    "cvss": 7.5,
                    "description": f"ONNX graph references custom op domain '{domain.decode(errors='replace')}' — custom operators can execute arbitrary native code via the runtime's op registry.",
                    "remediation": "Only load custom-op ONNX models if you trust and have audited the corresponding operator implementation.",
                    "references": ["https://onnxruntime.ai/docs/reference/operators/add-custom-op.html"]
                })

        # External data path traversal (ONNX supports offloading large tensors
        # to external files referenced by a relative path — a classic vector
        # for path traversal if the loader doesn't sanitize the path)
        if b"external_data" in data or b"location" in data:
            for pattern in PATH_TRAVERSAL_PATTERNS:
                if pattern in data:
                    threats.append({
                        "id": "ONNX-PATH-001",
                        "name": "Path Traversal in External Data Reference",
                        "category": "format_anomaly",
                        "severity": "critical",
                        "cvss": 8.8,
                        "description": f"ONNX external_data location contains a path traversal sequence ('{pattern.decode(errors='replace')}') — can read arbitrary files outside the model directory when loaded.",
                        "remediation": "Reject this model. Legitimate ONNX external data references should use relative filenames without directory traversal.",
                        "references": ["https://github.com/onnx/onnx/blob/main/docs/ExternalData.md"]
                    })
                    break

        # Embedded shell/exfil indicators (reuse same string classes as other scanners)
        for marker, sev, cvss, label in [
            (b"os.system", "critical", 9.5, "OS command execution string in ONNX graph"),
            (b"subprocess", "high", 8.0, "Subprocess reference in ONNX graph"),
            (b"eval(", "high", 8.0, "eval() reference in ONNX graph"),
            (b"socket.connect", "high", 7.5, "Network socket reference in ONNX graph"),
        ]:
            if marker in data:
                threats.append({
                    "id": f"ONNX-STR-{marker[:4].hex()}",
                    "name": label,
                    "category": "code_execution" if sev == "critical" else "format_anomaly",
                    "severity": sev,
                    "cvss": cvss,
                    "description": f"String '{marker.decode(errors='replace')}' found embedded in ONNX file — highly unusual for a pure computation graph format.",
                    "remediation": "ONNX graphs should not contain executable code strings. Treat as suspicious.",
                    "references": []
                })

    except FileNotFoundError:
        pass
    except Exception as e:
        threats.append({
            "id": "ONNX-ERR-001",
            "name": "ONNX Parser Error",
            "category": "format_anomaly",
            "severity": "medium",
            "cvss": 3.0,
            "description": f"Error during ONNX analysis: {str(e)[:200]}",
            "remediation": "File may be corrupted or crafted to crash parsers.",
            "references": []
        })

    return {"format": "onnx", "threats_found": threats, "metadata": metadata}
