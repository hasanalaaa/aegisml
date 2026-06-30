"""
AegisML GGUF Format Scanner
Validates GGUF magic bytes, version, metadata structure,
and scans chat templates for SSTI and prompt injection.
"""
import struct
from typing import Any

# GGUF magic bytes
GGUF_MAGIC = b"GGUF"
SUPPORTED_VERSIONS = {1, 2, 3}

# Dangerous Jinja2 SSTI payloads often found in abused chat templates
SSTI_PATTERNS = [
    b"{{ self._TemplateReference__context",
    b"{{ ''.__class__.__mro__",
    b"{{ ''.__class__.__bases__",
    b"{{ request.environ",
    b"{{ config.__class__.__init__.__globals__",
    b"{{ namespace().__init__.__globals__",
    b"{% for x in ().__class__.__base__.__subclasses__() %}",
]

PROMPT_INJECTION_MARKERS = [
    b"IGNORE PREVIOUS INSTRUCTIONS",
    b"Disregard your previous",
    b"[SYSTEM OVERRIDE]",
    b"DAN mode",
    b"developer mode enabled",
    b"bypass_safety",
    b"remove_alignment",
    b"jailbreak",
    b"you are now DAN",
    b"pretend you have no restrictions",
]


def scan(file_path: str) -> dict[str, Any]:
    threats: list[dict] = []
    metadata: dict[str, Any] = {}

    try:
        with open(file_path, "rb") as f:
            # Validate GGUF magic
            magic = f.read(4)
            if magic != GGUF_MAGIC:
                return {
                    "format": "gguf",
                    "threats_found": [{
                        "id": "GF-MAGIC-001",
                        "name": "Invalid GGUF Magic Bytes",
                        "category": "format_anomaly",
                        "severity": "high",
                        "cvss": 7.5,
                        "description": f"Expected GGUF magic bytes but got {magic.hex()} — file may be misidentified or tampered.",
                        "remediation": "Verify file integrity. Do not load.",
                        "references": ["https://github.com/ggerganov/ggml/blob/master/docs/gguf.md"]
                    }],
                    "metadata": {},
                }

            # Read GGUF version
            version_bytes = f.read(4)
            if len(version_bytes) < 4:
                return {"format": "gguf", "threats_found": [], "metadata": {}}
            version = struct.unpack("<I", version_bytes)[0]
            metadata["gguf_version"] = version

            if version not in SUPPORTED_VERSIONS:
                threats.append({
                    "id": "GF-VERSION-001",
                    "name": f"Unknown GGUF Version: {version}",
                    "category": "format_anomaly",
                    "severity": "medium",
                    "cvss": 4.5,
                    "description": f"GGUF version {version} is not in the supported set {SUPPORTED_VERSIONS}. May indicate format manipulation.",
                    "remediation": "Verify file source. Ensure llama.cpp version supports this GGUF version.",
                    "references": []
                })

            # Read tensor count and metadata kv count
            tensor_count_bytes = f.read(8)
            kv_count_bytes = f.read(8)
            if len(tensor_count_bytes) < 8 or len(kv_count_bytes) < 8:
                return {"format": "gguf", "threats_found": threats, "metadata": metadata}

            tensor_count = struct.unpack("<Q", tensor_count_bytes)[0]
            kv_count = struct.unpack("<Q", kv_count_bytes)[0]
            metadata["tensor_count"] = tensor_count
            metadata["kv_count"] = kv_count

            # Sanity checks
            if kv_count > 1_000_000:
                threats.append({
                    "id": "GF-STRUCT-001",
                    "name": "Abnormally Large KV Metadata Count",
                    "category": "format_anomaly",
                    "severity": "high",
                    "cvss": 7.0,
                    "description": f"GGUF claims {kv_count:,} metadata entries — far exceeding normal range. May cause parser overflow.",
                    "remediation": "Do not parse. File appears malformed or crafted to exploit parsers.",
                    "references": []
                })

            if tensor_count > 10_000:
                threats.append({
                    "id": "GF-STRUCT-002",
                    "name": "Abnormally High Tensor Count",
                    "category": "format_anomaly",
                    "severity": "medium",
                    "cvss": 4.0,
                    "description": f"GGUF reports {tensor_count:,} tensors — unusual for standard LLMs. May indicate format manipulation.",
                    "remediation": "Verify against known model architecture specifications.",
                    "references": []
                })

            # Read remaining content to scan for chat template patterns
            remaining = f.read(min(2 * 1024 * 1024, 4 * 1024 * 1024))  # Read up to 2-4MB for template scan

        # Scan for SSTI patterns in the metadata/templates section
        for pattern in SSTI_PATTERNS:
            if pattern in remaining:
                threats.append({
                    "id": "GF-SSTI-001",
                    "name": "Server-Side Template Injection Exploit",
                    "category": "template_injection",
                    "severity": "critical",
                    "cvss": 9.8,
                    "description": f"Known Jinja2 SSTI exploit payload found in GGUF chat template: {pattern[:60]}...",
                    "remediation": "Do not use this model's chat template. Report to model publisher.",
                    "references": ["https://portswigger.net/web-security/server-side-template-injection"]
                })
                break

        # Scan for prompt injection in chat template
        for pattern in PROMPT_INJECTION_MARKERS:
            if pattern in remaining:
                threats.append({
                    "id": "GF-INJ-001",
                    "name": "Prompt Injection in GGUF Chat Template",
                    "category": "prompt_injection",
                    "severity": "high",
                    "cvss": 8.0,
                    "description": f"Prompt injection string found in GGUF chat template: '{pattern.decode(errors='replace')}'",
                    "remediation": "Review and sanitize the chat template. Use a trusted model from the original author.",
                    "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"]
                })
                break

    except FileNotFoundError:
        pass
    except Exception as e:
        threats.append({
            "id": "GF-ERR-001",
            "name": "GGUF Parser Error",
            "category": "format_anomaly",
            "severity": "medium",
            "cvss": 4.0,
            "description": f"Parser error during GGUF scan: {str(e)[:200]}",
            "remediation": "File may be corrupted or crafted to crash parsers.",
            "references": []
        })

    return {"format": "gguf", "threats_found": threats, "metadata": metadata}
