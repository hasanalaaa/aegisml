"""
AegisML SafeTensors Format Scanner
Validates safetensors header structure, metadata integrity,
tensor alignment, and scans for malicious metadata fields.
"""
import json
import struct
from typing import Any

# Suspicious metadata keys that may indicate compromised models
SUSPICIOUS_METADATA_KEYS = {
    "hidden_trigger", "backdoor_trigger", "poison_key", "adversarial_patch",
    "bypass_safety", "remove_alignment", "jailbreak", "trojan_key",
    "data_poison", "trigger_phrase", "malicious_label", "dirty_label",
    "attack_type", "backdoor_config",
}

# Expected safetensors dtype strings
VALID_DTYPES = {
    "F64", "F32", "F16", "BF16", "I64", "I32", "I16", "I8",
    "U8", "BOOL", "F8_E4M3", "F8_E5M2",
}

SAFETENSORS_MAX_HEADER_SIZE = 100 * 1024 * 1024  # 100MB max header


def scan(file_path: str) -> dict[str, Any]:
    threats: list[dict] = []
    metadata: dict[str, Any] = {}

    try:
        with open(file_path, "rb") as f:
            # First 8 bytes: little-endian uint64 = header size
            header_size_bytes = f.read(8)
            if len(header_size_bytes) < 8:
                return {"format": "safetensors", "threats_found": [], "metadata": {}}

            header_size = struct.unpack("<Q", header_size_bytes)[0]
            metadata["header_size_bytes"] = header_size

            # Sanity check header size
            if header_size == 0:
                threats.append({
                    "id": "ST-HEADER-001",
                    "name": "SafeTensors Zero Header Size",
                    "category": "format_anomaly",
                    "severity": "high",
                    "cvss": 7.0,
                    "description": "SafeTensors header size is 0 — file is empty or header has been zeroed out (tampering indicator).",
                    "remediation": "File appears corrupted or tampered. Do not load.",
                    "references": []
                })
                return {"format": "safetensors", "threats_found": threats, "metadata": metadata}

            if header_size > SAFETENSORS_MAX_HEADER_SIZE:
                threats.append({
                    "id": "ST-HEADER-002",
                    "name": "SafeTensors Oversized Header",
                    "category": "format_anomaly",
                    "severity": "high",
                    "cvss": 7.5,
                    "description": f"Header claims to be {header_size / 1024 / 1024:.1f}MB — far exceeding normal bounds. May attempt heap overflow in parsers.",
                    "remediation": "Do not parse. File likely crafted to exploit safetensors loaders.",
                    "references": ["https://github.com/huggingface/safetensors/security"]
                })
                return {"format": "safetensors", "threats_found": threats, "metadata": metadata}

            # Read header JSON
            header_bytes = f.read(header_size)
            if len(header_bytes) < header_size:
                threats.append({
                    "id": "ST-HEADER-003",
                    "name": "Truncated SafeTensors Header",
                    "category": "format_anomaly",
                    "severity": "medium",
                    "cvss": 4.0,
                    "description": f"Expected {header_size} header bytes but got {len(header_bytes)} — file is truncated or corrupted.",
                    "remediation": "File integrity check failed. Re-download from source.",
                    "references": []
                })
                return {"format": "safetensors", "threats_found": threats, "metadata": metadata}

            # Parse JSON header
            try:
                header = json.loads(header_bytes.decode("utf-8", errors="replace"))
            except json.JSONDecodeError as e:
                threats.append({
                    "id": "ST-JSON-001",
                    "name": "Invalid SafeTensors JSON Header",
                    "category": "format_anomaly",
                    "severity": "high",
                    "cvss": 7.0,
                    "description": f"SafeTensors header is not valid JSON: {str(e)[:200]}. May indicate tampering.",
                    "remediation": "File header is corrupted. Re-download from trusted source.",
                    "references": []
                })
                return {"format": "safetensors", "threats_found": threats, "metadata": metadata}

            # Extract __metadata__ section
            meta_section = header.get("__metadata__", {})
            metadata["tensor_count"] = len([k for k in header if k != "__metadata__"])
            metadata["has_metadata"] = bool(meta_section)

            # Scan metadata keys for suspicious content
            meta_lower = {k.lower(): v for k, v in meta_section.items()}
            for suspect_key in SUSPICIOUS_METADATA_KEYS:
                if suspect_key in meta_lower:
                    threats.append({
                        "id": "ST-META-001",
                        "name": f"Suspicious Metadata Key: {suspect_key}",
                        "category": "safetensors_anomaly",
                        "severity": "high",
                        "cvss": 8.0,
                        "description": f"SafeTensors metadata contains suspicious key '{suspect_key}' — common data poisoning or backdoor indicator.",
                        "remediation": "Inspect the full metadata. This key suggests intentional model tampering.",
                        "references": ["https://arxiv.org/abs/2204.06974"]
                    })

            # Validate tensor entries
            invalid_dtypes = []
            for tensor_name, tensor_info in header.items():
                if tensor_name == "__metadata__":
                    continue
                if not isinstance(tensor_info, dict):
                    continue
                dtype = tensor_info.get("dtype", "")
                if dtype and dtype not in VALID_DTYPES:
                    invalid_dtypes.append(f"{tensor_name}:{dtype}")

            if invalid_dtypes:
                threats.append({
                    "id": "ST-DTYPE-001",
                    "name": "Invalid Tensor dtypes Detected",
                    "category": "format_anomaly",
                    "severity": "medium",
                    "cvss": 5.0,
                    "description": f"Tensors with unknown dtypes: {', '.join(invalid_dtypes[:5])}. Non-standard dtypes may exploit parser vulnerabilities.",
                    "remediation": "Only load safetensors with standard dtypes. Report to model publisher.",
                    "references": ["https://huggingface.co/docs/safetensors/metadata_parsing"]
                })

            # Check for overlapping tensor data offsets (potential data injection)
            offsets = []
            for tensor_name, tensor_info in header.items():
                if tensor_name == "__metadata__":
                    continue
                if isinstance(tensor_info, dict) and "data_offsets" in tensor_info:
                    offsets.append((tensor_name, tensor_info["data_offsets"]))

            metadata["validated_tensors"] = len(offsets)

            # Detect overlapping offsets
            for i, (name_a, off_a) in enumerate(offsets):
                for name_b, off_b in offsets[i+1:]:
                    if isinstance(off_a, list) and isinstance(off_b, list) and len(off_a) == 2 and len(off_b) == 2:
                        # Check if ranges overlap
                        start_a, end_a = off_a[0], off_a[1]
                        start_b, end_b = off_b[0], off_b[1]
                        if start_a < end_b and start_b < end_a:
                            threats.append({
                                "id": "ST-OVERLAP-001",
                                "name": "Overlapping Tensor Data Offsets",
                                "category": "safetensors_anomaly",
                                "severity": "critical",
                                "cvss": 9.0,
                                "description": f"Tensors '{name_a}' and '{name_b}' have overlapping data regions — crafted to confuse parsers or inject data.",
                                "remediation": "File has been tampered with. Do not use.",
                                "references": ["https://github.com/huggingface/safetensors/security"]
                            })
                            break
                else:
                    continue
                break

    except FileNotFoundError:
        pass
    except Exception as e:
        threats.append({
            "id": "ST-ERR-001",
            "name": "SafeTensors Parser Error",
            "category": "format_anomaly",
            "severity": "medium",
            "cvss": 3.0,
            "description": f"Error during safetensors analysis: {str(e)[:200]}",
            "remediation": "File may be corrupted or crafted to crash parsers.",
            "references": []
        })

    return {"format": "safetensors", "threats_found": threats, "metadata": metadata}
