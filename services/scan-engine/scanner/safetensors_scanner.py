import struct
import json
import re
from typing import List, Dict, Any

from .patterns import COMPILED_PATTERNS
from .cvss import calculate_from_dict
from .entropy import calculate_shannon_entropy

def scan_safetensors_data(data: bytes) -> List[Dict[str, Any]]:
    """
    Scans SafeTensors files.
    Extracts the JSON header exactly by reading the first 8 bytes length prefix,
    and analyzes the metadata for base64 payloads, unexpected URLs, and high entropy strings.
    """
    threats = []
    
    if len(data) < 8:
        return threats

    # 1. Structural Pattern Matching on entire file
    for pattern_info in COMPILED_PATTERNS:
        matches = pattern_info["compiled"].finditer(data)
        for match in matches:
            cvss_score, sev, vector = calculate_from_dict(pattern_info["default_cvss"])
            threats.append({
                "type": "pattern_match",
                "pattern_id": pattern_info["id"],
                "category": pattern_info["category"],
                "offset": match.start(),
                "severity": pattern_info["severity"],
                "cvss_score": cvss_score,
                "cvss_vector": vector,
                "desc": pattern_info["desc"]
            })

    # 2. Extract and Parse JSON Header
    try:
        header_size = struct.unpack('<Q', data[:8])[0]
        if header_size > len(data) - 8:
            # Malformed SafeTensors
            raise ValueError("Header size exceeds file size")
            
        header_bytes = data[8:8+header_size]
        header_json = json.loads(header_bytes.decode('utf-8'))
        
        # Analyze Metadata inside __metadata__ if present
        metadata = header_json.get("__metadata__", {})
        
        for k, v in metadata.items():
            if isinstance(v, str):
                # Check for high entropy (base64 packed payload)
                entropy = calculate_shannon_entropy(v.encode('utf-8'))
                if entropy > 7.0 and len(v) > 64:
                    threats.append({
                        "type": "high_entropy_metadata",
                        "category": "obfuscation_payload",
                        "offset": 8,
                        "severity": "high",
                        "cvss_score": 7.5,
                        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "desc": f"High entropy string found in metadata field '{k}'. Possible hidden payload."
                    })
                    
                # Look for suspicious URLs in metadata
                url_match = re.search(r'https?://[^\s\'"]+', v)
                if url_match:
                    threats.append({
                        "type": "suspicious_url_metadata",
                        "category": "network_exfiltration",
                        "offset": 8,
                        "severity": "medium",
                        "cvss_score": 5.5,
                        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        "desc": f"External URL found in metadata: {url_match.group(0)}"
                    })
    except Exception as e:
        threats.append({
            "type": "malformed_safetensors",
            "category": "obfuscation_payload",
            "offset": 0,
            "severity": "low",
            "cvss_score": 3.3,
            "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            "desc": f"SafeTensors header is malformed: {str(e)}"
        })

    return threats
