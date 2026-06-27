import re
from typing import List, Dict, Any

from .patterns import COMPILED_PATTERNS
from .cvss import calculate_from_dict
from .entropy import detect_encrypted_sections

# Known suspicious ONNX operators that could lead to RCE or weird behavior
# PyOp allows running arbitrary Python code in ONNX runtime.
SUSPICIOUS_ONNX_OPS = [b"PyOp", b"CustomOp", b"StringNormalizer"]

def scan_onnx_data(data: bytes) -> List[Dict[str, Any]]:
    """
    Scans ONNX files.
    ONNX models are Protobuf payloads. Without the full ONNX library (which is heavy),
    we perform deep structural analysis, entropy checks, and search for dangerous 
    op_types directly in the binary structure.
    """
    threats = []

    # 1. Structural Pattern Matching
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

    # 2. Check for Dangerous ONNX Operators
    for op in SUSPICIOUS_ONNX_OPS:
        # Protobuf strings are prefixed by their length. 
        # But simply finding the raw bytes of "PyOp" is a strong indicator.
        if op in data:
            threats.append({
                "type": "dangerous_onnx_op",
                "category": "code_execution",
                "offset": data.find(op),
                "severity": "critical",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "desc": f"Suspicious ONNX Operator found: {op.decode('utf-8')}. Can execute arbitrary code."
            })

    # 3. Check for high entropy sections (possible embedded payloads)
    entropy_results = detect_encrypted_sections(data, chunk_size=4096, threshold=7.8)
    threats.extend(entropy_results)

    return threats
