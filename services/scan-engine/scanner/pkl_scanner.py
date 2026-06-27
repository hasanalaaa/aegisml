import pickletools
import io
from typing import List, Dict, Any

from .patterns import COMPILED_PATTERNS
from .cvss import calculate_from_dict

SAFE_GLOBALS = {
    ("numpy.core.multiarray", "_reconstruct"),
    ("numpy.core.multiarray", "scalar"),
    ("numpy", "dtype"),
    ("collections", "OrderedDict"),
    ("torch._utils", "_rebuild_tensor_v2"),
    # Add more safe ML globals here
}

def scan_pickle_data(data: bytes) -> List[Dict[str, Any]]:
    """
    Statically analyzes pickle bytecode for dangerous operations
    like arbitrary GLOBAL imports or REDUCE execution.
    """
    threats = []
    
    # Check regex patterns first (for obfuscation/base64/direct string matches)
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
            
    # Trace Opcodes securely without executing
    try:
        f = io.BytesIO(data)
        for opcode, arg, pos in pickletools.genops(f):
            if opcode.name == "GLOBAL":
                module, name = arg.split(" ", 1)
                if (module, name) not in SAFE_GLOBALS:
                    # Flag as potentially dangerous
                    threats.append({
                        "type": "unsafe_global",
                        "category": "code_execution",
                        "offset": pos,
                        "severity": "high" if module in ["os", "subprocess", "sys", "builtins", "pty"] else "medium",
                        "cvss_score": 8.4 if module in ["os", "subprocess", "builtins"] else 5.5,
                        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "desc": f"Unsafe GLOBAL import: {module}.{name}"
                    })
            elif opcode.name == "REDUCE":
                threats.append({
                    "type": "reduce_execution",
                    "category": "deserialization_exploit",
                    "offset": pos,
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "desc": "Execution of arbitrary callable via REDUCE opcode."
                })
    except Exception as e:
        # Malformed pickle
        threats.append({
            "type": "malformed_pickle",
            "category": "obfuscation_payload",
            "offset": 0,
            "severity": "medium",
            "cvss_score": 5.5,
            "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H",
            "desc": f"Pickle stream is malformed or intentionally corrupted: {str(e)}"
        })

    return threats
