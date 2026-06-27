from typing import Dict, Any, List

from .pkl_scanner import scan_pickle_data
from .gguf_scanner import scan_gguf_data
from .safetensors_scanner import scan_safetensors_data
from .onnx_scanner import scan_onnx_data
from .entropy import detect_encrypted_sections
from .cvss import calculate_cvss_v3

class ScanEngine:
    """
    Advanced Mathematical & Structural File Scanner Orchestrator.
    Detects real file types based on Magic Bytes, invokes specific scanners,
    calculates Entropy and aggregates CVSS v3.1 scores.
    """

    @staticmethod
    def identify_file_type(data: bytes, filename: str) -> str:
        """Identify file type by Magic Bytes, fallback to extension."""
        if data.startswith(b"\x80\x02") or data.startswith(b"\x80\x03") or data.startswith(b"\x80\x04") or data.startswith(b"\x80\x05"):
            return "pickle"
        if data.startswith(b"GGUF"):
            return "gguf"
        # SafeTensors doesn't have fixed magic bytes, but starts with 8-byte uint64 length.
        # Check if extension is safetensors
        if filename.endswith(".safetensors"):
            return "safetensors"
        if data.startswith(b"\x08") and b"onnx" in data[:100]:
            return "onnx"
            
        # Fallback to extension
        ext = filename.split('.')[-1].lower()
        if ext in ['pkl', 'pickle', 'pt', 'pth', 'bin']:
            return "pickle"
        if ext == 'gguf':
            return "gguf"
        if ext == 'onnx':
            return "onnx"
            
        return "unknown"

    @staticmethod
    def scan(data: bytes, filename: str) -> Dict[str, Any]:
        """
        Perform a full advanced scan on the model file.
        Returns the unified results.
        """
        file_type = ScanEngine.identify_file_type(data, filename)
        threats = []
        
        # 1. Type-Specific Structural Scan
        if file_type == "pickle":
            threats.extend(scan_pickle_data(data))
        elif file_type == "gguf":
            threats.extend(scan_gguf_data(data))
        elif file_type == "safetensors":
            threats.extend(scan_safetensors_data(data))
        elif file_type == "onnx":
            threats.extend(scan_onnx_data(data))
        else:
            # Fallback generic scan
            threats.extend(scan_pickle_data(data)) # Generic pattern matching is inside pkl_scanner

        # 2. Global Entropy Check (if not already handled extensively by type scanner)
        if file_type not in ["onnx", "safetensors"]: # ONNX and safetensors handle it internally for specific areas
            entropy_threats = detect_encrypted_sections(data, chunk_size=8192, threshold=7.8)
            threats.extend(entropy_threats)

        # 3. Aggregate CVSS Score
        max_cvss = 0.0
        final_severity = "None"
        
        for t in threats:
            if t.get("cvss_score", 0.0) > max_cvss:
                max_cvss = t["cvss_score"]
                final_severity = t.get("severity", "None")

        # Sort threats by severity
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "None": 0}
        threats.sort(key=lambda x: severity_order.get(x.get("severity", "None").lower(), 0), reverse=True)

        return {
            "status": "danger" if threats else "safe",
            "file_type": file_type,
            "cvss_score": max_cvss,
            "severity": final_severity,
            "threats_found": len(threats),
            "threats": threats,
            "details": f"Analyzed {len(data)} bytes. Found {len(threats)} potential threats."
        }
