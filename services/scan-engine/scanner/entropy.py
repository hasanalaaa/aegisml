import math
from collections import Counter

def calculate_entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(c/length * math.log2(c/length) for c in counts.values())

def detect_encrypted_sections(data: bytes, chunk_size=4096) -> list[dict]:
    sections = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        ent = calculate_entropy(chunk)
        if ent > 7.5:
            sections.append({
                "offset": i,
                "size": len(chunk),
                "entropy": ent,
                "type": "possible_encrypted_payload"
            })
    return sections

def analyze(file_path: str) -> dict:
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            
        overall_entropy = calculate_entropy(data)
        suspicious_sections = detect_encrypted_sections(data)
        
        risk_level = "low"
        if overall_entropy > 7.8 or len(suspicious_sections) > 5:
            risk_level = "critical"
        elif overall_entropy > 7.5 or len(suspicious_sections) > 0:
            risk_level = "high"
            
        return {
            "overall_entropy": overall_entropy,
            "suspicious_sections": suspicious_sections,
            "risk_level": risk_level
        }
    except Exception as e:
        return {
            "overall_entropy": 0.0,
            "suspicious_sections": [],
            "risk_level": "low",
            "error": str(e)
        }
