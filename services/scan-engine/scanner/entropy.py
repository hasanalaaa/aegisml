import math
from typing import List, Dict, Any

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of a byte string."""
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    
    # Calculate frequency of each byte (0-255)
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
        
    for count in counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
        
    return entropy

def detect_encrypted_sections(data: bytes, chunk_size: int = 4096, threshold: float = 7.5) -> List[Dict[str, Any]]:
    """
    Scans data in chunks to find sections with high entropy (> 7.5).
    High entropy usually indicates encrypted, compressed, or heavily obfuscated payloads.
    """
    results = []
    
    if len(data) < 256:
        # Too small to have meaningful entropy analysis
        return results

    for offset in range(0, len(data), chunk_size):
        chunk = data[offset:offset+chunk_size]
        
        # We only care if chunk is decently sized
        if len(chunk) < 64:
            continue
            
        entropy = calculate_shannon_entropy(chunk)
        if entropy > threshold:
            results.append({
                "type": "possible_encrypted_payload",
                "offset": offset,
                "size": len(chunk),
                "entropy": round(entropy, 3),
                "severity": "high",
                "desc": f"High entropy chunk detected ({round(entropy, 3)}). Possible encrypted payload."
            })
            
    return results
