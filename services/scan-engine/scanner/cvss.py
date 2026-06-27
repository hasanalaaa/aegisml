from typing import Tuple, Dict

# CVSS v3.1 Metrics and Weights
# Attack Vector (AV)
AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
# Attack Complexity (AC)
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
# Privileges Required (PR) -> varies if Scope is changed
PR_WEIGHTS = {
    "N": {"U": 0.85, "C": 0.85},
    "L": {"U": 0.62, "C": 0.68},
    "H": {"U": 0.27, "C": 0.50}
}
# User Interaction (UI)
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
# Scope (S) -> does not have direct weight, impacts PR and overall score calculations

# Confidentiality (C), Integrity (I), Availability (A)
CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}

def roundup(val: float) -> float:
    """CVSS v3.1 specific roundup function: round up to the nearest 0.1"""
    return (int(val * 100000) + (10000 if int(val * 100000) % 100000 > 0 else 0)) // 10000 / 10.0

def calculate_cvss_v3(av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> Tuple[float, str, str]:
    """
    Calculate CVSS v3.1 Base Score.
    Returns: (score, severity, vector_string)
    """
    # 1. Base Metrics Values
    exploitability_subscore = 8.22 * AV_WEIGHTS[av] * AC_WEIGHTS[ac] * PR_WEIGHTS[pr][s] * UI_WEIGHTS[ui]
    
    iss = 1 - ((1 - CIA_WEIGHTS[c]) * (1 - CIA_WEIGHTS[i]) * (1 - CIA_WEIGHTS[a]))
    
    if s == "U":
        impact_subscore = 6.42 * iss
    else:
        impact_subscore = 7.52 * (iss - 0.029) - 3.25 * ((iss * 0.02) ** 15)
        
    # 2. Base Score Calculation
    if impact_subscore <= 0:
        base_score = 0.0
    else:
        if s == "U":
            base_score = roundup(min(impact_subscore + exploitability_subscore, 10.0))
        else:
            base_score = roundup(min(1.08 * (impact_subscore + exploitability_subscore), 10.0))
            
    # 3. Determine Severity
    if base_score == 0.0:
        severity = "None"
    elif 0.1 <= base_score <= 3.9:
        severity = "Low"
    elif 4.0 <= base_score <= 6.9:
        severity = "Medium"
    elif 7.0 <= base_score <= 8.9:
        severity = "High"
    else:
        severity = "Critical"
        
    # 4. Generate Vector String
    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    
    return float(base_score), severity.lower(), vector

def calculate_from_dict(cvss_dict: Dict[str, str]) -> Tuple[float, str, str]:
    """Helper to calculate from dictionary."""
    return calculate_cvss_v3(
        av=cvss_dict.get("av", "L"),
        ac=cvss_dict.get("ac", "L"),
        pr=cvss_dict.get("pr", "N"),
        ui=cvss_dict.get("ui", "N"),
        s=cvss_dict.get("s", "U"),
        c=cvss_dict.get("c", "H"),
        i=cvss_dict.get("i", "H"),
        a=cvss_dict.get("a", "H")
    )
