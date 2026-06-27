import re
from typing import List, Dict, Any
import jinja2
from jinja2 import Environment, meta

from .patterns import COMPILED_PATTERNS
from .cvss import calculate_from_dict

def scan_gguf_data(data: bytes) -> List[Dict[str, Any]]:
    """
    Scans GGUF files.
    GGUF files can contain malicious Jinja2 templates in tokenizer.chat_template
    that might lead to Server-Side Template Injection (SSTI) if executed unsafely by the runner.
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

    # 2. Extract potential Jinja2 templates (SSTI check)
    # We look for blocks containing {% ... %} or {{ ... }}
    # GGUF chat templates are usually stored as strings in KV metadata.
    # To avoid writing a full binary parser for GGUF here, we extract string-like blobs 
    # that look like Jinja templates and parse their AST.
    
    template_pattern = re.compile(b"(\\{%[\\s\\S]*?%\\}|\\{\\{[\\s\\S]*?\\}\\})")
    
    found_templates = set()
    for match in template_pattern.finditer(data):
        template_str = match.group(1).decode("utf-8", errors="ignore")
        found_templates.add(template_str)
        
    env = Environment()
    for template_str in found_templates:
        try:
            ast = env.parse(template_str)
            # Find undeclared variables
            variables = meta.find_undeclared_variables(ast)
            
            dangerous_globals = {"system", "os", "subprocess", "__class__", "__subclasses__", "globals"}
            intersect = dangerous_globals.intersection(variables)
            
            if intersect:
                threats.append({
                    "type": "ssti_risk",
                    "category": "command_injection",
                    "offset": 0,
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "desc": f"Jinja2 Template Injection risk detected. Dangerous variables requested: {intersect}"
                })
        except Exception:
            # Not a valid Jinja template or unparseable
            pass
            
    return threats
