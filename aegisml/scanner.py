from __future__ import annotations
import json, os, uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Union

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False

SUPPORTED_EXTENSIONS = {".gguf", ".safetensors", ".pkl", ".pickle", ".pt", ".pth"}

THREAT_PATTERNS: List[tuple] = [
    ("os.system",    "critical", "code_execution",  "System command execution"),
    ("subprocess",   "high",     "code_execution",  "External process execution"),
    ("eval",         "critical", "code_execution",  "Dynamic code evaluation"),
    ("exec",         "critical", "code_execution",  "Code execution function"),
    ("pickle.loads", "high",     "deserialization", "Unsafe pickle deserialization"),
    ("__reduce__",   "critical", "deserialization", "Pickle execution hook"),
    ("import os",    "high",     "system_access",   "OS module import"),
    ("shutil",       "medium",   "file_operations", "File system operations"),
    ("base64",       "medium",   "obfuscation",     "Potential code obfuscation"),
    ("socket",       "high",     "network",         "Network socket access"),
    ("requests",     "medium",   "network",         "HTTP request capability"),
    ("urllib",       "medium",   "network",         "URL access capability"),
    ("__import__",   "high",     "code_execution",  "Dynamic import"),
    ("ctypes",       "critical", "system_access",   "Low-level system access"),
]

SEVERITY_SCORES = {"critical": 35, "high": 20, "medium": 10, "low": 5}
BASE_RISK = {".pkl": 30, ".pickle": 30, ".pt": 25, ".pth": 25, ".gguf": 5, ".safetensors": 3}


@dataclass
class Threat:
    pattern: str
    severity: str
    description: str
    category: str
    location: str = ""

    def to_dict(self) -> dict:
        return {"pattern": self.pattern, "severity": self.severity,
                "description": self.description, "category": self.category, "location": self.location}


@dataclass
class ScanResult:
    scan_id: str
    filename: str
    risk_score: float
    risk_level: str
    threats: List[Threat] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    ai_analysis: Optional[dict] = None
    source_url: Optional[str] = None

    @property
    def is_safe(self) -> bool:
        return self.risk_score < 30

    @property
    def verdict(self) -> str:
        if self.ai_analysis:
            return self.ai_analysis.get("verdict", "UNKNOWN")
        if self.risk_score < 30: return "SAFE"
        if self.risk_score < 60: return "SUSPICIOUS"
        if self.risk_score < 85: return "DANGEROUS"
        return "CRITICAL"

    def to_dict(self) -> dict:
        return {"scan_id": self.scan_id, "filename": self.filename,
                "risk_score": self.risk_score, "risk_level": self.risk_level,
                "threats": [t.to_dict() for t in self.threats],
                "metadata": self.metadata, "ai_analysis": self.ai_analysis,
                "source_url": self.source_url}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def __repr__(self) -> str:
        return f"ScanResult(file={self.filename!r}, score={self.risk_score}, level={self.risk_level!r}, threats={len(self.threats)})"


class AegisML:
    def __init__(self, api_url: Optional[str] = None, api_key: Optional[str] = None,
                 anthropic_api_key: Optional[str] = None, timeout: int = 300) -> None:
        self.api_url = api_url or os.getenv("AEGISML_API_URL", "")
        self.api_key = api_key or os.getenv("AEGISML_API_KEY", "")
        self.anthropic_api_key = anthropic_api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.timeout = timeout

    def scan(self, file_path: Union[str, Path]) -> ScanResult:
        path = Path(file_path)
        if not path.exists(): raise FileNotFoundError(f"File not found: {path}")
        if not path.is_file(): raise ValueError(f"Not a file: {path}")
        ext = path.suffix.lower()
        if ext not in SUPPORTED_EXTENSIONS:
            raise ValueError(f"Unsupported format: {ext}")
        if self.api_url and _HAS_HTTPX:
            return self._scan_via_api(path)
        return self._scan_local(path)

    def scan_url(self, url: str) -> ScanResult:
        if not self.api_url: raise ValueError("api_url is required for URL scanning")
        if not _HAS_HTTPX: raise RuntimeError("httpx is required: pip install httpx")
        return self._scan_url_via_api(url)

    def scan_directory(self, dir_path: Union[str, Path]) -> List[ScanResult]:
        path = Path(dir_path)
        results: List[ScanResult] = []
        for f in path.rglob("*"):
            if f.is_file() and f.suffix.lower() in SUPPORTED_EXTENSIONS:
                try:
                    results.append(self.scan(f))
                except Exception as e:
                    print(f"Warning: Could not scan {f}: {e}")
        return results

    def _scan_local(self, path: Path) -> ScanResult:
        scan_id = str(uuid.uuid4())
        ext = path.suffix.lower()
        file_size = path.stat().st_size
        threats: List[Threat] = []
        try:
            with open(path, "rb") as f:
                content = f.read(min(file_size, 10 * 1024 * 1024))
            text_content = content.decode("utf-8", errors="ignore")
            for pattern, severity, category, description in THREAT_PATTERNS:
                if pattern.encode() in content or pattern in text_content:
                    threats.append(Threat(pattern=pattern, severity=severity,
                                          description=description, category=category, location=str(path)))
        except Exception:
            pass
        base_risk = BASE_RISK.get(ext, 15)
        threat_score = sum(SEVERITY_SCORES.get(t.severity, 5) for t in threats)
        risk_score = min(100, base_risk + threat_score)
        risk_level = ("clean" if risk_score < 30 else "suspicious" if risk_score < 60
                      else "malicious" if risk_score < 85 else "critical")
        ai_analysis = None
        if self.anthropic_api_key:
            ai_analysis = self._claude_judge(scan_id, path.name, risk_score, risk_level, threats)
        return ScanResult(scan_id=scan_id, filename=path.name, risk_score=risk_score,
                          risk_level=risk_level, threats=threats,
                          metadata={"file_size": file_size, "extension": ext}, ai_analysis=ai_analysis)

    def _scan_via_api(self, path: Path) -> ScanResult:
        import httpx
        headers: dict = {}
        if self.api_key: headers["Authorization"] = f"Bearer {self.api_key}"
        with open(path, "rb") as f:
            files = {"file": (path.name, f, "application/octet-stream")}
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(f"{self.api_url}/api/v1/scan/file", files=files, headers=headers)
                resp.raise_for_status()
                data: dict = resp.json()
        return self._parse_api_result(data.get("result", data))

    def _scan_url_via_api(self, url: str) -> ScanResult:
        import httpx
        headers: dict = {"Content-Type": "application/json"}
        if self.api_key: headers["Authorization"] = f"Bearer {self.api_key}"
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(f"{self.api_url}/api/v1/scan/url", json={"url": url}, headers=headers)
            resp.raise_for_status()
            data: dict = resp.json()
        return self._parse_api_result(data.get("result", data))

    def _parse_api_result(self, data: dict) -> ScanResult:
        threats = [Threat(pattern=t.get("pattern", ""), severity=t.get("severity", "medium"),
                          description=t.get("description", ""), category=t.get("category", "unknown"),
                          location=t.get("location", "")) for t in data.get("threats", [])]
        return ScanResult(scan_id=data.get("scan_id", ""), filename=data.get("filename", ""),
                          risk_score=data.get("risk_score", 0), risk_level=data.get("risk_level", "unknown"),
                          threats=threats, metadata=data.get("metadata", {}),
                          ai_analysis=data.get("ai_analysis"), source_url=data.get("source_url"))

    def _claude_judge(self, scan_id: str, filename: str, risk_score: float,
                      risk_level: str, threats: List[Threat]) -> Optional[dict]:
        try:
            import anthropic as ant
            client = ant.Anthropic(api_key=self.anthropic_api_key)
            threat_list = [{"pattern": t.pattern, "severity": t.severity} for t in threats[:10]]
            msg = client.messages.create(
                model="claude-sonnet-4-6", max_tokens=1000,
                messages=[{"role": "user", "content": (
                    f"Analyze this AI model scan. Respond ONLY with JSON.\n"
                    f"File: {filename}, Risk: {risk_score}/100, Level: {risk_level}, "
                    f"Threats: {json.dumps(threat_list)}\n"
                    '{"verdict":"SAFE or SUSPICIOUS or DANGEROUS or CRITICAL",'
                    '"confidence":0-100,"summary_en":"...","summary_ar":"...",'
                    '"key_risks":[],"recommendation":"...","recommendation_ar":"..."}'
                )}])
            text = msg.content[0].text.replace("```json", "").replace("```", "").strip()
            return json.loads(text)
        except Exception:
            return None
