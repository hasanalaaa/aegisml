"""
AegisML GitHub Actions CI/CD Integration — Real Scan Pipeline

Previously `handle_github_scan()` was a hardcoded mock: it returned a fixed
"HIGH" risk_level and a fake report_url for every single request regardless
of the model actually being scanned, which means every CI pipeline using the
official GitHub Action either always failed (false positive blocking every
merge) or, if `fail_on` was set loosely, always silently "passed" without
ever actually scanning anything. This is a real engineering bug now fixed:
this module downloads the model, runs it through the real ScanEngine, and
persists + returns a genuine verdict.

This module is intentionally self-contained (downloads + scans inline rather
than reusing main.py's background-task helpers) to avoid a circular import:
main.py imports integrations.router, which imports this module, so this
module cannot import back from main.py.
"""
import hashlib
import logging
import os
import tempfile
import uuid
from typing import Any
from urllib.parse import urlparse

import httpx

from database import AsyncSessionLocal, ScanRecord

logger = logging.getLogger("aegisml.github_action")

ALLOWED_HOSTS = frozenset({"huggingface.co", "www.huggingface.co"})
SUPPORTED_EXTENSIONS = frozenset(
    {".gguf", ".safetensors", ".pkl", ".pickle", ".pt", ".pth", ".bin", ".onnx"}
)
CI_MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1GB cap for CI runs (keep pipelines fast)

# Severity ranking used to compare the scan's worst finding against the
# user-supplied `fail_on` threshold (e.g. fail_on="HIGH" fails the build on
# HIGH or CRITICAL findings, but lets MEDIUM/LOW through).
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
RISK_LEVEL_TO_SEVERITY = {
    "clean": "LOW",
    "suspicious": "MEDIUM",
    "malicious": "HIGH",
    "critical": "CRITICAL",
}


class GitHubScanError(Exception):
    """Raised for any condition that should surface as a 4xx to the Action."""
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def _validate_model_url(url: str) -> tuple[str, str, str]:
    url = (url or "").strip()
    if not url:
        raise GitHubScanError(400, "model_url is required")
    if len(url) > 2048:
        raise GitHubScanError(400, "model_url too long (max 2048 chars)")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise GitHubScanError(400, "Only HTTP/HTTPS URLs are allowed")

    hostname = (parsed.hostname or "").lower()
    if hostname not in ALLOWED_HOSTS:
        raise GitHubScanError(400, "Only HuggingFace URLs are allowed for CI scans")

    path_parts = parsed.path.rstrip("/").split("/")
    raw_filename = path_parts[-1].split("?")[0] if path_parts else ""
    if not raw_filename:
        raise GitHubScanError(400, "Could not determine filename from model_url")

    ext = os.path.splitext(raw_filename)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise GitHubScanError(
            400,
            f"Unsupported file extension '{ext}'. Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}",
        )
    return url, raw_filename, ext


async def handle_github_scan(url: str, fail_on: str) -> dict[str, Any]:
    """Download a model from HuggingFace and run a real, synchronous scan
    for use in a CI/CD gate. Raises GitHubScanError for invalid input or
    download failures, which the router translates into HTTP error codes."""
    fail_on_normalized = (fail_on or "CRITICAL").upper()
    if fail_on_normalized not in SEVERITY_RANK:
        fail_on_normalized = "CRITICAL"

    validated_url, filename, ext = _validate_model_url(url)
    scan_id = str(uuid.uuid4())
    temp_path: str | None = None

    try:
        sha256 = hashlib.sha256()
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=True, max_redirects=5) as client:
            hf_token = os.getenv("HF_TOKEN")
            headers = {"Authorization": f"Bearer {hf_token}"} if hf_token else {}
            async with client.stream("GET", validated_url, headers=headers) as response:
                if response.status_code != 200:
                    raise GitHubScanError(
                        502, f"Failed to download model: HuggingFace returned HTTP {response.status_code}"
                    )
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        if int(content_length) > CI_MAX_FILE_SIZE:
                            raise GitHubScanError(
                                413,
                                f"Model exceeds CI scan limit of {CI_MAX_FILE_SIZE // (1024*1024)}MB",
                            )
                    except ValueError:
                        pass

                with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                    downloaded = 0
                    async for chunk in response.aiter_bytes(chunk_size=1024 * 1024):
                        downloaded += len(chunk)
                        if downloaded > CI_MAX_FILE_SIZE:
                            raise GitHubScanError(413, "Model exceeds CI scan limit during download")
                        sha256.update(chunk)
                        tmp.write(chunk)
                    temp_path = tmp.name

        from scanner import engine as scanner_engine
        scan_result = await scanner_engine.scan(file_path=temp_path, scan_id=scan_id, manager_ws=None)

        file_hash = sha256.hexdigest()
        engine_verdict = scan_result["verdict"]  # safe / suspicious / dangerous / critical
        risk_level_map = {
            "safe": "clean", "suspicious": "suspicious",
            "dangerous": "malicious", "critical": "critical",
        }
        risk_level = risk_level_map.get(engine_verdict, "suspicious")
        finding_severity = RISK_LEVEL_TO_SEVERITY[risk_level]

        # Persist so the CI run is independently auditable via the normal
        # scan UI/API — the report_url returned below is therefore real,
        # not a hardcoded placeholder.
        async with AsyncSessionLocal() as db:
            record = ScanRecord(
                scan_id=scan_id,
                filename=filename,
                file_size=downloaded,
                file_extension=ext,
                file_hash=file_hash,
                risk_score=round(scan_result["highest_cvss"] * 10, 1),
                risk_level=risk_level,
                threats=scan_result["threats"],
                metadata_info={
                    "format_detected": scan_result["format_detected"],
                    "entropy_analysis": scan_result["entropy_analysis"],
                    "patterns_checked": scan_result.get("patterns_checked", 0),
                    "ci_run": True,
                },
                source_type="url",
                source_url=validated_url,
                is_public=True,
            )
            db.add(record)
            await db.commit()

        passed = SEVERITY_RANK[finding_severity] < SEVERITY_RANK[fail_on_normalized]

        frontend_url = os.getenv("FRONTEND_URL", "https://aegisml.vercel.app")

        return {
            "scan_id": scan_id,
            "model_url": validated_url,
            "filename": filename,
            "status": "completed",
            "risk_level": finding_severity,
            "threat_count": scan_result["threat_count"],
            "highest_cvss": scan_result["highest_cvss"],
            "fail_on_threshold": fail_on_normalized,
            "verdict": "passed" if passed else "failed",
            "report_url": f"{frontend_url}/scan/{scan_id}",
        }

    except GitHubScanError:
        raise
    except httpx.RequestError as e:
        raise GitHubScanError(502, f"Network error downloading model: {e}")
    except Exception as e:
        logger.error("CI scan failed for %s: %s", url, e, exc_info=True)
        raise GitHubScanError(500, f"Internal scan error: {e}")
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
