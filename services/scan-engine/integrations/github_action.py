"""Bounded Hugging Face download and synchronous CI scan integration.

The pipeline stays self-contained because ``main.py`` imports this module
through the integrations router; importing the API helpers here would create a
circular dependency.
"""
import logging
import os
import tempfile
import uuid
from typing import Any
from urllib.parse import unquote, urlparse

import httpx

from database import AsyncSessionLocal, ScanRecord
from input_security import (
    InputSecurityError,
    sanitize_filename,
    secure_hf_stream,
    validate_hf_download_url,
    validate_model_header,
)

logger = logging.getLogger("aegisml.github_action")

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

    try:
        url = validate_hf_download_url(url, initial=True)
    except InputSecurityError as exc:
        raise GitHubScanError(400, str(exc)) from exc

    parsed = urlparse(url)
    path_parts = parsed.path.rstrip("/").split("/")
    raw_filename = unquote(path_parts[-1]) if path_parts else ""
    if not raw_filename:
        raise GitHubScanError(400, "Could not determine filename from model_url")
    filename = sanitize_filename(raw_filename)
    if filename == "unknown":
        raise GitHubScanError(400, "Could not determine filename from model_url")

    ext = os.path.splitext(filename)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise GitHubScanError(
            400,
            f"Unsupported file extension '{ext}'. Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}",
        )
    return url, filename, ext


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
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=False) as client:
            hf_token = os.getenv("HF_TOKEN")
            headers = {"Authorization": f"Bearer {hf_token}"} if hf_token else {}
            async with secure_hf_stream(client, validated_url, headers=headers) as response:
                if response.status_code != 200:
                    raise GitHubScanError(
                        502, f"Failed to download model: HuggingFace returned HTTP {response.status_code}"
                    )
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        declared_size = int(content_length)
                    except ValueError:
                        pass
                    else:
                        if declared_size < 0:
                            raise GitHubScanError(502, "HuggingFace returned an invalid download size")
                        if declared_size > CI_MAX_FILE_SIZE:
                            raise GitHubScanError(
                                413,
                                f"Model exceeds CI scan limit of {CI_MAX_FILE_SIZE // (1024*1024)}MB",
                            )

                with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                    # Record immediately so partial downloads are always
                    # removed if the stream errors or exceeds its size cap.
                    temp_path = tmp.name
                    downloaded = 0
                    head = b""
                    async for chunk in response.aiter_bytes(chunk_size=1024 * 1024):
                        if len(head) < 16:
                            head += chunk[: 16 - len(head)]
                        downloaded += len(chunk)
                        if downloaded > CI_MAX_FILE_SIZE:
                            raise GitHubScanError(413, "Model exceeds CI scan limit during download")
                        tmp.write(chunk)

                validate_model_header(ext, downloaded, head)

        from scanner import engine as scanner_engine
        scan_result = await scanner_engine.scan(file_path=temp_path, scan_id=scan_id, manager_ws=None)

        # The local engine owns the authoritative full-byte SHA-256 pass.
        # Reusing it avoids rereading arbitrarily large artifacts in CI.
        file_hash = scan_result["file_hash"]
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
                    "format_specific": scan_result.get("format_specific", {}),
                    "coverage": scan_result["coverage"],
                    "scan_passes": scan_result.get("scan_passes", []),
                    "file_hash": file_hash,
                    "ci_run": True,
                },
                source_type="url",
                source_url=validated_url,
                is_public=False,
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
    except InputSecurityError as exc:
        raise GitHubScanError(400, str(exc)) from exc
    except httpx.RequestError as exc:
        raise GitHubScanError(502, "Network error downloading model") from exc
    except Exception as exc:
        logger.error("CI scan %s failed (%s)", scan_id, type(exc).__name__)
        raise GitHubScanError(500, "Internal scan error") from exc
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
