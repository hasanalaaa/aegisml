"""AegisML Scan Engine — FastAPI backend for AI model malware inspection.

Endpoints:
    GET  /health              → Service health check
    POST /api/v1/scan/file    → Upload and scan a model file
    POST /api/v1/scan/hf      → Queue a Hugging Face repo scan
    GET  /api/v1/scan/{id}    → Retrieve scan result by ID
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

# ── Ensure the aegisml package is importable ─────────────────────────
# In Docker, aegisml is installed as a package.
# For local development, add the project root to sys.path.
_project_root = Path(__file__).resolve().parent.parent.parent
if _project_root not in [Path(p) for p in sys.path]:
    sys.path.insert(0, str(_project_root))

from aegisml.inspectors.base import InspectorResult
from aegisml.inspectors.gguf_inspector import GGUFInspector
from aegisml.inspectors.static_inspector import StaticInspector
from aegisml.inspectors.safetensors_inspector import SafeTensorsInspector

from models import (
    Finding,
    HFScanQueued,
    HFScanRequest,
    HealthResponse,
    ScanResult,
    ScanStatus,
    SeverityLevel,
)

# ── App setup ────────────────────────────────────────────────────────

app = FastAPI(
    title="AegisML Scan Engine",
    description="AI Model Malware Inspector — REST API for scanning model files.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory scan store ─────────────────────────────────────────────
# Maps scan_id → ScanResult dict.  Will be replaced with a database later.
_scan_store: dict[str, dict[str, Any]] = {}

# ── Inspector registry ───────────────────────────────────────────────
_FORMAT_MAP: dict[str, dict[str, Any]] = {
    ".gguf":        {"cls": GGUFInspector,       "label": "gguf"},
    ".pkl":         {"cls": StaticInspector,      "label": "pickle"},
    ".pickle":      {"cls": StaticInspector,      "label": "pickle"},
    ".pt":          {"cls": StaticInspector,      "label": "pytorch"},
    ".pth":         {"cls": StaticInspector,      "label": "pytorch"},
    ".safetensors": {"cls": SafeTensorsInspector, "label": "safetensors"},
}


def _generate_scan_id() -> str:
    """Generate a short unique scan identifier."""
    return f"scan_{uuid.uuid4().hex[:12]}"


def _inspector_result_to_api(
    result: InspectorResult,
    scan_id: str,
    duration_ms: float,
    model_format: str | None,
    filename: str | None,
) -> dict[str, Any]:
    """Convert an InspectorResult to an API-compatible dict."""
    findings = [
        Finding(
            type=f.get("type", "unknown"),
            severity=f.get("severity", "clean"),
            description=f.get("detail", ""),
            pattern=f.get("pattern"),
        ).model_dump()
        for f in result.findings
    ]

    return ScanResult(
        scan_id=scan_id,
        status=ScanStatus.completed,
        risk_score=result.risk_score,
        severity=SeverityLevel(result.severity),
        findings=[Finding(**f) for f in findings],
        duration_ms=round(duration_ms, 2),
        model_format=model_format,
        filename=filename,
    ).model_dump()


# ── Routes ───────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check() -> HealthResponse:
    """Service health check."""
    return HealthResponse()


@app.post("/api/v1/scan/file", response_model=ScanResult, tags=["Scan"])
async def scan_file(file: UploadFile = File(...)) -> dict[str, Any]:
    """Upload a model file, scan it, and return the result.

    The file is saved to a temporary directory, inspected with the
    appropriate format-specific inspector, and then deleted.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required.")

    suffix = Path(file.filename).suffix.lower()
    fmt_entry = _FORMAT_MAP.get(suffix)

    if fmt_entry is None:
        supported = ", ".join(sorted(_FORMAT_MAP.keys()))
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported file extension '{suffix}'. "
                f"Supported formats: {supported}"
            ),
        )

    scan_id = _generate_scan_id()
    tmp_path: str | None = None

    try:
        # Save uploaded file to a temp location
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=suffix, prefix="aegisml_"
        ) as tmp:
            tmp_path = tmp.name
            contents = await file.read()
            tmp.write(contents)

        # Run the inspector
        inspector = fmt_entry["cls"]()
        start = time.perf_counter()
        result: InspectorResult = inspector.inspect(tmp_path)
        duration_ms = (time.perf_counter() - start) * 1000.0

        # Build API response
        api_result = _inspector_result_to_api(
            result=result,
            scan_id=scan_id,
            duration_ms=duration_ms,
            model_format=fmt_entry["label"],
            filename=file.filename,
        )

        # Store for later retrieval
        _scan_store[scan_id] = api_result

        return api_result

    finally:
        # Always clean up the temp file
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


@app.post("/api/v1/scan/hf", response_model=HFScanQueued, tags=["Scan"])
async def scan_huggingface(request: HFScanRequest) -> dict[str, Any]:
    """Queue a scan for a Hugging Face model repository.

    Returns immediately with a scan_id that can be polled via
    GET /api/v1/scan/{scan_id}.

    NOTE: Actual HF download + scan is not yet implemented.
    This endpoint currently creates a queued placeholder.
    """
    scan_id = _generate_scan_id()

    # Store a queued placeholder
    _scan_store[scan_id] = ScanResult(
        scan_id=scan_id,
        status=ScanStatus.queued,
        risk_score=0.0,
        severity=SeverityLevel.clean,
        findings=[],
        duration_ms=None,
        model_format=None,
        filename=request.repo_id,
    ).model_dump()

    return HFScanQueued(
        scan_id=scan_id,
        status=ScanStatus.queued,
        repo_id=request.repo_id,
    ).model_dump()


@app.get("/api/v1/scan/{scan_id}", response_model=ScanResult, tags=["Scan"])
async def get_scan_result(scan_id: str) -> dict[str, Any]:
    """Retrieve a scan result by its ID.

    Returns the full scan result if found, or 404 if the scan_id
    is unknown.
    """
    result = _scan_store.get(scan_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"Scan '{scan_id}' not found.",
        )
    return result
