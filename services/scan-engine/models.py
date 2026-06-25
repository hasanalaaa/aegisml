"""Pydantic models for the AegisML Scan Engine API."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────

class SeverityLevel(str, Enum):
    """Risk severity classification."""
    clean = "clean"
    suspicious = "suspicious"
    malicious = "malicious"
    critical = "critical"


class ScanStatus(str, Enum):
    """Lifecycle status of a scan job."""
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


# ── Request models ───────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """Request body for initiating a scan.

    Provide either a local model_path or a Hugging Face repo_id.
    """
    model_path: Optional[str] = Field(
        default=None,
        description="Local filesystem path to the model file.",
        examples=["/models/llama-7b.gguf"],
    )
    hf_repo_id: Optional[str] = Field(
        default=None,
        description="Hugging Face repository ID (org/model).",
        examples=["TheBloke/Llama-2-7B-GGUF"],
    )


class HFScanRequest(BaseModel):
    """Request body for scanning a Hugging Face model."""
    repo_id: str = Field(
        ...,
        description="Hugging Face repository ID (org/model).",
        examples=["TheBloke/Llama-2-7B-GGUF"],
    )


# ── Response models ──────────────────────────────────────────────────

class Finding(BaseModel):
    """A single finding from the inspection process."""
    type: str = Field(
        ...,
        description="Finding category identifier.",
        examples=["dangerous_pattern", "invalid_magic", "chat_template_injection"],
    )
    severity: str = Field(
        ...,
        description="Severity level of this finding.",
        examples=["clean", "suspicious", "malicious", "critical"],
    )
    description: str = Field(
        ...,
        description="Human-readable description of the finding.",
    )
    pattern: Optional[str] = Field(
        default=None,
        description="The specific pattern that was matched, if applicable.",
        examples=["os.system", "__reduce__", "eval()"],
    )


class ScanResult(BaseModel):
    """Complete result of a model file scan."""
    scan_id: str = Field(
        ...,
        description="Unique identifier for this scan.",
        examples=["scan_a1b2c3d4"],
    )
    status: ScanStatus = Field(
        ...,
        description="Current status of the scan.",
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Overall risk score from 0 (safe) to 100 (critical).",
    )
    severity: SeverityLevel = Field(
        default=SeverityLevel.clean,
        description="Overall severity classification.",
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="List of individual findings from the scan.",
    )
    duration_ms: Optional[float] = Field(
        default=None,
        description="Scan duration in milliseconds.",
    )
    model_format: Optional[str] = Field(
        default=None,
        description="Detected model file format.",
        examples=["gguf", "pickle", "safetensors"],
    )
    filename: Optional[str] = Field(
        default=None,
        description="Original filename of the scanned file.",
    )


class HFScanQueued(BaseModel):
    """Response when a Hugging Face scan is queued."""
    scan_id: str = Field(
        ...,
        description="Unique identifier to poll for results.",
    )
    status: ScanStatus = Field(
        default=ScanStatus.queued,
        description="Initial status (always 'queued').",
    )
    repo_id: str = Field(
        ...,
        description="The Hugging Face repo that will be scanned.",
    )


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "ok"
    version: str = "0.1.0"
    service: str = "aegisml-scan-engine"
