"""Async service adapter for the trusted offline :mod:`aegisml_scanner`.

The local scanner owns byte evidence, offsets, entropy, format inspection,
coverage, and SHA-256. This module adds only service admission, an async-safe
progress bridge, and the response shape expected by existing API consumers.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import Future
import logging
import os
from typing import Any, Optional

from aegisml_scanner import AegisML, ScanResult
from aegisml_scanner.scanner import DEFAULT_CHUNK_SIZE

from .admission import AdmissionTimeout, get_admission_controller


logger = logging.getLogger("aegisml.scanner.engine")


class IncompleteScanError(RuntimeError):
    """The scanner could not produce the complete evidence required for safety."""

    def __init__(self, scan_id: str, coverage: dict[str, Any], errors: list[str]):
        self.scan_id = scan_id
        self.coverage = coverage
        self.errors = errors
        super().__init__(
            f"scan {scan_id} has incomplete coverage: "
            f"{coverage!r}; errors={errors!r}"
        )


class ScanEngine:
    """Preserve the async service contract while delegating static analysis."""

    async def scan(
        self,
        file_path: str,
        scan_id: str,
        manager_ws: Optional[Any] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> dict[str, Any]:
        file_size = os.path.getsize(file_path)
        await self._emit(
            manager_ws,
            scan_id,
            "header_check",
            10,
            "Validating artifact and preparing bounded local scan...",
            0,
        )
        await self._emit(
            manager_ws,
            scan_id,
            "signature_scan",
            25,
            "Running full-byte evidence scan...",
            0,
        )

        loop = asyncio.get_running_loop()
        progress_futures: list[Future[Any]] = []
        last_progress = -1

        def bridge_progress(bytes_scanned: int, total_bytes: int) -> None:
            """Schedule bounded progress updates back onto the service loop."""
            nonlocal last_progress
            ratio = bytes_scanned / total_bytes if total_bytes else 1.0
            progress = 25 + min(55, int(ratio * 55))
            if progress <= last_progress:
                return
            last_progress = progress
            progress_futures.append(
                asyncio.run_coroutine_threadsafe(
                    self._emit(
                        manager_ws,
                        scan_id,
                        "signature_scan",
                        progress,
                        "Scanning artifact bytes...",
                        0,
                        bytes_scanned=bytes_scanned,
                        total_bytes=total_bytes,
                    ),
                    loop,
                )
            )

        local_scanner = AegisML(
            api_url="",
            anthropic_api_key="",
            chunk_size=chunk_size,
            progress=bridge_progress if manager_ws is not None else None,
        )
        admission = get_admission_controller()
        try:
            async with admission.admit(file_size, scan_id):
                local_result = await asyncio.to_thread(local_scanner.scan, file_path)
        except AdmissionTimeout as exc:
            logger.warning("Scan %s rejected by admission control: %s", scan_id, exc)
            await self._emit(
                manager_ws,
                scan_id,
                "failed",
                100,
                "Scanner is at capacity for this file size. Please retry.",
                0,
            )
            raise
        except Exception:
            await self._emit(
                manager_ws,
                scan_id,
                "failed",
                100,
                "Local evidence scan failed.",
                0,
            )
            raise
        finally:
            if progress_futures:
                await asyncio.gather(
                    *(asyncio.wrap_future(item) for item in progress_futures),
                    return_exceptions=True,
                )

        await self._emit(
            manager_ws,
            scan_id,
            "structure_scan",
            85,
            "Validating format-specific evidence and coverage...",
            len(local_result.threats),
        )

        metadata = dict(local_result.metadata)
        coverage = dict(metadata.get("coverage") or {})
        errors = list(metadata.get("errors") or [])
        if coverage.get("complete") is not True:
            await self._emit(
                manager_ws,
                scan_id,
                "failed",
                100,
                "Scan coverage is incomplete; no safety verdict was issued.",
                len(local_result.threats),
            )
            raise IncompleteScanError(scan_id, coverage, errors)

        # The service owns the terminal event because it still has to apply IOC
        # enrichment and persist the report. Emitting ``complete`` here would
        # let clients race a result that does not exist yet.
        return self._adapt(local_result, metadata, coverage, file_size)

    @staticmethod
    def _adapt(
        result: ScanResult,
        metadata: dict[str, Any],
        coverage: dict[str, Any],
        file_size: int,
    ) -> dict[str, Any]:
        threats: list[dict[str, Any]] = []
        for threat in result.threats:
            item = threat.to_dict()
            item.setdefault("name", item.get("pattern") or item.get("id", "finding"))
            item.setdefault("references", [])
            threats.append(item)

        highest_cvss = max(
            (float(item.get("cvss", 0.0)) for item in threats),
            default=0.0,
        )
        entropy_state = coverage.get("entropy", "incomplete")
        entropy_analysis = {
            "overall_entropy": float(metadata.get("entropy", 0.0)),
            "suspicious_sections": [],
            # Entropy is evidence, not a threat verdict. Quantized/compressed
            # weights are commonly high entropy and must not create findings.
            "risk_level": "informational",
            "sampled": entropy_state == "sampled",
            "bytes_analyzed": int(metadata.get("entropy_bytes_analyzed", 0)),
            "total_bytes": int(metadata.get("total_bytes", file_size)),
            "coverage": entropy_state,
            "error": None,
        }
        verdict = result.verdict.lower()
        if verdict not in {"safe", "suspicious", "dangerous", "critical"}:
            raise IncompleteScanError("unknown", coverage, [f"invalid_verdict:{verdict}"])

        return {
            "verdict": verdict,
            "threat_count": len(threats),
            "threats": threats,
            "entropy_analysis": entropy_analysis,
            "format_detected": metadata.get("format_detected", "generic"),
            "highest_cvss": round(highest_cvss, 1),
            "file_hash": metadata["sha256"],
            "file_size": file_size,
            "patterns_checked": int(metadata.get("patterns_checked", 0)),
            "signatures_checked": int(metadata.get("signatures_checked", 0)),
            "format_specific": dict(metadata.get("format") or {}),
            "coverage": coverage,
            # v3 evidence: what the engine actually looked at, so the UI can show
            # provenance instead of a bare score.
            "engine_version": metadata.get("engine_version", ""),
            "ruleset_version": metadata.get("ruleset_version", ""),
            "signature_tier": metadata.get("signature_tier", ""),
            "structure": dict(metadata.get("regions") or {}),
            "byte_profile": dict(metadata.get("profile") or {}),
            "tensor_forensics": metadata.get("tensor_forensics"),
            "embedded_analyzed": int(metadata.get("embedded_analyzed", 0)),
            "throughput_mib_s": metadata.get("throughput_mib_s", 0),
            "scan_passes": [
                "structural_inventory",
                "full_byte_evidence",
                "nested_payloads",
                "tensor_forensics",
                "correlation_and_scoring",
            ],
        }

    async def _emit(
        self,
        manager_ws: Optional[Any],
        scan_id: str,
        stage: str,
        progress: int,
        message: str,
        threat_count: int,
        **evidence: Any,
    ) -> None:
        if manager_ws is None:
            return
        payload = {
            "stage": stage,
            "progress": progress,
            "message": message,
            "threat_count": threat_count,
            **evidence,
        }
        try:
            await manager_ws.send_progress(scan_id, payload)
        except Exception:
            # Progress transport is best-effort and cannot weaken scan results.
            logger.debug("Progress delivery failed for scan %s", scan_id, exc_info=True)


engine = ScanEngine()
