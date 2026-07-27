"""
AegisML Scan Admission Control — size-aware scheduling

One bounded, size-aware admission layer keeps a worker process healthy under
load.  Each admitted job executes one bounded-memory local scanner pass, so
there is no nested per-pass fan-out to schedule separately.

**Size-class admission** — concurrent scans are bounded *per file-size
   class*, so a burst of multi-GB uploads cannot monopolize RAM/disk while
   small scans starve behind them (and vice versa). ARQ's ``max_jobs`` stays
   the coarse outer bound; this is the size-aware inner bound.

Everything is env-tunable without a code change:

    ADMISSION_SMALL_MAX_BYTES    default 33554432   (32 MiB)
    ADMISSION_LARGE_MIN_BYTES    default 536870912  (512 MiB)
    ADMISSION_SMALL_PERMITS      default 8
    ADMISSION_MEDIUM_PERMITS     default 3
    ADMISSION_LARGE_PERMITS      default 1
    ADMISSION_TIMEOUT_SECONDS    default 0          (0 = wait, never reject)

Loop-awareness: asyncio primitives bind to the loop they are first awaited
on. Servers run one loop per process, but tests and startup checks call
``asyncio.run()`` repeatedly — so semaphores are transparently rebuilt when
the running loop changes instead of dying with "bound to a different loop".
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from dataclasses import dataclass

logger = logging.getLogger("aegisml.scanner.admission")

SMALL, MEDIUM, LARGE = "small", "medium", "large"
_CLASSES = (SMALL, MEDIUM, LARGE)


class AdmissionTimeout(RuntimeError):
    """A scan waited longer than ADMISSION_TIMEOUT_SECONDS for a slot."""


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        logger.warning("Invalid int in env %s; using default %s", name, default)
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        logger.warning("Invalid float in env %s; using default %s", name, default)
        return default


@dataclass(frozen=True)
class AdmissionConfig:
    small_max_bytes: int
    large_min_bytes: int
    permits: dict[str, int]
    timeout_seconds: float  # 0 = wait forever

    @staticmethod
    def from_env() -> "AdmissionConfig":
        return AdmissionConfig(
            small_max_bytes=_env_int("ADMISSION_SMALL_MAX_BYTES", 32 * 1024 * 1024),
            large_min_bytes=_env_int("ADMISSION_LARGE_MIN_BYTES", 512 * 1024 * 1024),
            permits={
                SMALL: max(1, _env_int("ADMISSION_SMALL_PERMITS", 8)),
                MEDIUM: max(1, _env_int("ADMISSION_MEDIUM_PERMITS", 3)),
                LARGE: max(1, _env_int("ADMISSION_LARGE_PERMITS", 1)),
            },
            timeout_seconds=max(0.0, _env_float("ADMISSION_TIMEOUT_SECONDS", 0.0)),
        )


class AdmissionController:
    """Size-class weighted admission for scan jobs."""

    def __init__(self, config: AdmissionConfig | None = None):
        self.config = config or AdmissionConfig.from_env()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._sems: dict[str, asyncio.Semaphore] = {}
        self._in_flight = {c: 0 for c in _CLASSES}
        self._waiting = {c: 0 for c in _CLASSES}

    def classify(self, file_size: int) -> str:
        if file_size >= self.config.large_min_bytes:
            return LARGE
        if file_size > self.config.small_max_bytes:
            return MEDIUM
        return SMALL

    def _sem(self, size_class: str) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        if loop is not self._loop:
            # New/changed loop (fresh asyncio.run): rebuild primitives.
            self._loop = loop
            self._sems = {
                c: asyncio.Semaphore(self.config.permits[c]) for c in _CLASSES
            }
        return self._sems[size_class]

    @contextlib.asynccontextmanager
    async def admit(self, file_size: int, scan_id: str = ""):
        """``async with controller.admit(size, scan_id):`` around heavy work.

        Blocks until a slot for the file's size class frees up. With a
        configured timeout, raises :class:`AdmissionTimeout` instead of
        queueing forever (surfaced by the caller as a failed scan).
        """
        size_class = self.classify(file_size)
        sem = self._sem(size_class)
        timeout = self.config.timeout_seconds or None

        self._waiting[size_class] += 1
        try:
            try:
                await asyncio.wait_for(sem.acquire(), timeout)
            except asyncio.TimeoutError:
                raise AdmissionTimeout(
                    f"scan {scan_id or '?'} ({size_class}, {file_size} bytes) waited "
                    f"more than {timeout:.0f}s for an admission slot"
                ) from None
        finally:
            self._waiting[size_class] -= 1

        self._in_flight[size_class] += 1
        try:
            yield size_class
        finally:
            self._in_flight[size_class] -= 1
            sem.release()

    def stats(self) -> dict:
        """Observability snapshot (safe to expose on a health endpoint)."""
        return {
            "permits": dict(self.config.permits),
            "in_flight": dict(self._in_flight),
            "waiting": dict(self._waiting),
            "thresholds": {
                "small_max_bytes": self.config.small_max_bytes,
                "large_min_bytes": self.config.large_min_bytes,
            },
        }


_controller: AdmissionController | None = None


def get_admission_controller() -> AdmissionController:
    """Process-wide admission controller (lazy; env read at first use)."""
    global _controller
    if _controller is None:
        _controller = AdmissionController()
    return _controller
