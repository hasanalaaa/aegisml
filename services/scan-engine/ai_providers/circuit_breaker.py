"""
Circuit breaker for outbound AI-provider calls — v3.2 (Phase 2).

Why: without a breaker, a degraded provider adds its full HTTP timeout to
*every* scan while the fallback chain walks past it. The breaker sits inside
``AIProviderManager``'s chain: an OPEN provider is skipped instantly, the
chain moves on (ultimately to the deterministic static-engine verdict), and
the provider is re-probed only after a cooldown.

States
------
    CLOSED     normal; ``failure_threshold`` consecutive failures → OPEN
    OPEN       reject instantly; after ``reset_timeout`` seconds → HALF_OPEN
    HALF_OPEN  admit up to ``half_open_max_calls`` trial calls;
               success → CLOSED, failure → OPEN again

Usage contract: every ``allow() == True`` MUST be followed by exactly one
``record_success()`` / ``record_failure()`` / ``record_neutral()`` so
half-open trial slots are returned. ``record_neutral`` is for outcomes that
say nothing about provider health (e.g. a caller-supplied invalid API key).

Thread-safe (plain lock + monotonic clock); no asyncio primitives, so it is
event-loop-agnostic and trivially unit-testable with a fake clock.
"""
from __future__ import annotations

import threading
import time
from enum import Enum
from typing import Callable


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(RuntimeError):
    """Raised by callers that cannot fall back when a circuit is OPEN."""


class CircuitBreaker:
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        reset_timeout: float = 60.0,
        half_open_max_calls: int = 1,
        clock: Callable[[], float] = time.monotonic,
    ):
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if reset_timeout <= 0:
            raise ValueError("reset_timeout must be > 0")
        if half_open_max_calls < 1:
            raise ValueError("half_open_max_calls must be >= 1")

        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.half_open_max_calls = half_open_max_calls
        self._clock = clock

        self._lock = threading.Lock()
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at = 0.0
        self._half_open_in_flight = 0

        # lifetime counters for observability
        self._total_successes = 0
        self._total_failures = 0
        self._times_opened = 0

    # ── gate ────────────────────────────────────────────────────────

    def allow(self) -> bool:
        """True if a call may proceed. May consume a HALF_OPEN trial slot —
        pair every True with exactly one record_*() call."""
        with self._lock:
            if self._state is CircuitState.CLOSED:
                return True
            if self._state is CircuitState.OPEN:
                if self._clock() - self._opened_at < self.reset_timeout:
                    return False
                # cooldown elapsed — probe the provider again
                self._state = CircuitState.HALF_OPEN
                self._half_open_in_flight = 0
            # HALF_OPEN: admit a bounded number of concurrent trials
            if self._half_open_in_flight < self.half_open_max_calls:
                self._half_open_in_flight += 1
                return True
            return False

    # ── outcomes ────────────────────────────────────────────────────

    def record_success(self) -> None:
        with self._lock:
            self._total_successes += 1
            self._consecutive_failures = 0
            if self._state is not CircuitState.CLOSED:
                self._state = CircuitState.CLOSED
                self._half_open_in_flight = 0

    def record_failure(self) -> None:
        with self._lock:
            self._total_failures += 1
            if self._state is CircuitState.HALF_OPEN:
                self._trip_locked()  # failed probe — straight back to OPEN
                return
            self._consecutive_failures += 1
            if (
                self._state is CircuitState.CLOSED
                and self._consecutive_failures >= self.failure_threshold
            ):
                self._trip_locked()

    def record_neutral(self) -> None:
        """Return a trial slot without judging provider health."""
        with self._lock:
            if self._state is CircuitState.HALF_OPEN and self._half_open_in_flight > 0:
                self._half_open_in_flight -= 1

    def _trip_locked(self) -> None:
        self._state = CircuitState.OPEN
        self._opened_at = self._clock()
        self._times_opened += 1
        self._consecutive_failures = 0
        self._half_open_in_flight = 0

    # ── observability ───────────────────────────────────────────────

    @property
    def state(self) -> CircuitState:
        """Effective state (reports HALF_OPEN once an OPEN cooldown expires,
        without mutating — mutation happens in allow())."""
        with self._lock:
            if (
                self._state is CircuitState.OPEN
                and self._clock() - self._opened_at >= self.reset_timeout
            ):
                return CircuitState.HALF_OPEN
            return self._state

    def snapshot(self) -> dict:
        with self._lock:
            state = self._state
            if (
                state is CircuitState.OPEN
                and self._clock() - self._opened_at >= self.reset_timeout
            ):
                state = CircuitState.HALF_OPEN
            return {
                "name": self.name,
                "state": state.value,
                "consecutive_failures": self._consecutive_failures,
                "total_successes": self._total_successes,
                "total_failures": self._total_failures,
                "times_opened": self._times_opened,
                "failure_threshold": self.failure_threshold,
                "reset_timeout_seconds": self.reset_timeout,
            }
