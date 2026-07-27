"""
AegisML — Phase 2 resilience regression suite.

Covers the v3.2 (scalability & fault tolerance) upgrades:
  * CircuitBreaker state machine — CLOSED/OPEN/HALF_OPEN transitions on a
    fake clock, trial-slot accounting, neutral outcomes for credential
    errors, observability snapshots
  * AIProviderManager fallback chain — OPEN providers skipped instantly,
    auth errors never trip a breaker, graceful degradation to the
    deterministic static-engine verdict, CircuitOpenError when fallback
    is disabled
  * size-class admission control — classification boundaries, per-class
    permits, AdmissionTimeout, event-loop-replacement safety

Run from services/scan-engine so the packages are importable:

    cd services/scan-engine
    python -m pytest ../../tests/test_resilience.py -v
"""
import asyncio
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "services", "scan-engine"))

from ai_providers.circuit_breaker import CircuitBreaker, CircuitOpenError, CircuitState
from scanner.admission import (
    AdmissionConfig,
    AdmissionController,
    AdmissionTimeout,
)

# The provider manager imports every AI SDK at module scope; in minimal
# environments (no SDK wheels) only the pure-Python resilience units are
# testable, so the chain-level tests skip rather than error.
try:
    from ai_providers.base import AIAnalysisResult
    from ai_providers.manager import AIProviderManager
    _MANAGER_AVAILABLE = True
except ImportError:  # pragma: no cover
    _MANAGER_AVAILABLE = False

needs_manager = pytest.mark.skipif(
    not _MANAGER_AVAILABLE, reason="AI provider SDKs not installed")


# ── helpers ──────────────────────────────────────────────────────────

class _Clock:
    """Deterministic monotonic clock for breaker tests."""
    def __init__(self):
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


def _breaker(threshold=3, reset=60.0, half_open=1):
    clock = _Clock()
    return CircuitBreaker("test", failure_threshold=threshold,
                          reset_timeout=reset, half_open_max_calls=half_open,
                          clock=clock), clock


# ── CircuitBreaker state machine ─────────────────────────────────────

def test_breaker_starts_closed_and_allows():
    cb, _ = _breaker()
    assert cb.state is CircuitState.CLOSED
    assert cb.allow()
    cb.record_success()


def test_breaker_trips_after_consecutive_failures():
    cb, _ = _breaker(threshold=3)
    for _ in range(3):
        assert cb.allow()
        cb.record_failure()
    assert cb.state is CircuitState.OPEN
    assert not cb.allow()  # rejected instantly, no timeout paid


def test_breaker_success_resets_failure_streak():
    cb, _ = _breaker(threshold=3)
    for _ in range(2):
        cb.allow(); cb.record_failure()
    cb.allow(); cb.record_success()
    for _ in range(2):
        cb.allow(); cb.record_failure()
    assert cb.state is CircuitState.CLOSED  # streak broken; never reached 3


def test_breaker_half_open_probe_success_closes():
    cb, clock = _breaker(threshold=1, reset=60.0)
    cb.allow(); cb.record_failure()
    assert not cb.allow()
    clock.advance(60.0)
    assert cb.state is CircuitState.HALF_OPEN  # effective state, no mutation
    assert cb.allow()          # the single trial slot
    assert not cb.allow()      # concurrent trial rejected
    cb.record_success()
    assert cb.state is CircuitState.CLOSED
    assert cb.allow()
    cb.record_success()


def test_breaker_half_open_probe_failure_reopens():
    cb, clock = _breaker(threshold=1, reset=60.0)
    cb.allow(); cb.record_failure()
    clock.advance(60.0)
    assert cb.allow()
    cb.record_failure()
    assert cb.state is CircuitState.OPEN
    assert not cb.allow()
    clock.advance(59.9)
    assert not cb.allow()      # full cooldown restarts after a failed probe
    clock.advance(0.2)
    assert cb.allow()


def test_breaker_neutral_returns_trial_slot_without_judging():
    cb, clock = _breaker(threshold=1, reset=60.0)
    cb.allow(); cb.record_failure()
    clock.advance(60.0)
    assert cb.allow()
    cb.record_neutral()        # e.g. caller-supplied invalid BYOK key
    assert cb.state is CircuitState.HALF_OPEN
    assert cb.allow()          # slot was returned; provider still on probation


def test_breaker_snapshot_shape_and_counters():
    cb, _ = _breaker(threshold=1)
    cb.allow(); cb.record_failure()
    snap = cb.snapshot()
    assert snap["name"] == "test"
    assert snap["state"] == "open"
    assert snap["total_failures"] == 1
    assert snap["times_opened"] == 1
    assert {"total_successes", "consecutive_failures",
            "failure_threshold", "reset_timeout_seconds"}.issubset(snap)


def test_breaker_rejects_invalid_configuration():
    for kwargs in ({"failure_threshold": 0}, {"reset_timeout": 0},
                   {"half_open_max_calls": 0}):
        with pytest.raises(ValueError):
            CircuitBreaker("bad", **kwargs)


# ── AdmissionController ──────────────────────────────────────────────

def _config(small_max=100, large_min=1000, small=1, medium=1, large=1, timeout=0.0):
    return AdmissionConfig(
        small_max_bytes=small_max, large_min_bytes=large_min,
        permits={"small": small, "medium": medium, "large": large},
        timeout_seconds=timeout)


def test_admission_classify_boundaries():
    ctl = AdmissionController(_config())
    assert ctl.classify(0) == "small"
    assert ctl.classify(100) == "small"      # inclusive upper bound
    assert ctl.classify(101) == "medium"
    assert ctl.classify(999) == "medium"
    assert ctl.classify(1000) == "large"     # inclusive lower bound


def test_admission_serializes_within_size_class():
    ctl = AdmissionController(_config(small=1))
    peak = {"v": 0}

    async def job():
        async with ctl.admit(10, "job"):
            peak["v"] = max(peak["v"], ctl.stats()["in_flight"]["small"])
            await asyncio.sleep(0.01)

    async def main():
        await asyncio.gather(*(job() for _ in range(4)))

    asyncio.run(main())
    assert peak["v"] == 1                     # never two small scans at once
    assert ctl.stats()["in_flight"]["small"] == 0


def test_admission_classes_do_not_block_each_other():
    ctl = AdmissionController(_config(small=1, large=1))
    order = []

    async def main():
        async with ctl.admit(10, "small-hog"):
            # a large scan must be admitted while the small slot is held
            async with ctl.admit(5000, "large"):
                order.append(dict(ctl.stats()["in_flight"]))

    asyncio.run(main())
    assert order == [{"small": 1, "medium": 0, "large": 1}]


def test_admission_timeout_raises_instead_of_queueing_forever():
    ctl = AdmissionController(_config(small=1, timeout=0.05))

    async def main():
        async with ctl.admit(10, "holder"):
            with pytest.raises(AdmissionTimeout):
                async with ctl.admit(10, "starved"):
                    pass  # pragma: no cover

    asyncio.run(main())
    stats = ctl.stats()
    assert stats["waiting"]["small"] == 0     # waiter accounting restored
    assert stats["in_flight"]["small"] == 0


def test_admission_survives_event_loop_replacement():
    ctl = AdmissionController(_config())

    async def one_scan():
        async with ctl.admit(10, "x"):
            pass

    asyncio.run(one_scan())
    asyncio.run(one_scan())                   # fresh loop: must not raise
    assert ctl.stats()["in_flight"]["small"] == 0


def test_admission_stats_shape():
    stats = AdmissionController(_config()).stats()
    assert {"permits", "in_flight", "waiting", "thresholds"} == set(stats)
    assert stats["thresholds"] == {"small_max_bytes": 100, "large_min_bytes": 1000}


def test_local_engine_integration_scan_bytes_smoke():
    # `scanner` exports the async service adapter instance as `engine`.
    from scanner import engine as scan_engine
    payload = b"\x00" * 512 + b"os.system" + b"\x00" * 512
    fd, path = tempfile.mkstemp(suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        f.write(payload)
    try:
        # A deliberately small chunk exercises cross-chunk evidence through
        # the supported adapter contract, rather than a retired private pass.
        result = asyncio.run(
            scan_engine.scan(path, "resilience-smoke", chunk_size=64)
        )
        threats = result["threats"]
        assert isinstance(threats, list)
        assert any(t["id"] == "AML.RCE.OS_SYSTEM" for t in threats)
        for t in threats:
            assert {"id", "name", "severity", "cvss", "description"}.issubset(t)
    finally:
        os.remove(path)


# ── AIProviderManager × CircuitBreaker chain ─────────────────────────

class _AuthError(Exception):
    status_code = 401


class _FakeProvider:
    """Duck-typed provider: manager only calls .analyze()."""
    def __init__(self, name, exc=None):
        self._name, self.exc, self.calls = name, exc, 0

    async def analyze(self, file_info, scan_results, model, api_key):
        self.calls += 1
        if self.exc is not None:
            raise self.exc
        return AIAnalysisResult(verdict="safe", confidence=0.9,
                                explanation="ok", threats=[],
                                recommendations=[], provider=self._name,
                                model="fake-1")


def _manager(providers, threshold=2):
    m = AIProviderManager()
    m.providers = providers
    m.fallback_order = list(providers)
    m.breakers = {name: CircuitBreaker(f"ai:{name}", failure_threshold=threshold,
                                       reset_timeout=60.0)
                  for name in providers}
    m._is_configured = lambda name: True
    return m


@needs_manager
def test_manager_open_circuit_is_skipped_instantly():
    bad = _FakeProvider("primary", exc=RuntimeError("boom"))
    good = _FakeProvider("backup")
    m = _manager({"primary": bad, "backup": good}, threshold=2)

    async def main():
        for _ in range(3):
            res = await m.analyze({}, {}, provider="primary")
            assert res.provider == "backup"

    asyncio.run(main())
    # calls 1+2 tripped the breaker; call 3 must not touch the provider
    assert bad.calls == 2
    assert m.breakers["primary"].state is CircuitState.OPEN


@needs_manager
def test_manager_static_fallback_when_everything_is_open():
    m = _manager({"a": _FakeProvider("a", exc=RuntimeError("x")),
                  "b": _FakeProvider("b", exc=RuntimeError("y"))}, threshold=1)

    async def main():
        first = await m.analyze({}, {"threat_count": 2}, provider="a")
        second = await m.analyze({}, {"threat_count": 2}, provider="a")
        return first, second

    first, second = asyncio.run(main())
    assert first.provider == "static-engine"   # both failed
    assert second.provider == "static-engine"  # both skipped (open)
    assert second.verdict == "suspicious"      # threat_count > 0
    assert m.providers["a"].calls == 1         # no second timeout paid


@needs_manager
def test_manager_auth_errors_never_trip_the_breaker():
    flaky_key = _FakeProvider("a", exc=_AuthError("invalid x-api-key"))
    m = _manager({"a": flaky_key, "b": _FakeProvider("b")}, threshold=2)

    async def main():
        for _ in range(5):
            res = await m.analyze({}, {}, provider="a", user_api_key="bad")
            assert res.provider == "b"

    asyncio.run(main())
    assert flaky_key.calls == 5                # never skipped
    assert m.breakers["a"].state is CircuitState.CLOSED


@needs_manager
def test_manager_no_fallback_raises_circuit_open_error():
    m = _manager({"a": _FakeProvider("a", exc=RuntimeError("x"))}, threshold=1)

    async def main():
        with pytest.raises(RuntimeError):
            await m.analyze({}, {}, provider="a", user_api_key="k", fallback=False)
        with pytest.raises(CircuitOpenError):
            await m.analyze({}, {}, provider="a", user_api_key="k", fallback=False)

    asyncio.run(main())


@needs_manager
def test_manager_snapshots_cover_every_provider():
    m = _manager({"a": _FakeProvider("a"), "b": _FakeProvider("b")})
    snaps = m.circuit_snapshots()
    assert [s["name"] for s in snaps] == ["ai:a", "ai:b"]
    assert all(s["state"] == "closed" for s in snaps)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
