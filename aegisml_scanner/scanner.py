"""AegisML v3 — offline, no-execution security analysis of AI model artifacts.

The engine runs four passes and never executes the artifact:

1. **inventory** — the structural parser for the detected format publishes a
   region map (which byte span is which tensor / archive member) and the
   findings that follow from the container itself;
2. **evidence** — one sequential read computes SHA-256, BLAKE2b, every literal
   signature with byte offsets, harvested strings for the regex rules, and a
   block-level entropy / printability / LSB profile;
3. **depth** — nested payloads discovered by the parser (archive members,
   embedded pickles, marshalled bytecode, model configuration) are scanned
   recursively with the same engine under a depth and byte budget;
4. **correlation** — offsets are resolved to region names, tensor payloads are
   sampled for value-level anomalies, and the risk score is assembled from the
   findings with an explicit, reproducible formula.

Memory is O(chunk + directory) in every pass, so a 1 TiB artifact costs the same
resident memory as a 1 MiB one.  Any pass that stops at a safety limit
downgrades coverage, and an incomplete scan can never be reported as safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from importlib.util import find_spec
import json
import os
from pathlib import Path
import stat
import time
from typing import Callable, Iterator, List, Optional, Sequence, Union
import uuid

from . import formats
from . import parallel
from .formats.common import KIND_TENSOR, Region
from .matcher import (
    ByteProfiler,
    DEFAULT_RUN_GATE,
    DEFAULT_STRING_BUDGET,
    LiteralMatcher,
    RegexScanner,
    RuleHit,
    StringHarvester,
    has_text_run,
)
from .rules import ALL_RULES, RULESET_VERSION, SEVERITY_RANK, Rule, build_ruleset, signature_count
from . import tensors as tensor_forensics


ENGINE_VERSION = "3.0.0"
DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024
MAX_RECORDED_OFFSETS = 32
DEFAULT_ENTROPY_FULL_LIMIT = 256 * 1024 * 1024
DEFAULT_ENTROPY_SAMPLE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_DEPTH = 4
DEFAULT_EMBEDDED_BUDGET = 512 * 1024 * 1024
#: Below this size every byte is checked against every signature.  Above it the
#: adaptive tier is used unless ``signatures="full"`` is requested explicitly.
DEFAULT_FULL_SIGNATURE_LIMIT = 2 * 1024 * 1024 * 1024
MATCHER_BACKEND = "atom-prefilter/stdlib-memmem"

_HAS_HTTPX = find_spec("httpx") is not None

_LEVELS = ("clean", "suspicious", "malicious", "critical")


@dataclass
class Threat:
    """One finding.  Field names from the 1.x/2.x SDK are preserved."""

    pattern: str
    severity: str
    description: str
    category: str
    location: str = ""
    id: str = "AML.GENERIC"
    byte_offsets: List[int] = field(default_factory=list)
    occurrences: int = 1
    cvss: float = 0.0
    remediation: str = ""
    region: str = ""
    evidence: List[str] = field(default_factory=list)
    attack: List[str] = field(default_factory=list)
    cwe: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    confidence: str = "high"
    source: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "pattern": self.pattern,
            "severity": self.severity,
            "description": self.description,
            "category": self.category,
            "location": self.location,
            "byte_offsets": self.byte_offsets,
            "occurrences": self.occurrences,
            "cvss": self.cvss,
            "remediation": self.remediation,
            "region": self.region,
            "evidence": self.evidence,
            "attack": self.attack,
            "cwe": self.cwe,
            "references": self.references,
            "confidence": self.confidence,
            "source": self.source,
        }


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
    def coverage(self) -> dict:
        return self.metadata.get("coverage", {})

    @property
    def is_safe(self) -> bool:
        return bool(self.coverage.get("complete")) and self.risk_score < 30

    @property
    def verdict(self) -> str:
        if self.risk_score >= 85:
            return "CRITICAL"
        if self.risk_score >= 60:
            return "DANGEROUS"
        if self.risk_score >= 30:
            return "SUSPICIOUS"
        if not self.coverage.get("complete", True):
            return "INCOMPLETE"
        return "SAFE"

    def counts(self) -> dict:
        tally = {name: 0 for name in SEVERITY_RANK}
        for threat in self.threats:
            tally[threat.severity] = tally.get(threat.severity, 0) + 1
        return tally

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "filename": self.filename,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "verdict": self.verdict,
            "is_safe": self.is_safe,
            "severity_counts": self.counts(),
            "threats": [threat.to_dict() for threat in self.threats],
            "metadata": self.metadata,
            "ai_analysis": self.ai_analysis,
            "source_url": self.source_url,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def __repr__(self) -> str:
        return (
            f"ScanResult(file={self.filename!r}, verdict={self.verdict}, "
            f"score={self.risk_score}, threats={len(self.threats)})"
        )


ProgressCallback = Callable[[int, int], None]


class AegisML:
    """Offline scanner with optional, explicitly enabled remote and AI enrichment."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        anthropic_api_key: Optional[str] = None,
        timeout: int = 300,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        max_recorded_offsets: int = MAX_RECORDED_OFFSETS,
        progress: Optional[ProgressCallback] = None,
        entropy_mode: str = "auto",
        entropy_full_limit: int = DEFAULT_ENTROPY_FULL_LIMIT,
        entropy_sample_bytes: int = DEFAULT_ENTROPY_SAMPLE_BYTES,
        *,
        deep: bool = True,
        strings: bool = True,
        string_budget: int = DEFAULT_STRING_BUDGET,
        tensor_stats: str = "auto",
        max_depth: int = DEFAULT_MAX_DEPTH,
        embedded_budget: int = DEFAULT_EMBEDDED_BUDGET,
        rule_packs: Sequence[Union[str, Path]] = (),
        signatures: str = "auto",
        extra_hashes: bool = False,
        jobs: int = 1,
        full_signature_limit: int = DEFAULT_FULL_SIGNATURE_LIMIT,
        run_gate: int = DEFAULT_RUN_GATE,
    ) -> None:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        if max_recorded_offsets <= 0:
            raise ValueError("max_recorded_offsets must be positive")
        if entropy_mode not in {"auto", "full", "off"}:
            raise ValueError("entropy_mode must be auto, full, or off")
        if tensor_stats not in {"auto", "on", "off"}:
            raise ValueError("tensor_stats must be auto, on, or off")
        if max_depth < 0:
            raise ValueError("max_depth must not be negative")
        if signatures not in {"auto", "full", "adaptive"}:
            raise ValueError("signatures must be auto, full, or adaptive")
        if run_gate < 8:
            raise ValueError("run_gate must be at least 8 bytes")
        # Network and provider access is a constructor decision.  Ambient
        # environment variables must never turn a local scan into an upload.
        self.api_url = api_url or ""
        self.api_key = api_key or os.getenv("AEGISML_API_KEY", "")
        self.anthropic_api_key = anthropic_api_key or ""
        self.timeout = timeout
        self.chunk_size = chunk_size
        self.max_recorded_offsets = max_recorded_offsets
        self.progress = progress
        self.entropy_mode = entropy_mode
        self.entropy_full_limit = entropy_full_limit
        self.entropy_sample_bytes = entropy_sample_bytes
        self.deep = deep
        self.strings = strings
        self.string_budget = string_budget
        self.tensor_stats = tensor_stats
        self.max_depth = max_depth
        self.embedded_budget = embedded_budget
        self.signatures = signatures
        self.extra_hashes = extra_hashes
        self.jobs = max(1, int(jobs))
        self.full_signature_limit = full_signature_limit
        self.run_gate = run_gate
        self.ruleset: tuple[Rule, ...] = build_ruleset(rule_packs) if rule_packs else ALL_RULES
        self._regex = RegexScanner(self.ruleset, "string")

    # -- public API ---------------------------------------------------------
    @staticmethod
    def rules(ruleset: Sequence[Rule] = ALL_RULES) -> list[dict]:
        """Return the stable public rule inventory."""
        return [rule.to_dict() for rule in ruleset]

    def scan(self, file_path: Union[str, Path]) -> ScanResult:
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if path.is_symlink():
            raise ValueError(f"Refusing to scan symlink: {path}")
        if not path.is_file():
            raise ValueError(f"Not a file: {path}")
        if self.api_url:
            if not _HAS_HTTPX:
                raise RuntimeError(
                    "Remote scanning requires: pip install 'aegisml-scanner[remote]'"
                )
            return self._scan_via_api(path)
        return self._scan_local(path)

    def scan_bytes(self, name: str, data: bytes) -> ScanResult:
        """Scan an in-memory artifact with the same engine used for files."""
        started = time.monotonic()
        digest = hashlib.sha256(data).hexdigest()
        detected = formats.detect(name, data[: formats.HEADER_BYTES])
        report = formats.inspect_buffer(name, data, detected)
        threats = _threats_from_findings(report.findings, name)
        matcher = LiteralMatcher(self.ruleset)
        matcher.feed(data, 0)
        threats.extend(self._threats_from_hits(matcher.finish(), name))
        if self.strings:
            harvester = StringHarvester(self.string_budget)
            harvester.feed(data, 0)
            harvester.finish()
            threats.extend(self._threats_from_hits(self._regex.scan(harvester.strings), name))
        budget = [self.embedded_budget]
        for item in report.embedded:
            threats.extend(self._scan_embedded(item, name, 1, budget))
        errors = [] if report.status in {"complete", "not_applicable"} else [f"format_{report.status}"]
        score, level = _score(threats)
        metadata = {
            "file_size": len(data),
            "total_bytes": len(data),
            "bytes_scanned": len(data),
            "sha256": digest,
            "format_detected": detected,
            "engine_version": ENGINE_VERSION,
            "ruleset_version": RULESET_VERSION,
            "duration_ms": round((time.monotonic() - started) * 1000, 3),
            "errors": errors,
            "format": report.metadata,
            "coverage": {
                "complete": not errors,
                "byte_scan": "full",
                "sha256": "full",
                "entropy": "off",
                "format_specific": report.status,
                "depth": "full" if self.deep else "off",
            },
        }
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            filename=name,
            risk_score=score,
            risk_level=level,
            threats=threats,
            metadata=metadata,
        )

    def scan_url(self, url: str) -> ScanResult:
        if not self.api_url:
            raise ValueError("api_url is required for URL scanning")
        if not _HAS_HTTPX:
            raise RuntimeError("Remote scanning requires: pip install 'aegisml-scanner[remote]'")
        return self._scan_url_via_api(url)

    def iter_directory(self, dir_path: Union[str, Path]) -> Iterator[ScanResult]:
        """Scan regular files deterministically without following symlinks."""
        path = Path(dir_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"Directory not found: {path}")
        if not path.is_dir():
            raise ValueError(f"Not a directory: {path}")
        for candidate in sorted(path.rglob("*")):
            if candidate.is_file() and not candidate.is_symlink():
                yield self.scan(candidate)

    def scan_directory(self, dir_path: Union[str, Path]) -> List[ScanResult]:
        return list(self.iter_directory(dir_path))

    def scan_repository(self, dir_path: Union[str, Path]) -> tuple[List[ScanResult], List[Threat]]:
        """Scan a model repository and add findings that only exist across files."""
        results = self.scan_directory(dir_path)
        return results, _repository_findings(Path(dir_path).expanduser(), results)

    # -- local engine -------------------------------------------------------
    def _scan_local(self, path: Path) -> ScanResult:
        if self.jobs > 1 and path.stat().st_size >= 2 * parallel.MIN_SEGMENT:
            return self._scan_local_parallel(path)
        return self._scan_local_sequential(path)

    def _scan_local_parallel(self, path: Path) -> ScanResult:
        """Same engine, evidence pass spread over worker processes."""
        started = time.monotonic()
        size = path.stat().st_size
        header = path.open("rb").read(formats.HEADER_BYTES)
        detected = formats.detect(path.name, header)
        format_report = _safe_inspect(path, detected)
        tier = self._tier(size)
        merged = parallel.scan_file(
            path,
            jobs=self.jobs,
            tier=tier,
            chunk_size=self.chunk_size,
            run_gate=self.run_gate,
            string_budget=min(self.string_budget, 8 * 1024 * 1024),
            entropy_mode=self.entropy_mode,
            progress=self.progress,
        )
        threats = self._threats_from_merged(merged["literal"], path.name)
        threats.extend(self._threats_from_merged(merged["regex"], path.name))
        threats.extend(_threats_from_findings(format_report.findings, path.name))
        embedded_budget = [self.embedded_budget]
        embedded_scanned = 0
        if self.deep:
            for item in format_report.embedded:
                embedded_scanned += 1
                threats.extend(self._scan_embedded(item, path.name, 1, embedded_budget))
        regions = format_report.regions
        _attach_regions(threats, regions)
        forensics = None
        if self._tensor_stats_enabled(regions, size):
            forensics = tensor_forensics.analyze(path, regions)
            threats.extend(_threats_from_findings(forensics.findings, path.name))
        errors: list[str] = []
        if format_report.status not in {"complete", "not_applicable"}:
            errors.append(f"format_scan_{format_report.status}")
        threats = _dedupe(threats)
        score, level = _score(threats)
        duration_ms = round((time.monotonic() - started) * 1000, 3)
        entropy = _histogram_entropy(merged["histogram"], merged["sampled_bytes"])
        metadata = {
            "file_size": size,
            "extension": path.suffix.lower(),
            "format_detected": detected,
            "sha256": merged["sha256"],
            "entropy": round(entropy, 6),
            "entropy_bytes_analyzed": merged["sampled_bytes"],
            "total_bytes": size,
            "bytes_scanned": size,
            "chunk_size": self.chunk_size,
            "patterns_checked": len(self.ruleset),
            "signatures_checked": signature_count(self.ruleset),
            "matcher_backend": MATCHER_BACKEND + f"/parallel-{merged['segments']}",
            "ruleset_version": RULESET_VERSION,
            "engine_version": ENGINE_VERSION,
            "duration_ms": duration_ms,
            "header_hex": header[:16].hex(),
            "errors": errors,
            "format": format_report.metadata,
            "blake2b": "",
            "throughput_mib_s": round((size / (1024 * 1024)) / max(duration_ms / 1000, 1e-6), 2),
            "signature_tier": tier,
            "deep_scanned_bytes": merged["deep_bytes"],
            "jobs": self.jobs,
            "segments": merged["segments"],
            "profile": {
                "entropy": round(entropy, 6),
                "entropy_coverage": "sampled" if self.entropy_mode == "auto" else self.entropy_mode,
                "bytes_analyzed": merged["sampled_bytes"],
                "blocks_measured": merged["blocks"],
                "mean_block_entropy": round(
                    merged["entropy_sum"] / merged["blocks"], 4) if merged["blocks"] else 0.0,
                "lsb_bias": round(
                    abs(merged["odd_bytes"] / merged["lsb_samples"] - 0.5), 6)
                if merged["lsb_samples"] else 0.0,
                "high_entropy_blocks": merged["high_entropy_blocks"][:8],
                "text_dense_blocks": merged["text_blocks"][:8],
            },
            "regions": {
                "count": len(regions),
                "tensors": sum(1 for region in regions if region.kind == KIND_TENSOR),
                "sample": [region.to_dict() for region in regions[:32]],
            },
            "embedded_analyzed": embedded_scanned,
            "tensor_forensics": forensics.metadata() if forensics else None,
            "coverage": {
                "complete": not errors,
                "byte_scan": "full",
                "sha256": "full",
                "entropy": "sampled" if self.entropy_mode == "auto" else self.entropy_mode,
                "signatures": tier,
                "signature_bytes": merged["deep_bytes"],
                "format_specific": format_report.status,
                "strings": "truncated" if merged["strings_truncated"] else "text-regions",
                "depth": "full" if self.deep else "off",
                "tensor_values": "sampled" if forensics else "off",
            },
        }
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            filename=path.name,
            risk_score=score,
            risk_level=level,
            threats=threats,
            metadata=metadata,
        )

    def _threats_from_merged(self, merged: dict, location: str) -> list[Threat]:
        hits: dict[int, RuleHit] = {}
        for index, payload in merged.items():
            occurrences, offsets, evidence = payload
            hit = RuleHit(int(index))
            hit.occurrences = occurrences
            hit.offsets = list(offsets)
            hit.evidence = list(evidence)
            hits[int(index)] = hit
        return self._threats_from_hits(hits, location)

    def _scan_local_sequential(self, path: Path) -> ScanResult:
        started = time.monotonic()
        errors: list[str] = []

        initial_path_state = os.stat(path, follow_symlinks=False)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            initial_stream_state = os.fstat(stream.fileno())
            if not stat.S_ISREG(initial_stream_state.st_mode):
                raise ValueError(f"Not a regular file: {path}")
            initial_size = initial_stream_state.st_size
            header = stream.read(min(formats.HEADER_BYTES, self.chunk_size))
            stream.seek(0)
            detected = formats.detect(path.name, header)

            # Pass 1: structural inventory (needs its own bounded reads).
            format_report = _safe_inspect(path, detected)

            # Pass 2: single sequential evidence read.
            tier = self._tier(initial_size)
            structural_spans = _non_tensor_spans(format_report.regions)
            matcher = LiteralMatcher(self.ruleset)
            magics = LiteralMatcher(self.ruleset, binary_only=True) if tier == "adaptive" else None
            harvester = StringHarvester(self.string_budget) if self.strings else None
            profiler = ByteProfiler(mode=self.entropy_mode, total_bytes=initial_size)
            sha256 = hashlib.sha256()
            blake = hashlib.blake2b(digest_size=32) if self.extra_hashes else None
            bytes_scanned = 0
            deep_bytes = 0
            text_bytes = 0
            carry = b""
            overlap = matcher.overlap
            while True:
                chunk = stream.read(self.chunk_size)
                if not chunk:
                    break
                sha256.update(chunk)
                if blake is not None:
                    blake.update(chunk)
                profiler.feed(chunk, bytes_scanned)
                structural = _overlaps(structural_spans, bytes_scanned, bytes_scanned + len(chunk))
                # One translate+find decides whether this chunk can hold a
                # command line, URL, template or script at all.
                textual = structural or has_text_run(chunk, self.run_gate)
                deep = True if tier == "full" else textual
                if not deep:
                    # Binary magics still cover every byte of skipped data.
                    magics.feed(chunk, bytes_scanned, carry=carry)
                if deep:
                    deep_bytes += len(chunk)
                    matcher.feed(chunk, bytes_scanned, carry=carry)
                if harvester is not None and textual:
                    text_bytes += len(chunk)
                    harvester.feed(chunk, bytes_scanned)
                keep = min(overlap, len(chunk))
                carry = chunk[len(chunk) - keep:]
                bytes_scanned += len(chunk)
                if self.progress is not None:
                    self.progress(bytes_scanned, initial_size)
            final_stream_state = os.fstat(stream.fileno())

        profiler.finish()
        if harvester is not None:
            harvester.finish()

        state_after = _stat_or_none(path)
        stable = (
            bytes_scanned == initial_size
            and _same_state(initial_path_state, initial_stream_state)
            and _same_state(initial_stream_state, final_stream_state)
            and state_after is not None
            and _same_state(initial_stream_state, state_after)
        )
        if not stable:
            errors.append("file_changed_during_scan")

        hits = matcher.finish()
        if magics is not None:
            for index, hit in magics.finish().items():
                existing = hits.get(index)
                if existing is None:
                    hits[index] = hit
                elif hit.occurrences > existing.occurrences:
                    hits[index] = hit
        threats = self._threats_from_hits(hits, path.name)
        if harvester is not None:
            threats.extend(self._threats_from_hits(self._regex.scan(harvester.strings), path.name))
            if harvester.truncated:
                errors.append("string_budget_exhausted")
        threats.extend(_threats_from_findings(format_report.findings, path.name))

        # Pass 3: bounded recursion into nested payloads.
        embedded_budget = [self.embedded_budget]
        embedded_scanned = 0
        if self.deep:
            for item in format_report.embedded:
                embedded_scanned += 1
                threats.extend(self._scan_embedded(item, path.name, 1, embedded_budget))

        # Pass 4: correlation and value-level forensics.
        regions = format_report.regions
        _attach_regions(threats, regions)
        forensics = None
        if self._tensor_stats_enabled(regions, initial_size):
            forensics = tensor_forensics.analyze(path, regions)
            threats.extend(_threats_from_findings(forensics.findings, path.name))
        threats.extend(_profile_threats(profiler, regions, path.name))

        format_status = format_report.status
        if format_status not in {"complete", "not_applicable"}:
            errors.append(f"format_scan_{format_status}")
        complete = not errors
        byte_evidence_complete = stable and bytes_scanned == initial_size

        threats = _dedupe(threats)
        score, level = _score(threats)
        duration_ms = round((time.monotonic() - started) * 1000, 3)
        metadata = {
            # 1.x/2.x compatible keys
            "file_size": initial_size,
            "extension": path.suffix.lower(),
            "format_detected": detected,
            "sha256": sha256.hexdigest(),
            "entropy": round(profiler.entropy, 6),
            "entropy_bytes_analyzed": profiler.sampled_bytes,
            "total_bytes": initial_size,
            "bytes_scanned": bytes_scanned,
            "chunk_size": self.chunk_size,
            "patterns_checked": len(self.ruleset),
            "signatures_checked": signature_count(self.ruleset),
            "matcher_backend": MATCHER_BACKEND,
            "ruleset_version": RULESET_VERSION,
            "engine_version": ENGINE_VERSION,
            "duration_ms": duration_ms,
            "header_hex": header[:16].hex(),
            "errors": errors,
            "format": format_report.metadata,
            # 3.x evidence
            "blake2b": blake.hexdigest() if blake is not None else "",
            "throughput_mib_s": round(
                (bytes_scanned / (1024 * 1024)) / max(duration_ms / 1000, 1e-6), 2
            ),
            "atoms": matcher.atom_count,
            "signature_tier": tier,
            "deep_scanned_bytes": deep_bytes,
            "string_scanned_bytes": text_bytes,
            "profile": profiler.to_dict(),
            "regions": {
                "count": len(regions),
                "tensors": sum(1 for region in regions if region.kind == KIND_TENSOR),
                "sample": [region.to_dict() for region in regions[:32]],
            },
            "embedded_analyzed": embedded_scanned,
            "strings_harvested": len(harvester.strings) if harvester else 0,
            "tensor_forensics": forensics.metadata() if forensics else None,
            "coverage": {
                "complete": complete,
                "byte_scan": "full" if byte_evidence_complete else "incomplete",
                "sha256": "full" if byte_evidence_complete else "incomplete",
                "entropy": profiler.coverage,
                "signatures": tier,
                "signature_bytes": deep_bytes,
                "format_specific": format_status,
                "strings": "truncated" if (harvester and harvester.truncated) else (
                    "text-regions" if harvester else "off"
                ),
                "depth": "full" if self.deep else "off",
                "tensor_values": "sampled" if forensics else "off",
            },
        }
        result = ScanResult(
            scan_id=str(uuid.uuid4()),
            filename=path.name,
            risk_score=score,
            risk_level=level,
            threats=threats,
            metadata=metadata,
        )
        if self.anthropic_api_key:
            result.ai_analysis = self._claude_judge(
                result.scan_id, path.name, score, level, threats
            )
        return result

    def _tier(self, size: int) -> str:
        """Choose the signature tier for this artifact."""
        if self.signatures != "auto":
            return self.signatures
        return "full" if size <= self.full_signature_limit else "adaptive"

    def _tensor_stats_enabled(self, regions: Sequence[Region], size: int) -> bool:
        if self.tensor_stats == "off":
            return False
        if not any(region.kind == KIND_TENSOR for region in regions):
            return False
        return True

    def _scan_embedded(
        self, item: formats.Embedded, parent: str, depth: int, budget: list[int]
    ) -> list[Threat]:
        """Scan a nested payload with the full rule set under a byte budget."""
        if depth > self.max_depth or budget[0] <= 0:
            return [
                Threat(
                    id="AML.COVERAGE.DEPTH_LIMIT",
                    pattern="depth-limit",
                    severity="medium",
                    description=(
                        f"Nested payload {item.path!r} was not analysed: "
                        f"{'depth limit' if depth > self.max_depth else 'byte budget'} reached."
                    ),
                    category="coverage",
                    location=f"{parent}!{item.path}",
                    cvss=5.0,
                    remediation="Extract the payload in isolation and scan it directly.",
                    confidence="high",
                    source=parent,
                )
            ]
        budget[0] -= len(item.data)
        location = f"{parent}!{item.path}"
        threats: list[Threat] = []

        matcher = LiteralMatcher(self.ruleset)
        matcher.feed(item.data, 0)
        threats.extend(self._threats_from_hits(matcher.finish(), location))
        if self.strings:
            harvester = StringHarvester(min(self.string_budget, 8 * 1024 * 1024), wide=False)
            harvester.feed(item.data, 0)
            harvester.finish()
            threats.extend(self._threats_from_hits(self._regex.scan(harvester.strings), location))

        inner = formats.inspect_buffer(item.path, item.data)
        threats.extend(_threats_from_findings(inner.findings, location))
        for nested in inner.embedded:
            threats.extend(self._scan_embedded(nested, location, depth + 1, budget))
        for threat in threats:
            threat.source = threat.source or parent
            if "!" not in threat.location:
                # Offsets below this point are relative to the nested payload;
                # marking the location keeps them from being mapped onto the
                # parent file's region map.
                threat.location = location
        return threats

    def _threats_from_hits(self, hits: dict[int, RuleHit], location: str) -> list[Threat]:
        threats: list[Threat] = []
        for index, hit in sorted(hits.items()):
            rule = self.ruleset[index]
            threats.append(
                Threat(
                    id=rule.id,
                    pattern=(
                        " | ".join(p.decode("utf-8", "backslashreplace") for p in rule.patterns)
                        if rule.patterns
                        else rule.regex
                    )[:400],
                    severity=rule.severity,
                    description=rule.description,
                    category=rule.category,
                    location=location,
                    byte_offsets=hit.offsets[: self.max_recorded_offsets],
                    occurrences=hit.occurrences,
                    cvss=rule.cvss,
                    remediation=rule.remediation,
                    evidence=hit.evidence,
                    attack=list(rule.attack),
                    cwe=list(rule.cwe),
                    references=list(rule.references),
                    confidence=rule.confidence,
                )
            )
        return threats

    # -- remote enrichment (opt-in) ----------------------------------------
    def _scan_via_api(self, path: Path) -> ScanResult:
        import httpx

        headers: dict = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        with path.open("rb") as stream:
            files = {"file": (path.name, stream, "application/octet-stream")}
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    f"{self.api_url.rstrip('/')}/api/v1/scan/file", files=files, headers=headers
                )
                response.raise_for_status()
                data: dict = response.json()
        return self._parse_api_result(data.get("result", data))

    def _scan_url_via_api(self, url: str) -> ScanResult:
        import httpx

        headers: dict = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(
                f"{self.api_url.rstrip('/')}/api/v1/scan/url", json={"url": url}, headers=headers
            )
            response.raise_for_status()
            data: dict = response.json()
        return self._parse_api_result(data.get("result", data))

    @staticmethod
    def _parse_api_result(data: dict) -> ScanResult:
        threats = [
            Threat(
                id=item.get("id", "AML.REMOTE"),
                pattern=item.get("pattern", item.get("name", "")),
                severity=item.get("severity", "medium"),
                description=item.get("description", ""),
                category=item.get("category", "unknown"),
                location=item.get("location", ""),
                byte_offsets=item.get("byte_offsets", []),
                occurrences=item.get("occurrences", 1),
                cvss=float(item.get("cvss", 0.0)),
                remediation=item.get("remediation", ""),
                region=item.get("region", ""),
                evidence=item.get("evidence", []),
                attack=item.get("attack", []),
                cwe=item.get("cwe", []),
                references=item.get("references", []),
                confidence=item.get("confidence", "high"),
            )
            for item in data.get("threats", [])
        ]
        metadata = dict(data.get("metadata", {}))
        metadata.setdefault("coverage", {"complete": data.get("status") == "completed"})
        return ScanResult(
            scan_id=data.get("scan_id", ""),
            filename=data.get("filename", ""),
            risk_score=float(data.get("risk_score", 0)),
            risk_level=data.get("risk_level", "unknown"),
            threats=threats,
            metadata=metadata,
            ai_analysis=data.get("ai_analysis"),
            source_url=data.get("source_url"),
        )

    def _claude_judge(
        self, scan_id: str, filename: str, risk_score: float, risk_level: str,
        threats: List[Threat],
    ) -> Optional[dict]:
        """Best-effort explanation only; never changes the deterministic verdict."""
        try:  # pragma: no cover - optional network enrichment
            import anthropic as ant

            client = ant.Anthropic(api_key=self.anthropic_api_key)
            summary = [{"id": t.id, "severity": t.severity} for t in threats[:20]]
            message = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=1000,
                messages=[
                    {
                        "role": "user",
                        "content": (
                            "Explain this deterministic AI artifact scan. Respond only with JSON.\n"
                            f"File: {filename}, risk: {risk_score}/100, level: {risk_level}, "
                            f"findings: {json.dumps(summary)}\n"
                            '{"confidence":0,"summary_en":"","summary_ar":"",'
                            '"key_risks":[],"recommendation":"","recommendation_ar":""}'
                        ),
                    }
                ],
            )
            text = message.content[0].text.replace("```json", "").replace("```", "").strip()
            return json.loads(text)
        except Exception:
            return None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _safe_inspect(path: Path, detected: str):
    from .formats.common import FormatReport, finding as make_finding

    try:
        return formats.inspect_path(path, detected)
    except Exception as error:  # defensive: a parser must never crash a scan
        report = FormatReport(status="error", format=detected)
        report.add(
            make_finding(
                "AML.FORMAT.PARSER_ERROR", "high", 7.0,
                f"Structural parser failed: {str(error)[:180]}.",
                category="coverage",
                remediation="Treat an unparseable model as untrusted.",
            )
        )
        return report


def _histogram_entropy(histogram: Sequence[int], total: int) -> float:
    import math

    if total <= 0:
        return 0.0
    result = 0.0
    for count in histogram:
        if count:
            probability = count / total
            result -= probability * math.log2(probability)
    return result


def _stat_or_none(path: Path):
    try:
        return os.stat(path, follow_symlinks=False)
    except OSError:
        return None


def _same_state(first, second) -> bool:
    """Compare identity and mutation-sensitive fields, ignoring access time."""
    return (
        first.st_dev, first.st_ino, first.st_mode,
        first.st_size, first.st_mtime_ns, first.st_ctime_ns,
    ) == (
        second.st_dev, second.st_ino, second.st_mode,
        second.st_size, second.st_mtime_ns, second.st_ctime_ns,
    )


def _threats_from_findings(findings: Sequence[dict], location: str) -> list[Threat]:
    threats: list[Threat] = []
    for item in findings:
        threats.append(
            Threat(
                id=item.get("id", "AML.FORMAT.UNKNOWN"),
                pattern=item.get("id", "structural finding"),
                severity=item.get("severity", "medium"),
                description=item.get("description", "Structural anomaly detected."),
                category=item.get("category", "format_anomaly"),
                location=item.get("location") or location,
                byte_offsets=list(item.get("byte_offsets", [])),
                occurrences=int(item.get("occurrences", 1)),
                cvss=float(item.get("cvss", 0.0)),
                remediation=item.get("remediation", "Verify the artifact source."),
                evidence=list(item.get("evidence", [])),
                attack=list(item.get("attack", [])),
                cwe=list(item.get("cwe", [])),
                references=list(item.get("references", [])),
                confidence=item.get("confidence", "high"),
            )
        )
    return threats


def _non_tensor_spans(regions: Sequence[Region]) -> list[tuple[int, int]]:
    """Byte ranges that always get the full signature sweep in adaptive mode.

    Everything that is not raw tensor payload — headers, metadata, archive
    members, padding and unclaimed slack — is structurally capable of carrying a
    signature, so it is never skipped regardless of artifact size.
    """
    spans = [
        (region.start, region.end)
        for region in regions
        if region.kind != KIND_TENSOR and region.end > region.start
    ]
    if not spans:
        return []
    spans.sort()
    merged = [spans[0]]
    for start, end in spans[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def _overlaps(spans: Sequence[tuple[int, int]], start: int, end: int) -> bool:
    if not spans:
        return False
    import bisect

    starts = [span[0] for span in spans]
    index = bisect.bisect_right(starts, end) - 1
    while index >= 0:
        span_start, span_end = spans[index]
        if span_end > start:
            if span_start < end:
                return True
        else:
            return False
        index -= 1
    return False


def _attach_regions(threats: Sequence[Threat], regions: Sequence[Region]) -> None:
    """Resolve byte offsets to the semantic region that contains them."""
    if not regions:
        return
    ordered = sorted(regions, key=lambda region: region.start)
    starts = [region.start for region in ordered]
    import bisect

    for threat in threats:
        if threat.region or not threat.byte_offsets:
            continue
        if "!" in threat.location:
            # The offset is relative to a nested payload, not to this file, so
            # resolving it against the top-level region map would be a lie.
            continue
        offset = threat.byte_offsets[0]
        index = bisect.bisect_right(starts, offset) - 1
        while index >= 0:
            region = ordered[index]
            if region.start <= offset < region.end:
                threat.region = region.name
                break
            index -= 1


def _profile_threats(
    profiler: ByteProfiler, regions: Sequence[Region], location: str
) -> list[Threat]:
    """Turn block-level statistics into findings, without crying wolf.

    High entropy alone is normal for quantized weights, so entropy is reported
    as evidence.  A *text-dense* block inside a binary artifact is different:
    weights are not ASCII, and a 1 MiB run of printable bytes in a tensor file
    is either an embedded document or an embedded program.
    """
    threats: list[Threat] = []
    tensor_spans = [(region.start, region.end, region.name) for region in regions
                    if region.kind == KIND_TENSOR]
    for block in profiler.text_blocks(0.92):
        name = ""
        for start, end, region_name in tensor_spans:
            if start <= block.offset < end:
                name = region_name
                break
        if not tensor_spans and profiler.blocks_measured <= 2:
            continue  # a small text file is text; that is not a finding
        threats.append(
            Threat(
                id="AML.PROFILE.TEXT_IN_BINARY",
                pattern="printable-block",
                severity="medium",
                description=(
                    f"A {block.length:,}-byte block at offset {block.offset:,} is "
                    f"{block.printable_ratio:.0%} printable text"
                    + (f", inside tensor {name!r}" if name else "")
                    + "; binary model data is not text."
                ),
                category="evasion",
                location=location,
                byte_offsets=[block.offset],
                cvss=5.5,
                remediation="Extract the block and review it as a document or program.",
                region=name,
                confidence="medium",
            )
        )
        if len(threats) >= 4:
            break
    return threats


def _dedupe(threats: Sequence[Threat]) -> list[Threat]:
    """Collapse identical findings, keeping the widest evidence."""
    merged: dict[tuple[str, str, str], Threat] = {}
    for threat in threats:
        key = (threat.id, threat.location, threat.description[:120])
        existing = merged.get(key)
        if existing is None:
            merged[key] = threat
            continue
        existing.occurrences += threat.occurrences
        for offset in threat.byte_offsets:
            if offset not in existing.byte_offsets and len(existing.byte_offsets) < 64:
                existing.byte_offsets.append(offset)
        for item in threat.evidence:
            if item not in existing.evidence and len(existing.evidence) < 8:
                existing.evidence.append(item)
    ordered = sorted(
        merged.values(),
        key=lambda threat: (-SEVERITY_RANK.get(threat.severity, 0), -threat.cvss, threat.id),
    )
    return ordered


def _score(threats: Sequence[Threat]) -> tuple[float, str]:
    """Deterministic, explainable risk score.

    The dominant term is the worst finding, because one proven code-execution
    path is already fatal.  Corroborating findings add a bounded amount, so a
    file with ten independent critical findings ranks above one with a single
    borderline match, without letting low-severity noise reach a high score.
    """
    if not threats:
        return 0.0, "clean"
    weights = {"critical": 6.0, "high": 3.0, "medium": 1.0, "low": 0.3, "info": 0.0}
    top = max(threat.cvss for threat in threats)
    base = top * 10
    support = sum(weights.get(threat.severity, 0.0) for threat in threats)
    # The first finding is already counted by ``base``.
    support -= weights.get(
        max(threats, key=lambda threat: threat.cvss).severity, 0.0
    )
    score = min(100.0, base + min(20.0, support))
    if score >= 85:
        level = "critical"
    elif score >= 60:
        level = "malicious"
    elif score >= 30:
        level = "suspicious"
    else:
        level = "clean"
    return round(score, 1), level


def _repository_findings(root: Path, results: Sequence[ScanResult]) -> list[Threat]:
    """Findings that only exist when files are considered together."""
    threats: list[Threat] = []
    names = {result.filename.lower() for result in results}
    has_auto_map = any(
        threat.id in {"AML.CONFIG.AUTO_MAP", "AML.CONFIG.TRUST_REMOTE_CODE"}
        for result in results for threat in result.threats
    )
    python_files = sorted(name for name in names if name.endswith(".py"))
    if has_auto_map and python_files:
        threats.append(
            Threat(
                id="AML.REPO.REMOTE_CODE_CHAIN",
                pattern="auto_map + python",
                severity="critical",
                description=(
                    "The repository combines an auto_map/trust_remote_code configuration with "
                    f"{len(python_files)} Python module(s) ({', '.join(python_files[:4])}). "
                    "Loading this model with trust_remote_code=True runs that code."
                ),
                category="supply_chain",
                location=root.name,
                cvss=9.2,
                remediation=(
                    "Review every module, or use a model whose architecture ships in the library."
                ),
                attack=["AML.T0010"],
                cwe=["CWE-829"],
            )
        )
    pickle_like = sorted(
        name for name in names
        if name.endswith((".bin", ".pt", ".pth", ".ckpt", ".pkl"))
    )
    if pickle_like and any(name.endswith(".safetensors") for name in names):
        threats.append(
            Threat(
                id="AML.REPO.REDUNDANT_PICKLE",
                pattern="pickle beside safetensors",
                severity="low",
                description=(
                    f"The repository ships both SafeTensors weights and {len(pickle_like)} "
                    "pickle-based checkpoint(s); a loader that prefers the pickle re-introduces "
                    "deserialization risk."
                ),
                category="supply_chain",
                location=root.name,
                cvss=3.5,
                remediation="Delete the pickle checkpoints or pin the loader to SafeTensors.",
                confidence="medium",
            )
        )
    return threats


__all__ = [
    "AegisML",
    "ScanResult",
    "Threat",
    "ENGINE_VERSION",
    "RULESET_VERSION",
    "DEFAULT_CHUNK_SIZE",
]
