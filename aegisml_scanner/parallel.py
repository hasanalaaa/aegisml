"""Segment-parallel evidence scanning for very large artifacts.

A single sequential pass is bounded by one core.  For terabyte-scale weights the
file is split into contiguous segments that are scanned in separate processes,
while SHA-256 runs in a background *thread* of the parent — ``hashlib`` releases
the GIL, so hashing overlaps with the workers instead of competing with them.

Correctness across the cut points is preserved by giving every worker the
``overlap`` bytes that precede its segment and discarding any match that ends
before the segment start, so a signature straddling a boundary is reported
exactly once, at its true absolute offset.
"""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import threading
from typing import Any, Sequence

from .matcher import ByteProfiler, LiteralMatcher, RegexScanner, StringHarvester, has_text_run
from .rules import ALL_RULES, Rule, build_ruleset


MIN_SEGMENT = 64 * 1024 * 1024
DEFAULT_CHUNK = 8 * 1024 * 1024


@dataclass(frozen=True)
class SegmentJob:
    path: str
    start: int
    end: int
    overlap: int
    chunk_size: int
    tier: str
    run_gate: int
    string_budget: int
    entropy_mode: str
    packs: tuple[str, ...]


def _ruleset(packs: Sequence[str]) -> tuple[Rule, ...]:
    return build_ruleset(packs) if packs else ALL_RULES


def scan_segment(job: SegmentJob) -> dict[str, Any]:
    """Worker entry point: evidence for one byte range, as plain data."""
    rules = _ruleset(job.packs)
    matcher = LiteralMatcher(rules)
    magics = LiteralMatcher(rules, binary_only=True) if job.tier != "full" else None
    harvester = StringHarvester(job.string_budget, wide=False)
    regex = RegexScanner(rules, "string")
    profiler = ByteProfiler(mode=job.entropy_mode, total_bytes=job.end - job.start)

    carry = b""
    position = job.start
    deep_bytes = 0
    with open(job.path, "rb") as stream:
        if job.start and job.overlap:
            stream.seek(max(0, job.start - job.overlap))
            carry = stream.read(min(job.overlap, job.start))
        stream.seek(job.start)
        while position < job.end:
            chunk = stream.read(min(job.chunk_size, job.end - position))
            if not chunk:
                break
            profiler.feed(chunk, position)
            textual = has_text_run(chunk, job.run_gate)
            deep = True if job.tier == "full" else textual
            if deep:
                deep_bytes += len(chunk)
                matcher.feed(chunk, position, carry=carry)
            elif magics is not None:
                magics.feed(chunk, position, carry=carry)
            if textual:
                harvester.feed(chunk, position)
            keep = min(matcher.overlap, len(chunk))
            carry = chunk[len(chunk) - keep:]
            position += len(chunk)
    harvester.finish()
    profiler.finish()

    hits = dict(matcher.finish())
    if magics is not None:
        for index, hit in magics.finish().items():
            hits.setdefault(index, hit)
    literal = {
        index: (hit.occurrences, hit.offsets[:32], hit.evidence[:4])
        for index, hit in hits.items()
    }
    pattern_hits = {
        index: (hit.occurrences, hit.offsets[:32], hit.evidence[:4])
        for index, hit in regex.scan(harvester.strings).items()
    }
    return {
        "start": job.start,
        "end": job.end,
        "literal": literal,
        "regex": pattern_hits,
        "deep_bytes": deep_bytes,
        "histogram": profiler.histogram,
        "sampled_bytes": profiler.sampled_bytes,
        "odd_bytes": profiler.odd_bytes,
        "lsb_samples": profiler.lsb_samples,
        "blocks": profiler.blocks_measured,
        "entropy_sum": profiler.entropy_sum,
        "text_blocks": [stat.to_dict() for stat in profiler.text_blocks(0.85)[:8]],
        "high_entropy_blocks": [stat.to_dict() for stat in profiler.high_entropy_blocks()[:8]],
        "strings_truncated": harvester.truncated,
    }


def plan(size: int, jobs: int, overlap: int, chunk_size: int, **options: Any) -> list[SegmentJob]:
    count = max(1, min(jobs, max(1, size // MIN_SEGMENT)))
    span = -(-size // count)
    segments: list[SegmentJob] = []
    start = 0
    while start < size:
        end = min(size, start + span)
        segments.append(
            SegmentJob(start=start, end=end, overlap=overlap, chunk_size=chunk_size, **options)
        )
        start = end
    return segments


def scan_file(
    path: Path,
    *,
    jobs: int,
    tier: str = "auto",
    chunk_size: int = DEFAULT_CHUNK,
    run_gate: int = 24,
    string_budget: int = 8 * 1024 * 1024,
    entropy_mode: str = "auto",
    packs: Sequence[str] = (),
    progress=None,
) -> dict[str, Any]:
    """Run the evidence pass in parallel and return merged, plain-data results."""
    size = path.stat().st_size
    rules = _ruleset(packs)
    overlap = LiteralMatcher(rules).overlap
    effective_tier = tier if tier != "auto" else "full"
    segments = plan(
        size, jobs, overlap, chunk_size,
        path=str(path), tier=effective_tier, run_gate=run_gate,
        string_budget=string_budget, entropy_mode=entropy_mode, packs=tuple(packs),
    )

    digest: dict[str, str] = {}

    def hash_file() -> None:
        sha = hashlib.sha256()
        with open(path, "rb") as stream:
            while True:
                block = stream.read(chunk_size)
                if not block:
                    break
                sha.update(block)
        digest["sha256"] = sha.hexdigest()

    hasher = threading.Thread(target=hash_file, daemon=True)
    hasher.start()

    merged: dict[str, Any] = {
        "literal": {}, "regex": {}, "deep_bytes": 0, "histogram": [0] * 256,
        "sampled_bytes": 0, "odd_bytes": 0, "lsb_samples": 0, "blocks": 0,
        "entropy_sum": 0.0, "text_blocks": [], "high_entropy_blocks": [],
        "strings_truncated": False, "segments": len(segments),
    }
    completed = 0
    if len(segments) == 1:
        results = [scan_segment(segments[0])]
    else:
        with ProcessPoolExecutor(max_workers=min(jobs, len(segments))) as pool:
            results = list(pool.map(scan_segment, segments))
    for result in results:
        completed += 1
        _merge(merged, result)
        if progress is not None:
            progress(min(size, completed * (size // max(1, len(segments)))), size)
    hasher.join()
    merged["sha256"] = digest.get("sha256", "")
    merged["overlap"] = overlap
    merged["tier"] = effective_tier
    return merged


def _merge(target: dict[str, Any], part: dict[str, Any]) -> None:
    for key in ("literal", "regex"):
        for index, (occurrences, offsets, evidence) in part[key].items():
            current = target[key].get(index)
            if current is None:
                target[key][index] = [occurrences, list(offsets), list(evidence)]
            else:
                current[0] += occurrences
                for offset in offsets:
                    if len(current[1]) < 64:
                        current[1].append(offset)
                for item in evidence:
                    if item not in current[2] and len(current[2]) < 8:
                        current[2].append(item)
    target["deep_bytes"] += part["deep_bytes"]
    target["sampled_bytes"] += part["sampled_bytes"]
    target["odd_bytes"] += part["odd_bytes"]
    target["lsb_samples"] += part["lsb_samples"]
    target["blocks"] += part["blocks"]
    target["entropy_sum"] += part["entropy_sum"]
    target["strings_truncated"] = target["strings_truncated"] or part["strings_truncated"]
    for value, count in enumerate(part["histogram"]):
        target["histogram"][value] += count
    target["text_blocks"].extend(part["text_blocks"])
    target["high_entropy_blocks"].extend(part["high_entropy_blocks"])
    target["text_blocks"].sort(key=lambda item: -item["printable_ratio"])
    del target["text_blocks"][16:]
    target["high_entropy_blocks"].sort(key=lambda item: -item["entropy"])
    del target["high_entropy_blocks"][16:]


def available_jobs() -> int:
    return max(1, (os.cpu_count() or 1))
