"""Streaming evidence primitives: multi-signature matching and byte statistics.

Everything here is standard library only and works on a sliding window, so a
1 TiB artifact costs the same memory as a 1 MiB one.

**Matching strategy.**  CPython has no multi-pattern automaton, but it does have
a very fast single-needle search (``bytes.find`` reaches ~2 GiB/s).  The index
below therefore computes a minimal *anchor cover*: a small set of short byte
sequences such that every signature contains at least one anchor.  A chunk is
searched once per anchor — 36 passes for 327 signatures instead of 327 — and
every anchor hit is verified against the full signatures registered to it.
Because an anchor is by construction a substring of its signature, the cover
cannot introduce a false negative.

**Scan tiers.**  Even at 36 passes a full signature sweep runs at tens of MiB/s,
which is the wrong default for a terabyte of float weights.  Two tiers make the
trade explicit and measurable:

``full``
    every byte is checked against every signature.

``adaptive``
    every byte is still hashed, profiled and checked against the binary magics;
    the full signature set additionally covers all structural regions (headers,
    metadata, archive members, unclaimed slack), every nested payload, and every
    chunk containing a printable run at least ``run_gate`` bytes long — that is,
    every place a command line, URL, script or encoded payload can actually
    live.  The chosen tier is reported in the scan's coverage block.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import heapq
import math
import re
from typing import Iterable, Iterator, Sequence

from .rules import Rule


MIN_STRING_LENGTH = 6
DEFAULT_STRING_BUDGET = 32 * 1024 * 1024
DEFAULT_BLOCK_SIZE = 1024 * 1024
DEFAULT_RUN_GATE = 24
ENTROPY_SAMPLE_PER_BLOCK = 16 * 1024
MAX_TRACKED_BLOCKS = 64
MAX_OFFSETS_PER_RULE = 64
MAX_EVIDENCE_PER_RULE = 8
ANCHOR_LENGTH = 2
BINARY_ANCHOR_LENGTH = 4
#: With few anchors, repeated ``bytes.find`` (~2 GiB/s per needle) beats one
#: compiled alternation (~90 MiB/s regardless of branch count).  Above this many
#: anchors the single regex pass wins.
FIND_LOOP_MAX_ANCHORS = 20

_STRING_RE = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_STRING_LENGTH)

_ODD_TABLE = bytes((value & 1) for value in range(256))
#: Gate table: text-ish bytes map to 1 so a printable run is a run of 0x01.
_TEXT_TABLE = bytes(
    1 if (0x20 <= value <= 0x7E or value in (0x09, 0x0A, 0x0D)) else 0 for value in range(256)
)
_PRINTABLE_TABLE = bytes(1 if 0x20 <= value <= 0x7E else 0 for value in range(256))
_NULL_TABLE = bytes(1 if value == 0 else 0 for value in range(256))

_TEXT_BYTES = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def is_binary_signature(pattern: bytes) -> bool:
    """True when the signature cannot occur inside ordinary text."""
    return any(byte not in _TEXT_BYTES for byte in pattern)


# ---------------------------------------------------------------------------
# Anchor cover
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SignatureIndex:
    """Anchor cover plus the verification table for one rule set."""

    anchors: tuple[tuple[bytes, tuple[tuple[int, bytes, int], ...]], ...]
    binary_anchors: tuple[tuple[bytes, tuple[tuple[int, bytes, int], ...]], ...]
    max_pattern_length: int
    signature_count: int

    @property
    def overlap(self) -> int:
        return max(1, self.max_pattern_length - 1)


_INDEX_CACHE: dict[tuple, SignatureIndex] = {}


def build_index(rules: Sequence[Rule], anchor_length: int = ANCHOR_LENGTH) -> SignatureIndex:
    """Build (and memoise) the anchor cover for a rule set."""
    key = tuple(rules)
    cached = _INDEX_CACHE.get(key)
    if cached is not None:
        return cached

    entries: list[tuple[int, bytes]] = []
    for index, rule in enumerate(rules):
        for pattern in rule.patterns:
            entries.append((index, pattern.lower()))
    index_map = _cover(entries, anchor_length)
    # Binary magics are distinctive, so a longer anchor makes them essentially
    # miss-only on tensor data and lets the cheap search path handle them.
    binary_entries = [(i, p) for i, p in entries if is_binary_signature(p)]
    binary_map = _cover(binary_entries, BINARY_ANCHOR_LENGTH)
    longest = max((len(pattern) for _index, pattern in entries), default=1)
    result = SignatureIndex(
        anchors=index_map,
        binary_anchors=binary_map,
        max_pattern_length=longest,
        signature_count=len(entries),
    )
    _INDEX_CACHE[key] = result
    return result


def _cover(
    entries: Sequence[tuple[int, bytes]], anchor_length: int
) -> tuple[tuple[bytes, tuple[tuple[int, bytes, int], ...]], ...]:
    """Greedy minimum set cover: fewest anchors that touch every signature."""
    if not entries:
        return ()
    uncovered = set(range(len(entries)))
    assignment: dict[bytes, list[tuple[int, bytes, int]]] = {}
    while uncovered:
        counts: dict[bytes, set[int]] = {}
        for position in uncovered:
            _rule_index, pattern = entries[position]
            if len(pattern) >= anchor_length:
                grams = {
                    pattern[start: start + anchor_length]
                    for start in range(len(pattern) - anchor_length + 1)
                }
            else:
                grams = {pattern}
            for gram in grams:
                counts.setdefault(gram, set()).add(position)
        anchor, covered = max(counts.items(), key=lambda item: (len(item[1]), -len(item[0])))
        bucket = assignment.setdefault(anchor, [])
        for position in covered:
            rule_index, pattern = entries[position]
            bucket.append((rule_index, pattern, pattern.find(anchor)))
        uncovered -= covered
    return tuple((anchor, tuple(bucket)) for anchor, bucket in sorted(assignment.items()))


@dataclass
class RuleHit:
    rule_index: int
    occurrences: int = 0
    offsets: list[int] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def record(self, offset: int, sample: str = "") -> None:
        self.occurrences += 1
        if len(self.offsets) < MAX_OFFSETS_PER_RULE:
            self.offsets.append(offset)
        if sample and len(self.evidence) < MAX_EVIDENCE_PER_RULE and sample not in self.evidence:
            self.evidence.append(sample)


class LiteralMatcher:
    """Anchor-covered, chunk-streaming matcher for literal byte signatures."""

    def __init__(self, rules: Sequence[Rule], *, binary_only: bool = False) -> None:
        self.rules = tuple(rules)
        self.index = build_index(self.rules)
        self._anchors = self.index.binary_anchors if binary_only else self.index.anchors
        self._buckets = {anchor: bucket for anchor, bucket in self._anchors}
        self._anchor_lengths = sorted({len(anchor) for anchor, _ in self._anchors})
        self._use_regex = len(self._anchors) > FIND_LOOP_MAX_ANCHORS
        self._scan = (
            re.compile(b"|".join(re.escape(anchor) for anchor, _ in self._anchors))
            if self._anchors and self._use_regex
            else None
        )
        self.overlap = self.index.overlap
        self.hits: dict[int, RuleHit] = {}
        self._carry = b""
        self._carry_start = 0

    @property
    def atom_count(self) -> int:
        return len(self._anchors)

    def feed(self, chunk: bytes, chunk_start: int, *, carry: bytes = b"") -> None:
        """Scan ``chunk``.  ``carry`` supplies the bytes immediately before it.

        One compiled alternation over the anchor cover walks the whole window in
        a single C pass.  ``finditer`` reports non-overlapping matches, so after
        each anchor at ``p`` the ``anchor_length - 1`` positions it consumed are
        probed directly; that keeps the scan exact for anchors that overlap in
        the data while still paying for only one pass.
        """
        if not chunk or not self._anchors:
            return
        prefix = carry if carry else (
            self._carry if self._carry_start + len(self._carry) == chunk_start else b""
        )
        window = prefix + chunk if prefix else chunk
        window_start = chunk_start - len(prefix)
        tail_length = len(prefix)
        lowered = window.lower()
        buckets = self._buckets
        if self._scan is None:
            for anchor, bucket in self._anchors:
                position = lowered.find(anchor)
                while position >= 0:
                    self._verify(bucket, position, lowered, window, window_start, tail_length)
                    position = lowered.find(anchor, position + 1)
        else:
            lengths = self._anchor_lengths
            limit = len(lowered)
            for match in self._scan.finditer(lowered):
                position = match.start()
                consumed = match.end() - position
                self._verify(buckets.get(match.group()), position, lowered, window,
                             window_start, tail_length)
                for shift in range(1, consumed):
                    probe = position + shift
                    for length in lengths:
                        if probe + length > limit:
                            break
                        self._verify(buckets.get(lowered[probe: probe + length]), probe,
                                     lowered, window, window_start, tail_length)
        keep = min(self.overlap, len(chunk))
        self._carry = chunk[len(chunk) - keep:]
        self._carry_start = chunk_start + len(chunk) - keep

    def _verify(self, bucket, position: int, lowered: bytes, window: bytes,
                window_start: int, tail_length: int) -> None:
        if not bucket:
            return
        for rule_index, pattern, relative in bucket:
            start = position - relative
            if start < 0:
                continue
            end = start + len(pattern)
            if end <= tail_length:
                continue  # already reported with the previous chunk
            if lowered[start:end] != pattern:
                continue
            hit = self.hits.get(rule_index)
            if hit is None:
                hit = self.hits[rule_index] = RuleHit(rule_index)
            hit.record(window_start + start, _context(window, start, end))

    def finish(self) -> dict[int, RuleHit]:
        self._carry = b""
        return self.hits


def _context(window: bytes, start: int, end: int, span: int = 24) -> str:
    """Short printable excerpt around a match, for the evidence field."""
    left = max(0, start - span)
    right = min(len(window), end + span)
    excerpt = window[left:right]
    cleaned = bytes(byte if 0x20 <= byte <= 0x7E else 0x2E for byte in excerpt)
    return cleaned.decode("ascii", "replace")


# ---------------------------------------------------------------------------
# String harvesting and regex rules
# ---------------------------------------------------------------------------
class StringHarvester:
    """Extract printable strings (narrow and optionally UTF-16LE) under a budget."""

    def __init__(
        self,
        budget: int = DEFAULT_STRING_BUDGET,
        *,
        wide: bool = True,
        min_length: int = MIN_STRING_LENGTH,
    ) -> None:
        self.budget = budget
        self.wide = wide
        self.min_length = max(4, min_length)
        self.harvested = 0
        self.truncated = False
        self._pattern = (
            _STRING_RE if min_length == MIN_STRING_LENGTH
            else re.compile(rb"[\x20-\x7e\t]{%d,}" % self.min_length)
        )
        self._tail = b""
        self._tail_start = 0
        self.strings: list[tuple[int, str]] = []

    def feed(self, chunk: bytes, chunk_start: int) -> None:
        if self.truncated or not chunk:
            return
        contiguous = self._tail and self._tail_start + len(self._tail) == chunk_start
        window = self._tail + chunk if contiguous else chunk
        window_start = chunk_start - (len(self._tail) if contiguous else 0)
        tail_length = len(self._tail) if contiguous else 0
        for match in self._pattern.finditer(window):
            if match.end() <= tail_length:
                continue
            if match.end() == len(window):
                break  # may continue into the next chunk; carried over below
            self._append(window_start + match.start(), match.group())
            if self.truncated:
                return
        carry = min(4096, len(window))
        self._tail = window[len(window) - carry:]
        self._tail_start = window_start + len(window) - carry
        if self.wide:
            self._feed_wide(chunk, chunk_start)

    def _feed_wide(self, chunk: bytes, chunk_start: int) -> None:
        for phase in (0, 1):
            stripped = chunk[phase::2]
            if len(stripped) < self.min_length:
                continue
            zeros = chunk[1 - phase::2]
            if zeros.translate(_NULL_TABLE).count(1) < len(zeros) // 2:
                continue  # not a UTF-16LE dense region
            for match in self._pattern.finditer(stripped):
                self._append(chunk_start + phase + match.start() * 2, match.group())
                if self.truncated:
                    return

    def _append(self, offset: int, raw: bytes) -> None:
        text = raw.decode("ascii", "replace")
        if self.harvested + len(text) > self.budget:
            self.truncated = True
            return
        self.harvested += len(text)
        self.strings.append((offset, text))

    def finish(self) -> None:
        if self._tail and not self.truncated:
            for match in self._pattern.finditer(self._tail):
                self._append(self._tail_start + match.start(), match.group())
        self._tail = b""


class RegexScanner:
    """Evaluate regular-expression rules over harvested strings."""

    def __init__(self, rules: Sequence[Rule], context: str = "string") -> None:
        self.entries: list[tuple[int, re.Pattern[str]]] = []
        for index, rule in enumerate(rules):
            if not rule.regex or context not in rule.contexts:
                continue
            try:
                self.entries.append((index, re.compile(rule.regex)))
            except re.error:  # pragma: no cover - packs are validated on load
                continue

    def scan(self, strings: Iterable[tuple[int, str]]) -> dict[int, RuleHit]:
        hits: dict[int, RuleHit] = {}
        if not self.entries:
            return hits
        for offset, text in strings:
            for index, compiled in self.entries:
                for match in compiled.finditer(text):
                    hit = hits.get(index)
                    if hit is None:
                        hit = hits[index] = RuleHit(index)
                    hit.record(offset + match.start(), _redact(match.group(0)))
                    if hit.occurrences > 4096:
                        break
        return hits


def _redact(value: str, keep: int = 8, limit: int = 96) -> str:
    """Keep evidence useful without echoing a full secret into a report."""
    trimmed = value[:limit]
    if len(trimmed) <= keep * 2:
        return trimmed
    return f"{trimmed[:keep]}...{trimmed[-4:]}"


# ---------------------------------------------------------------------------
# Byte statistics
# ---------------------------------------------------------------------------
@dataclass
class BlockStat:
    offset: int
    length: int
    entropy: float
    printable_ratio: float

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "length": self.length,
            "entropy": round(self.entropy, 4),
            "printable_ratio": round(self.printable_ratio, 4),
        }


class ByteProfiler:
    """Block-level entropy, printability and LSB statistics.

    All work is C-level (:meth:`bytes.translate`, :meth:`bytes.count`).  Entropy
    uses a bounded contiguous sample per block because a 256-way histogram costs
    256 ``memchr`` passes; printability and LSB cover every byte because they
    cost one pass each.
    """

    def __init__(
        self,
        *,
        mode: str = "auto",
        block_size: int = DEFAULT_BLOCK_SIZE,
        total_bytes: int = 0,
        sample_per_block: int = ENTROPY_SAMPLE_PER_BLOCK,
    ) -> None:
        if mode not in {"auto", "full", "off"}:
            raise ValueError("entropy mode must be auto, full, or off")
        self.mode = mode
        self.block_size = max(4096, block_size)
        self.sample_per_block = max(4096, sample_per_block)
        self.histogram = [0] * 256
        self.sampled_bytes = 0
        self.total_bytes = total_bytes
        self._pending = bytearray()
        self._pending_offset = 0
        self._high_entropy: list[tuple[float, int, BlockStat]] = []
        self._text_blocks: list[tuple[float, int, BlockStat]] = []
        self._sequence = 0
        self.blocks_measured = 0
        self.entropy_sum = 0.0
        self.printable_sum = 0.0
        self.odd_bytes = 0
        self.lsb_samples = 0
        self.bytes_seen = 0

    @property
    def coverage(self) -> str:
        if self.mode == "off":
            return "off"
        return "full" if self.mode == "full" else "sampled"

    def feed(self, chunk: bytes, chunk_start: int) -> None:
        if self.mode == "off" or not chunk:
            return
        self.bytes_seen += len(chunk)
        if not self._pending:
            self._pending_offset = chunk_start
        self._pending.extend(chunk)
        while len(self._pending) >= self.block_size:
            block = bytes(self._pending[: self.block_size])
            self._measure(block, self._pending_offset)
            del self._pending[: self.block_size]
            self._pending_offset += self.block_size

    def _measure(self, block: bytes, offset: int) -> None:
        if self.mode == "full" or len(block) <= self.sample_per_block:
            sample = block
        else:
            # Three spread windows beat one prefix at catching a payload that
            # occupies only part of the block, at the same C cost.
            third = self.sample_per_block // 3
            middle = (len(block) - third) // 2
            sample = block[:third] + block[middle: middle + third] + block[-third:]
        counts = [sample.count(value) for value in range(256)]
        entropy = _entropy(counts, len(sample))
        histogram = self.histogram
        odd = 0
        printable_count = 0
        for value, count in enumerate(counts):
            if not count:
                continue
            histogram[value] += count
            if value & 1:
                odd += count
            if 0x20 <= value <= 0x7E:
                printable_count += count
        # Every statistic comes from one 256-way histogram of the block sample:
        # one pass instead of three, which is what keeps profiling near disk speed.
        self.sampled_bytes += len(sample)
        self.odd_bytes += odd
        self.lsb_samples += len(sample)
        printable = printable_count / len(sample)
        stat = BlockStat(offset, len(block), entropy, printable)
        self.blocks_measured += 1
        self.entropy_sum += entropy
        self.printable_sum += printable
        self._sequence += 1
        _bounded_push(self._high_entropy, (entropy, self._sequence, stat))
        _bounded_push(self._text_blocks, (printable, self._sequence, stat))

    def finish(self) -> None:
        if self._pending:
            self._measure(bytes(self._pending), self._pending_offset)
            self._pending = bytearray()

    @property
    def entropy(self) -> float:
        return _entropy(self.histogram, self.sampled_bytes)

    @property
    def lsb_bias(self) -> float:
        if self.lsb_samples < 4096:
            return 0.0
        return abs(self.odd_bytes / self.lsb_samples - 0.5)

    def high_entropy_blocks(self, minimum: float = 7.4) -> list[BlockStat]:
        return [stat for score, _, stat in sorted(self._high_entropy, reverse=True) if score >= minimum]

    def text_blocks(self, minimum: float = 0.85) -> list[BlockStat]:
        return [stat for score, _, stat in sorted(self._text_blocks, reverse=True) if score >= minimum]

    def to_dict(self) -> dict:
        mean = self.entropy_sum / self.blocks_measured if self.blocks_measured else 0.0
        return {
            "entropy": round(self.entropy, 6),
            "entropy_coverage": self.coverage,
            "bytes_analyzed": self.sampled_bytes,
            "block_size": self.block_size,
            "blocks_measured": self.blocks_measured,
            "mean_block_entropy": round(mean, 4),
            "lsb_bias": round(self.lsb_bias, 6),
            "high_entropy_blocks": [item.to_dict() for item in self.high_entropy_blocks()[:8]],
            "text_dense_blocks": [item.to_dict() for item in self.text_blocks()[:8]],
        }


def _bounded_push(heap: list, item: tuple) -> None:
    if len(heap) < MAX_TRACKED_BLOCKS:
        heapq.heappush(heap, item)
    else:
        heapq.heappushpop(heap, item)


def _entropy(counts: Sequence[int], total: int) -> float:
    if total <= 0:
        return 0.0
    result = 0.0
    for count in counts:
        if count:
            probability = count / total
            result -= probability * math.log2(probability)
    return result


def has_text_run(chunk: bytes, minimum: int = DEFAULT_RUN_GATE) -> bool:
    """True when the chunk contains a printable run of at least ``minimum`` bytes.

    One ``translate`` plus one ``find`` — both C — so this runs at ~400 MiB/s
    and decides whether the expensive signature sweep is worth running on a
    block of raw tensor data.
    """
    if len(chunk) < minimum:
        return False
    return chunk.translate(_TEXT_TABLE).find(b"\x01" * minimum) >= 0


def iter_chunks(stream, chunk_size: int) -> Iterator[tuple[bytes, int]]:
    """Yield ``(chunk, absolute_offset)`` pairs from a binary stream."""
    offset = 0
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            return
        yield chunk, offset
        offset += len(chunk)
