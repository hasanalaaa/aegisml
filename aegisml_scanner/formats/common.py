"""Shared contract for the no-execution format parsers.

A parser answers three questions and nothing else:

1. *What is in this container?* → :class:`Region` entries that map byte spans to
   semantic names (tensor, archive member, header, slack).
2. *What is structurally wrong or dangerous?* → findings.
3. *What is nested inside it that must be scanned in its own right?* →
   :class:`Embedded` payloads handed back to the orchestrator.

Parsers never import model code, never call ``pickle.load``, never extract to
disk, and never touch the network.  Every limit that stops a parser early
downgrades the reported status, which in turn downgrades scan coverage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, BinaryIO


# ---------------------------------------------------------------------------
# Safety limits.  Each one, when reached, must produce a coverage finding.
# ---------------------------------------------------------------------------
MAX_HEADER_BYTES = 128 * 1024 * 1024
MAX_EMBEDDED_BYTES = 64 * 1024 * 1024
MAX_EMBEDDED_ITEMS = 512
MAX_TOTAL_EMBEDDED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 100_000
MAX_ARCHIVE_DEPTH = 4
MAX_COMPRESSION_RATIO = 200
MAX_PICKLE_BYTES = 128 * 1024 * 1024
MAX_PICKLE_OPCODES = 4_000_000
MAX_PICKLE_STREAMS = 32
MAX_TENSORS = 4_000_000
MAX_TENSOR_RANK = 32
MAX_DIMENSION = 2**48
MAX_STRING_FIELD = 1024 * 1024

KIND_TENSOR = "tensor"
KIND_HEADER = "header"
KIND_MEMBER = "member"
KIND_PADDING = "padding"
KIND_SLACK = "slack"
KIND_METADATA = "metadata"


@dataclass(frozen=True)
class Region:
    """A named byte span inside the artifact."""

    name: str
    start: int
    end: int
    kind: str = KIND_TENSOR
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def length(self) -> int:
        return max(0, self.end - self.start)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "name": self.name,
            "start": self.start,
            "end": self.end,
            "length": self.length,
            "kind": self.kind,
        }
        if self.detail:
            payload["detail"] = self.detail
        return payload


@dataclass
class Embedded:
    """A nested payload that the orchestrator scans recursively."""

    path: str
    data: bytes
    kind: str = "member"
    declared_size: int = 0
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class FormatReport:
    status: str = "not_applicable"
    format: str = "generic"
    metadata: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    regions: list[Region] = field(default_factory=list)
    embedded: list[Embedded] = field(default_factory=list)

    def add(self, finding: dict[str, Any]) -> None:
        self.findings.append(finding)

    def cap(self, reason: str) -> None:
        """Mark analysis as bounded rather than complete."""
        if self.status != "error":
            self.status = "capped"
        self.add(
            finding(
                "AML.COVERAGE.LIMIT",
                "high",
                7.0,
                f"Structural analysis stopped at a safety limit: {reason}.",
                category="coverage",
                remediation="Re-run with raised limits in an isolated environment, "
                "or treat the artifact as unverified.",
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "format": self.format,
            "metadata": self.metadata,
            "regions": len(self.regions),
        }


def finding(
    finding_id: str,
    severity: str,
    cvss: float,
    description: str,
    *,
    category: str = "format_anomaly",
    remediation: str = "Do not load the artifact until it is independently verified.",
    byte_offsets: list[int] | None = None,
    location: str = "",
    evidence: list[str] | None = None,
    attack: tuple[str, ...] = (),
    cwe: tuple[str, ...] = (),
    references: tuple[str, ...] = (),
    confidence: str = "high",
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "cvss": cvss,
        "description": description,
        "category": category,
        "remediation": remediation,
        "byte_offsets": byte_offsets or [],
        "location": location,
        "evidence": evidence or [],
        "attack": list(attack),
        "cwe": list(cwe),
        "references": list(references),
        "confidence": confidence,
    }


class ParseError(ValueError):
    """The container is structurally invalid."""


class LimitError(ParseError):
    """A parser safety limit was reached before the container was exhausted."""


class BoundedReader:
    """Bounds-checked sequential reader that never maps the whole file."""

    def __init__(self, stream: BinaryIO, size: int, *, base: int = 0) -> None:
        self.stream = stream
        self.size = size
        self.base = base

    @property
    def position(self) -> int:
        return self.stream.tell() - self.base

    @property
    def remaining(self) -> int:
        return self.size - self.position

    def read_exact(self, length: int) -> bytes:
        if length < 0 or length > self.remaining:
            raise ParseError(
                f"read of {length:,} bytes at offset {self.position:,} exceeds the container"
            )
        data = self.stream.read(length)
        if len(data) != length:
            raise ParseError(f"truncated read at offset {self.position - len(data):,}")
        return data

    def unpack(self, format_code: str) -> Any:
        import struct

        size = struct.calcsize("<" + format_code)
        return struct.unpack("<" + format_code, self.read_exact(size))[0]

    def skip(self, length: int) -> None:
        import os

        if length < 0 or length > self.remaining:
            raise ParseError(
                f"skip of {length:,} bytes at offset {self.position:,} exceeds the container"
            )
        self.stream.seek(length, os.SEEK_CUR)

    def seek(self, offset: int) -> None:
        if offset < 0 or offset > self.size:
            raise ParseError(f"seek to {offset:,} is outside the container")
        self.stream.seek(self.base + offset)


def checked_element_bytes(shape: list[int], width: int) -> int | None:
    """Multiply a shape safely; ``None`` when it overflows a sane budget."""
    if width <= 0:
        return None
    elements = 1
    for dimension in shape:
        if dimension < 0:
            return None
        elements *= dimension
        if elements > 2**63 // width:
            return None
    return elements * width


def printable(value: bytes | str, limit: int = 160) -> str:
    if isinstance(value, str):
        text = value
    else:
        text = value.decode("utf-8", "backslashreplace")
    text = "".join(char if 0x20 <= ord(char) <= 0x7E else "." for char in text)
    return text[:limit]
