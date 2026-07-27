"""Defensive, no-execution parsers for model container metadata.

Every parser returns findings plus an explicit coverage state.  Parsers never
import model code, unpickle objects, or extract archives.
"""

from __future__ import annotations

import codecs
import hashlib
import json
import os
from pathlib import Path
import pickletools
import re
import struct
from typing import Any, BinaryIO
import zipfile


MAX_SAFETENSORS_HEADER = 100 * 1024 * 1024
MAX_SAFETENSORS_TENSORS = 1_000_000
MAX_TENSOR_RANK = 32
MAX_DIMENSION = 2**48
MAX_PICKLE_BYTES = 64 * 1024 * 1024
MAX_PICKLE_OPCODES = 1_000_000
MAX_PICKLE_STREAMS = 16
MAX_ZIP_ENTRIES = 100_000
MAX_ZIP_CENTRAL_DIRECTORY = 64 * 1024 * 1024
MAX_GGUF_METADATA = 1_000_000
MAX_GGUF_TENSORS = 10_000_000
MAX_GGUF_COMPLEX_ARRAY_ITEMS = 10_000_000
MAX_GGUF_ARRAY_DEPTH = 16
MAX_GGUF_ALIGNMENT = 1024 * 1024
MAX_GGUF_RANK = 16

_GGUF_FIXED_VALUE_FORMATS = {
    0: "B",
    1: "b",
    2: "H",
    3: "h",
    4: "I",
    5: "i",
    6: "f",
    7: "B",
    10: "Q",
    11: "q",
    12: "d",
}
_GGUF_KEY = re.compile(rb"[a-z0-9_]+(?:\.[a-z0-9_]+)*\Z")

_DTYPE_WIDTHS = {
    "BOOL": 1,
    "U8": 1,
    "I8": 1,
    "F8_E4M3": 1,
    "F8_E5M2": 1,
    "I16": 2,
    "U16": 2,
    "F16": 2,
    "BF16": 2,
    "I32": 4,
    "U32": 4,
    "F32": 4,
    "I64": 8,
    "U64": 8,
    "F64": 8,
}

_DANGEROUS_GLOBALS = {
    ("os", "system"),
    ("os", "popen"),
    ("posix", "system"),
    ("posix", "popen"),
    ("nt", "system"),
    ("nt", "popen"),
    ("subprocess", "Popen"),
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "compile"),
    ("builtins", "__import__"),
    ("__builtin__", "eval"),
    ("__builtin__", "exec"),
    ("ctypes", "CDLL"),
    ("ctypes", "WinDLL"),
    ("marshal", "loads"),
    ("pickle", "loads"),
    ("_pickle", "loads"),
    ("socket", "socket"),
    ("runpy", "run_path"),
}


def _finding(
    finding_id: str,
    severity: str,
    cvss: float,
    description: str,
    *,
    category: str = "format_anomaly",
    remediation: str = "Do not load the artifact until it is independently verified.",
    byte_offsets: list[int] | None = None,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "cvss": cvss,
        "description": description,
        "category": category,
        "remediation": remediation,
        "byte_offsets": byte_offsets or [],
    }


def inspect(path: Path, detected_format: str) -> dict[str, Any]:
    """Inspect the format metadata selected by extension and file header."""
    suffix = path.suffix.lower()
    if suffix == ".safetensors":
        return _safetensors(path)
    if detected_format == "gguf" or suffix == ".gguf":
        return _gguf(path)
    if detected_format == "pickle" or suffix in {".pkl", ".pickle", ".joblib"}:
        return _raw_pickle(path)
    if detected_format == "zip" and suffix in {".pt", ".pth", ".bin"}:
        return _pytorch_zip(path)
    return {"status": "not_applicable", "metadata": {}, "findings": []}


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key[:120]}")
        result[key] = value
    return result


def _safetensors(path: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}
    size = path.stat().st_size
    with path.open("rb") as stream:
        raw_length = stream.read(8)
        if len(raw_length) != 8:
            findings.append(
                _finding(
                    "AML.FORMAT.SAFETENSORS.HEADER",
                    "high",
                    7.0,
                    "SafeTensors file is too short to contain its header length.",
                )
            )
            return _report("complete", metadata, findings)
        header_length = struct.unpack("<Q", raw_length)[0]
        metadata["header_bytes"] = header_length
        if header_length == 0 or header_length > MAX_SAFETENSORS_HEADER:
            findings.append(
                _finding(
                    "AML.FORMAT.SAFETENSORS.HEADER",
                    "high",
                    7.5,
                    f"Unsafe SafeTensors header length: {header_length:,} bytes.",
                )
            )
            status = "capped" if header_length > MAX_SAFETENSORS_HEADER else "complete"
            return _report(status, metadata, findings)
        if header_length > size - 8:
            findings.append(
                _finding(
                    "AML.FORMAT.SAFETENSORS.TRUNCATED",
                    "high",
                    7.2,
                    "SafeTensors header extends beyond the end of the file.",
                )
            )
            return _report("complete", metadata, findings)
        header_bytes = stream.read(header_length)

    try:
        header_text = header_bytes.decode("utf-8", errors="strict")
        header = json.loads(header_text, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        findings.append(
            _finding(
                "AML.FORMAT.SAFETENSORS.JSON",
                "high",
                7.0,
                f"Invalid SafeTensors JSON header: {str(error)[:160]}.",
            )
        )
        return _report("complete", metadata, findings)
    if not isinstance(header, dict):
        findings.append(
            _finding(
                "AML.FORMAT.SAFETENSORS.JSON",
                "high",
                7.0,
                "SafeTensors header root is not a JSON object.",
            )
        )
        return _report("complete", metadata, findings)

    tensor_items = [(key, value) for key, value in header.items() if key != "__metadata__"]
    metadata["tensor_count"] = len(tensor_items)
    if len(tensor_items) > MAX_SAFETENSORS_TENSORS:
        findings.append(
            _finding(
                "AML.FORMAT.SAFETENSORS.TENSOR_COUNT",
                "high",
                7.0,
                f"Header declares {len(tensor_items):,} tensors, above the parser safety limit.",
            )
        )
        return _report("capped", metadata, findings)

    extra_metadata = header.get("__metadata__", {})
    if not isinstance(extra_metadata, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in extra_metadata.items()
    ):
        findings.append(
            _finding(
                "AML.FORMAT.SAFETENSORS.METADATA",
                "medium",
                5.0,
                "SafeTensors __metadata__ must be a string-to-string object.",
            )
        )

    data_region_size = size - 8 - header_length
    spans: list[tuple[int, int, str]] = []
    dtype_counts: dict[str, int] = {}
    for name, tensor in tensor_items:
        if not isinstance(tensor, dict) or not {"dtype", "shape", "data_offsets"}.issubset(tensor):
            findings.append(
                _finding(
                    "AML.FORMAT.SAFETENSORS.TENSOR_SCHEMA",
                    "high",
                    7.0,
                    f"Tensor {name[:120]!r} is missing dtype, shape, or data_offsets.",
                )
            )
            continue
        dtype = tensor.get("dtype")
        shape = tensor.get("shape")
        offsets = tensor.get("data_offsets")
        valid_shape = (
            isinstance(shape, list)
            and len(shape) <= MAX_TENSOR_RANK
            and all(
                isinstance(dim, int)
                and not isinstance(dim, bool)
                and 0 <= dim <= MAX_DIMENSION
                for dim in shape
            )
        )
        if dtype not in _DTYPE_WIDTHS or not valid_shape:
            findings.append(
                _finding(
                    "AML.FORMAT.SAFETENSORS.TENSOR_SCHEMA",
                    "high",
                    7.0,
                    f"Tensor {name[:120]!r} has an invalid dtype or shape.",
                )
            )
            continue
        dtype_counts[dtype] = dtype_counts.get(dtype, 0) + 1
        valid_offsets = (
            isinstance(offsets, list)
            and len(offsets) == 2
            and all(isinstance(value, int) and not isinstance(value, bool) for value in offsets)
        )
        if not valid_offsets:
            findings.append(
                _finding(
                    "AML.FORMAT.SAFETENSORS.OFFSET",
                    "critical",
                    9.0,
                    f"Tensor {name[:120]!r} has malformed data offsets.",
                )
            )
            continue
        start, end = offsets
        if start < 0 or end < start or end > data_region_size:
            findings.append(
                _finding(
                    "AML.FORMAT.SAFETENSORS.OFFSET",
                    "critical",
                    9.0,
                    f"Tensor {name[:120]!r} points outside the {data_region_size:,}-byte data region.",
                )
            )
            continue
        expected_bytes = _checked_tensor_bytes(shape, _DTYPE_WIDTHS[dtype])
        if expected_bytes is None or end - start != expected_bytes:
            findings.append(
                _finding(
                    "AML.FORMAT.SAFETENSORS.SIZE",
                    "high",
                    7.5,
                    f"Tensor {name[:120]!r} byte span does not equal dtype width × shape.",
                )
            )
        spans.append((start, end, name))

    metadata["validated_tensors"] = len(spans)
    metadata["dtype_counts"] = dtype_counts
    cursor = 0
    for start, end, name in sorted(spans):
        if start < cursor:
            findings.append(
                _finding(
                    "AML.FORMAT.SAFETENSORS.OVERLAP",
                    "critical",
                    9.0,
                    f"Tensor {name[:120]!r} overlaps an earlier tensor data range.",
                )
            )
            break
        if start > cursor:
            findings.append(
                _finding(
                    "AML.FORMAT.SAFETENSORS.SLACK",
                    "medium",
                    4.0,
                    f"SafeTensors data region has an unclaimed {start - cursor:,}-byte gap.",
                )
            )
        cursor = max(cursor, end)
    if spans and cursor < data_region_size:
        findings.append(
            _finding(
                "AML.FORMAT.SAFETENSORS.SLACK",
                "medium",
                4.0,
                f"SafeTensors data region has {data_region_size - cursor:,} trailing unclaimed bytes.",
            )
        )
    return _report("complete", metadata, findings)


def _checked_tensor_bytes(shape: list[int], width: int) -> int | None:
    elements = 1
    for dimension in shape:
        elements *= dimension
        if elements > 2**63 // width:
            return None
    return elements * width


class _GGUFParseError(ValueError):
    pass


class _GGUFLimitError(_GGUFParseError):
    pass


class _GGUFReader:
    """Bounds-check every GGUF read/seek without mapping or loading the model."""

    def __init__(self, stream: BinaryIO, size: int) -> None:
        self.stream = stream
        self.size = size

    @property
    def position(self) -> int:
        return self.stream.tell()

    @property
    def remaining(self) -> int:
        return self.size - self.position

    def read_exact(self, length: int) -> bytes:
        if length < 0 or length > self.remaining:
            raise _GGUFParseError(
                f"read of {length:,} bytes at offset {self.position:,} exceeds the file"
            )
        data = self.stream.read(length)
        if len(data) != length:
            raise _GGUFParseError(f"truncated read at offset {self.position - len(data):,}")
        return data

    def unpack(self, format_code: str) -> Any:
        size = struct.calcsize("<" + format_code)
        return struct.unpack("<" + format_code, self.read_exact(size))[0]

    def skip(self, length: int) -> None:
        if length < 0 or length > self.remaining:
            raise _GGUFParseError(
                f"skip of {length:,} bytes at offset {self.position:,} exceeds the file"
            )
        self.stream.seek(length, os.SEEK_CUR)

    def read_utf8(self, *, max_length: int, keep: bool) -> str | None:
        length = self.unpack("Q")
        if length > max_length:
            raise _GGUFLimitError(f"string length {length:,} exceeds limit {max_length:,}")
        if length > self.remaining:
            raise _GGUFParseError(f"string length {length:,} exceeds remaining file bytes")
        if keep:
            try:
                return self.read_exact(length).decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise _GGUFParseError(f"invalid UTF-8 string: {error}") from error

        decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
        remaining = length
        try:
            while remaining:
                chunk = self.read_exact(min(1024 * 1024, remaining))
                decoder.decode(chunk, final=False)
                remaining -= len(chunk)
            decoder.decode(b"", final=True)
        except UnicodeDecodeError as error:
            raise _GGUFParseError(f"invalid UTF-8 string: {error}") from error
        return None


def _gguf(path: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {
        "parser_scope": "metadata_and_tensor_directory",
        "endianness_assumed": "little",
        "metadata_parsed": 0,
        "tensor_info_parsed": 0,
    }
    file_size = path.stat().st_size
    with path.open("rb") as stream:
        reader = _GGUFReader(stream, file_size)
        try:
            header = reader.read_exact(24)
            if header[:4] != b"GGUF":
                raise _GGUFParseError("missing GGUF magic")
            version, tensor_count, metadata_count = struct.unpack("<IQQ", header[4:24])
            metadata.update(
                {
                    "version": version,
                    "tensor_count": tensor_count,
                    "metadata_count": metadata_count,
                }
            )
            if version not in {2, 3}:
                findings.append(
                    _finding(
                        "AML.FORMAT.GGUF.VERSION",
                        "medium",
                        4.5,
                        f"GGUF version {version} is not supported by the bounded structural parser.",
                    )
                )
                return _report("capped", metadata, findings)
            if metadata_count > MAX_GGUF_METADATA:
                findings.append(
                    _finding(
                        "AML.FORMAT.GGUF.METADATA_COUNT",
                        "high",
                        7.0,
                        f"GGUF declares an unsafe metadata count of {metadata_count:,}.",
                    )
                )
                return _report("capped", metadata, findings)
            if tensor_count > MAX_GGUF_TENSORS:
                findings.append(
                    _finding(
                        "AML.FORMAT.GGUF.TENSOR_COUNT",
                        "high",
                        7.0,
                        f"GGUF declares an unsafe tensor count of {tensor_count:,}.",
                    )
                )
                return _report("capped", metadata, findings)

            alignment = 32
            seen_keys: set[bytes] = set()
            for _ in range(metadata_count):
                key = reader.read_utf8(max_length=65_535, keep=True)
                assert key is not None
                key_bytes = key.encode("utf-8")
                if not _GGUF_KEY.fullmatch(key_bytes):
                    findings.append(
                        _finding(
                            "AML.FORMAT.GGUF.METADATA_KEY",
                            "medium",
                            4.0,
                            f"Invalid GGUF metadata key {key[:120]!r}.",
                        )
                    )
                key_digest = hashlib.blake2b(key_bytes, digest_size=16).digest()
                if key_digest in seen_keys:
                    findings.append(
                        _finding(
                            "AML.FORMAT.GGUF.DUPLICATE_KEY",
                            "high",
                            7.0,
                            f"Duplicate GGUF metadata key {key[:120]!r}.",
                        )
                    )
                seen_keys.add(key_digest)
                value_type = reader.unpack("I")
                value = _read_gguf_value(
                    reader,
                    value_type,
                    depth=0,
                    capture=key == "general.alignment" and value_type == 4,
                )
                if key == "general.alignment":
                    if value_type != 4 or not isinstance(value, int):
                        raise _GGUFParseError("general.alignment must be UINT32")
                    alignment = value
                metadata["metadata_parsed"] += 1

            if (
                alignment < 8
                or alignment > MAX_GGUF_ALIGNMENT
                or alignment % 8 != 0
            ):
                raise _GGUFParseError(
                    f"invalid general.alignment {alignment}; expected an 8-byte multiple"
                )
            metadata["alignment"] = alignment

            max_offset = -1
            max_offset_name = ""
            for _ in range(tensor_count):
                name = reader.read_utf8(max_length=64, keep=True)
                assert name is not None
                rank = reader.unpack("I")
                if rank > MAX_GGUF_RANK:
                    raise _GGUFLimitError(f"tensor {name!r} declares rank {rank}")
                for _dimension in range(rank):
                    reader.unpack("Q")
                tensor_type = reader.unpack("I")
                if tensor_type >= 40:
                    findings.append(
                        _finding(
                            "AML.FORMAT.GGUF.TENSOR_TYPE",
                            "medium",
                            4.5,
                            f"Tensor {name[:64]!r} declares unknown GGML type {tensor_type}.",
                        )
                    )
                offset = reader.unpack("Q")
                if offset % alignment:
                    findings.append(
                        _finding(
                            "AML.FORMAT.GGUF.TENSOR_ALIGNMENT",
                            "high",
                            7.0,
                            f"Tensor {name[:64]!r} offset is not aligned to {alignment} bytes.",
                        )
                    )
                if offset > max_offset:
                    max_offset = offset
                    max_offset_name = name
                metadata["tensor_info_parsed"] += 1

            directory_end = reader.position
            data_offset = directory_end + ((-directory_end) % alignment)
            if data_offset > file_size:
                raise _GGUFParseError("aligned tensor-data offset extends beyond the file")
            padding = reader.read_exact(data_offset - directory_end)
            if any(padding):
                findings.append(
                    _finding(
                        "AML.FORMAT.GGUF.PADDING",
                        "medium",
                        4.0,
                        "GGUF tensor-directory padding contains non-zero bytes.",
                    )
                )
            tensor_data_bytes = file_size - data_offset
            metadata["tensor_data_offset"] = data_offset
            metadata["tensor_data_bytes"] = tensor_data_bytes
            if max_offset >= tensor_data_bytes and tensor_count:
                findings.append(
                    _finding(
                        "AML.FORMAT.GGUF.TENSOR_OFFSET",
                        "critical",
                        9.0,
                        f"Tensor {max_offset_name[:64]!r} offset {max_offset:,} lies outside the tensor data region.",
                    )
                )
        except _GGUFLimitError as error:
            findings.append(
                _finding(
                    "AML.FORMAT.GGUF.LIMIT",
                    "high",
                    7.0,
                    f"GGUF structural analysis hit a safety limit: {str(error)[:160]}.",
                    category="coverage",
                )
            )
            return _report("capped", metadata, findings)
        except (_GGUFParseError, OSError, struct.error) as error:
            findings.append(
                _finding(
                    "AML.FORMAT.GGUF.STRUCTURE",
                    "high",
                    7.0,
                    f"Invalid GGUF structure: {str(error)[:160]}.",
                )
            )
    return _report("complete", metadata, findings)


def _read_gguf_value(
    reader: _GGUFReader,
    value_type: int,
    *,
    depth: int,
    capture: bool = False,
) -> Any:
    if depth > MAX_GGUF_ARRAY_DEPTH:
        raise _GGUFLimitError("metadata arrays are nested too deeply")
    if value_type in _GGUF_FIXED_VALUE_FORMATS:
        value = reader.unpack(_GGUF_FIXED_VALUE_FORMATS[value_type])
        if value_type == 7 and value not in {0, 1}:
            raise _GGUFParseError(f"invalid boolean value {value}")
        return value if capture else None
    if value_type == 8:
        return reader.read_utf8(max_length=reader.remaining, keep=capture)
    if value_type != 9:
        raise _GGUFParseError(f"unknown metadata value type {value_type}")

    element_type = reader.unpack("I")
    count = reader.unpack("Q")
    if element_type not in {*_GGUF_FIXED_VALUE_FORMATS, 8, 9}:
        raise _GGUFParseError(f"unknown metadata array element type {element_type}")
    if element_type in _GGUF_FIXED_VALUE_FORMATS and not capture:
        reader.skip(struct.calcsize("<" + _GGUF_FIXED_VALUE_FORMATS[element_type]) * count)
        return None
    if count > MAX_GGUF_COMPLEX_ARRAY_ITEMS:
        raise _GGUFLimitError(f"complex metadata array contains {count:,} elements")
    for _ in range(count):
        _read_gguf_value(reader, element_type, depth=depth + 1, capture=False)
    return None


def _raw_pickle(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    with path.open("rb") as stream:
        data = stream.read(MAX_PICKLE_BYTES + 1)
    capped = len(data) > MAX_PICKLE_BYTES
    if capped:
        data = data[:MAX_PICKLE_BYTES]
    findings, metadata = _analyze_pickle_bytes(data, source=path.name)
    findings.append(
        _finding(
            "AML.FORMAT.PICKLE.UNSAFE",
            "medium",
            5.0,
            "Pickle can execute code while loading even when no known gadget is found.",
            category="deserialization",
            remediation="Prefer SafeTensors or use a restricted weights-only loader.",
        )
    )
    metadata["bytes_analyzed"] = len(data)
    metadata["total_bytes"] = size
    if capped:
        findings.append(
            _finding(
                "AML.FORMAT.PICKLE.CAPPED",
                "high",
                7.0,
                f"Pickle opcode analysis was capped at {MAX_PICKLE_BYTES:,} bytes.",
                category="coverage",
            )
        )
    return _report("capped" if capped else "complete", metadata, findings)


def _zip_directory_limits(path: Path) -> tuple[int | None, int | None]:
    """Return classic ZIP entry count and central-directory size from EOCD."""
    size = path.stat().st_size
    with path.open("rb") as stream:
        stream.seek(max(0, size - (65_535 + 22)))
        tail = stream.read()
    position = tail.rfind(b"PK\x05\x06")
    if position < 0 or len(tail) - position < 22:
        return None, None
    fields = struct.unpack("<4s4H2LH", tail[position : position + 22])
    entries, directory_size = fields[4], fields[5]
    if entries == 0xFFFF or directory_size == 0xFFFFFFFF:
        return None, None  # ZIP64 requires a separate record; let zipfile parse it.
    return entries, directory_size


def _pytorch_zip(path: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {"pickles_analyzed": 0}
    entry_count, directory_size = _zip_directory_limits(path)
    metadata["archive_entries_declared"] = entry_count
    metadata["central_directory_bytes"] = directory_size
    if entry_count is not None and entry_count > MAX_ZIP_ENTRIES:
        findings.append(
            _finding(
                "AML.FORMAT.ZIP.ENTRY_COUNT",
                "high",
                7.0,
                f"Archive declares {entry_count:,} entries, above the safety limit.",
            )
        )
        return _report("capped", metadata, findings)
    if directory_size is not None and directory_size > MAX_ZIP_CENTRAL_DIRECTORY:
        findings.append(
            _finding(
                "AML.FORMAT.ZIP.DIRECTORY_SIZE",
                "high",
                7.0,
                "ZIP central directory exceeds the parser memory budget.",
            )
        )
        return _report("capped", metadata, findings)

    status = "complete"
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            metadata["archive_entries"] = len(infos)
            if len(infos) > MAX_ZIP_ENTRIES:
                findings.append(
                    _finding(
                        "AML.FORMAT.ZIP.ENTRY_COUNT",
                        "high",
                        7.0,
                        f"Archive contains {len(infos):,} entries, above the safety limit.",
                    )
                )
                return _report("capped", metadata, findings)
            pickle_infos = []
            for info in infos:
                normalized = info.filename.replace("\\", "/")
                if normalized.startswith("/") or "../" in f"/{normalized}":
                    findings.append(
                        _finding(
                            "AML.FORMAT.ZIP.PATH_TRAVERSAL",
                            "critical",
                            8.8,
                            f"Archive entry uses an unsafe path: {normalized[:160]!r}.",
                        )
                    )
                if normalized.lower().endswith(".pkl"):
                    pickle_infos.append(info)
            metadata["pickle_entries"] = len(pickle_infos)
            if not pickle_infos:
                findings.append(
                    _finding(
                        "AML.FORMAT.PYTORCH.MISSING_PICKLE",
                        "high",
                        7.0,
                        "PyTorch ZIP contains no pickle metadata entry.",
                    )
                )
            for info in pickle_infos:
                if info.file_size > MAX_PICKLE_BYTES:
                    status = "capped"
                    findings.append(
                        _finding(
                            "AML.FORMAT.PICKLE.CAPPED",
                            "high",
                            7.0,
                            f"Embedded pickle {info.filename[:120]!r} exceeds the analysis limit.",
                            category="coverage",
                        )
                    )
                    continue
                with archive.open(info) as stream:
                    data = stream.read(MAX_PICKLE_BYTES + 1)
                if len(data) > MAX_PICKLE_BYTES:
                    status = "capped"
                    continue
                pickle_findings, pickle_metadata = _analyze_pickle_bytes(
                    data, source=info.filename
                )
                findings.extend(pickle_findings)
                metadata.setdefault("pickle_reports", {})[info.filename[:200]] = pickle_metadata
                metadata["pickles_analyzed"] += 1
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        findings.append(
            _finding(
                "AML.FORMAT.ZIP.INVALID",
                "high",
                7.0,
                f"Invalid PyTorch ZIP container: {str(error)[:160]}.",
            )
        )
    return _report(status, metadata, findings)


def _analyze_pickle_bytes(data: bytes, *, source: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    references: list[str] = []
    seen_findings: set[tuple[str, str, str]] = set()
    cursor = 0
    streams = 0
    opcode_count = 0
    reduce_count = 0

    while cursor < len(data) and streams < MAX_PICKLE_STREAMS:
        while cursor < len(data) and data[cursor] in b"\x00 \t\r\n":
            cursor += 1
        if cursor >= len(data):
            break
        streams += 1
        stack: list[Any] = []
        memo: dict[int, Any] = {}
        next_memo = 0
        last_relative_position = -1
        stopped = False
        try:
            for opcode, argument, relative_position in pickletools.genops(data[cursor:]):
                opcode_count += 1
                last_relative_position = relative_position
                if opcode_count > MAX_PICKLE_OPCODES:
                    findings.append(
                        _finding(
                            "AML.FORMAT.PICKLE.OPCODE_LIMIT",
                            "high",
                            7.0,
                            "Pickle opcode count exceeds the analysis safety limit.",
                            category="coverage",
                        )
                    )
                    return findings, {
                        "source": source,
                        "streams": streams,
                        "opcode_count": opcode_count,
                        "truncated": True,
                    }
                name = opcode.name
                absolute_position = cursor + relative_position
                if name in {
                    "SHORT_BINUNICODE",
                    "BINUNICODE",
                    "BINUNICODE8",
                    "UNICODE",
                    "SHORT_BINSTRING",
                    "BINSTRING",
                    "STRING",
                    "BINBYTES",
                    "SHORT_BINBYTES",
                    "BINBYTES8",
                }:
                    stack.append(_pickle_string(argument))
                elif name == "MEMOIZE":
                    memo[next_memo] = stack[-1] if stack else None
                    next_memo += 1
                elif name in {"BINPUT", "LONG_BINPUT", "PUT"}:
                    index = int(argument)
                    memo[index] = stack[-1] if stack else None
                    next_memo = max(next_memo, index + 1)
                elif name in {"BINGET", "LONG_BINGET", "GET"}:
                    stack.append(memo.get(int(argument)))
                elif name == "STACK_GLOBAL":
                    global_name = stack.pop() if stack else None
                    module_name = stack.pop() if stack else None
                    if isinstance(module_name, str) and isinstance(global_name, str):
                        references.append(f"{module_name}.{global_name}")
                        _classify_pickle_global(
                            module_name,
                            global_name,
                            absolute_position,
                            findings,
                            seen_findings,
                        )
                    stack.append(None)
                elif name in {"GLOBAL", "INST"}:
                    value = _pickle_string(argument)
                    if " " in value:
                        module_name, global_name = value.split(" ", 1)
                        references.append(f"{module_name}.{global_name}")
                        _classify_pickle_global(
                            module_name,
                            global_name,
                            absolute_position,
                            findings,
                            seen_findings,
                        )
                    stack.append(None)
                elif name == "REDUCE":
                    reduce_count += 1
                elif name in {"EXT1", "EXT2", "EXT4"}:
                    findings.append(
                        _finding(
                            "AML.FORMAT.PICKLE.EXTENSION",
                            "high",
                            7.5,
                            f"Pickle extension-registry opcode at byte {absolute_position}.",
                            category="deserialization",
                            byte_offsets=[absolute_position],
                        )
                    )
                elif name == "BUILD":
                    findings.append(
                        _finding(
                            "AML.FORMAT.PICKLE.BUILD",
                            "medium",
                            6.0,
                            f"Pickle BUILD/__setstate__ opcode at byte {absolute_position}.",
                            category="deserialization",
                            byte_offsets=[absolute_position],
                        )
                    )
                elif name == "STOP":
                    stopped = True
                    break
                elif name not in {"PROTO", "FRAME", "MARK"}:
                    # Keep memo-backed strings but avoid consuming stale direct
                    # operands across unrelated structural operations.
                    if name in {"POP", "POP_MARK"}:
                        stack.clear()
        except Exception as error:
            findings.append(
                _finding(
                    "AML.FORMAT.PICKLE.PARSER",
                    "high",
                    7.0,
                    f"Pickle parser stopped at byte {cursor}: {str(error)[:160]}.",
                    category="deserialization",
                )
            )
            break
        if not stopped or last_relative_position < 0:
            break
        cursor += last_relative_position + 1

    if cursor < len(data) and streams >= MAX_PICKLE_STREAMS:
        findings.append(
            _finding(
                "AML.FORMAT.PICKLE.STREAM_LIMIT",
                "high",
                7.0,
                "Pickle contains more concatenated streams than the analysis limit.",
                category="coverage",
            )
        )
    if reduce_count:
        dangerous = any(
            finding["id"] == "AML.FORMAT.PICKLE.DANGEROUS_GLOBAL" for finding in findings
        )
        findings.append(
            _finding(
                "AML.FORMAT.PICKLE.REDUCE",
                "critical" if dangerous else "high",
                9.5 if dangerous else 8.0,
                f"Pickle contains {reduce_count} REDUCE opcode(s), which invoke callables while loading.",
                category="deserialization",
            )
        )
    return findings, {
        "source": source,
        "streams": streams,
        "opcode_count": opcode_count,
        "reduce_count": reduce_count,
        "global_references": references[:100],
        "truncated": False,
    }


def _pickle_string(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _classify_pickle_global(
    module_name: str,
    global_name: str,
    position: int,
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str, str]],
) -> None:
    key = ("global", module_name, global_name)
    if key in seen:
        return
    seen.add(key)
    if (module_name, global_name) not in _DANGEROUS_GLOBALS:
        return
    findings.append(
        _finding(
            "AML.FORMAT.PICKLE.DANGEROUS_GLOBAL",
            "critical",
            9.8,
            f"Pickle resolves dangerous global {module_name}.{global_name} at byte {position}.",
            category="code_execution",
            remediation="Never load this pickle; convert a verified source model to SafeTensors.",
            byte_offsets=[position],
        )
    )


def _report(
    status: str, metadata: dict[str, Any], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    return {"status": status, "metadata": metadata, "findings": findings}
