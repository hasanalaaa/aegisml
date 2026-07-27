"""Tensor containers: SafeTensors, GGUF and NumPy .npy.

These formats are "safe" only in the sense that they hold numbers.  The attack
surface is the *directory*: offsets that overlap, spans that leave unclaimed
slack for a payload, metadata fields that are rendered as templates, and dtypes
that quietly re-enable Pickle.  Every parser here validates the directory
exactly, and publishes a region map so the byte-level evidence pass can say
which tensor a suspicious offset belongs to.
"""

from __future__ import annotations

import ast
import codecs
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any, BinaryIO

from .common import (
    MAX_HEADER_BYTES,
    MAX_STRING_FIELD,
    MAX_TENSOR_RANK,
    MAX_TENSORS,
    MAX_DIMENSION,
    BoundedReader,
    Embedded,
    FormatReport,
    KIND_HEADER,
    KIND_METADATA,
    KIND_SLACK,
    KIND_TENSOR,
    LimitError,
    ParseError,
    Region,
    checked_element_bytes,
    finding,
    printable,
)


# ---------------------------------------------------------------------------
# SafeTensors
# ---------------------------------------------------------------------------
MAX_SAFETENSORS_HEADER = 100 * 1024 * 1024

_DTYPE_WIDTHS = {
    "BOOL": 1, "U8": 1, "I8": 1, "F8_E4M3": 1, "F8_E5M2": 1,
    "I16": 2, "U16": 2, "F16": 2, "BF16": 2,
    "I32": 4, "U32": 4, "F32": 4,
    "I64": 8, "U64": 8, "F64": 8,
}
_FLOAT_DTYPES = {"F16", "BF16", "F32", "F64"}


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key[:120]}")
        result[key] = value
    return result


def safetensors_report(path: Path) -> FormatReport:
    report = FormatReport(status="complete", format="safetensors")
    metadata: dict[str, Any] = {}
    report.metadata = metadata
    size = path.stat().st_size

    with path.open("rb") as stream:
        raw_length = stream.read(8)
        if len(raw_length) != 8:
            report.add(_st_finding("HEADER", 7.0, "File is too short to contain its header length."))
            return report
        header_length = struct.unpack("<Q", raw_length)[0]
        metadata["header_bytes"] = header_length
        if header_length == 0 or header_length > MAX_SAFETENSORS_HEADER:
            report.add(
                _st_finding("HEADER", 7.5, f"Unsafe header length: {header_length:,} bytes.")
            )
            if header_length > MAX_SAFETENSORS_HEADER:
                report.status = "capped"
            return report
        if header_length > size - 8:
            report.add(_st_finding("TRUNCATED", 7.2, "Header extends beyond the end of the file."))
            return report
        header_bytes = stream.read(header_length)

    report.regions.append(Region("__header__", 0, 8 + header_length, KIND_HEADER))
    try:
        header = json.loads(header_bytes.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        report.add(_st_finding("JSON", 7.0, f"Invalid JSON header: {str(error)[:160]}."))
        return report
    if not isinstance(header, dict):
        report.add(_st_finding("JSON", 7.0, "Header root is not a JSON object."))
        return report

    tensor_items = [(k, v) for k, v in header.items() if k != "__metadata__"]
    metadata["tensor_count"] = len(tensor_items)
    if len(tensor_items) > MAX_TENSORS:
        report.cap(f"header declares {len(tensor_items):,} tensors")
        return report

    extra = header.get("__metadata__", {})
    if extra:
        if not isinstance(extra, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in extra.items()
        ):
            report.add(
                _st_finding("METADATA", 5.0, "__metadata__ must be a string-to-string object.")
            )
        else:
            metadata["metadata_keys"] = sorted(extra)[:64]
            blob = "\n".join(f"{k}={v}" for k, v in extra.items())
            if blob:
                report.embedded.append(
                    Embedded(path="__metadata__", data=blob.encode("utf-8", "replace"),
                             kind="metadata")
                )
            oversize = [k for k, v in extra.items() if len(v) > 64 * 1024]
            if oversize:
                report.add(
                    finding(
                        "AML.SAFETENSORS.METADATA_BLOB", "medium", 5.5,
                        f"__metadata__ carries oversized value(s) ({', '.join(oversize[:3])}); "
                        "free-form blobs in a weights header are a smuggling channel.",
                        category="evasion",
                        remediation="Keep model cards outside the tensor container.",
                    )
                )

    data_region_size = size - 8 - header_length
    data_start = 8 + header_length
    spans: list[tuple[int, int, str, str]] = []
    dtype_counts: dict[str, int] = {}
    for name, tensor in tensor_items:
        if not isinstance(tensor, dict) or not {"dtype", "shape", "data_offsets"} <= set(tensor):
            report.add(_st_finding("TENSOR_SCHEMA", 7.0,
                                   f"Tensor {printable(name)!r} is missing dtype, shape or data_offsets."))
            continue
        dtype, shape, offsets = tensor["dtype"], tensor["shape"], tensor["data_offsets"]
        valid_shape = (
            isinstance(shape, list) and len(shape) <= MAX_TENSOR_RANK
            and all(isinstance(d, int) and not isinstance(d, bool) and 0 <= d <= MAX_DIMENSION for d in shape)
        )
        if dtype not in _DTYPE_WIDTHS or not valid_shape:
            report.add(_st_finding("TENSOR_SCHEMA", 7.0,
                                   f"Tensor {printable(name)!r} has an invalid dtype or shape."))
            continue
        dtype_counts[dtype] = dtype_counts.get(dtype, 0) + 1
        if not (
            isinstance(offsets, list) and len(offsets) == 2
            and all(isinstance(v, int) and not isinstance(v, bool) for v in offsets)
        ):
            report.add(_st_finding("OFFSET", 9.0,
                                   f"Tensor {printable(name)!r} has malformed data offsets.", "critical"))
            continue
        start, end = offsets
        if start < 0 or end < start or end > data_region_size:
            report.add(_st_finding(
                "OFFSET", 9.0,
                f"Tensor {printable(name)!r} points outside the {data_region_size:,}-byte data region.",
                "critical",
            ))
            continue
        expected = checked_element_bytes(shape, _DTYPE_WIDTHS[dtype])
        if expected is None or end - start != expected:
            report.add(_st_finding("SIZE", 7.5,
                                   f"Tensor {printable(name)!r} byte span does not equal dtype width x shape."))
        spans.append((start, end, name, dtype))

    metadata["validated_tensors"] = len(spans)
    metadata["dtype_counts"] = dtype_counts
    cursor = 0
    for start, end, name, dtype in sorted(spans):
        report.regions.append(
            Region(name, data_start + start, data_start + end, KIND_TENSOR,
                   {"dtype": dtype, "float": dtype in _FLOAT_DTYPES})
        )
        if start < cursor:
            report.add(_st_finding(
                "OVERLAP", 9.0,
                f"Tensor {printable(name)!r} overlaps an earlier tensor range; two readers "
                "will disagree about the model's weights.",
                "critical",
            ))
            break
        if start > cursor:
            gap = start - cursor
            report.regions.append(Region(f"__slack__@{cursor}", data_start + cursor, data_start + start, KIND_SLACK))
            report.add(_slack_finding(gap, data_start + cursor))
        cursor = max(cursor, end)
    if spans and cursor < data_region_size:
        gap = data_region_size - cursor
        report.regions.append(
            Region("__trailing__", data_start + cursor, size, KIND_SLACK)
        )
        report.add(_slack_finding(gap, data_start + cursor, trailing=True))
    return report


def _st_finding(code: str, cvss: float, description: str, severity: str = "high") -> dict[str, Any]:
    return finding(
        f"AML.SAFETENSORS.{code}", severity, cvss, description,
        category="format_anomaly",
        remediation="Re-export the tensors from a trusted checkpoint.",
        cwe=("CWE-1284",),
    )


def _slack_finding(gap: int, offset: int, *, trailing: bool = False) -> dict[str, Any]:
    where = "after the last tensor" if trailing else "between tensors"
    severity = "high" if gap >= 4096 else "medium"
    return finding(
        "AML.SAFETENSORS.SLACK", severity, 7.0 if gap >= 4096 else 4.0,
        f"{gap:,} bytes {where} are not claimed by any tensor (offset {offset:,}); "
        "unclaimed space in a weights file is a payload hiding place.",
        category="evasion", byte_offsets=[offset],
        remediation="Re-serialize the model; a correct SafeTensors file has no unclaimed bytes.",
        cwe=("CWE-1284",),
    )


# ---------------------------------------------------------------------------
# GGUF
# ---------------------------------------------------------------------------
MAX_GGUF_METADATA = 1_000_000
MAX_GGUF_TENSORS = 10_000_000
MAX_GGUF_ARRAY_ITEMS = 10_000_000
MAX_GGUF_ARRAY_DEPTH = 16
MAX_GGUF_ALIGNMENT = 1024 * 1024
MAX_GGUF_RANK = 16
_GGUF_KEY = re.compile(rb"[a-z0-9_]+(?:\.[a-z0-9_]+)*\Z")
_GGUF_FIXED = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f", 7: "B", 10: "Q", 11: "q", 12: "d"}

#: Metadata keys whose value is later interpreted, not just displayed.
_GGUF_TEMPLATE_KEYS = {
    "tokenizer.chat_template",
    "tokenizer.ggml.chat_template",
    "tokenizer.rwkv.world",
    "general.description",
    "general.license",
    "general.source.url",
    "general.url",
}
_GGML_TYPE_MAX = 40


class _GGUFReader(BoundedReader):
    def read_utf8(self, *, max_length: int, keep: bool) -> str | None:
        length = self.unpack("Q")
        if length > max_length:
            raise LimitError(f"string length {length:,} exceeds limit {max_length:,}")
        if length > self.remaining:
            raise ParseError(f"string length {length:,} exceeds remaining file bytes")
        if keep:
            try:
                return self.read_exact(length).decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise ParseError(f"invalid UTF-8 string: {error}") from error
        decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
        remaining = length
        try:
            while remaining:
                chunk = self.read_exact(min(1024 * 1024, remaining))
                decoder.decode(chunk, final=False)
                remaining -= len(chunk)
            decoder.decode(b"", final=True)
        except UnicodeDecodeError as error:
            raise ParseError(f"invalid UTF-8 string: {error}") from error
        return None


def gguf_report(path: Path) -> FormatReport:
    report = FormatReport(status="complete", format="gguf")
    metadata: dict[str, Any] = {
        "parser_scope": "metadata_and_tensor_directory",
        "metadata_parsed": 0,
        "tensor_info_parsed": 0,
    }
    report.metadata = metadata
    captured: dict[str, str] = {}
    file_size = path.stat().st_size

    with path.open("rb") as stream:
        reader = _GGUFReader(stream, file_size)
        try:
            header = reader.read_exact(24)
            if header[:4] != b"GGUF":
                raise ParseError("missing GGUF magic")
            version, tensor_count, metadata_count = struct.unpack("<IQQ", header[4:24])
            metadata.update({"version": version, "tensor_count": tensor_count,
                             "metadata_count": metadata_count})
            if version not in {2, 3}:
                report.add(_gguf_finding("VERSION", "medium", 4.5,
                                         f"GGUF version {version} is outside the validated range."))
                report.status = "capped"
                return report
            if metadata_count > MAX_GGUF_METADATA:
                report.cap(f"GGUF declares {metadata_count:,} metadata entries")
                return report
            if tensor_count > MAX_GGUF_TENSORS:
                report.cap(f"GGUF declares {tensor_count:,} tensors")
                return report

            alignment = 32
            seen: set[bytes] = set()
            for _ in range(metadata_count):
                key = reader.read_utf8(max_length=65_535, keep=True) or ""
                key_bytes = key.encode("utf-8")
                if not _GGUF_KEY.fullmatch(key_bytes):
                    report.add(_gguf_finding("METADATA_KEY", "medium", 4.0,
                                             f"Invalid GGUF metadata key {printable(key)!r}."))
                digest = hashlib.blake2b(key_bytes, digest_size=16).digest()
                if digest in seen:
                    report.add(_gguf_finding("DUPLICATE_KEY", "high", 7.0,
                                             f"Duplicate GGUF metadata key {printable(key)!r}; "
                                             "readers disagree on which value wins."))
                seen.add(digest)
                value_type = reader.unpack("I")
                keep = key in _GGUF_TEMPLATE_KEYS or (key == "general.alignment" and value_type == 4)
                value = _read_gguf_value(reader, value_type, depth=0, capture=keep)
                if key == "general.alignment":
                    if value_type != 4 or not isinstance(value, int):
                        raise ParseError("general.alignment must be UINT32")
                    alignment = value
                elif keep and isinstance(value, str):
                    captured[key] = value[:MAX_STRING_FIELD]
                metadata["metadata_parsed"] += 1

            if alignment < 8 or alignment > MAX_GGUF_ALIGNMENT or alignment % 8:
                raise ParseError(f"invalid general.alignment {alignment}")
            metadata["alignment"] = alignment
            directory_start = reader.position
            report.regions.append(Region("__metadata__", 0, directory_start, KIND_METADATA))

            tensors: list[tuple[str, int, int]] = []  # name, offset, declared bytes
            for _ in range(tensor_count):
                name = reader.read_utf8(max_length=1024, keep=True) or ""
                rank = reader.unpack("I")
                if rank > MAX_GGUF_RANK:
                    raise LimitError(f"tensor {printable(name)!r} declares rank {rank}")
                dimensions = [reader.unpack("Q") for _ in range(rank)]
                tensor_type = reader.unpack("I")
                if tensor_type >= _GGML_TYPE_MAX:
                    report.add(_gguf_finding(
                        "TENSOR_TYPE", "medium", 4.5,
                        f"Tensor {printable(name)!r} declares unknown GGML type {tensor_type}."))
                offset = reader.unpack("Q")
                if offset % alignment:
                    report.add(_gguf_finding(
                        "TENSOR_ALIGNMENT", "high", 7.0,
                        f"Tensor {printable(name)!r} offset {offset:,} is not aligned to "
                        f"{alignment} bytes; misaligned reads are a known parser-crash vector."))
                elements = 1
                for dimension in dimensions:
                    elements = min(elements * max(1, dimension), 2**62)
                tensors.append((name, offset, elements))
                metadata["tensor_info_parsed"] += 1

            directory_end = reader.position
            data_offset = directory_end + ((-directory_end) % alignment)
            if data_offset > file_size:
                raise ParseError("aligned tensor-data offset extends beyond the file")
            padding = reader.read_exact(data_offset - directory_end)
            if any(padding):
                report.add(_gguf_finding(
                    "PADDING", "medium", 5.0,
                    f"{len(padding)} padding bytes before the tensor data are non-zero; "
                    "padding is a classic place to hide a small payload.",
                    category="evasion"))
            tensor_data_bytes = file_size - data_offset
            metadata["tensor_data_offset"] = data_offset
            metadata["tensor_data_bytes"] = tensor_data_bytes

            ordered = sorted(tensors, key=lambda item: item[1])
            for index, (name, offset, _elements) in enumerate(ordered):
                end = ordered[index + 1][1] if index + 1 < len(ordered) else tensor_data_bytes
                report.regions.append(
                    Region(name, data_offset + offset, data_offset + max(offset, end), KIND_TENSOR,
                           {"gguf_offset": offset})
                )
                if offset >= tensor_data_bytes and tensor_count:
                    report.add(_gguf_finding(
                        "TENSOR_OFFSET", "critical", 9.0,
                        f"Tensor {printable(name)!r} offset {offset:,} lies outside the "
                        "tensor-data region."))
            _inspect_gguf_metadata(report, captured)
            if captured:
                blob = "\n".join(f"{k}={v}" for k, v in captured.items())
                report.embedded.append(
                    Embedded(path="__gguf_metadata__", data=blob.encode("utf-8", "replace"),
                             kind="metadata")
                )
                metadata["captured_keys"] = sorted(captured)
        except LimitError as error:
            report.cap(str(error))
            return report
        except (ParseError, OSError, struct.error) as error:
            report.status = "error"
            report.add(_gguf_finding("STRUCTURE", "high", 7.0,
                                     f"Invalid GGUF structure: {str(error)[:160]}."))
    return report


def _gguf_finding(code: str, severity: str, cvss: float, description: str,
                  category: str = "format_anomaly") -> dict[str, Any]:
    return finding(
        f"AML.GGUF.{code}", severity, cvss, description, category=category,
        remediation="Re-download the model from the publisher and re-verify its checksum.",
        cwe=("CWE-1284",),
    )


def _read_gguf_value(reader: _GGUFReader, value_type: int, *, depth: int, capture: bool) -> Any:
    if depth > MAX_GGUF_ARRAY_DEPTH:
        raise LimitError("metadata arrays are nested too deeply")
    if value_type in _GGUF_FIXED:
        value = reader.unpack(_GGUF_FIXED[value_type])
        if value_type == 7 and value not in {0, 1}:
            raise ParseError(f"invalid boolean value {value}")
        return value if capture else None
    if value_type == 8:
        return reader.read_utf8(max_length=reader.remaining, keep=capture)
    if value_type != 9:
        raise ParseError(f"unknown metadata value type {value_type}")
    element_type = reader.unpack("I")
    count = reader.unpack("Q")
    if element_type not in {*_GGUF_FIXED, 8, 9}:
        raise ParseError(f"unknown metadata array element type {element_type}")
    if element_type in _GGUF_FIXED and not capture:
        reader.skip(struct.calcsize("<" + _GGUF_FIXED[element_type]) * count)
        return None
    if count > MAX_GGUF_ARRAY_ITEMS:
        raise LimitError(f"complex metadata array contains {count:,} elements")
    for _ in range(count):
        _read_gguf_value(reader, element_type, depth=depth + 1, capture=False)
    return None


_JINJA_DANGEROUS = re.compile(
    r"(__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__|"
    r"lipsum|cycler|joiner|namespace|self\.__init__|request\.|config\.__|"
    r"\.popen|\.system|os\.|subprocess|attr\s*\(|\|\s*attr)"
)


def _inspect_gguf_metadata(report: FormatReport, captured: dict[str, str]) -> None:
    template = captured.get("tokenizer.chat_template") or captured.get("tokenizer.ggml.chat_template")
    if not template:
        return
    report.metadata["chat_template_bytes"] = len(template)
    match = _JINJA_DANGEROUS.search(template)
    if match:
        report.add(
            finding(
                "AML.GGUF.CHAT_TEMPLATE_SSTI", "critical", 9.3,
                "The GGUF chat template contains Jinja attribute-traversal syntax "
                f"({printable(match.group(0), 40)}). Runtimes render this template, so the "
                "expression executes on the inference host.",
                category="injection",
                remediation="Replace the template with the publisher's official version, or "
                "render templates in a sandboxed Jinja environment.",
                attack=("AML.T0011",), cwe=("CWE-1336",),
                references=("CVE-2024-34359",),
                evidence=[printable(template[max(0, match.start() - 60): match.end() + 60], 200)],
            )
        )
    elif len(template) > 32 * 1024:
        report.add(
            finding(
                "AML.GGUF.CHAT_TEMPLATE_SIZE", "medium", 5.0,
                f"The GGUF chat template is {len(template):,} bytes, far larger than a "
                "normal prompt template.",
                category="evasion",
                remediation="Diff the template against the publisher's release.",
                confidence="medium",
            )
        )


# ---------------------------------------------------------------------------
# NumPy .npy
# ---------------------------------------------------------------------------
_NPY_MAGIC = b"\x93NUMPY"


def npy_report(path: Path, *, data: bytes | None = None) -> FormatReport:
    report = FormatReport(status="complete", format="npy")
    metadata: dict[str, Any] = {}
    report.metadata = metadata
    try:
        if data is None:
            with path.open("rb") as stream:
                prefix = stream.read(10)
                if not prefix.startswith(_NPY_MAGIC):
                    raise ParseError("missing NumPy magic")
                header_length, header_start = _npy_header_length(prefix, stream)
                header_bytes = stream.read(header_length)
                size = path.stat().st_size
        else:
            prefix = data[:10]
            if not prefix.startswith(_NPY_MAGIC):
                raise ParseError("missing NumPy magic")
            import io

            stream = io.BytesIO(data[6:])
            stream.seek(4 if data[6] == 1 else 6)
            header_length, header_start = _npy_header_length(prefix, None, data=data)
            header_bytes = data[header_start: header_start + header_length]
            size = len(data)
        if header_length > MAX_HEADER_BYTES:
            report.cap(f"npy header is {header_length:,} bytes")
            return report
        text = header_bytes.decode("latin-1").strip()
        descriptor = ast.literal_eval(text)
    except (ParseError, OSError, ValueError, SyntaxError, IndexError) as error:
        report.status = "error"
        report.add(
            finding(
                "AML.NPY.STRUCTURE", "high", 7.0,
                f"Invalid NumPy .npy header: {str(error)[:160]}.",
                category="format_anomaly",
            )
        )
        return report

    if not isinstance(descriptor, dict):
        report.add(finding("AML.NPY.STRUCTURE", "high", 7.0,
                           "NumPy header is not a dictionary.", category="format_anomaly"))
        return report
    dtype = descriptor.get("descr")
    shape = descriptor.get("shape")
    metadata.update({"dtype": str(dtype)[:120], "shape": list(shape) if isinstance(shape, tuple) else shape,
                     "fortran_order": bool(descriptor.get("fortran_order"))})
    report.regions.append(Region("__header__", 0, header_start + header_length, KIND_HEADER))
    if isinstance(dtype, str) and ("O" in dtype or dtype.endswith("O")):
        report.add(
            finding(
                "AML.NPY.OBJECT_DTYPE", "critical", 9.4,
                "The array declares an object dtype, so loading it requires "
                "allow_pickle=True and executes embedded Pickle opcodes.",
                category="deserialization",
                remediation="Re-export the array with a numeric dtype; never load with allow_pickle.",
                attack=("AML.T0010",), cwe=("CWE-502",),
            )
        )
        payload_start = header_start + header_length
        report.embedded.append(
            Embedded(path="__npy_object_payload__",
                     data=_read_slice(path, payload_start, size, data),
                     kind="pickle")
        )
    elif isinstance(dtype, list):
        report.metadata["structured_fields"] = len(dtype)
    return report


def _npy_header_length(prefix: bytes, stream: BinaryIO | None, *, data: bytes | None = None
                       ) -> tuple[int, int]:
    major = prefix[6]
    if major == 1:
        length = struct.unpack("<H", prefix[8:10])[0]
        return length, 10
    if data is not None:
        length = struct.unpack("<I", data[8:12])[0]
        return length, 12
    assert stream is not None
    stream.seek(8)
    length = struct.unpack("<I", stream.read(4))[0]
    return length, 12


def _read_slice(path: Path, start: int, end: int, data: bytes | None) -> bytes:
    limit = 32 * 1024 * 1024
    if data is not None:
        return data[start: min(end, start + limit)]
    with path.open("rb") as stream:
        stream.seek(start)
        return stream.read(min(limit, max(0, end - start)))
