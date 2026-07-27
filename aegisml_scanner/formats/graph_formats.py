"""Computation-graph formats: ONNX, TensorFlow SavedModel and TFLite.

A graph is a program.  These parsers read the serialized program structure —
Protocol Buffers for ONNX/TensorFlow, FlatBuffers for TFLite — and report the
operators that reach outside the tensor sandbox: Python callbacks, filesystem
ops, custom operators backed by a native library, and external tensor data that
points at an attacker-chosen path.

Protocol Buffer decoding is schema-free (the ``protoc --decode_raw`` heuristic),
so no generated code or third-party runtime is required, and a malformed
message degrades coverage instead of crashing.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any, Iterator

from .common import (
    Embedded,
    FormatReport,
    KIND_METADATA,
    Region,
    finding,
    printable,
)


MAX_PROTOBUF_DEPTH = 12
MAX_PROTOBUF_FIELDS = 2_000_000
MAX_STRING_KEEP = 4096


# ---------------------------------------------------------------------------
# Schema-free Protocol Buffers decoding
# ---------------------------------------------------------------------------
class _Budget:
    def __init__(self, fields: int = MAX_PROTOBUF_FIELDS) -> None:
        self.remaining = fields
        self.exhausted = False

    def spend(self) -> bool:
        if self.remaining <= 0:
            self.exhausted = True
            return False
        self.remaining -= 1
        return True


def _read_varint(data: bytes, position: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while position < len(data):
        byte = data[position]
        position += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, position
        shift += 7
        if shift > 70:
            raise ValueError("varint too long")
    raise ValueError("truncated varint")


def _looks_like_message(blob: bytes) -> bool:
    """Cheap check that a length-delimited field is a nested message."""
    if not blob or len(blob) > 64 * 1024 * 1024:
        return False
    position = 0
    fields = 0
    while position < len(blob) and fields < 64:
        try:
            key, position = _read_varint(blob, position)
        except ValueError:
            return False
        wire = key & 7
        if key >> 3 == 0:
            return False
        if wire == 0:
            try:
                _, position = _read_varint(blob, position)
            except ValueError:
                return False
        elif wire == 1:
            position += 8
        elif wire == 2:
            try:
                length, position = _read_varint(blob, position)
            except ValueError:
                return False
            if length < 0 or position + length > len(blob):
                return False
            position += length
        elif wire == 5:
            position += 4
        else:
            return False
        fields += 1
    return position == len(blob) and fields > 0


def iter_protobuf(data: bytes, budget: _Budget, depth: int = 0) -> Iterator[tuple[int, int, Any]]:
    """Yield ``(depth, field_number, value)`` triples for a protobuf message."""
    position = 0
    while position < len(data):
        if not budget.spend():
            return
        try:
            key, position = _read_varint(data, position)
        except ValueError:
            return
        field_number, wire = key >> 3, key & 7
        if wire == 0:
            try:
                value, position = _read_varint(data, position)
            except ValueError:
                return
            yield depth, field_number, value
        elif wire == 1:
            value = data[position: position + 8]
            position += 8
            yield depth, field_number, value
        elif wire == 2:
            try:
                length, position = _read_varint(data, position)
            except ValueError:
                return
            blob = data[position: position + length]
            if len(blob) != length:
                return
            position += length
            if depth < MAX_PROTOBUF_DEPTH and _looks_like_message(blob):
                yield depth, field_number, ("message", blob)
                yield from iter_protobuf(blob, budget, depth + 1)
            else:
                yield depth, field_number, blob
        elif wire == 5:
            value = data[position: position + 4]
            position += 4
            yield depth, field_number, value
        else:
            return


def _strings(data: bytes, budget: _Budget) -> list[str]:
    collected: list[str] = []
    for _depth, _field, value in iter_protobuf(data, budget):
        if isinstance(value, bytes) and 2 <= len(value) <= MAX_STRING_KEEP:
            try:
                text = value.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if text.isprintable() or "\n" in text:
                collected.append(text)
    return collected


# ---------------------------------------------------------------------------
# ONNX
# ---------------------------------------------------------------------------
_KNOWN_ONNX_DOMAINS = {
    "", "ai.onnx", "ai.onnx.ml", "ai.onnx.training", "ai.onnx.preview.training",
    "com.microsoft", "com.microsoft.nchwc", "com.microsoft.experimental",
    "org.pytorch.aten", "com.ms.internal.nhwc",
}

_DANGEROUS_ONNX_OPS = {
    "PythonOp": ("critical", 9.5, "executes a Python callable inside the inference graph"),
    "ATen": ("high", 7.5, "dispatches to a PyTorch ATen kernel outside the ONNX standard"),
    "Inverse": ("low", 2.0, ""),
}


def onnx_report(path: Path, *, data: bytes | None = None) -> FormatReport:
    report = FormatReport(status="complete", format="onnx")
    metadata: dict[str, Any] = {}
    report.metadata = metadata
    payload = data if data is not None else path.read_bytes() if path.stat().st_size <= 512 * 1024 * 1024 else None
    if payload is None:
        # Only the graph structure is needed; tensor payloads sit at the end of
        # the message, so a bounded prefix still covers node definitions.
        with path.open("rb") as stream:
            payload = stream.read(512 * 1024 * 1024)
        report.status = "capped"
        report.add(
            finding(
                "AML.ONNX.PARTIAL", "medium", 5.0,
                "ONNX model exceeds the in-memory graph budget; only the first 512 MiB "
                "of the message was structurally decoded.",
                category="coverage",
                remediation="Split external tensor data out of the model file.",
            )
        )

    budget = _Budget()
    domains: set[str] = set()
    op_types: list[str] = []
    external_locations: list[str] = []
    node_count = 0
    producer = ""

    for depth, field_number, value in iter_protobuf(payload, budget):
        if isinstance(value, tuple):
            continue
        if depth == 0 and field_number == 2 and isinstance(value, bytes):
            producer = value.decode("utf-8", "replace")[:120]
        # NodeProto.op_type is field 4 and NodeProto.domain is field 7; both
        # live one level below GraphProto.node.
        if depth >= 1 and isinstance(value, bytes) and 0 < len(value) <= 256:
            try:
                text = value.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if field_number == 4 and text.isidentifier():
                op_types.append(text)
                node_count += 1
            elif field_number == 7 and (text == "" or "." in text or text.isidentifier()):
                domains.add(text)
            elif field_number == 1 and depth >= 2 and text in {"location"}:
                pass
        if depth >= 2 and field_number == 2 and isinstance(value, bytes) and len(value) <= 4096:
            try:
                text = value.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if ("/" in text or "\\" in text or ".." in text) and len(text) < 512 and "\n" not in text:
                external_locations.append(text)

    if budget.exhausted:
        report.cap("ONNX message exceeds the field-decoding budget")

    metadata.update(
        {
            "producer": producer,
            "nodes": node_count,
            "distinct_ops": len(set(op_types)),
            "domains": sorted(domains)[:32],
        }
    )
    report.regions.append(Region("__graph__", 0, len(payload), KIND_METADATA))

    unknown_domains = sorted(d for d in domains if d not in _KNOWN_ONNX_DOMAINS)
    if unknown_domains:
        report.add(
            finding(
                "AML.ONNX.CUSTOM_DOMAIN", "high", 8.0,
                f"Graph declares non-standard operator domain(s): "
                f"{', '.join(printable(d, 40) for d in unknown_domains[:5])}. Running the model "
                "requires loading a matching native custom-operator library.",
                category="native_code",
                remediation="Only run custom-op models with a runtime you control and a "
                "reviewed operator library.",
                attack=("AML.T0011",), cwe=("CWE-829",),
            )
        )
    for op in sorted(set(op_types)):
        classification = _DANGEROUS_ONNX_OPS.get(op)
        if classification and classification[2]:
            severity, cvss, why = classification
            report.add(
                finding(
                    "AML.ONNX.DANGEROUS_OP", severity, cvss,
                    f"Graph contains the {op} operator, which {why}.",
                    category="code_execution",
                    remediation="Reject graphs that embed host callbacks.",
                    attack=("AML.T0011",), cwe=("CWE-829",),
                )
            )
    for location in external_locations[:32]:
        if ".." in location.split("/") or location.startswith(("/", "\\")) or (
            len(location) > 1 and location[1] == ":"
        ):
            report.add(
                finding(
                    "AML.ONNX.EXTERNAL_DATA_PATH", "critical", 9.0,
                    f"External tensor data points at {printable(location)!r}, which escapes "
                    "the model directory; loading the model reads an attacker-chosen path.",
                    category="format_anomaly",
                    remediation="Reject the model; external data must be a sibling file name.",
                    attack=("T1005",), cwe=("CWE-22",),
                )
            )
    if external_locations:
        metadata["external_data_references"] = [printable(item, 120) for item in external_locations[:16]]
    return report


# ---------------------------------------------------------------------------
# TensorFlow SavedModel / GraphDef
# ---------------------------------------------------------------------------
_DANGEROUS_TF_OPS = {
    "PyFunc": ("critical", 9.5, "invokes a Python callback registered on the host"),
    "PyFuncStateless": ("critical", 9.5, "invokes a Python callback registered on the host"),
    "EagerPyFunc": ("critical", 9.5, "invokes a Python callback registered on the host"),
    "ReadFile": ("high", 8.0, "reads an arbitrary file from the inference host"),
    "WriteFile": ("critical", 9.2, "writes an arbitrary file on the inference host"),
    "MergeV2Checkpoints": ("high", 7.5, "manipulates checkpoint files on disk"),
    "Save": ("medium", 6.0, "writes tensors to disk during inference"),
    "SaveV2": ("medium", 6.0, "writes tensors to disk during inference"),
    "SaveSlices": ("medium", 6.0, "writes tensors to disk during inference"),
    "Restore": ("medium", 6.2, "reads tensors from a path chosen by the graph"),
    "RestoreV2": ("medium", 6.2, "reads tensors from a path chosen by the graph"),
    "MatchingFiles": ("medium", 5.5, "enumerates host filesystem paths"),
    "DeleteSessionTensor": ("low", 3.0, ""),
    "PrintV2": ("low", 3.0, ""),
}


def savedmodel_report(path: Path, *, data: bytes | None = None) -> FormatReport:
    report = FormatReport(status="complete", format="tf_savedmodel")
    metadata: dict[str, Any] = {}
    report.metadata = metadata
    payload = data if data is not None else path.read_bytes()
    budget = _Budget()
    texts = _strings(payload, budget)
    if budget.exhausted:
        report.cap("SavedModel message exceeds the field-decoding budget")
    op_names = {text for text in texts if text.isidentifier()}
    metadata["distinct_symbols"] = len(op_names)
    report.regions.append(Region("__graph_def__", 0, len(payload), KIND_METADATA))

    for op, (severity, cvss, why) in _DANGEROUS_TF_OPS.items():
        if op in op_names and why:
            report.add(
                finding(
                    "AML.TF.DANGEROUS_OP", severity, cvss,
                    f"SavedModel graph references the {op} operator, which {why}.",
                    category="code_execution" if severity == "critical" else "format_anomaly",
                    remediation="Load the model with a restricted op allowlist, or reject it.",
                    attack=("AML.T0011",), cwe=("CWE-829",),
                )
            )
    joined = "\n".join(texts)
    if joined:
        report.embedded.append(
            Embedded(path="__savedmodel_strings__", data=joined.encode("utf-8", "replace"),
                     kind="metadata")
        )
    return report


# ---------------------------------------------------------------------------
# TFLite (FlatBuffers)
# ---------------------------------------------------------------------------
def tflite_report(path: Path, *, data: bytes | None = None) -> FormatReport:
    report = FormatReport(status="complete", format="tflite")
    metadata: dict[str, Any] = {}
    report.metadata = metadata
    payload = data if data is not None else path.read_bytes()
    if len(payload) < 16 or payload[4:8] not in (b"TFL3", b"TFL2"):
        report.status = "error"
        report.add(
            finding(
                "AML.TFLITE.STRUCTURE", "high", 7.0,
                "File does not carry a TFLite FlatBuffer identifier.",
                category="format_anomaly",
            )
        )
        return report
    try:
        root = _flat_root(payload)
        version = _flat_field_scalar(payload, root, 0, "I") or 0
        metadata["schema_version"] = version
        operator_codes = _flat_field_vector(payload, root, 1)
        custom_codes: list[str] = []
        for table in operator_codes[:4096]:
            custom = _flat_field_string(payload, table, 1)
            if custom:
                custom_codes.append(custom)
        metadata["operator_codes"] = len(operator_codes)
        metadata["custom_operators"] = custom_codes[:32]
        description = _flat_field_string(payload, root, 3) or ""
        if description:
            metadata["description"] = printable(description, 200)
        if custom_codes:
            report.add(
                finding(
                    "AML.TFLITE.CUSTOM_OP", "high", 8.2,
                    f"Model declares {len(custom_codes)} custom operator(s) "
                    f"({', '.join(printable(c, 30) for c in custom_codes[:5])}); each one is "
                    "resolved from a native delegate library at load time.",
                    category="native_code",
                    remediation="Only run custom-op TFLite models with a reviewed delegate.",
                    attack=("AML.T0011",), cwe=("CWE-829",),
                )
            )
    except (ValueError, struct.error, IndexError) as error:
        report.status = "error"
        report.add(
            finding(
                "AML.TFLITE.STRUCTURE", "high", 7.0,
                f"Invalid TFLite FlatBuffer structure: {str(error)[:160]}.",
                category="format_anomaly",
            )
        )
    return report


def _flat_root(data: bytes) -> int:
    root = struct.unpack_from("<I", data, 0)[0]
    if root >= len(data):
        raise ValueError("root table offset out of range")
    return root


def _flat_vtable(data: bytes, table: int) -> tuple[int, int]:
    delta = struct.unpack_from("<i", data, table)[0]
    vtable = table - delta
    if not 0 <= vtable < len(data) - 4:
        raise ValueError("vtable offset out of range")
    vtable_size = struct.unpack_from("<H", data, vtable)[0]
    return vtable, vtable_size


def _flat_field_offset(data: bytes, table: int, index: int) -> int:
    vtable, vtable_size = _flat_vtable(data, table)
    position = vtable + 4 + index * 2
    if position + 2 > vtable + vtable_size:
        return 0
    return struct.unpack_from("<H", data, position)[0]


def _flat_field_scalar(data: bytes, table: int, index: int, code: str) -> Any:
    offset = _flat_field_offset(data, table, index)
    if not offset:
        return None
    return struct.unpack_from("<" + code, data, table + offset)[0]


def _flat_indirect(data: bytes, table: int, index: int) -> int:
    offset = _flat_field_offset(data, table, index)
    if not offset:
        return 0
    position = table + offset
    return position + struct.unpack_from("<I", data, position)[0]


def _flat_field_string(data: bytes, table: int, index: int) -> str:
    position = _flat_indirect(data, table, index)
    if not position or position + 4 > len(data):
        return ""
    length = struct.unpack_from("<I", data, position)[0]
    if length > 1 << 20 or position + 4 + length > len(data):
        raise ValueError("string length out of range")
    return data[position + 4: position + 4 + length].decode("utf-8", "replace")


def _flat_field_vector(data: bytes, table: int, index: int) -> list[int]:
    position = _flat_indirect(data, table, index)
    if not position or position + 4 > len(data):
        return []
    count = struct.unpack_from("<I", data, position)[0]
    if count > 1 << 20:
        raise ValueError("vector length out of range")
    entries = []
    base = position + 4
    for item in range(count):
        cell = base + item * 4
        if cell + 4 > len(data):
            break
        entries.append(cell + struct.unpack_from("<I", data, cell)[0])
    return entries
