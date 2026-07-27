"""Keras model containers: legacy HDF5 (.h5) and the v3 archive (.keras).

Keras is the format where "just weights" is provably false.  A ``Lambda`` layer
stores a marshalled Python code object; a custom layer stores a
``registered_name`` that the loader imports.  Both run on ``load_model``, which
is why the format has produced repeated safe-mode bypasses
(CVE-2024-3660, CVE-2025-1550, CVE-2025-9905).

The parser reads the serialized *configuration* only.  It never calls
``keras.models.load_model``, never unmarshals a code object, and never imports a
custom object.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
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


HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
MAX_CONFIG_BYTES = 16 * 1024 * 1024
MAX_CONFIG_SEARCH = 256 * 1024 * 1024
MAX_LAYERS = 100_000

_SAFE_KERAS_MODULES = (
    "keras", "keras.layers", "keras.src", "tensorflow", "tf_keras",
    "keras.metrics", "keras.losses", "keras.optimizers", "keras.initializers",
    "keras.regularizers", "keras.constraints", "keras.activations",
)

_DANGEROUS_LAYER_CLASSES = {
    "Lambda": (
        "critical", 9.3,
        "stores a marshalled Python code object that Keras executes on load",
    ),
    "TFOpLambda": (
        "high", 8.0,
        "wraps a raw TensorFlow op selected by name at load time",
    ),
    "SlicingOpLambda": ("medium", 6.0, "wraps a raw TensorFlow slicing op"),
}

_PY_BYTECODE_HINTS = (b"\xe3\x00", b"__code__", b"co_code", b"<lambda>")


def hdf5_report(path: Path, *, data: bytes | None = None) -> FormatReport:
    report = FormatReport(status="complete", format="hdf5")
    metadata: dict[str, Any] = {}
    report.metadata = metadata

    head = data[:64] if data is not None else _read_head(path, 64)
    if not head.startswith(HDF5_MAGIC):
        report.status = "error"
        report.add(
            finding(
                "AML.HDF5.STRUCTURE", "high", 7.0,
                "File does not start with the HDF5 signature.",
                category="format_anomaly",
            )
        )
        return report
    if len(head) >= 9:
        metadata["superblock_version"] = head[8]
    size = len(data) if data is not None else path.stat().st_size
    metadata["file_bytes"] = size
    report.regions.append(Region("__superblock__", 0, 96, KIND_METADATA))

    configs = list(_find_config_blobs(path, data))
    metadata["config_blobs"] = len(configs)
    if size > MAX_CONFIG_SEARCH and not configs:
        report.status = "capped"
        report.add(
            finding(
                "AML.HDF5.PARTIAL", "medium", 5.0,
                f"Only the first {MAX_CONFIG_SEARCH // (1024 * 1024)} MiB were searched for a "
                "serialized model configuration.",
                category="coverage",
                remediation="Convert the checkpoint to SafeTensors for full structural coverage.",
            )
        )
    for offset, blob in configs:
        report.embedded.append(
            Embedded(path=f"__model_config__@{offset}", data=blob, kind="keras_config",
                     detail={"offset": offset})
        )
        analyze_config(blob, report, location=f"model_config@{offset}", offset=offset)
    if not configs:
        report.add(
            finding(
                "AML.HDF5.NO_CONFIG", "info", 0.0,
                "No serialized Keras configuration was found; the file appears to hold "
                "weights only.",
                category="coverage", confidence="medium",
                remediation="No action required.",
            )
        )
    return report


def _read_head(path: Path, count: int) -> bytes:
    with path.open("rb") as stream:
        return stream.read(count)


def _find_config_blobs(path: Path, data: bytes | None) -> Iterator[tuple[int, bytes]]:
    """Locate embedded JSON model configurations without an HDF5 library.

    Keras stores ``model_config`` as a single JSON attribute value, so a bounded
    brace-balanced extraction around the marker recovers it exactly, regardless
    of the surrounding HDF5 object-header layout.
    """
    marker = b'"class_name"'
    found = 0
    for chunk, base in _iter_search_chunks(path, data):
        start = 0
        while found < 8:
            index = chunk.find(marker, start)
            if index < 0:
                break
            begin = chunk.rfind(b"{", 0, index)
            if begin < 0:
                start = index + len(marker)
                continue
            blob = _balanced_object(chunk, begin)
            if blob is not None and len(blob) > 32:
                found += 1
                yield base + begin, blob
                start = begin + len(blob)
            else:
                start = index + len(marker)
        if found >= 8:
            return


def _iter_search_chunks(path: Path, data: bytes | None) -> Iterator[tuple[bytes, int]]:
    if data is not None:
        yield data[:MAX_CONFIG_SEARCH], 0
        return
    window = 8 * 1024 * 1024
    overlap = 1024 * 1024
    position = 0
    with path.open("rb") as stream:
        previous = b""
        while position < MAX_CONFIG_SEARCH:
            chunk = stream.read(window)
            if not chunk:
                break
            yield previous + chunk, position - len(previous)
            position += len(chunk)
            previous = chunk[-overlap:]


def _balanced_object(data: bytes, start: int) -> bytes | None:
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, min(len(data), start + MAX_CONFIG_BYTES)):
        byte = data[index]
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte == 0x7B:
            depth += 1
        elif byte == 0x7D:
            depth -= 1
            if depth == 0:
                return data[start: index + 1]
    return None


# ---------------------------------------------------------------------------
# Configuration analysis (shared by .h5 and .keras)
# ---------------------------------------------------------------------------
def keras_archive_config(report: FormatReport, blob: bytes, location: str) -> None:
    analyze_config(blob, report, location=location, offset=0)


def analyze_config(blob: bytes, report: FormatReport, *, location: str, offset: int) -> None:
    try:
        document = json.loads(blob.decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return
    layers = 0
    dangerous_modules: set[str] = set()
    for node in _walk(document):
        if not isinstance(node, dict):
            continue
        class_name = node.get("class_name")
        if isinstance(class_name, str):
            layers += 1
            if layers > MAX_LAYERS:
                report.cap("Keras configuration declares too many layers")
                return
            classification = _DANGEROUS_LAYER_CLASSES.get(class_name)
            if classification:
                severity, cvss, why = classification
                report.add(
                    finding(
                        f"AML.KERAS.{class_name.upper()}_LAYER", severity, cvss,
                        f"Model configuration contains a {class_name} layer, which {why}.",
                        category="code_execution", location=location,
                        byte_offsets=[offset],
                        remediation="Rebuild the model without Lambda layers; loading it with "
                                    "safe_mode=False is remote code execution.",
                        attack=("AML.T0010", "AML.T0011"), cwe=("CWE-502",),
                        references=("CVE-2024-3660", "CVE-2025-1550", "CVE-2025-9905"),
                        evidence=[printable(json.dumps(node.get("config", {}))[:300])],
                    )
                )
        module = node.get("module")
        registered = node.get("registered_name")
        if isinstance(module, str) and module and not module.startswith(_SAFE_KERAS_MODULES):
            dangerous_modules.add(module)
        if isinstance(registered, str) and registered and ">" not in registered:
            if not registered.startswith(_SAFE_KERAS_MODULES):
                dangerous_modules.add(registered)
        for key in ("function", "output_shape", "module", "value"):
            payload = node.get(key)
            _inspect_encoded_payload(payload, report, location, offset, key)
    if dangerous_modules:
        report.add(
            finding(
                "AML.KERAS.CUSTOM_OBJECT", "high", 8.2,
                f"Model configuration references object(s) outside the Keras namespace: "
                f"{', '.join(printable(m, 40) for m in sorted(dangerous_modules)[:5])}. Loading "
                "imports them from the current environment or from repository code.",
                category="supply_chain", location=location,
                remediation="Load only with an explicit, reviewed custom_objects mapping.",
                attack=("AML.T0010",), cwe=("CWE-829",),
            )
        )
    report.metadata.setdefault("keras", {})["layers"] = layers


def _walk(node: Any, depth: int = 0) -> Iterator[Any]:
    if depth > 64:
        return
    yield node
    if isinstance(node, dict):
        for value in node.values():
            yield from _walk(value, depth + 1)
    elif isinstance(node, list):
        for value in node[:100_000]:
            yield from _walk(value, depth + 1)


_B64 = re.compile(r"^[A-Za-z0-9+/\s]{40,}={0,2}$")


def _inspect_encoded_payload(payload: Any, report: FormatReport, location: str,
                             offset: int, key: str) -> None:
    candidates: list[str] = []
    if isinstance(payload, str):
        candidates = [payload]
    elif isinstance(payload, list):
        candidates = [item for item in payload if isinstance(item, str)]
    elif isinstance(payload, dict):
        candidates = [item for item in payload.values() if isinstance(item, str)]
    for candidate in candidates[:8]:
        if len(candidate) < 40 or not _B64.match(candidate):
            continue
        try:
            decoded = base64.b64decode(candidate[: 4 * 1024 * 1024], validate=False)
        except (binascii.Error, ValueError):
            continue
        if not decoded:
            continue
        looks_like_code = any(hint in decoded for hint in _PY_BYTECODE_HINTS) or decoded[:1] == b"\xe3"
        report.add(
            finding(
                "AML.KERAS.MARSHALLED_CODE" if looks_like_code else "AML.KERAS.ENCODED_BLOB",
                "critical" if looks_like_code else "medium",
                9.6 if looks_like_code else 5.5,
                (
                    f"Configuration field {key!r} carries a base64 blob that decodes to "
                    "Python bytecode; Keras unmarshals and executes it while loading."
                    if looks_like_code
                    else f"Configuration field {key!r} carries an opaque base64 blob of "
                         f"{len(decoded):,} bytes."
                ),
                category="code_execution" if looks_like_code else "evasion",
                location=location, byte_offsets=[offset],
                remediation="Reject the model; a layer definition never needs encoded bytecode.",
                attack=("AML.T0011",), cwe=("CWE-502",),
                references=("CVE-2024-3660", "CVE-2025-1550"),
                evidence=[printable(decoded[:120])],
            )
        )
        if looks_like_code:
            report.embedded.append(
                Embedded(path=f"{location}#{key}.marshalled", data=decoded[: 4 * 1024 * 1024],
                         kind="bytecode")
            )
