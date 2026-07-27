"""Format detection and dispatch for the no-execution parsers."""

from __future__ import annotations

import posixpath
from pathlib import Path

from .common import (
    MAX_PICKLE_BYTES,
    Embedded,
    FormatReport,
    Region,
    finding,
    printable,
)
from . import containers, graph_formats, keras, pickle_vm, tensor_formats, text_configs


HEADER_BYTES = 512

_EXECUTABLE_MAGICS: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"MZ\x90\x00", "pe"),
    (b"\xca\xfe\xba\xbe", "macho"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xfe\xed\xfa\xce", "macho"),
)

_PICKLE_EXTENSIONS = {".pkl", ".pickle", ".joblib", ".dat", ".sav"}
_PYTORCH_EXTENSIONS = {".pt", ".pth", ".bin", ".ckpt", ".pkl", ".model"}
_CONFIG_NAMES = {
    "config.json", "tokenizer_config.json", "generation_config.json",
    "preprocessor_config.json", "adapter_config.json", "quantize_config.json",
    "model_index.json", "special_tokens_map.json", "chat_template.json",
    "processor_config.json", "feature_extractor_config.json",
}

#: Model-ish extensions used to decide that an executable header is a disguise.
MODEL_EXTENSIONS = {
    ".bin", ".ckpt", ".gguf", ".ggml", ".h5", ".hdf5", ".joblib", ".keras",
    ".msgpack", ".npy", ".npz", ".onnx", ".pb", ".pickle", ".pkl", ".pt",
    ".pth", ".safetensors", ".tflite", ".mlmodel", ".engine", ".plan",
    ".pdparams", ".params", ".caffemodel", ".weights", ".model", ".sav",
}


def detect(name: str, header: bytes) -> str:
    """Return a coarse format label from magic bytes plus file name."""
    lowered = name.lower()
    suffix = posixpath.splitext(lowered)[1]
    base = posixpath.basename(lowered)

    for magic, label in _EXECUTABLE_MAGICS:
        if header.startswith(magic):
            return label
    if header.startswith(b"\x89HDF\r\n\x1a\n"):
        return "hdf5"
    if header.startswith(b"GGUF"):
        return "gguf"
    if header.startswith(b"\x93NUMPY"):
        return "npy"
    if header.startswith(b"\x1f\x8b"):
        return "gzip"
    if header.startswith(b"BZh") or header.startswith(b"\xfd7zXZ\x00"):
        return "compressed"
    if header[257:262] == b"ustar":
        return "tar"
    if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06"):
        if suffix in {".keras"}:
            return "keras_v3"
        if suffix == ".npz":
            return "npz"
        if suffix in _PYTORCH_EXTENSIONS or base in {"model.pt", "pytorch_model.bin"}:
            return "pytorch"
        return "zip"
    if len(header) >= 8 and header[4:8] in (b"TFL3", b"TFL2"):
        return "tflite"
    if header.startswith((b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05", b"\x80\x06")):
        return "pickle"
    if suffix == ".safetensors":
        return "safetensors"
    if suffix == ".onnx":
        return "onnx"
    if suffix in {".pb", ".pbtxt"} or base in {"saved_model.pb", "keras_metadata.pb"}:
        return "tf_savedmodel"
    if suffix == ".tflite":
        return "tflite"
    if suffix in {".gguf", ".ggml"}:
        return "gguf"
    if suffix in {".h5", ".hdf5", ".keras"}:
        return "hdf5"
    if suffix in {".npy"}:
        return "npy"
    if suffix in _PICKLE_EXTENSIONS and header[:1] in b"(cd]}\x80":
        return "pickle"
    if base in _CONFIG_NAMES or (suffix == ".json" and base.endswith("config.json")):
        return "config"
    if base in {"requirements.txt", "requirements-dev.txt", "constraints.txt"}:
        return "requirements"
    if suffix in {".py", ".pyw"}:
        return "python"
    if suffix == ".ipynb":
        return "notebook"
    if suffix in {".json"}:
        return "json"
    if suffix in {".tar"}:
        return "tar"
    if suffix in {".zip", ".whl"}:
        return "zip"
    # SafeTensors without the extension: 8-byte little-endian header length
    # followed immediately by a JSON object.
    if len(header) >= 10 and header[8:10] in (b'{"', b"{ "):
        length = int.from_bytes(header[:8], "little")
        if 2 <= length <= 100 * 1024 * 1024:
            return "safetensors"
    if header.startswith(b"{") or header.startswith(b"[{"):
        return "json"
    return "generic"


def inspect_path(path: Path, detected: str) -> FormatReport:
    """Run the structural parser matching ``detected`` on a file on disk."""
    if detected == "safetensors":
        return tensor_formats.safetensors_report(path)
    if detected == "gguf":
        return tensor_formats.gguf_report(path)
    if detected == "npy":
        return tensor_formats.npy_report(path)
    if detected == "hdf5":
        return keras.hdf5_report(path)
    if detected == "keras_v3":
        return _keras_archive(path)
    if detected in {"pytorch", "zip", "npz"}:
        return containers.zip_report(path, hint="pytorch" if detected == "pytorch" else detected)
    if detected == "tar":
        return containers.tar_report(path)
    if detected == "gzip":
        return containers.gzip_report(path)
    if detected == "pickle":
        return _pickle_file(path)
    if detected == "onnx":
        return graph_formats.onnx_report(path)
    if detected == "tf_savedmodel":
        return graph_formats.savedmodel_report(path)
    if detected == "tflite":
        return graph_formats.tflite_report(path)
    if detected in {"elf", "pe", "macho"}:
        return _executable(path.name, detected)
    if detected in {"config", "json", "python", "requirements", "notebook"}:
        try:
            data = path.read_bytes()
        except OSError as error:  # pragma: no cover - permission edge case
            report = FormatReport(status="error", format=detected)
            report.add(
                finding("AML.IO.UNREADABLE", "high", 7.0,
                        f"Cannot read {printable(path.name)!r}: {error}", category="coverage")
            )
            return report
        return inspect_buffer(path.name, data, detected)
    return FormatReport(status="not_applicable", format=detected)


def inspect_buffer(name: str, data: bytes, detected: str | None = None) -> FormatReport:
    """Run the structural parser for an in-memory payload (archive member)."""
    label = detected or detect(name, data[:HEADER_BYTES])
    base = posixpath.basename(name.lower())
    if label == "pickle" or base.endswith((".pkl", ".pickle")) or base in {"data.pkl", "constants.pkl"}:
        return _pickle_buffer(name, data)
    if label == "safetensors":
        report = FormatReport(status="not_applicable", format="safetensors")
        return report
    if label == "npy":
        return tensor_formats.npy_report(Path(name), data=data)
    if label == "hdf5":
        return keras.hdf5_report(Path(name), data=data)
    if label == "onnx":
        return graph_formats.onnx_report(Path(name), data=data)
    if label == "tf_savedmodel":
        return graph_formats.savedmodel_report(Path(name), data=data)
    if label == "tflite":
        return graph_formats.tflite_report(Path(name), data=data)
    if label in {"config", "json"} or base in _CONFIG_NAMES:
        report = text_configs.config_report(data, location=name)
        if base in {"config.json", "metadata.json"} and b'"class_name"' in data[:4096]:
            keras.keras_archive_config(report, data, name)
        return report
    if label == "python" or base.endswith(".py"):
        return text_configs.python_report(data, location=name)
    if label == "notebook":
        return text_configs.notebook_report(data, location=name)
    if label == "requirements":
        return text_configs.requirements_report(data, location=name)
    if label in {"elf", "pe", "macho"}:
        return _executable(name, label)
    if base.endswith((".pyc", ".pyo")):
        return _bytecode(name, data)
    return FormatReport(status="not_applicable", format=label)


def _keras_archive(path: Path) -> FormatReport:
    report = containers.zip_report(path, hint="keras_v3")
    report.format = "keras_v3"
    for item in list(report.embedded):
        base = posixpath.basename(item.path.lower())
        if base in {"config.json", "metadata.json"}:
            keras.keras_archive_config(report, item.data, item.path)
    return report


def _pickle_file(path: Path) -> FormatReport:
    size = path.stat().st_size
    with path.open("rb") as stream:
        data = stream.read(MAX_PICKLE_BYTES + 1)
    capped = len(data) > MAX_PICKLE_BYTES
    report = _pickle_buffer(path.name, data[:MAX_PICKLE_BYTES] if capped else data)
    report.metadata["total_bytes"] = size
    if capped:
        report.cap(f"pickle exceeds the {MAX_PICKLE_BYTES:,}-byte opcode-analysis budget")
    return report


def _pickle_buffer(name: str, data: bytes) -> FormatReport:
    report = FormatReport(status="complete", format="pickle")
    analysis = pickle_vm.analyze(data, source=name)
    report.findings.extend(analysis.findings)
    report.metadata = analysis.metadata()
    report.metadata["bytes_analyzed"] = len(data)
    if analysis.truncated:
        report.status = "capped"
    report.add(
        finding(
            "AML.PICKLE.FORMAT_UNSAFE", "low", 3.5,
            "Pickle can execute code while loading, even when no known gadget is present.",
            category="deserialization",
            remediation="Prefer SafeTensors, or load with a restricted weights-only unpickler.",
            location=name, attack=("AML.T0010",), cwe=("CWE-502",), confidence="high",
        )
    )
    return report


def _executable(name: str, label: str) -> FormatReport:
    report = FormatReport(status="complete", format=label)
    suffix = posixpath.splitext(name.lower())[1]
    disguised = suffix in MODEL_EXTENSIONS
    report.add(
        finding(
            "AML.FORMAT.DISGUISED_EXECUTABLE" if disguised else "AML.FORMAT.EXECUTABLE",
            "critical" if disguised else "high",
            10.0 if disguised else 8.0,
            (
                f"The file is named as a model but begins with a {label.upper()} executable header."
                if disguised
                else f"The artifact is a {label.upper()} executable, not model data."
            ),
            category="native_code", location=name, byte_offsets=[0],
            remediation="Do not execute or load this file; quarantine and verify its source.",
            attack=("T1027.009",), cwe=("CWE-506",),
        )
    )
    return report


def _bytecode(name: str, data: bytes) -> FormatReport:
    report = FormatReport(status="complete", format="pyc")
    report.add(
        finding(
            "AML.PYC.BYTECODE", "high", 8.0,
            f"Compiled Python bytecode {printable(name)!r} is shipped with the model; "
            "the source cannot be reviewed and importing it executes the module.",
            category="obfuscation", location=name,
            remediation="Require reviewable source; delete compiled artifacts from the repository.",
            attack=("T1027",), cwe=("CWE-506",),
        )
    )
    report.metadata = {"magic": data[:4].hex(), "bytes": len(data)}
    return report


__all__ = [
    "Embedded",
    "FormatReport",
    "HEADER_BYTES",
    "MODEL_EXTENSIONS",
    "Region",
    "detect",
    "inspect_buffer",
    "inspect_path",
]
