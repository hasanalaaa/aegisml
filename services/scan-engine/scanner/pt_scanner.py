"""
AegisML PyTorch (.pt/.pth/.bin) Format Scanner
PyTorch checkpoints are ZIP archives (modern format) or raw pickle (legacy
torch.save). This scanner detects which variant is in use and inspects the
embedded pickle stream for the same dangerous opcodes as pkl_scanner, since
torch.load() ultimately unpickles whatever is inside.
"""
import zipfile
import io
from typing import Any
from . import pkl_scanner

ZIP_MAGIC = b"PK\x03\x04"
PICKLE_MAGICS = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")


def scan(file_path: str) -> dict[str, Any]:
    threats: list[dict] = []
    metadata: dict[str, Any] = {}

    try:
        with open(file_path, "rb") as f:
            head = f.read(8)

        if head.startswith(ZIP_MAGIC):
            # Modern torch.save format: a ZIP containing data.pkl + tensor storages
            metadata["container_format"] = "zip (modern torch.save)"
            try:
                with zipfile.ZipFile(file_path, "r") as zf:
                    names = zf.namelist()
                    metadata["archive_entries"] = len(names)

                    pkl_entries = [n for n in names if n.endswith(("data.pkl", "/data.pkl")) or n.endswith(".pkl")]
                    if not pkl_entries:
                        threats.append({
                            "id": "PT-STRUCT-001",
                            "name": "PyTorch Archive Missing data.pkl",
                            "category": "format_anomaly",
                            "severity": "high",
                            "cvss": 7.0,
                            "description": "ZIP-based PyTorch checkpoint has no data.pkl entry — does not match expected torch.save structure.",
                            "remediation": "Verify the file is a genuine PyTorch checkpoint and not a renamed/crafted ZIP.",
                            "references": []
                        })

                    for entry_name in pkl_entries[:5]:  # cap to avoid zip-bomb style abuse
                        info = zf.getinfo(entry_name)
                        if info.file_size > 100 * 1024 * 1024:
                            threats.append({
                                "id": "PT-ZIP-001",
                                "name": "Oversized Embedded Pickle Entry",
                                "category": "format_anomaly",
                                "severity": "medium",
                                "cvss": 5.0,
                                "description": f"Embedded pickle '{entry_name}' is {info.file_size / 1024 / 1024:.1f}MB — unusually large for a state-dict pickle.",
                                "remediation": "Inspect manually before loading.",
                                "references": []
                            })
                            continue
                        try:
                            pkl_bytes = zf.read(entry_name)
                            tmp_buffer = io.BytesIO(pkl_bytes)
                            # Reuse pkl_scanner's opcode logic by writing to a temp-like path is
                            # unnecessary; inline a lightweight opcode scan instead.
                            import pickletools
                            ops = list(pickletools.genops(pkl_bytes))
                            for opcode, arg, pos in ops:
                                if opcode.name in ("GLOBAL", "INST") and isinstance(arg, str) and " " in arg:
                                    mod, name = arg.split(" ", 1)
                                    if (mod, name) in pkl_scanner.DANGEROUS_GLOBALS:
                                        threats.append({
                                            "id": "PT-OPC-001",
                                            "name": f"Dangerous GLOBAL opcode in {entry_name}: {mod}.{name}",
                                            "category": "code_execution",
                                            "severity": "critical",
                                            "cvss": 9.8,
                                            "description": f"Embedded pickle '{entry_name}' references {mod}.{name}() — arbitrary code execution on torch.load().",
                                            "remediation": "Use torch.load(weights_only=True) which blocks arbitrary globals, or convert to safetensors.",
                                            "references": ["https://pytorch.org/docs/stable/notes/serialization.html#torch.load"]
                                        })
                        except Exception:
                            continue
            except zipfile.BadZipFile:
                threats.append({
                    "id": "PT-ZIP-002",
                    "name": "Corrupted PyTorch ZIP Container",
                    "category": "format_anomaly",
                    "severity": "medium",
                    "cvss": 4.0,
                    "description": "File has ZIP magic bytes but is not a valid ZIP archive.",
                    "remediation": "Re-download the file; it may be truncated or corrupted.",
                    "references": []
                })

        elif head[:2] in PICKLE_MAGICS:
            # Legacy torch.save: raw pickle stream — delegate to pkl_scanner
            metadata["container_format"] = "raw pickle (legacy torch.save)"
            pkl_result = pkl_scanner.scan(file_path)
            threats.extend(pkl_result.get("threats_found", []))
            metadata.update(pkl_result.get("metadata", {}))

        else:
            metadata["container_format"] = "unrecognized"
            threats.append({
                "id": "PT-MAGIC-001",
                "name": "Unrecognized PyTorch File Header",
                "category": "format_anomaly",
                "severity": "medium",
                "cvss": 4.5,
                "description": f"File extension suggests PyTorch checkpoint but header bytes ({head.hex()}) match neither ZIP nor pickle protocol magic.",
                "remediation": "Verify file integrity and source before loading.",
                "references": []
            })

    except FileNotFoundError:
        pass
    except Exception as e:
        threats.append({
            "id": "PT-ERR-001",
            "name": "PyTorch Parser Error",
            "category": "format_anomaly",
            "severity": "medium",
            "cvss": 3.0,
            "description": f"Error during PyTorch checkpoint analysis: {str(e)[:200]}",
            "remediation": "File may be corrupted or crafted to crash parsers.",
            "references": []
        })

    return {"format": "pytorch", "threats_found": threats, "metadata": metadata}
