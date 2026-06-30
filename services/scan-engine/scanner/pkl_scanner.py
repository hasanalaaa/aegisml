"""
AegisML Pickle Format Scanner
Inspects pickle streams for dangerous opcodes, __reduce__ hooks,
and code execution patterns using opcode-level analysis.
"""
import pickletools
import io
import struct
from typing import Any

# Dangerous pickle opcodes and their meanings
DANGEROUS_GLOBALS = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "execve"),
    ("posix", "system"),
    ("posix", "popen"),
    ("posix", "execv"),
    ("posix", "execve"),
    ("posix", "spawnv"),
    ("nt", "system"),
    ("nt", "popen"),
    ("_posixsubprocess", "fork_exec"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "run"),
    ("subprocess", "check_output"),
    ("builtins", "exec"),
    ("builtins", "eval"),
    ("builtins", "compile"),
    ("builtins", "__import__"),
    ("builtins", "getattr"),
    ("__builtin__", "exec"),
    ("__builtin__", "eval"),
    ("ctypes", "cdll"),
    ("ctypes", "CDLL"),
    ("ctypes", "WinDLL"),
    ("importlib", "import_module"),
    ("marshal", "loads"),
    ("marshal", "load"),
    ("pickle", "loads"),
    ("pty", "spawn"),
}


def _check_global_impl(mod: str, name: str, pos: int, threats: list) -> bool:
    """Flag a resolved (module, name) global reference if it's dangerous.
    Returns True if a threat was appended."""
    if (mod, name) in DANGEROUS_GLOBALS:
        threats.append({
            "id": "PKL-OPC-001",
            "name": f"Dangerous global reference: {mod}.{name}",
            "category": "code_execution",
            "severity": "critical",
            "cvss": 9.8,
            "description": f"Pickle resolves the global {mod}.{name}() at byte offset {pos} — arbitrary code execution on deserialization.",
            "remediation": "Never load this pickle file. Convert model to safetensors.",
            "references": ["https://docs.python.org/3/library/pickle.html#what-can-be-pickled-and-unpickled"]
        })
        return True
    return False


def scan(file_path: str) -> dict[str, Any]:
    threats: list[dict] = []
    metadata: dict[str, Any] = {}

    try:
        with open(file_path, "rb") as f:
            data = f.read(min(50 * 1024 * 1024, 500 * 1024 * 1024))  # Max 50MB for opcode analysis

        # Validate pickle magic
        if not data or data[0] not in (0x80, ord('{')):
            # Not a standard pickle
            pass
        else:
            if data[0] == 0x80:
                proto = data[1] if len(data) > 1 else 0
                metadata["pickle_protocol"] = proto
                if proto >= 5:
                    threats.append({
                        "id": "PKL-PROTO-001",
                        "name": f"Pickle Protocol {proto} (Modern, Higher Risk)",
                        "category": "code_execution",
                        "severity": "medium",
                        "cvss": 4.0,
                        "description": f"Pickle protocol {proto} supports advanced features including buffer pickles. Verify the source.",
                        "remediation": "Use safetensors format instead. Protocol 4+ supports more complex deserialization graphs.",
                        "references": ["https://docs.python.org/3/library/pickle.html#data-stream-format"]
                    })

        # Opcode-level analysis using pickletools
        try:
            ops = list(pickletools.genops(data))
            metadata["opcode_count"] = len(ops)

            found_reduce = False
            # Track the last two string values pushed onto the stack, because
            # modern pickle (protocol >= 2, the default since Py3) resolves
            # globals via STACK_GLOBAL, which pops <module> and <name> off the
            # stack rather than carrying them inline like the legacy GLOBAL
            # opcode did. We keep a small rolling window of recent string
            # pushes so we can reconstruct the (module, name) pair.
            recent_strings: list[str] = []

            for opcode, arg, pos in ops:
                op_name = opcode.name

                # Capture string literals that may become a GLOBAL's operands
                if op_name in ("SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8",
                               "SHORT_BINSTRING", "BINSTRING", "UNICODE", "STRING"):
                    if isinstance(arg, (str, bytes)):
                        recent_strings.append(arg.decode() if isinstance(arg, bytes) else arg)
                        recent_strings = recent_strings[-4:]  # keep window small

                # Legacy GLOBAL / INST: "c<module>\n<name>\n" → arg "module name"
                if op_name in ("GLOBAL", "INST"):
                    if isinstance(arg, str) and " " in arg:
                        mod, name = arg.split(" ", 1)
                        _check_global_impl(mod, name, pos, threats)

                # Modern STACK_GLOBAL: module and name are the two most recent
                # string pushes on the stack (name pushed last).
                elif op_name == "STACK_GLOBAL":
                    if len(recent_strings) >= 2:
                        mod, name = recent_strings[-2], recent_strings[-1]
                        _check_global_impl(mod, name, pos, threats)

                # REDUCE: invokes a callable with args during unpickling
                elif op_name == "REDUCE" and not found_reduce:
                    found_reduce = True
                    threats.append({
                        "id": "PKL-OPC-002",
                        "name": "Pickle REDUCE Opcode Detected",
                        "category": "code_execution",
                        "severity": "high",
                        "cvss": 8.5,
                        "description": f"REDUCE opcode at byte {pos} — executes a callable with arguments during deserialization. High risk if callable is dangerous.",
                        "remediation": "Use torch.load(weights_only=True) or convert to safetensors.",
                        "references": []
                    })

        except Exception:
            # pickletools.genops can fail on non-standard/corrupted pickles
            # Fall through to byte pattern matching (already done by engine.py)
            pass

    except FileNotFoundError:
        pass
    except Exception as e:
        threats.append({
            "id": "PKL-ERR-001",
            "name": "Pickle Parser Error",
            "category": "format_anomaly",
            "severity": "medium",
            "cvss": 3.0,
            "description": f"Error during pickle opcode analysis: {str(e)[:200]}. File may be corrupted.",
            "remediation": "Treat corrupted pickle files as potentially malicious.",
            "references": []
        })

    return {"format": "pickle", "threats_found": threats, "metadata": metadata}
