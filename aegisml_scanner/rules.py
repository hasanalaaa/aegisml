"""Deterministic detection catalogue for AI model artifacts.

Two rule families share one schema:

* **literal rules** carry raw byte signatures matched case-insensitively during
  the single streaming pass over the artifact;
* **pattern rules** carry a regular expression evaluated against printable
  strings harvested from the same pass (and against archive members, model
  configuration and embedded source).

Every rule declares severity, CVSS, category, MITRE ATLAS/ATT&CK technique,
CWE, and remediation, so a finding is explainable without reading this file.

The catalogue is data, not code: :func:`load_pack` merges user supplied packs
(JSON) so an organisation can extend detection without forking the scanner.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Iterable, Sequence


RULESET_VERSION = "2026.07.3"

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITIES = tuple(SEVERITY_RANK)

# Contexts a rule may be evaluated in.  ``bytes`` is the raw artifact stream,
# ``string`` the harvested printable strings, ``code`` embedded source or
# bytecode, ``config`` structured model configuration.
CONTEXT_BYTES = "bytes"
CONTEXT_STRING = "string"
CONTEXT_CODE = "code"
CONTEXT_CONFIG = "config"

_ATOM_TOKEN = re.compile(rb"[a-z0-9_./\\:@-]{4,}")


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    category: str
    cvss: float
    description: str
    remediation: str
    patterns: tuple[bytes, ...] = ()
    regex: str = ""
    atoms: tuple[bytes, ...] = ()
    attack: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    contexts: tuple[str, ...] = (CONTEXT_BYTES,)
    confidence: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "category": self.category,
            "cvss": self.cvss,
            "description": self.description,
            "remediation": self.remediation,
            "patterns": [p.decode("utf-8", "backslashreplace") for p in self.patterns],
            "regex": self.regex,
            "attack": list(self.attack),
            "cwe": list(self.cwe),
            "references": list(self.references),
            "contexts": list(self.contexts),
            "confidence": self.confidence,
        }


def _lit(
    rule_id: str,
    severity: str,
    category: str,
    cvss: float,
    description: str,
    remediation: str,
    patterns: Sequence[bytes],
    *,
    attack: Sequence[str] = (),
    cwe: Sequence[str] = (),
    references: Sequence[str] = (),
    atoms: Sequence[bytes] = (),
    confidence: str = "high",
) -> Rule:
    return Rule(
        id=rule_id,
        severity=severity,
        category=category,
        cvss=cvss,
        description=description,
        remediation=remediation,
        patterns=tuple(patterns),
        atoms=tuple(atoms),
        attack=tuple(attack),
        cwe=tuple(cwe),
        references=tuple(references),
        confidence=confidence,
    )


def _rx(
    rule_id: str,
    severity: str,
    category: str,
    cvss: float,
    description: str,
    remediation: str,
    regex: str,
    *,
    attack: Sequence[str] = (),
    cwe: Sequence[str] = (),
    references: Sequence[str] = (),
    contexts: Sequence[str] = (CONTEXT_STRING,),
    confidence: str = "medium",
) -> Rule:
    return Rule(
        id=rule_id,
        severity=severity,
        category=category,
        cvss=cvss,
        description=description,
        remediation=remediation,
        regex=regex,
        attack=tuple(attack),
        cwe=tuple(cwe),
        references=tuple(references),
        contexts=tuple(contexts),
        confidence=confidence,
    )


_REJECT = "Do not load the artifact; obtain a signed build from a trusted source."
_REVIEW = "Review the referenced code path before the artifact is used."

# --------------------------------------------------------------------------
# 1. Direct code execution primitives
# --------------------------------------------------------------------------
_EXECUTION: tuple[Rule, ...] = (
    _lit(
        "AML.RCE.OS_SYSTEM", "critical", "code_execution", 9.8,
        "Operating-system command execution primitive referenced by the artifact.",
        _REJECT,
        (b"os.system", b"os\nsystem", b"posix\nsystem", b"nt\nsystem",
         b"os.popen", b"posix\npopen", b"nt\npopen", b"os\npopen",
         b"os.execv", b"os.execve", b"os.execl", b"os.spawnv", b"os\nexecv", b"os\nspawnv"),
        attack=("AML.T0011", "T1059"), cwe=("CWE-78", "CWE-502"),
    ),
    _lit(
        "AML.RCE.SUBPROCESS", "critical", "code_execution", 9.6,
        "Process-spawning primitive referenced by the artifact.",
        _REJECT,
        (b"subprocess.popen", b"subprocess.run", b"subprocess.call",
         b"subprocess.check_output", b"subprocess.check_call",
         b"subprocess\npopen", b"subprocess\nrun", b"subprocess\ncall",
         b"subprocess\ncheck_output", b"subprocess\ngetoutput"),
        attack=("AML.T0011", "T1059"), cwe=("CWE-78",),
    ),
    _lit(
        "AML.RCE.DYNAMIC_EVAL", "critical", "code_execution", 9.4,
        "Dynamic evaluation or compilation primitive embedded in the artifact.",
        _REJECT,
        (b"builtins\neval", b"builtins\nexec", b"builtins\ncompile",
         b"__builtin__\neval", b"__builtin__\nexec", b"__builtin__\ncompile",
         b"eval(", b"exec(", b"compile(", b"execfile("),
        attack=("AML.T0011", "T1059.006"), cwe=("CWE-95",),
    ),
    _lit(
        "AML.RCE.DYNAMIC_IMPORT", "high", "code_execution", 8.2,
        "Dynamic module loading can resolve attacker-controlled code at load time.",
        _REVIEW,
        (b"__import__(", b"importlib.import_module", b"importlib\nimport_module",
         b"importlib.util.spec_from_file_location", b"imp.load_source",
         b"builtins\n__import__", b"runpy\nrun_path", b"runpy.run_path"),
        attack=("AML.T0011",), cwe=("CWE-470",),
    ),
    _lit(
        "AML.RCE.CTYPES", "critical", "native_code", 9.5,
        "Native-library loading primitive embedded in the artifact.",
        _REJECT,
        (b"ctypes.cdll", b"ctypes.windll", b"ctypes\ncdll", b"ctypes\nwindll",
         b"ctypes.util.find_library", b"cdll.loadlibrary", b"ctypes\npythonapi",
         b"cffi.ffi(", b"_ctypes\ndlopen"),
        attack=("AML.T0011", "T1129"), cwe=("CWE-114",),
    ),
    _lit(
        "AML.RCE.SHELL_UNIX", "high", "code_execution", 8.1,
        "Unix shell interpreter path embedded in artifact content.",
        _REVIEW,
        (b"/bin/sh", b"/bin/bash", b"/bin/zsh", b"/usr/bin/env sh",
         b"/usr/bin/env bash", b"/usr/bin/env python", b"#!/bin/"),
        attack=("T1059.004",), cwe=("CWE-78",),
    ),
    _lit(
        "AML.RCE.SHELL_WINDOWS", "high", "code_execution", 8.3,
        "Windows command interpreter primitive embedded in artifact content.",
        _REVIEW,
        (b"cmd.exe /c", b"cmd /c ", b"powershell.exe", b"powershell -enc",
         b"powershell -e ", b"-encodedcommand", b"wscript.shell", b"rundll32",
         b"mshta ", b"regsvr32 /"),
        attack=("T1059.001", "T1059.003"), cwe=("CWE-78",),
    ),
    _lit(
        "AML.RCE.PTY_SPAWN", "critical", "code_execution", 9.0,
        "Interactive shell spawning primitive (reverse-shell building block).",
        _REJECT,
        (b"pty.spawn", b"pty\nspawn", b"os.dup2", b"os\ndup2"),
        attack=("T1059",), cwe=("CWE-78",),
    ),
    _lit(
        "AML.RCE.NODE_CHILD_PROCESS", "critical", "code_execution", 9.1,
        "Node.js process execution primitive embedded in the artifact.",
        _REJECT,
        (b"child_process", b"require('child_process')", b'require("child_process")',
         b"execsync(", b"spawnsync("),
        attack=("T1059.007",), cwe=("CWE-78",),
    ),
    _lit(
        "AML.RCE.JAVA_RUNTIME", "critical", "code_execution", 9.0,
        "JVM runtime execution gadget referenced in artifact content.",
        _REJECT,
        (b"java.lang.runtime", b"getruntime().exec", b"processbuilder",
         b"javax.script.scriptengine"),
        attack=("T1059",), cwe=("CWE-78",),
    ),
)

# --------------------------------------------------------------------------
# 2. Deserialization / serializer abuse
# --------------------------------------------------------------------------
_DESERIALIZATION: tuple[Rule, ...] = (
    _lit(
        "AML.DESER.REDUCE_HOOK", "high", "deserialization", 8.5,
        "Custom Pickle reduction hook can invoke a callable while the model loads.",
        "Use SafeTensors or a weights-only loader; never unpickle untrusted files.",
        (b"__reduce__", b"__reduce_ex__", b"__setstate__", b"__wrapped__"),
        attack=("AML.T0010", "AML.T0011"), cwe=("CWE-502",),
    ),
    _lit(
        "AML.DESER.PICKLE_LOADS", "high", "deserialization", 8.0,
        "Nested unsafe deserialization primitive found inside model content.",
        "Do not pass untrusted bytes to Pickle loaders.",
        (b"pickle.loads", b"pickle.load(", b"_pickle\nloads", b"pickle\nloads",
         b"cpickle.loads", b"dill.loads", b"dill\nloads", b"cloudpickle.loads",
         b"joblib.load", b"torch.load(", b"pandas.read_pickle"),
        attack=("AML.T0010",), cwe=("CWE-502",),
    ),
    _lit(
        "AML.DESER.MARSHAL", "high", "obfuscation", 7.8,
        "Python bytecode unmarshalling can hide an executable payload.",
        _REJECT,
        (b"marshal.loads", b"marshal\nloads", b"marshal.load(", b"types\ncodetype",
         b"types.functiontype", b"types\nfunctiontype"),
        attack=("AML.T0011", "T1027"), cwe=("CWE-502",),
    ),
    _lit(
        "AML.DESER.YAML_UNSAFE", "high", "deserialization", 8.1,
        "Unsafe YAML loader construct that instantiates arbitrary Python objects.",
        "Load configuration with yaml.safe_load only.",
        (b"!!python/object", b"!!python/name", b"!!python/module",
         b"yaml.unsafe_load", b"yaml.load(", b"loader=yaml.loader"),
        attack=("AML.T0010",), cwe=("CWE-502",),
    ),
    _lit(
        "AML.DESER.NUMPY_PICKLE", "high", "deserialization", 8.0,
        "NumPy object-array loading path re-enables Pickle execution.",
        "Store weights as plain numeric dtypes; never load with allow_pickle=True.",
        (b"allow_pickle=true", b"numpy.core.multiarray._reconstruct",
         b"numpy\n_reconstruct", b"numpy.core.multiarray\nscalar"),
        attack=("AML.T0010",), cwe=("CWE-502",),
    ),
    _lit(
        "AML.DESER.KERAS_LAMBDA", "critical", "code_execution", 9.3,
        "Keras Lambda layer carries marshalled Python bytecode executed at load time.",
        "Rebuild the model without Lambda layers, or load with safe_mode and a pinned Keras.",
        (b'"class_name": "lambda"', b'"class_name":"lambda"',
         b"'class_name': 'lambda'", b"keras.layers.core.lambda",
         b"function_type\": \"lambda", b"\"module\": \"builtins\""),
        attack=("AML.T0011",), cwe=("CWE-502",),
        references=("CVE-2024-3660", "CVE-2025-1550", "CVE-2025-9905"),
    ),
    _lit(
        "AML.DESER.TF_PYFUNC", "critical", "code_execution", 9.2,
        "TensorFlow graph references a Python-callback op that executes host code.",
        _REJECT,
        (b"pyfunc", b"pyfuncstateless", b"eagerpyfunc", b"scriptops"),
        attack=("AML.T0011",), cwe=("CWE-502",),
    ),
    _lit(
        "AML.DESER.JAVA_SERIAL", "high", "deserialization", 8.0,
        "Java serialized-object stream header embedded in the artifact.",
        _REJECT,
        (b"\xac\xed\x00\x05", b"java.io.objectinputstream"),
        atoms=(b"\xac\xed\x00\x05", b"objectinputstream"),
        cwe=("CWE-502",),
    ),
)

# --------------------------------------------------------------------------
# 3. Network, exfiltration, staged download
# --------------------------------------------------------------------------
_NETWORK: tuple[Rule, ...] = (
    _lit(
        "AML.NET.SOCKET", "high", "network", 7.7,
        "Raw network socket capability embedded in model content.",
        "Block egress and review the referenced code path.",
        (b"socket.socket", b"socket\nsocket", b"socket.create_connection",
         b"socket\ncreate_connection", b"af_inet", b"sock_stream"),
        attack=("T1095",), cwe=("CWE-923",),
    ),
    _lit(
        "AML.NET.HTTP_CLIENT", "medium", "network", 6.2,
        "HTTP client capability may download code or exfiltrate data.",
        "Run only inside a network-restricted sandbox and review destinations.",
        (b"requests.get(", b"requests.post(", b"urllib.request.urlopen",
         b"urllib\nurlopen", b"httpx.get(", b"httpx.post(", b"http.client.httpconnection",
         b"aiohttp.clientsession", b"xmlhttprequest", b"fetch(\"http"),
        attack=("T1071",), cwe=("CWE-829",),
    ),
    _lit(
        "AML.NET.DOWNLOAD_EXEC", "critical", "download_execution", 9.3,
        "Command-line download primitive indicates a staged second-stage payload.",
        _REJECT,
        (b"curl http", b"curl -s http", b"wget http", b"wget -q http",
         b"invoke-webrequest", b"downloadstring(", b"downloadfile(",
         b"certutil -urlcache", b"bitsadmin /transfer"),
        attack=("T1105",), cwe=("CWE-494",),
    ),
    _lit(
        "AML.NET.REVERSE_SHELL", "critical", "network", 9.7,
        "Reverse-shell construction pattern embedded in artifact content.",
        _REJECT,
        (b"connect((\"", b"nc -e /bin/", b"ncat -e ", b"bash -i >&",
         b"sh -i >&", b"/dev/tcp/", b"socket.af_inet,socket.sock_stream"),
        attack=("T1059", "T1571"), cwe=("CWE-78",),
    ),
    _lit(
        "AML.NET.EXFIL_ENDPOINT", "high", "data_exfiltration", 7.5,
        "Known data-drop or tunnelling service referenced in artifact content.",
        "Treat the artifact as an exfiltration stager; investigate the endpoint offline.",
        (b"webhook.site", b"requestbin", b"pipedream.net", b"burpcollaborator",
         b"interact.sh", b"ngrok.io", b"trycloudflare.com", b"pastebin.com/raw",
         b"transfer.sh", b"0x0.st", b"termbin.com", b"discord.com/api/webhooks",
         b"api.telegram.org/bot"),
        attack=("T1567",), cwe=("CWE-200",),
    ),
    _lit(
        "AML.NET.DNS_TUNNEL", "medium", "data_exfiltration", 6.5,
        "DNS resolution primitive that can be used as a covert channel.",
        _REVIEW,
        (b"socket.gethostbyname", b"dns.resolver", b"nslookup ", b"dig +short"),
        attack=("T1071.004",), cwe=("CWE-200",),
    ),
)

# --------------------------------------------------------------------------
# 4. Obfuscation & evasion
# --------------------------------------------------------------------------
_OBFUSCATION: tuple[Rule, ...] = (
    _lit(
        "AML.OBF.BASE64_DECODE", "medium", "obfuscation", 5.3,
        "Base64 decoding capability may be used to unpack hidden content.",
        "Decode and inspect the payload before trusting the artifact.",
        (b"base64.b64decode", b"base64\nb64decode", b"base64.decodebytes",
         b"b64decode(", b"atob(", b"frombase64string"),
        attack=("T1140",), cwe=("CWE-506",),
    ),
    _lit(
        "AML.OBF.COMPRESSION_DECODE", "medium", "obfuscation", 5.5,
        "In-memory decompression of an embedded blob, a common payload-packing step.",
        "Extract and inspect the decompressed content offline.",
        (b"zlib.decompress", b"zlib\ndecompress", b"bz2.decompress",
         b"lzma.decompress", b"gzip.decompress", b"codecs\ndecode"),
        attack=("T1140",), cwe=("CWE-506",),
    ),
    _lit(
        "AML.OBF.CHAR_ARITHMETIC", "medium", "obfuscation", 5.4,
        "String reconstruction gadget used to hide identifiers from naive scanners.",
        _REVIEW,
        (b"\".join(chr(", b"''.join(chr(", b"chr(ord(", b"getattr(__import__",
         b"fromcharcode(", b"[::-1])"),
        attack=("T1027",), cwe=("CWE-506",),
    ),
    _lit(
        "AML.OBF.PYC_MAGIC", "high", "obfuscation", 7.2,
        "Compiled Python bytecode header embedded inside the artifact.",
        "Disassemble the bytecode offline; never import it.",
        (b"\x33\x0d\x0d\x0a", b"\x42\x0d\x0d\x0a", b"\x55\x0d\x0d\x0a",
         b"\x6f\x0d\x0d\x0a", b"\xa7\x0d\x0d\x0a", b"\xcb\x0d\x0d\x0a",
         b"\xf3\x0d\x0d\x0a"),
        atoms=(b"\x0d\x0d\x0a",),
        attack=("T1027",), cwe=("CWE-506",), confidence="medium",
    ),
    _lit(
        "AML.OBF.ANTI_ANALYSIS", "high", "evasion", 7.6,
        "Sandbox or debugger detection logic embedded in artifact content.",
        "Treat evasion logic as intent; quarantine the artifact.",
        (b"sys.gettrace", b"ptrace(", b"isdebuggerpresent", b"vboxservice",
         b"vmware", b"/proc/self/status", b"docker/.dockerenv", b"cuckoo"),
        attack=("T1497",), cwe=("CWE-506",), confidence="medium",
    ),
    _lit(
        "AML.OBF.ENV_HARVEST", "high", "credential_exposure", 7.9,
        "Environment or credential harvesting primitive embedded in the artifact.",
        "Rotate any credential reachable from the loading host.",
        (b"os.environ", b"os\nenviron", b"getenv(\"aws", b"~/.aws/credentials",
         b"~/.ssh/id_rsa", b"/.kube/config", b"~/.docker/config.json",
         b"huggingface/token", b"~/.netrc"),
        attack=("T1552",), cwe=("CWE-522",),
    ),
)

# --------------------------------------------------------------------------
# 5. Persistence & host tampering
# --------------------------------------------------------------------------
_PERSISTENCE: tuple[Rule, ...] = (
    _lit(
        "AML.PERSIST.SSH_KEYS", "critical", "persistence", 9.1,
        "Reference to modifying SSH authorized keys.",
        "Reject and audit the host for unauthorized persistence.",
        (b".ssh/authorized_keys", b".ssh\\authorized_keys"),
        attack=("T1098.004",), cwe=("CWE-732",),
    ),
    _lit(
        "AML.PERSIST.STARTUP", "high", "persistence", 8.4,
        "Startup, service or scheduled-task persistence path referenced.",
        _REJECT,
        (b"/etc/cron", b"crontab -", b"/etc/rc.local", b"launchagents",
         b"currentversion\\run", b"schtasks /create", b"systemd/system/",
         b"~/.bashrc", b"~/.zshrc", b"/etc/profile.d/"),
        attack=("T1053", "T1547"), cwe=("CWE-732",),
    ),
    _lit(
        "AML.PERSIST.SITECUSTOMIZE", "critical", "persistence", 9.0,
        "Python interpreter auto-import persistence path referenced.",
        _REJECT,
        (b"sitecustomize", b"usercustomize", b".pth\n", b"site-packages/"),
        attack=("T1546",), cwe=("CWE-732",), confidence="medium",
    ),
    _lit(
        "AML.PERSIST.DESTRUCTIVE", "critical", "impact", 9.4,
        "Destructive filesystem or database command embedded in artifact content.",
        _REJECT,
        (b"rm -rf /", b"shutil.rmtree", b"drop database", b"drop schema",
         b"format c:", b"mkfs.", b"dd if=/dev/zero"),
        attack=("T1485",), cwe=("CWE-77",),
    ),
)

# --------------------------------------------------------------------------
# 6. Secrets & injection
# --------------------------------------------------------------------------
_SECRETS: tuple[Rule, ...] = (
    _lit(
        "AML.SECRET.PRIVATE_KEY", "high", "credential_exposure", 8.0,
        "Private-key material is embedded in the artifact.",
        "Treat the key as compromised, rotate it, and remove it from the model.",
        (b"-----begin private key-----", b"-----begin rsa private key-----",
         b"-----begin openssh private key-----", b"-----begin ec private key-----",
         b"-----begin pgp private key block-----", b"-----begin dsa private key-----"),
        attack=("T1552.004",), cwe=("CWE-798",),
    ),
    _lit(
        "AML.INJECT.SCRIPT_TAG", "medium", "injection", 5.8,
        "Active script content embedded in model metadata or sidecar data.",
        "Escape metadata on display and review the payload source.",
        (b"<script", b"javascript:", b"onerror=", b"onload=", b"<iframe",
         b"document.cookie", b"innerhtml ="),
        attack=("T1059.007",), cwe=("CWE-79",),
    ),
    _lit(
        "AML.INJECT.TEMPLATE_SSTI", "critical", "injection", 9.1,
        "Server-side template injection gadget usable from a chat template.",
        "Strip the template and rebuild it from a trusted tokenizer configuration.",
        (b"__class__", b"__mro__", b"__subclasses__", b"__globals__",
         b"self.__init__.__globals__", b"lipsum.__globals__", b"cycler.__init__",
         b"joiner.__init__", b"namespace.__init__", b"request.application"),
        attack=("AML.T0011",), cwe=("CWE-1336",),
        references=("CVE-2024-34359",),
    ),
    _lit(
        "AML.INJECT.SQL", "medium", "injection", 6.0,
        "SQL statement embedded in model content or metadata.",
        _REVIEW,
        (b"union select ", b"' or '1'='1", b"; drop table ", b"information_schema"),
        cwe=("CWE-89",), confidence="medium",
    ),
    _lit(
        "AML.PROMPT.OVERRIDE", "low", "prompt_injection", 3.1,
        "Instruction-override text targeting systems that consume model metadata.",
        "Keep metadata outside privileged prompts and require explicit quoting.",
        (b"ignore previous instructions", b"ignore all previous instructions",
         b"disregard the above", b"you are now dan", b"developer mode enabled",
         b"system prompt:", b"</system>", b"[[system]]"),
        attack=("AML.T0051",), cwe=("CWE-1427",), confidence="medium",
    ),
    _lit(
        "AML.PROMPT.EXFIL_MARKDOWN", "medium", "prompt_injection", 5.5,
        "Prompt payload that renders a remote image or link, a known chat exfiltration path.",
        "Disallow remote resource rendering for model-sourced text.",
        (b"![](http", b"![image](http", b"<img src=\"http"),
        attack=("AML.T0051",), cwe=("CWE-1427",), confidence="medium",
    ),
)

# --------------------------------------------------------------------------
# 7. Supply chain & loader trust
# --------------------------------------------------------------------------
_SUPPLY_CHAIN: tuple[Rule, ...] = (
    _lit(
        "AML.SUPPLY.TRUST_REMOTE_CODE", "critical", "supply_chain", 9.0,
        "Model configuration requests execution of repository-supplied Python.",
        "Never enable trust_remote_code for an unaudited repository.",
        (b"trust_remote_code", b"\"auto_map\"", b"'auto_map'",
         b"--trust-remote-code"),
        attack=("AML.T0010",), cwe=("CWE-829",),
    ),
    _lit(
        "AML.SUPPLY.PIP_INSTALL", "high", "supply_chain", 8.0,
        "Package installation command embedded inside a model artifact.",
        "A model must never install software; treat this as a dropper.",
        (b"pip install ", b"pip3 install ", b"python -m pip install",
         b"npm install ", b"apt-get install", b"conda install"),
        attack=("T1195",), cwe=("CWE-829",),
    ),
    _lit(
        "AML.SUPPLY.DIRECT_URL_REQUIREMENT", "high", "supply_chain", 7.8,
        "Dependency pinned to a direct archive or VCS URL bypasses index integrity.",
        "Pin dependencies to index releases with hashes.",
        (b"git+https://", b"git+ssh://", b"@ https://", b"--index-url",
         b"--extra-index-url", b"--trusted-host"),
        attack=("T1195.002",), cwe=("CWE-494",), confidence="medium",
    ),
    _lit(
        "AML.SUPPLY.SETUP_HOOK", "high", "supply_chain", 8.2,
        "Build-time execution hook shipped alongside model weights.",
        "Model repositories must not ship build hooks; review the payload.",
        (b"cmdclass=", b"class postinstall", b"setuptools.command.install",
         b"build_py.run(", b"__init__.py\nexec("),
        attack=("T1195",), cwe=("CWE-829",), confidence="medium",
    ),
)

# --------------------------------------------------------------------------
# 8. Binary / container anomalies matched on raw bytes
# --------------------------------------------------------------------------
_BINARY: tuple[Rule, ...] = (
    _lit(
        "AML.BIN.EMBEDDED_ELF", "high", "native_code", 8.5,
        "ELF executable image embedded inside the artifact body.",
        "Extract and analyse the binary offline; do not run the model.",
        (b"\x7felf\x02\x01\x01", b"\x7felf\x01\x01\x01"),
        atoms=(b"\x7felf",), attack=("T1027.009",), cwe=("CWE-506",),
    ),
    _lit(
        "AML.BIN.EMBEDDED_PE", "high", "native_code", 8.5,
        "Windows PE executable image embedded inside the artifact body.",
        "Extract and analyse the binary offline; do not run the model.",
        (b"this program cannot be run in dos mode",),
        attack=("T1027.009",), cwe=("CWE-506",),
    ),
    _lit(
        "AML.BIN.EMBEDDED_MACHO", "high", "native_code", 8.4,
        "Mach-O executable image embedded inside the artifact body.",
        "Extract and analyse the binary offline; do not run the model.",
        (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"__lc_dyld_info"),
        atoms=(b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"__lc_dyld"),
        attack=("T1027.009",), cwe=("CWE-506",), confidence="medium",
    ),
    _lit(
        "AML.BIN.SHARED_LIBRARY", "high", "native_code", 8.0,
        "Native shared-library reference or loader call inside the artifact.",
        _REVIEW,
        (b"libc.so.6", b"kernel32.dll", b"ntdll.dll", b"dlopen(", b"loadlibrarya"),
        attack=("T1129",), cwe=("CWE-114",), confidence="medium",
    ),
    _lit(
        "AML.BIN.NESTED_ARCHIVE", "medium", "format_anomaly", 5.0,
        "Nested archive container found inside a model artifact.",
        "Unpack the nested container in isolation and scan its members.",
        (b"rar!\x1a\x07", b"7z\xbc\xaf\x27\x1c", b"\xfd7zxz\x00"),
        atoms=(b"rar!\x1a\x07", b"7z\xbc\xaf", b"7zxz\x00"),
        cwe=("CWE-506",), confidence="medium",
    ),
)

_LITERAL_RULES: tuple[Rule, ...] = (
    _EXECUTION + _DESERIALIZATION + _NETWORK + _OBFUSCATION
    + _PERSISTENCE + _SECRETS + _SUPPLY_CHAIN + _BINARY
)

# --------------------------------------------------------------------------
# 9. Regular-expression rules over harvested strings
# --------------------------------------------------------------------------
_REGEX_RULES: tuple[Rule, ...] = (
    _rx(
        "AML.RX.AWS_ACCESS_KEY", "critical", "credential_exposure", 9.0,
        "AWS access key identifier embedded in the artifact.",
        "Rotate the key immediately and purge it from the model history.",
        r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b",
        attack=("T1552",), cwe=("CWE-798",), confidence="high",
    ),
    _rx(
        "AML.RX.GITHUB_TOKEN", "critical", "credential_exposure", 9.0,
        "GitHub token embedded in the artifact.",
        "Revoke the token and audit repository access.",
        r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b",
        attack=("T1552",), cwe=("CWE-798",), confidence="high",
    ),
    _rx(
        "AML.RX.SLACK_TOKEN", "high", "credential_exposure", 8.2,
        "Slack token embedded in the artifact.",
        "Revoke the token and rotate the workspace app credentials.",
        r"\bxox[abposr]-[0-9A-Za-z-]{10,250}\b",
        attack=("T1552",), cwe=("CWE-798",),
    ),
    _rx(
        "AML.RX.PROVIDER_API_KEY", "high", "credential_exposure", 8.4,
        "Model-provider API key embedded in the artifact.",
        "Revoke the key; artifacts must never carry provider credentials.",
        r"\b(sk-ant-[A-Za-z0-9_\-]{20,}|sk-proj-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{32,}|hf_[A-Za-z0-9]{30,}|gsk_[A-Za-z0-9]{40,}|AIza[0-9A-Za-z_\-]{35})\b",
        attack=("T1552",), cwe=("CWE-798",),
    ),
    _rx(
        "AML.RX.JWT", "medium", "credential_exposure", 6.4,
        "JSON Web Token embedded in the artifact.",
        "Treat the token as leaked and invalidate the session.",
        r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
        cwe=("CWE-798",),
    ),
    _rx(
        "AML.RX.CONNECTION_STRING", "high", "credential_exposure", 7.8,
        "Database or broker connection string with inline credentials.",
        "Rotate the credential and move connection data out of the artifact.",
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:/@]+:[^\s:/@]+@[^\s/]+",
        cwe=("CWE-798",),
    ),
    _rx(
        "AML.RX.HARDCODED_IP_PORT", "medium", "network", 5.6,
        "Hard-coded IPv4 endpoint with a port, typical of a callback address.",
        "Confirm the endpoint is expected; models rarely embed literal endpoints.",
        r"\b(?!(?:127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.255)\b)(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b",
        attack=("T1571",), cwe=("CWE-1188",), confidence="low",
    ),
    _rx(
        "AML.RX.ONION_ADDRESS", "high", "network", 8.0,
        "Tor hidden-service address referenced by the artifact.",
        "Treat as covert command-and-control; quarantine the artifact.",
        r"\b[a-z2-7]{16,56}\.onion\b",
        attack=("T1090.003",), cwe=("CWE-506",),
    ),
    _rx(
        "AML.RX.BASE64_PAYLOAD", "medium", "obfuscation", 6.0,
        "Long Base64 blob adjacent to a decoder call is a packed-payload signature.",
        "Decode the blob offline and inspect the result.",
        r"(?:exec|eval|loads|decode|system)\s*\(\s*[a-zA-Z0-9_.]*\s*\(?\s*[\"'][A-Za-z0-9+/]{120,}={0,2}[\"']",
        attack=("T1027",), cwe=("CWE-506",),
    ),
    _rx(
        "AML.RX.POWERSHELL_ENCODED", "critical", "code_execution", 9.2,
        "Base64-encoded PowerShell command line.",
        _REJECT,
        r"(?i)powershell(?:\.exe)?[^\n]{0,40}-e(?:nc|ncoded(?:command)?)?\s+[A-Za-z0-9+/=]{40,}",
        attack=("T1059.001",), cwe=("CWE-78",), confidence="high",
    ),
    _rx(
        "AML.RX.HEX_SHELLCODE", "high", "native_code", 7.9,
        "Long escaped byte string, a common inline shellcode encoding.",
        "Disassemble the byte string offline before trusting the artifact.",
        r"(?:\\x[0-9a-fA-F]{2}){40,}",
        attack=("T1027",), cwe=("CWE-506",),
    ),
    _rx(
        "AML.RX.JINJA_EXPRESSION", "high", "injection", 8.0,
        "Jinja expression with attribute traversal inside a template field.",
        "Rebuild the chat template from the upstream tokenizer configuration.",
        r"\{\{[^}]{0,200}(?:__|\bself\b|\bconfig\b|\brequest\b|\bnamespace\b|\bcycler\b|\bjoiner\b|\blipsum\b)[^}]{0,200}\}\}",
        attack=("AML.T0011",), cwe=("CWE-1336",),
        references=("CVE-2024-34359",), contexts=(CONTEXT_STRING, CONTEXT_CONFIG),
    ),
    _rx(
        "AML.RX.FILE_WRITE_SENSITIVE", "high", "persistence", 8.1,
        "Write to a sensitive host path referenced in artifact content.",
        _REJECT,
        r"open\s*\(\s*[\"'](?:/etc/|/root/|~/\.|C:\\\\Windows\\\\)[^\"']{1,120}[\"']\s*,\s*[\"'][wa]",
        attack=("T1547",), cwe=("CWE-732",),
    ),
    _rx(
        "AML.RX.PATH_TRAVERSAL", "high", "format_anomaly", 7.6,
        "Path traversal sequence in an artifact-controlled path.",
        "Reject the artifact; extraction would write outside the target directory.",
        r"(?:^|[\"'\s=])(?:\.\./){2,}[A-Za-z0-9_./\\-]{1,120}",
        attack=("T1574",), cwe=("CWE-22",),
    ),
    _rx(
        "AML.RX.SUSPICIOUS_URL", "medium", "network", 6.1,
        "Raw script or archive download URL referenced by the artifact.",
        "Fetch and review the resource offline before use.",
        r"https?://[^\s\"'<>]{4,200}\.(?:sh|ps1|bat|cmd|exe|dll|so|dylib|py|zip|tar\.gz|whl)\b",
        attack=("T1105",), cwe=("CWE-494",),
    ),
    _rx(
        "AML.RX.IP_LITERAL_URL", "medium", "network", 6.3,
        "URL pointing directly at an IP literal instead of a hostname.",
        "Confirm the endpoint; IP-literal URLs evade domain reputation.",
        r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?/",
        attack=("T1071",), cwe=("CWE-1188",),
    ),
)

ALL_RULES: tuple[Rule, ...] = _LITERAL_RULES + _REGEX_RULES


# --------------------------------------------------------------------------
# Atom derivation for the prefiltered matcher
# --------------------------------------------------------------------------
def derive_atom(pattern: bytes) -> bytes:
    """Return a substring of ``pattern`` used as a cheap prefilter key.

    The atom is always a genuine substring, so stage-2 verification cannot
    produce a false negative.  Longer atoms are rarer, so the longest
    identifier-like token wins; otherwise the whole (short) pattern is used.
    """
    lowered = pattern.lower()
    candidates = _ATOM_TOKEN.findall(lowered)
    if candidates:
        best = max(candidates, key=len)
        if len(best) >= 4:
            return best
    return lowered


def rule_atoms(rule: Rule) -> tuple[tuple[bytes, bytes], ...]:
    """Return ``(atom, pattern)`` pairs for every literal signature."""
    pairs: list[tuple[bytes, bytes]] = []
    explicit = {atom.lower() for atom in rule.atoms}
    for pattern in rule.patterns:
        lowered = pattern.lower()
        chosen = b""
        for atom in explicit:
            if atom in lowered and len(atom) > len(chosen):
                chosen = atom
        if not chosen:
            chosen = derive_atom(pattern)
        pairs.append((chosen, lowered))
    return tuple(pairs)


# --------------------------------------------------------------------------
# Custom rule packs
# --------------------------------------------------------------------------
class RulePackError(ValueError):
    """A user supplied rule pack is malformed."""


def _decode_pattern(raw: str) -> bytes:
    """Decode a pack pattern.  ``hex:`` prefix allows non-printable bytes."""
    if raw.startswith("hex:"):
        return bytes.fromhex(raw[4:])
    return raw.encode("utf-8")


def load_pack(path: Path | str) -> tuple[Rule, ...]:
    """Load extra rules from a JSON pack.

    Schema::

        {"rules": [{"id": "ORG.RULE", "severity": "high", "category": "custom",
                    "cvss": 7.0, "description": "...", "remediation": "...",
                    "patterns": ["literal", "hex:deadbeef"], "regex": "..."}]}
    """
    source = Path(path).expanduser()
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RulePackError(f"cannot read rule pack {source}: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
        raise RulePackError("rule pack must be an object with a 'rules' array")

    loaded: list[Rule] = []
    for index, entry in enumerate(document["rules"]):
        if not isinstance(entry, dict):
            raise RulePackError(f"rule #{index} is not an object")
        rule_id = str(entry.get("id") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{3,80}", rule_id):
            raise RulePackError(f"rule #{index} has an invalid id: {rule_id!r}")
        severity = str(entry.get("severity", "medium")).lower()
        if severity not in SEVERITY_RANK:
            raise RulePackError(f"{rule_id}: severity must be one of {SEVERITIES}")
        patterns = tuple(_decode_pattern(str(p)) for p in entry.get("patterns", []))
        regex = str(entry.get("regex", ""))
        if not patterns and not regex:
            raise RulePackError(f"{rule_id}: needs at least one pattern or a regex")
        if regex:
            try:
                re.compile(regex)
            except re.error as error:
                raise RulePackError(f"{rule_id}: invalid regex: {error}") from error
        if any(not pattern for pattern in patterns):
            raise RulePackError(f"{rule_id}: empty pattern is not allowed")
        loaded.append(
            Rule(
                id=rule_id,
                severity=severity,
                category=str(entry.get("category", "custom")),
                cvss=float(entry.get("cvss", 5.0)),
                description=str(entry.get("description", "Custom rule match.")),
                remediation=str(entry.get("remediation", _REVIEW)),
                patterns=patterns,
                regex=regex,
                attack=tuple(str(v) for v in entry.get("attack", [])),
                cwe=tuple(str(v) for v in entry.get("cwe", [])),
                references=tuple(str(v) for v in entry.get("references", [])),
                contexts=tuple(entry.get("contexts", (CONTEXT_BYTES,) if patterns else (CONTEXT_STRING,))),
                confidence=str(entry.get("confidence", "medium")),
            )
        )
    return tuple(loaded)


def build_ruleset(packs: Iterable[Path | str] = ()) -> tuple[Rule, ...]:
    """Return the built-in catalogue extended with user packs (ids must be unique)."""
    rules = list(ALL_RULES)
    known = {rule.id for rule in rules}
    for pack in packs:
        for rule in load_pack(pack):
            if rule.id in known:
                raise RulePackError(f"duplicate rule id: {rule.id}")
            known.add(rule.id)
            rules.append(rule)
    return tuple(rules)


def inventory(rules: Iterable[Rule] = ALL_RULES) -> list[dict[str, Any]]:
    return [rule.to_dict() for rule in rules]


def signature_count(rules: Iterable[Rule] = ALL_RULES) -> int:
    return sum(len(rule.patterns) or 1 for rule in rules)
