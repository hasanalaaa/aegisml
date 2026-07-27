"""Repository-side artifacts: model configuration, Python source, notebooks.

A model repository is not only weights.  ``config.json`` decides whether the
loader imports repository Python (``auto_map`` / ``trust_remote_code``),
``tokenizer_config.json`` ships a template that the runtime renders, and the
``.py`` files next to the weights are executed verbatim by anyone who sets
``trust_remote_code=True``.

Python is analysed with :mod:`ast`, which parses without executing, so import
side effects never run.
"""

from __future__ import annotations

import ast
import json
import re
from typing import Any, Iterator

from .common import FormatReport, finding, printable


MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_FINDINGS_PER_FILE = 200

_DANGEROUS_CALLS = {
    "eval": ("critical", 9.4, "evaluates a runtime-built expression"),
    "exec": ("critical", 9.6, "executes a runtime-built statement"),
    "compile": ("high", 8.0, "compiles source at runtime"),
    "__import__": ("high", 8.2, "imports a module chosen at runtime"),
    "breakpoint": ("high", 8.0, "enters a debugger chosen by PYTHONBREAKPOINT"),
    "system": ("critical", 9.8, "runs an operating-system command"),
    "popen": ("critical", 9.6, "runs an operating-system command"),
    "check_output": ("critical", 9.4, "runs an operating-system command"),
    "check_call": ("critical", 9.4, "runs an operating-system command"),
    "Popen": ("critical", 9.6, "spawns a process"),
    "spawn": ("high", 8.4, "spawns a process"),
    "run_path": ("high", 8.6, "executes a Python file chosen at runtime"),
    "load_source": ("high", 8.6, "executes a Python file chosen at runtime"),
    "loads": ("medium", 6.5, "deserializes untrusted data"),
    "urlopen": ("high", 7.6, "performs a network request"),
    "urlretrieve": ("high", 8.0, "downloads a remote file"),
    "CDLL": ("critical", 9.2, "loads a native library"),
    "WinDLL": ("critical", 9.2, "loads a native library"),
    "rmtree": ("high", 7.8, "recursively deletes a directory"),
}

_DANGEROUS_MODULES = {
    "os": "medium", "subprocess": "high", "ctypes": "high", "socket": "high",
    "pty": "critical", "marshal": "high", "pickle": "medium", "dill": "high",
    "requests": "medium", "urllib": "medium", "shutil": "medium", "telnetlib": "high",
    "paramiko": "medium", "cryptography": "low", "base64": "low", "importlib": "medium",
}

_JINJA_DANGEROUS = re.compile(
    r"(__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__|"
    r"lipsum|cycler|joiner|namespace\s*\(|self\.__init__|\|\s*attr\s*\(|"
    r"\.popen|\.system\b|\bsubprocess\b)"
)

_REQUIREMENT_URL = re.compile(r"(?:git\+|https?://|file://)\S+", re.I)
_REQUIREMENT_OPTION = re.compile(r"^\s*--(index-url|extra-index-url|trusted-host|find-links|pre)\b", re.I | re.M)


def config_report(data: bytes, *, location: str) -> FormatReport:
    """Analyse a JSON (or JSON-like) model configuration document."""
    report = FormatReport(status="complete", format="config")
    try:
        document = json.loads(data.decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        report.status = "error"
        report.add(
            finding(
                "AML.CONFIG.INVALID", "medium", 4.0,
                f"Configuration is not valid JSON: {str(error)[:120]}.",
                category="format_anomaly", location=location,
                remediation="A malformed configuration cannot be reviewed; regenerate it.",
            )
        )
        return report
    if not isinstance(document, dict):
        return report

    auto_map = document.get("auto_map")
    if isinstance(auto_map, dict) and auto_map:
        targets = sorted({str(value) for value in auto_map.values()})
        report.add(
            finding(
                "AML.CONFIG.AUTO_MAP", "critical", 9.0,
                "Configuration declares auto_map, so loading this repository imports and runs "
                f"its own Python: {', '.join(printable(t, 60) for t in targets[:4])}.",
                category="supply_chain", location=location,
                remediation="Review every referenced module before setting trust_remote_code=True; "
                            "prefer a model with a native architecture in transformers.",
                attack=("AML.T0010",), cwe=("CWE-829",),
                evidence=[printable(json.dumps(auto_map)[:300])],
            )
        )
    for key in ("trust_remote_code", "allow_remote_code"):
        if document.get(key) is True:
            report.add(
                finding(
                    "AML.CONFIG.TRUST_REMOTE_CODE", "critical", 9.2,
                    f"Configuration sets {key}=true, which pre-authorises execution of "
                    "repository-supplied Python.",
                    category="supply_chain", location=location,
                    remediation="Remove the flag; the decision belongs to the operator, not the model.",
                    attack=("AML.T0010",), cwe=("CWE-829",),
                )
            )
    for key in ("chat_template", "default_chat_template"):
        template = document.get(key)
        if isinstance(template, str) and template:
            _inspect_template(report, template, location, key)
    templates = document.get("chat_template")
    if isinstance(templates, list):
        for entry in templates[:32]:
            if isinstance(entry, dict) and isinstance(entry.get("template"), str):
                _inspect_template(report, entry["template"], location, "chat_template[]")

    for key in ("custom_pipelines", "custom_object", "architectures"):
        value = document.get(key)
        if isinstance(value, dict) and value:
            report.add(
                finding(
                    "AML.CONFIG.CUSTOM_PIPELINE", "high", 8.0,
                    f"Configuration declares {key}, which resolves repository code at load time.",
                    category="supply_chain", location=location,
                    remediation="Audit the referenced implementation before use.",
                    cwe=("CWE-829",), confidence="medium",
                )
            )
    urls = [
        value for value in _iter_strings(document)
        if value.startswith(("http://", "https://", "ftp://")) and len(value) < 512
    ]
    suspicious = [url for url in urls if re.search(r"\.(sh|ps1|exe|dll|so|py|whl)(\?|$)", url)]
    if suspicious:
        report.add(
            finding(
                "AML.CONFIG.REMOTE_PAYLOAD", "high", 8.0,
                f"Configuration references downloadable code: "
                f"{', '.join(printable(u, 80) for u in suspicious[:3])}.",
                category="supply_chain", location=location,
                remediation="Fetch and review the resource offline before use.",
                attack=("T1105",), cwe=("CWE-494",),
            )
        )
    report.metadata = {"keys": sorted(document)[:64], "urls": len(urls)}
    return report


def _inspect_template(report: FormatReport, template: str, location: str, key: str) -> None:
    match = _JINJA_DANGEROUS.search(template)
    if match:
        report.add(
            finding(
                "AML.CONFIG.TEMPLATE_SSTI", "critical", 9.3,
                f"The {key} field contains Jinja attribute traversal "
                f"({printable(match.group(0), 40)}); the runtime renders this template, so the "
                "expression executes on the inference host.",
                category="injection", location=location,
                remediation="Replace the template with the publisher's official version.",
                attack=("AML.T0011",), cwe=("CWE-1336",),
                references=("CVE-2024-34359",),
                evidence=[printable(template[max(0, match.start() - 60): match.end() + 60], 200)],
            )
        )


def _iter_strings(node: Any, depth: int = 0) -> Iterator[str]:
    if depth > 32:
        return
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _iter_strings(value, depth + 1)
    elif isinstance(node, list):
        for value in node[:10_000]:
            yield from _iter_strings(value, depth + 1)


# ---------------------------------------------------------------------------
# Python source
# ---------------------------------------------------------------------------
def python_report(data: bytes, *, location: str) -> FormatReport:
    report = FormatReport(status="complete", format="python")
    if len(data) > MAX_SOURCE_BYTES:
        report.cap(f"source file is {len(data):,} bytes")
        return report
    try:
        tree = ast.parse(data.decode("utf-8", "replace"), filename=location or "<model>")
    except SyntaxError as error:
        report.status = "error"
        report.add(
            finding(
                "AML.PY.SYNTAX", "medium", 4.5,
                f"Python source does not parse: {str(error)[:120]}.",
                category="format_anomaly", location=location,
                remediation="Unparseable source in a model repository is suspicious in itself.",
            )
        )
        return report

    emitted = 0
    imports: set[str] = set()
    for node in ast.walk(tree):
        if emitted >= MAX_FINDINGS_PER_FILE:
            report.cap("too many findings in one source file")
            break
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imports.update(_import_names(node))
        elif isinstance(node, ast.Call):
            name = _call_name(node.func)
            classification = _DANGEROUS_CALLS.get(name)
            if classification:
                severity, cvss, why = classification
                report.add(
                    finding(
                        "AML.PY.DANGEROUS_CALL", severity, cvss,
                        f"{location or 'source'}:{getattr(node, 'lineno', 0)} calls "
                        f"{_render_call(node.func)}(), which {why}.",
                        category="code_execution", location=location,
                        remediation="Model repositories must not execute host commands.",
                        attack=("AML.T0011",), cwe=("CWE-94",),
                        evidence=[printable(_render_call(node.func), 120)],
                    )
                )
                emitted += 1
        elif isinstance(node, ast.Attribute) and node.attr in {"__globals__", "__subclasses__", "__mro__"}:
            report.add(
                finding(
                    "AML.PY.INTROSPECTION_GADGET", "high", 8.0,
                    f"{location or 'source'}:{getattr(node, 'lineno', 0)} uses {node.attr}, a "
                    "sandbox-escape gadget.",
                    category="evasion", location=location,
                    remediation="Remove the introspection chain.",
                    cwe=("CWE-470",),
                )
            )
            emitted += 1

    risky_imports = sorted(name for name in imports if name.split(".")[0] in _DANGEROUS_MODULES)
    if risky_imports:
        worst = max(
            (_DANGEROUS_MODULES[name.split(".")[0]] for name in risky_imports),
            key=lambda severity: ("low", "medium", "high", "critical").index(severity),
        )
        report.add(
            finding(
                "AML.PY.RISKY_IMPORT", worst,
                {"low": 3.0, "medium": 5.5, "high": 7.5, "critical": 9.0}[worst],
                f"Repository code imports host-facing module(s): {', '.join(risky_imports[:6])}.",
                category="supply_chain", location=location,
                remediation="Modelling code should need only tensor libraries.",
                cwe=("CWE-829",), confidence="medium",
            )
        )
    top_level = [
        node for node in tree.body
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
    ]
    if top_level:
        report.add(
            finding(
                "AML.PY.IMPORT_SIDE_EFFECT", "high", 7.8,
                f"{len(top_level)} statement(s) execute at import time (first at line "
                f"{getattr(top_level[0], 'lineno', 0)}); importing the module is enough to run them.",
                category="code_execution", location=location,
                remediation="Move executable statements behind a function or __main__ guard.",
                cwe=("CWE-94",),
            )
        )
    report.metadata = {"imports": sorted(imports)[:64], "statements": len(tree.body)}
    return report


def _import_names(node: ast.Import | ast.ImportFrom) -> Iterator[str]:
    if isinstance(node, ast.Import):
        for alias in node.names:
            yield alias.name
    elif node.module:
        yield node.module


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _render_call(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_render_call(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return f"{_render_call(node.func)}(...)"
    return "<expr>"


# ---------------------------------------------------------------------------
# Requirements & notebooks
# ---------------------------------------------------------------------------
def requirements_report(data: bytes, *, location: str) -> FormatReport:
    report = FormatReport(status="complete", format="requirements")
    text = data.decode("utf-8", "replace")
    urls = _REQUIREMENT_URL.findall(text)
    if urls:
        report.add(
            finding(
                "AML.REQ.DIRECT_URL", "high", 7.8,
                f"Dependency file installs from {len(urls)} direct URL(s), bypassing index "
                f"integrity: {', '.join(printable(u, 60) for u in urls[:3])}.",
                category="supply_chain", location=location,
                remediation="Pin dependencies to index releases with hashes.",
                attack=("T1195.002",), cwe=("CWE-494",),
            )
        )
    options = _REQUIREMENT_OPTION.findall(text)
    if options:
        report.add(
            finding(
                "AML.REQ.INDEX_OVERRIDE", "high", 7.6,
                f"Dependency file overrides package resolution ({', '.join(sorted(set(options))[:4])}), "
                "which enables dependency-confusion attacks.",
                category="supply_chain", location=location,
                remediation="Remove index overrides or pin them to an internal mirror you control.",
                attack=("T1195.002",), cwe=("CWE-494",),
            )
        )
    report.metadata = {"lines": text.count("\n") + 1, "direct_urls": len(urls)}
    return report


def notebook_report(data: bytes, *, location: str) -> FormatReport:
    report = FormatReport(status="complete", format="notebook")
    try:
        document = json.loads(data.decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        report.status = "error"
        return report
    cells = document.get("cells") if isinstance(document, dict) else None
    if not isinstance(cells, list):
        return report
    sources: list[str] = []
    for cell in cells[:5000]:
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        source = cell.get("source")
        if isinstance(source, list):
            sources.append("".join(str(line) for line in source))
        elif isinstance(source, str):
            sources.append(source)
    joined = "\n".join(sources)
    if not joined:
        return report
    if "!" in joined or "%" in joined:
        shell_lines = [line for line in joined.splitlines() if line.strip().startswith(("!", "%"))]
        if shell_lines:
            report.add(
                finding(
                    "AML.NOTEBOOK.SHELL_MAGIC", "high", 7.6,
                    f"Notebook runs {len(shell_lines)} shell/magic line(s), for example "
                    f"{printable(shell_lines[0], 80)!r}.",
                    category="code_execution", location=location,
                    remediation="Review every shell line before running the notebook.",
                    cwe=("CWE-78",),
                )
            )
    inner = python_report(joined.encode("utf-8"), location=f"{location}#code")
    report.findings.extend(inner.findings)
    report.metadata = {"code_cells": len(sources)}
    return report
