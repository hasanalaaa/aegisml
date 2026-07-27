"""Report rendering: terminal, JSON, JSONL, SARIF, Markdown and standalone HTML."""

from __future__ import annotations

import html
import json
import time
from typing import Iterable, Sequence

from .rules import SEVERITY_RANK
from .scanner import ENGINE_VERSION, RULESET_VERSION, ScanResult, Threat


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_ANSI = {
    "critical": "\033[1;97;41m",
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[0;36m",
    "info": "\033[0;90m",
    "reset": "\033[0m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "ok": "\033[1;32m",
}


def _paint(text: str, key: str, colour: bool) -> str:
    if not colour:
        return text
    return f"{_ANSI.get(key, '')}{text}{_ANSI['reset']}"


def _size(value: int) -> str:
    step = 1024.0
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if amount < step or unit == "PiB":
            return f"{amount:,.1f} {unit}" if unit != "B" else f"{int(amount):,} B"
        amount /= step
    return f"{amount:.1f} PiB"


# ---------------------------------------------------------------------------
# Terminal
# ---------------------------------------------------------------------------
def render_text(result: ScanResult, *, colour: bool = False, limit: int = 40) -> str:
    metadata = result.metadata
    coverage = result.coverage
    verdict = result.verdict
    badge = {
        "SAFE": ("ok", "PASS"),
        "INCOMPLETE": ("medium", "INCOMPLETE"),
        "SUSPICIOUS": ("medium", "SUSPICIOUS"),
        "DANGEROUS": ("high", "DANGEROUS"),
        "CRITICAL": ("critical", "CRITICAL"),
    }[verdict]
    counts = result.counts()
    lines = [
        _paint(f" AegisML {ENGINE_VERSION} · rules {RULESET_VERSION} ", "dim", colour),
        f"{_paint(' ' + badge[1] + ' ', badge[0], colour)}  {result.filename}",
        "",
        f"  risk        {result.risk_score:.0f}/100 ({result.risk_level})",
        f"  format      {metadata.get('format_detected', 'unknown')}",
        f"  size        {_size(int(metadata.get('file_size', 0)))}"
        f"   read {_size(int(metadata.get('bytes_scanned', 0)))}"
        f" @ {metadata.get('throughput_mib_s', 0)} MiB/s",
        f"  sha256      {metadata.get('sha256', 'unavailable')}",
        f"  findings    "
        + "  ".join(
            f"{name}={counts.get(name, 0)}" for name in _SEVERITY_ORDER if counts.get(name)
        )
        or "  findings    none",
        f"  coverage    "
        + ", ".join(f"{key}={value}" for key, value in coverage.items() if key != "complete"),
        f"  scan id     {result.scan_id}",
    ]
    regions = metadata.get("regions") or {}
    if regions.get("count"):
        lines.append(
            f"  structure   {regions['count']} regions, {regions.get('tensors', 0)} tensors"
        )
    if metadata.get("errors"):
        lines.append(_paint(f"  errors      {', '.join(metadata['errors'])}", "high", colour))

    if result.threats:
        lines.append("")
        lines.append(_paint("  findings", "bold", colour))
        for threat in result.threats[:limit]:
            head = _paint(f"[{threat.severity.upper():8}]", threat.severity, colour)
            where = f" @{threat.byte_offsets[0]:,}" if threat.byte_offsets else ""
            inside = threat.region or (
                threat.location.split("!", 1)[1] if "!" in threat.location else ""
            )
            if inside:
                where += f" in {inside}"
            lines.append(f"  {head} {threat.id}{where}")
            lines.append(f"           {threat.description}")
            if threat.evidence:
                lines.append(_paint(f"           evidence: {threat.evidence[0][:150]}", "dim", colour))
            if threat.remediation:
                lines.append(_paint(f"           fix: {threat.remediation}", "dim", colour))
        if len(result.threats) > limit:
            lines.append(f"  ... {len(result.threats) - limit} more finding(s)")
    else:
        lines.append("")
        lines.append(_paint("  no findings", "ok", colour))
    return "\n".join(lines)


def render_summary(result: ScanResult) -> str:
    counts = result.counts()
    return (
        f"{result.verdict:10} {result.risk_score:5.1f}  "
        f"C{counts.get('critical', 0):<3} H{counts.get('high', 0):<3} "
        f"M{counts.get('medium', 0):<3} L{counts.get('low', 0):<3}  {result.filename}"
    )


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def render_sarif(results: Sequence[ScanResult], tool_version: str) -> dict:
    rules: dict[str, dict] = {}
    entries: list[dict] = []
    for result in results:
        for threat in result.threats:
            rules.setdefault(
                threat.id,
                {
                    "id": threat.id,
                    "name": threat.id.replace(".", ""),
                    "shortDescription": {"text": threat.description[:200]},
                    "fullDescription": {"text": threat.description},
                    "help": {"text": threat.remediation or "See the AegisML documentation."},
                    "properties": {
                        "security-severity": str(threat.cvss),
                        "tags": ["security", threat.category] + list(threat.cwe) + list(threat.attack),
                    },
                },
            )
            entries.append(
                {
                    "ruleId": threat.id,
                    "level": _SARIF_LEVEL.get(threat.severity, "warning"),
                    "message": {"text": threat.description},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": threat.location or result.filename},
                                **(
                                    {"region": {"byteOffset": threat.byte_offsets[0]}}
                                    if threat.byte_offsets
                                    else {}
                                ),
                            }
                        }
                    ],
                    "partialFingerprints": {
                        "aegisml/v1": f"{threat.id}:{threat.location}:{threat.byte_offsets[:1]}"
                    },
                    "properties": {
                        "occurrences": threat.occurrences,
                        "region": threat.region,
                        "confidence": threat.confidence,
                        "scanId": result.scan_id,
                        "evidence": threat.evidence[:2],
                    },
                }
            )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AegisML",
                        "version": tool_version,
                        "semanticVersion": tool_version,
                        "informationUri": "https://github.com/hasanalaaa/aegisml",
                        "rules": list(rules.values()),
                    }
                },
                "results": entries,
                "invocations": [{"executionSuccessful": True}],
            }
        ],
    }


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def render_markdown(results: Sequence[ScanResult]) -> str:
    lines = [
        "# AegisML scan report",
        "",
        f"- engine `{ENGINE_VERSION}` · ruleset `{RULESET_VERSION}`",
        f"- generated {time.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"- artifacts scanned: {len(results)}",
        "",
        "| artifact | verdict | risk | findings | sha256 |",
        "|---|---|---:|---:|---|",
    ]
    for result in results:
        lines.append(
            f"| `{result.filename}` | **{result.verdict}** | {result.risk_score:.0f} | "
            f"{len(result.threats)} | `{result.metadata.get('sha256', '')[:16]}…` |"
        )
    for result in results:
        if not result.threats:
            continue
        lines += ["", f"## {result.filename}", ""]
        for threat in result.threats:
            offsets = ", ".join(f"{value:,}" for value in threat.byte_offsets[:4])
            lines.append(f"### `{threat.id}` — {threat.severity.upper()} (CVSS {threat.cvss})")
            lines.append("")
            lines.append(threat.description)
            lines.append("")
            if threat.region:
                lines.append(f"- region: `{threat.region}`")
            if offsets:
                lines.append(f"- byte offsets: {offsets}")
            if threat.attack:
                lines.append(f"- technique: {', '.join(threat.attack)}")
            if threat.cwe:
                lines.append(f"- weakness: {', '.join(threat.cwe)}")
            if threat.references:
                lines.append(f"- references: {', '.join(threat.references)}")
            if threat.evidence:
                lines.append("")
                lines.append("```")
                lines.extend(item[:200] for item in threat.evidence[:3])
                lines.append("```")
            lines.append("")
            lines.append(f"**Remediation.** {threat.remediation}")
            lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML (single self-contained file)
# ---------------------------------------------------------------------------
_HTML_STYLE = """
:root{
  --bg:#07090f; --panel:#0e1320; --panel-2:#131a2b; --line:#1e2740;
  --ink:#e8ecf6; --muted:#8e9bb5; --accent:#5b8cff; --ok:#22c55e;
  --low:#38bdf8; --medium:#f59e0b; --high:#f97316; --critical:#ef4444;
  --mono:ui-monospace,'SF Mono',Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 20% -10%,#16203a 0%,var(--bg) 55%);
  color:var(--ink);font:15px/1.6 system-ui,-apple-system,'Segoe UI',sans-serif;padding:32px 20px 64px}
.wrap{max-width:1080px;margin:0 auto}
header{display:flex;flex-wrap:wrap;gap:16px;align-items:center;justify-content:space-between;
  padding-bottom:20px;border-bottom:1px solid var(--line);margin-bottom:28px}
h1{font-size:20px;margin:0;letter-spacing:-.02em}
h1 span{color:var(--muted);font-weight:400}
.meta{color:var(--muted);font-size:13px;font-family:var(--mono)}
.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));margin-bottom:28px}
.card{background:linear-gradient(180deg,var(--panel) 0%,var(--panel-2) 100%);
  border:1px solid var(--line);border-radius:14px;padding:16px 18px}
.card .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}
.card .v{font-size:22px;font-weight:650;margin-top:6px;letter-spacing:-.02em}
.verdict{display:inline-flex;align-items:center;gap:8px;border-radius:999px;padding:6px 14px;
  font-weight:700;font-size:13px;letter-spacing:.04em}
.v-SAFE{background:rgba(34,197,94,.14);color:var(--ok);border:1px solid rgba(34,197,94,.35)}
.v-INCOMPLETE{background:rgba(245,158,11,.12);color:var(--medium);border:1px solid rgba(245,158,11,.35)}
.v-SUSPICIOUS{background:rgba(245,158,11,.14);color:var(--medium);border:1px solid rgba(245,158,11,.4)}
.v-DANGEROUS{background:rgba(249,115,22,.16);color:var(--high);border:1px solid rgba(249,115,22,.4)}
.v-CRITICAL{background:rgba(239,68,68,.18);color:var(--critical);border:1px solid rgba(239,68,68,.45)}
table{width:100%;border-collapse:collapse;margin-bottom:28px;font-size:14px}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em;font-weight:600}
td.mono,.mono{font-family:var(--mono);font-size:12.5px}
.finding{border:1px solid var(--line);border-radius:14px;margin-bottom:14px;overflow:hidden;
  background:var(--panel)}
.finding>summary{cursor:pointer;padding:14px 18px;display:flex;gap:12px;align-items:center;
  list-style:none}
.finding>summary::-webkit-details-marker{display:none}
.finding[open]>summary{border-bottom:1px solid var(--line)}
.sev{font-family:var(--mono);font-size:11px;font-weight:700;padding:3px 8px;border-radius:6px;
  letter-spacing:.06em;flex:none}
.s-critical{background:rgba(239,68,68,.18);color:var(--critical)}
.s-high{background:rgba(249,115,22,.16);color:var(--high)}
.s-medium{background:rgba(245,158,11,.14);color:var(--medium)}
.s-low{background:rgba(56,189,248,.14);color:var(--low)}
.s-info{background:rgba(142,155,181,.12);color:var(--muted)}
.fid{font-family:var(--mono);font-size:13px;font-weight:600}
.fdesc{color:var(--muted);font-size:13px;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap}
.body{padding:16px 18px;display:grid;gap:12px}
.body p{margin:0}
.kv{display:grid;grid-template-columns:130px 1fr;gap:6px 14px;font-size:13px}
.kv dt{color:var(--muted)}
.kv dd{margin:0;font-family:var(--mono);font-size:12.5px;word-break:break-all}
pre{background:#080b13;border:1px solid var(--line);border-radius:10px;padding:12px;
  overflow:auto;font-family:var(--mono);font-size:12px;margin:0;color:#c9d4ee}
.fix{border-left:3px solid var(--accent);padding:8px 12px;background:rgba(91,140,255,.07);
  border-radius:0 8px 8px 0;font-size:13.5px}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:40px}
.bar{height:6px;border-radius:999px;background:#0b1020;overflow:hidden;margin-top:10px}
.bar i{display:block;height:100%;border-radius:999px}
@media print{body{background:#fff;color:#000}.card,.finding{break-inside:avoid}}
"""


def render_html(results: Sequence[ScanResult], *, title: str = "AegisML scan report") -> str:
    parts: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>{html.escape(title)}</title><style>{_HTML_STYLE}</style></head><body><div class='wrap'>",
        "<header><h1>AegisML <span>artifact security report</span></h1>",
        f"<div class='meta'>engine {ENGINE_VERSION} · ruleset {RULESET_VERSION} · "
        f"{time.strftime('%Y-%m-%d %H:%M')}</div></header>",
    ]
    worst = max(
        (result for result in results),
        key=lambda item: item.risk_score,
        default=None,
    )
    total = sum(len(result.threats) for result in results)
    critical = sum(
        1 for result in results for threat in result.threats if threat.severity == "critical"
    )
    parts.append("<div class='grid'>")
    parts.append(_card("artifacts", str(len(results))))
    parts.append(_card("findings", str(total)))
    parts.append(_card("critical", str(critical)))
    if worst is not None:
        parts.append(
            _card(
                "highest risk",
                f"{worst.risk_score:.0f}<div class='bar'><i style='width:{min(100, worst.risk_score):.0f}%;"
                f"background:{_risk_colour(worst.risk_score)}'></i></div>",
            )
        )
    parts.append("</div>")

    parts.append("<table><thead><tr><th>artifact</th><th>verdict</th><th>risk</th>"
                 "<th>format</th><th>size</th><th>sha256</th></tr></thead><tbody>")
    for result in results:
        metadata = result.metadata
        parts.append(
            "<tr>"
            f"<td class='mono'>{html.escape(result.filename)}</td>"
            f"<td><span class='verdict v-{result.verdict}'>{result.verdict}</span></td>"
            f"<td class='mono'>{result.risk_score:.0f}</td>"
            f"<td class='mono'>{html.escape(str(metadata.get('format_detected', '')))}</td>"
            f"<td class='mono'>{_size(int(metadata.get('file_size', 0)))}</td>"
            f"<td class='mono'>{html.escape(str(metadata.get('sha256', ''))[:24])}…</td>"
            "</tr>"
        )
    parts.append("</tbody></table>")

    for result in results:
        if not result.threats:
            continue
        parts.append(f"<h2 class='mono'>{html.escape(result.filename)}</h2>")
        for threat in result.threats:
            parts.append(_finding_html(threat))
    parts.append(
        "<footer>Deterministic static analysis. The artifact was never executed, imported, "
        "unpickled or extracted. No scanner can prove a model is free of behavioural "
        "backdoors.</footer>"
    )
    parts.append("</div></body></html>")
    return "".join(parts)


def _card(key: str, value: str) -> str:
    return f"<div class='card'><div class='k'>{html.escape(key)}</div><div class='v'>{value}</div></div>"


def _risk_colour(score: float) -> str:
    if score >= 85:
        return "var(--critical)"
    if score >= 60:
        return "var(--high)"
    if score >= 30:
        return "var(--medium)"
    return "var(--ok)"


def _finding_html(threat: Threat) -> str:
    rows = []
    if threat.location:
        rows.append(("location", threat.location))
    if threat.region:
        rows.append(("region", threat.region))
    if threat.byte_offsets:
        rows.append(("byte offsets", ", ".join(f"{value:,}" for value in threat.byte_offsets[:8])))
    rows.append(("occurrences", str(threat.occurrences)))
    rows.append(("category", threat.category))
    rows.append(("cvss", f"{threat.cvss}"))
    rows.append(("confidence", threat.confidence))
    if threat.attack:
        rows.append(("technique", ", ".join(threat.attack)))
    if threat.cwe:
        rows.append(("weakness", ", ".join(threat.cwe)))
    if threat.references:
        rows.append(("references", ", ".join(threat.references)))
    kv = "".join(
        f"<dt>{html.escape(key)}</dt><dd>{html.escape(value)}</dd>" for key, value in rows
    )
    evidence = ""
    if threat.evidence:
        joined = "\n".join(html.escape(item[:400]) for item in threat.evidence[:4])
        evidence = f"<pre>{joined}</pre>"
    return (
        f"<details class='finding' {'open' if threat.severity in ('critical', 'high') else ''}>"
        f"<summary><span class='sev s-{threat.severity}'>{threat.severity.upper()}</span>"
        f"<span class='fid'>{html.escape(threat.id)}</span>"
        f"<span class='fdesc'>{html.escape(threat.description[:160])}</span></summary>"
        f"<div class='body'><p>{html.escape(threat.description)}</p>"
        f"{evidence}<dl class='kv'>{kv}</dl>"
        f"<div class='fix'><strong>Remediation.</strong> {html.escape(threat.remediation)}</div>"
        "</div></details>"
    )


def render(results: Sequence[ScanResult], encoding: str, *, colour: bool = False,
           tool_version: str = ENGINE_VERSION) -> str:
    if encoding == "json":
        payload = results[0].to_dict() if len(results) == 1 else [r.to_dict() for r in results]
        return json.dumps(payload, ensure_ascii=False, indent=2)
    if encoding == "jsonl":
        return "\n".join(json.dumps(item.to_dict(), ensure_ascii=False) for item in results)
    if encoding == "sarif":
        return json.dumps(render_sarif(results, tool_version), ensure_ascii=False, indent=2)
    if encoding == "markdown":
        return render_markdown(results)
    if encoding == "html":
        return render_html(results)
    if encoding == "summary":
        return "\n".join(render_summary(item) for item in results)
    return "\n\n".join(render_text(item, colour=colour) for item in results)


def filter_threats(results: Iterable[ScanResult], minimum: str) -> None:
    """Drop findings below ``minimum`` severity, in place."""
    threshold = SEVERITY_RANK.get(minimum, 0)
    for result in results:
        result.threats = [
            threat for threat in result.threats
            if SEVERITY_RANK.get(threat.severity, 0) >= threshold
        ]
