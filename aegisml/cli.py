#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from typing import List
from .scanner import AegisML, ScanResult


def format_result(result: ScanResult) -> str:
    score = result.risk_score
    icon = "✅" if score < 30 else "⚠️" if score < 60 else "🚨"
    lines = [f"\n{icon} AegisML Security Report", "=" * 50,
             f"File:        {result.filename}", f"Risk Score:  {score:.0f}/100",
             f"Risk Level:  {result.risk_level.upper()}", f"Verdict:     {result.verdict}",
             f"Threats:     {len(result.threats)}", f"Scan ID:     {result.scan_id}"]
    if result.threats:
        lines.append("\nThreats Detected:")
        for t in result.threats:
            lines.append(f"  [{t.severity.upper()}] {t.pattern}: {t.description}")
    if result.ai_analysis:
        ai = result.ai_analysis
        lines += ["\nClaude AI Analysis:",
                  f"  Verdict:    {ai.get('verdict', 'N/A')}",
                  f"  Confidence: {ai.get('confidence', 0)}%",
                  f"  Summary:    {ai.get('summary_en', 'N/A')}"]
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(prog="aegisml", description="AegisML — AI Model Security Scanner")
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan a model file or directory")
    scan_p.add_argument("path", help="Path to model file or directory")
    scan_p.add_argument("--format", choices=["text", "json", "summary"], default="text")
    scan_p.add_argument("--output", "-o", help="Output file path")
    scan_p.add_argument("--api-url", help="AegisML API URL")
    scan_p.add_argument("--api-key", help="AegisML API key")
    scan_p.add_argument("--anthropic-key", help="Anthropic API key")
    scan_p.add_argument("--fail-on-critical", action="store_true", default=True)
    scan_p.add_argument("--fail-on-dangerous", action="store_true", default=False)
    scan_p.add_argument("--quiet", "-q", action="store_true")

    sub.add_parser("version", help="Show version")

    args = parser.parse_args()

    if args.command == "version":
        from aegisml import __version__
        print(f"AegisML v{__version__}")
        return

    if args.command != "scan":
        parser.print_help()
        return

    scanner = AegisML(
        api_url=getattr(args, "api_url", None),
        api_key=getattr(args, "api_key", None),
        anthropic_api_key=getattr(args, "anthropic_key", None),
    )

    path = Path(args.path)
    results: List[ScanResult] = []

    if path.is_dir():
        if not args.quiet: print(f"🔍 Scanning directory: {path}")
        results = scanner.scan_directory(path)
    else:
        if not args.quiet: print(f"🔍 Scanning: {path.name}")
        results = [scanner.scan(path)]

    if args.format == "json":
        output = (json.dumps([r.to_dict() for r in results], ensure_ascii=False, indent=2)
                  if len(results) > 1 else results[0].to_json())
    elif args.format == "summary":
        lines = []
        for r in results:
            icon = "✅" if r.risk_score < 30 else "⚠️" if r.risk_score < 60 else "🚨"
            lines.append(f"{icon} {r.filename}: {r.risk_score:.0f}/100 ({r.risk_level}) — {len(r.threats)} threats")
        output = "\n".join(lines)
    else:
        output = "\n".join(format_result(r) for r in results)

    if getattr(args, "output", None):
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        if not args.quiet: print(f"✅ Results saved to: {args.output}")
    else:
        print(output)

    exit_code = 0
    for r in results:
        if args.fail_on_critical and r.risk_level == "critical": exit_code = 1
        if args.fail_on_dangerous and r.risk_level in ["malicious", "critical"]: exit_code = 1
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
