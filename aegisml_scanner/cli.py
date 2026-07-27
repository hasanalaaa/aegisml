"""Command-line interface for the offline AegisML scanner."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sys
from typing import Iterable, Sequence

from . import __version__
from . import report as reporting
from .parallel import available_jobs
from .rules import ALL_RULES, RULESET_VERSION, SEVERITY_RANK, build_ruleset, signature_count
from .scanner import (
    AegisML,
    DEFAULT_CHUNK_SIZE,
    DEFAULT_FULL_SIGNATURE_LIMIT,
    ENGINE_VERSION,
    ScanResult,
)


EXIT_OK = 0
EXIT_POLICY = 1
EXIT_OPERATIONAL = 2

_FORMATS = ("text", "summary", "json", "jsonl", "sarif", "markdown", "html")


def _size(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*(b|kib|kb|mib|mb|gib|gb|tib|tb)?\s*", value, re.I)
    if not match:
        raise argparse.ArgumentTypeError("use bytes or a suffix such as 64KiB, 8MiB, 1GiB")
    multiplier = {
        "b": 1, "kib": 1024, "kb": 1000, "mib": 1024**2, "mb": 1000**2,
        "gib": 1024**3, "gb": 1000**3, "tib": 1024**4, "tb": 1000**4,
    }[(match.group(2) or "b").lower()]
    result = int(match.group(1)) * multiplier
    if result <= 0:
        raise argparse.ArgumentTypeError("size must be positive")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegisml",
        description="Offline, no-execution security scanner for AI model artifacts",
        epilog="exit codes: 0 clean · 1 policy violation · 2 operational failure",
    )
    parser.add_argument("--version", action="version", version=f"AegisML {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="scan a file, directory or model repository")
    scan.add_argument("path", help="local file or directory (symlinks are never followed)")
    scan.add_argument("--format", choices=_FORMATS, default="text", help="report encoding")
    scan.add_argument("--output", "-o", type=Path, help="write the report to this path")
    scan.add_argument(
        "--fail-on", choices=("critical", "high", "medium", "low", "never"), default="critical",
        help="exit 1 when a finding meets this severity (default: critical)",
    )
    scan.add_argument(
        "--min-severity", choices=("critical", "high", "medium", "low", "info"), default="info",
        help="hide findings below this severity in the report",
    )
    scan.add_argument(
        "--signatures", choices=("auto", "full", "adaptive"), default="auto",
        help="full checks every byte against every signature; adaptive checks structural "
             "regions, nested payloads and every text-bearing block (default: auto by size)",
    )
    scan.add_argument(
        "--full-limit", type=_size, default=DEFAULT_FULL_SIGNATURE_LIMIT, metavar="SIZE",
        help="size below which auto selects the full tier (default: 2GiB)",
    )
    scan.add_argument(
        "--entropy", choices=("auto", "full", "off"), default="auto",
        help="auto samples the byte histogram per block; full counts every byte",
    )
    scan.add_argument(
        "--jobs", "-j", type=int, default=1, metavar="N",
        help=f"parallel worker processes (0 = all {available_jobs()} cores)",
    )
    scan.add_argument("--no-deep", action="store_true", help="do not recurse into nested payloads")
    scan.add_argument("--no-strings", action="store_true", help="disable string/regex analysis")
    scan.add_argument(
        "--tensor-stats", choices=("auto", "on", "off"), default="auto",
        help="value-level tensor forensics (NaN/Inf, text payloads, LSB channels)",
    )
    scan.add_argument("--rules", dest="rule_packs", action="append", default=[], metavar="PACK.json",
                      help="load an additional rule pack (repeatable)")
    scan.add_argument("--chunk-size", type=_size, default=DEFAULT_CHUNK_SIZE, metavar="SIZE",
                      help="bounded read size (default: 8MiB)")
    scan.add_argument("--max-offsets", type=int, default=32,
                      help="maximum byte offsets retained per rule (default: 32)")
    scan.add_argument("--include", action="append", default=[], metavar="GLOB",
                      help="only scan files matching this glob (repeatable)")
    scan.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                      help="skip files matching this glob (repeatable)")
    scan.add_argument("--progress", action="store_true", help="write progress to stderr")
    scan.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    scan.add_argument("--quiet", "-q", action="store_true", help="suppress diagnostics")

    serve = subcommands.add_parser("serve", help="run the local web interface (no network egress)")
    serve.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    serve.add_argument("--port", type=int, default=8765, help="bind port (default: 8765)")
    serve.add_argument("--root", type=Path, default=Path.cwd(),
                       help="directory the interface may browse and scan (default: cwd)")
    serve.add_argument("--open", action="store_true", help="print the URL and stay in foreground")

    verify = subcommands.add_parser("verify", help="create or check a SHA-256 artifact manifest")
    verify.add_argument("path", type=Path, help="file or directory")
    verify.add_argument("--manifest", "-m", type=Path, required=True, help="manifest file")
    verify.add_argument("--create", action="store_true", help="write the manifest instead of checking it")

    doctor = subcommands.add_parser("doctor", help="report offline readiness and optional extras")
    doctor.add_argument("--json", action="store_true", help="emit stable JSON")

    rules = subcommands.add_parser("rules", help="list the deterministic detection catalogue")
    rules.add_argument("--json", action="store_true", help="emit stable JSON")
    rules.add_argument("--severity", choices=("critical", "high", "medium", "low"))
    rules.add_argument("--category", help="filter by category substring")
    rules.add_argument("--rules", dest="rule_packs", action="append", default=[], metavar="PACK.json")

    explain = subcommands.add_parser("explain", help="show one rule in full")
    explain.add_argument("rule_id")

    version = subcommands.add_parser("version", help="show package, engine and rule-set versions")
    version.add_argument("--json", action="store_true", help="emit stable JSON")
    return parser


def _progress(scanned: int, total: int) -> None:
    percent = 100.0 if total == 0 else min(100.0, scanned / total * 100)
    bar = int(percent / 2.5)
    print(
        f"\r  [{'#' * bar}{'.' * (40 - bar)}] {percent:5.1f}%  {scanned:,}/{total:,} B",
        file=sys.stderr, end="",
    )
    if scanned >= total:
        print(file=sys.stderr)


def _error(message: str, *, machine: bool) -> int:
    if machine:
        print(json.dumps({"error": {"code": "scan_error", "message": message}}))
    else:
        print(f"aegisml: {message}", file=sys.stderr)
    return EXIT_OPERATIONAL


def _violates(results: Iterable[ScanResult], fail_on: str) -> bool:
    if fail_on == "never":
        return False
    threshold = SEVERITY_RANK[fail_on]
    return any(
        SEVERITY_RANK.get(threat.severity, 0) >= threshold
        for result in results for threat in result.threats
    )


def _selected(path: Path, include: Sequence[str], exclude: Sequence[str]) -> bool:
    name = path.as_posix()
    if include and not any(fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(path.name, pattern)
                           for pattern in include):
        return False
    if any(fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(path.name, pattern)
           for pattern in exclude):
        return False
    return True


def _engine(args) -> AegisML:
    return AegisML(
        api_url="",
        chunk_size=args.chunk_size,
        max_recorded_offsets=args.max_offsets,
        entropy_mode=args.entropy,
        progress=_progress if args.progress and not args.quiet else None,
        deep=not args.no_deep,
        strings=not args.no_strings,
        tensor_stats=args.tensor_stats,
        rule_packs=args.rule_packs,
        signatures=args.signatures,
        full_signature_limit=args.full_limit,
        jobs=args.jobs,
    )


def _scan_one(payload: tuple) -> dict:
    """Worker entry point for directory-level parallelism."""
    path, options = payload
    engine = AegisML(api_url="", **options)
    return engine.scan(path).to_dict()


def _collect(args) -> list[ScanResult]:
    target = Path(args.path).expanduser()
    engine = _engine(args)
    if target.is_file():
        return [engine.scan(target)]
    candidates = [
        item for item in sorted(target.rglob("*"))
        if item.is_file() and not item.is_symlink() and _selected(item, args.include, args.exclude)
    ]
    if not candidates:
        raise ValueError(f"no regular files matched under: {target}")
    if args.jobs > 1 and len(candidates) > 1:
        from concurrent.futures import ProcessPoolExecutor

        options = {
            "chunk_size": args.chunk_size,
            "max_recorded_offsets": args.max_offsets,
            "entropy_mode": args.entropy,
            "deep": not args.no_deep,
            "strings": not args.no_strings,
            "tensor_stats": args.tensor_stats,
            "rule_packs": args.rule_packs,
            "signatures": args.signatures,
            "full_signature_limit": args.full_limit,
        }
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            payloads = list(pool.map(_scan_one, [(item, options) for item in candidates]))
        return [_rehydrate(item) for item in payloads]
    return [engine.scan(item) for item in candidates]


def _rehydrate(payload: dict) -> ScanResult:
    from .scanner import Threat

    threats = [
        Threat(
            pattern=item.get("pattern", ""), severity=item.get("severity", "medium"),
            description=item.get("description", ""), category=item.get("category", ""),
            location=item.get("location", ""), id=item.get("id", "AML.GENERIC"),
            byte_offsets=item.get("byte_offsets", []), occurrences=item.get("occurrences", 1),
            cvss=float(item.get("cvss", 0.0)), remediation=item.get("remediation", ""),
            region=item.get("region", ""), evidence=item.get("evidence", []),
            attack=item.get("attack", []), cwe=item.get("cwe", []),
            references=item.get("references", []), confidence=item.get("confidence", "high"),
            source=item.get("source", ""),
        )
        for item in payload.get("threats", [])
    ]
    return ScanResult(
        scan_id=payload["scan_id"], filename=payload["filename"],
        risk_score=payload["risk_score"], risk_level=payload["risk_level"],
        threats=threats, metadata=payload.get("metadata", {}),
    )


def _doctor() -> dict:
    extras = {}
    for module in ("httpx", "anthropic"):
        try:
            __import__(module)
            extras[module] = True
        except ImportError:
            extras[module] = False
    return {
        "command": "aegisml",
        "distribution": "aegisml-scanner",
        "version": __version__,
        "engine_version": ENGINE_VERSION,
        "ruleset_version": RULESET_VERSION,
        "rules": len(ALL_RULES),
        "signatures": signature_count(ALL_RULES),
        "offline_ready": True,
        "network_required": False,
        "runtime_dependencies": 0,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpu_cores": available_jobs(),
        "optional_extras": {"remote": extras["httpx"], "ai": extras["anthropic"]},
        "exit_codes": {"ok": EXIT_OK, "policy": EXIT_POLICY, "operational": EXIT_OPERATIONAL},
    }


def _verify(args) -> int:
    root = args.path.expanduser()
    entries: dict[str, str] = {}
    targets = [root] if root.is_file() else [
        item for item in sorted(root.rglob("*")) if item.is_file() and not item.is_symlink()
    ]
    for item in targets:
        digest = hashlib.sha256()
        with item.open("rb") as stream:
            while True:
                block = stream.read(8 * 1024 * 1024)
                if not block:
                    break
                digest.update(block)
        key = item.name if root.is_file() else item.relative_to(root).as_posix()
        entries[key] = digest.hexdigest()
    if args.create:
        args.manifest.write_text(
            json.dumps({"algorithm": "sha256", "files": entries}, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {len(entries)} entries to {args.manifest}")
        return EXIT_OK
    try:
        document = json.loads(args.manifest.read_text(encoding="utf-8"))
        expected = document["files"]
    except (OSError, json.JSONDecodeError, KeyError) as error:
        return _error(f"cannot read manifest: {error}", machine=False)
    missing = sorted(set(expected) - set(entries))
    added = sorted(set(entries) - set(expected))
    changed = sorted(key for key in set(expected) & set(entries) if expected[key] != entries[key])
    for key in changed:
        print(f"CHANGED  {key}")
    for key in missing:
        print(f"MISSING  {key}")
    for key in added:
        print(f"ADDED    {key}")
    if changed or missing or added:
        print(f"\n{len(changed)} changed, {len(missing)} missing, {len(added)} added")
        return EXIT_POLICY
    print(f"verified {len(entries)} file(s); every digest matches")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    if args.command == "doctor":
        payload = _doctor()
        print(json.dumps(payload, indent=2) if args.json
              else "\n".join(f"{key}: {value}" for key, value in payload.items()))
        return EXIT_OK

    if args.command == "rules":
        try:
            ruleset = build_ruleset(args.rule_packs) if args.rule_packs else ALL_RULES
        except ValueError as error:
            return _error(str(error), machine=args.json)
        inventory = [rule.to_dict() for rule in ruleset]
        if args.severity:
            inventory = [rule for rule in inventory if rule["severity"] == args.severity]
        if args.category:
            inventory = [rule for rule in inventory if args.category in rule["category"]]
        if args.json:
            print(json.dumps(
                {"ruleset_version": RULESET_VERSION, "count": len(inventory), "rules": inventory},
                indent=2, ensure_ascii=False,
            ))
        else:
            for rule in inventory:
                signatures = len(rule["patterns"]) or ("regex" if rule["regex"] else 0)
                print(f"{rule['severity']:8} {rule['id']:38} cvss {rule['cvss']:4.1f}  "
                      f"{rule['category']:22} {signatures} sig")
            print(f"\n{len(inventory)} rule(s), {signature_count(ruleset)} signature(s), "
                  f"ruleset {RULESET_VERSION}")
        return EXIT_OK

    if args.command == "explain":
        for rule in ALL_RULES:
            if rule.id.lower() == args.rule_id.lower():
                print(json.dumps(rule.to_dict(), indent=2, ensure_ascii=False))
                return EXIT_OK
        return _error(f"unknown rule: {args.rule_id}", machine=False)

    if args.command == "version":
        payload = {
            "version": __version__,
            "engine_version": ENGINE_VERSION,
            "ruleset_version": RULESET_VERSION,
        }
        print(json.dumps(payload) if args.json
              else f"AegisML {__version__} (engine {ENGINE_VERSION}, rules {RULESET_VERSION})")
        return EXIT_OK

    if args.command == "verify":
        return _verify(args)

    if args.command == "serve":
        from .serve import serve

        return serve(host=args.host, port=args.port, root=args.root.expanduser().resolve())

    # scan
    machine = args.format in {"json", "jsonl", "sarif"}
    if args.max_offsets <= 0:
        return _error("--max-offsets must be positive", machine=machine)
    if args.jobs == 0:
        args.jobs = available_jobs()
    if args.jobs < 0:
        return _error("--jobs must not be negative", machine=machine)
    try:
        results = _collect(args)
    except (OSError, ValueError, RuntimeError) as error:
        return _error(str(error), machine=machine)

    if args.min_severity != "info":
        reporting.filter_threats(results, args.min_severity)
    colour = (
        not args.no_color and args.format == "text"
        and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    )
    body = reporting.render(results, args.format, colour=colour, tool_version=__version__)

    if args.output:
        try:
            args.output.expanduser().write_text(body + "\n", encoding="utf-8")
        except OSError as error:
            return _error(f"cannot write report: {error}", machine=machine)
        if not args.quiet:
            print(f"report: {args.output}", file=sys.stderr)
    else:
        print(body)

    if any(not result.coverage.get("complete") for result in results):
        if not args.quiet:
            print("aegisml: one or more required scan passes were incomplete; "
                  "no safety verdict was issued", file=sys.stderr)
        return EXIT_OPERATIONAL
    return EXIT_POLICY if _violates(results, args.fail_on) else EXIT_OK


if __name__ == "__main__":  # pragma: no cover - exercised via the package entry point
    raise SystemExit(main())
