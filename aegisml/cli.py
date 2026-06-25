"""AegisML Command-Line Interface.

Provides the ``aegisml`` CLI powered by Click and Rich.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aegisml import __version__
from aegisml.inspectors.base import InspectorResult
from aegisml.inspectors.gguf_inspector import GGUFInspector
from aegisml.inspectors.static_inspector import StaticInspector
from aegisml.inspectors.safetensors_inspector import SafeTensorsInspector

# Force UTF-8 on Windows to avoid cp1252 encoding errors with special chars
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

console = Console(force_terminal=True)

# ── Format -> Inspector mapping ──────────────────────────────────────
FORMAT_REGISTRY: dict[str, dict] = {
    ".gguf": {
        "inspector_cls": GGUFInspector,
        "label": "GGUF (GPT-Generated Unified Format)",
        "status": "[green]Supported[/green]",
        "risk_note": "[yellow]Medium[/yellow] -- metadata & templates can carry payloads",
    },
    ".pkl": {
        "inspector_cls": StaticInspector,
        "label": "Python Pickle",
        "status": "[green]Supported[/green]",
        "risk_note": "[red]High[/red] -- arbitrary code execution on deserialize",
    },
    ".pickle": {
        "inspector_cls": StaticInspector,
        "label": "Python Pickle",
        "status": "[green]Supported[/green]",
        "risk_note": "[red]High[/red] -- arbitrary code execution on deserialize",
    },
    ".pt": {
        "inspector_cls": StaticInspector,
        "label": "PyTorch Model (Pickle-based)",
        "status": "[green]Supported[/green]",
        "risk_note": "[red]High[/red] -- uses Pickle internally",
    },
    ".pth": {
        "inspector_cls": StaticInspector,
        "label": "PyTorch Checkpoint (Pickle-based)",
        "status": "[green]Supported[/green]",
        "risk_note": "[red]High[/red] -- uses Pickle internally",
    },
    ".safetensors": {
        "inspector_cls": SafeTensorsInspector,
        "label": "SafeTensors",
        "status": "[green]Supported[/green]",
        "risk_note": "[green]Low[/green] -- no code execution by design",
    },
}

# Severity -> (color, marker)
SEVERITY_STYLE: dict[str, tuple[str, str]] = {
    "clean":      ("green",       "[CLEAN]"),
    "suspicious": ("yellow",      "[WARN]"),
    "malicious":  ("dark_orange", "[ALERT]"),
    "critical":   ("red",         "[CRITICAL]"),
}


def _print_banner() -> None:
    """Print the AegisML welcome banner."""
    banner_text = Text()
    banner_text.append("AegisML", style="bold cyan")
    banner_text.append(f"  v{__version__}\n", style="dim")
    banner_text.append("AI Model Malware Inspector", style="italic white")

    console.print(
        Panel(
            banner_text,
            border_style="bright_cyan",
            padding=(1, 4),
            subtitle="[dim]Protecting AI from hidden threats[/dim]",
        )
    )
    console.print()


def _print_result(result: InspectorResult, file_path: str) -> None:
    """Render inspection results as a Rich table."""
    color, marker = SEVERITY_STYLE.get(result.severity, ("white", "[?]"))

    # ── Summary panel ────────────────────────────────────────────
    summary = Text()
    summary.append("File:     ", style="bold")
    summary.append(f"{file_path}\n")
    summary.append("Score:    ", style="bold")
    summary.append(f"{result.risk_score:.1f} / 100\n", style=f"bold {color}")
    summary.append("Severity: ", style="bold")
    summary.append(f"{marker}  {result.severity.upper()}", style=f"bold {color}")

    console.print(
        Panel(summary, title="[bold]Scan Result[/bold]", border_style=color)
    )

    # ── Findings table ───────────────────────────────────────────
    if not result.findings:
        console.print("[green]No findings -- model file appears clean.[/green]")
        return

    table = Table(
        title="Findings",
        show_lines=True,
        border_style="dim",
        header_style="bold magenta",
    )
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Type", style="cyan", min_width=18)
    table.add_column("Severity", justify="center", min_width=12)
    table.add_column("Detail", ratio=1)

    for idx, finding in enumerate(result.findings, start=1):
        f_color, f_marker = SEVERITY_STYLE.get(
            finding.get("severity", "clean"), ("white", "[?]")
        )
        table.add_row(
            str(idx),
            finding.get("type", "unknown"),
            f"[{f_color}]{f_marker}  {finding.get('severity', 'unknown').upper()}[/{f_color}]",
            finding.get("detail", ""),
        )

    console.print(table)


# ── CLI definition ───────────────────────────────────────────────

@click.group()
@click.version_option(version=__version__, prog_name="aegisml")
def cli() -> None:
    """AegisML -- AI Model Malware Inspector."""


@cli.command()
@click.argument("file_path", type=click.Path(exists=False))
def scan(file_path: str) -> None:
    """Scan an AI model file for malware and suspicious patterns.

    FILE_PATH is the path to the model file to inspect.
    """
    _print_banner()

    path = Path(file_path)

    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {file_path}")
        raise SystemExit(1)

    # Determine inspector based on file extension
    suffix = path.suffix.lower()
    fmt_entry = FORMAT_REGISTRY.get(suffix)

    if fmt_entry is not None:
        inspector_cls = fmt_entry["inspector_cls"]
        console.print(f"[dim]Inspecting {fmt_entry['label']} file...[/dim]\n")
        inspector = inspector_cls()
    else:
        supported = ", ".join(sorted(FORMAT_REGISTRY.keys()))
        console.print(
            f"[bold yellow]Warning:[/bold yellow] Unsupported file extension "
            f"'{suffix}'. Supported: {supported}\n"
            f"Attempting GGUF inspection as fallback.\n"
        )
        inspector = GGUFInspector()

    result = inspector.inspect(file_path)
    _print_result(result, file_path)

    # Exit with non-zero code if threats detected
    if result.severity in ("malicious", "critical"):
        raise SystemExit(2)


@cli.command("version")
def version_cmd() -> None:
    """Print the AegisML version."""
    _print_banner()


@cli.command("help-formats")
def help_formats() -> None:
    """Show a table of all supported model file formats."""
    _print_banner()

    table = Table(
        title="Supported Model Formats",
        show_lines=True,
        border_style="bright_cyan",
        header_style="bold magenta",
        title_style="bold cyan",
    )
    table.add_column("Extension", style="bold green", min_width=14)
    table.add_column("Format", style="white", min_width=30)
    table.add_column("Status", justify="center", min_width=14)
    table.add_column("Risk Level", min_width=30)

    for ext, info in FORMAT_REGISTRY.items():
        table.add_row(ext, info["label"], info["status"], info["risk_note"])

    console.print(table)
    console.print(
        "\n[dim]Use [bold]aegisml scan <file>[/bold] to inspect a model file.[/dim]"
    )


if __name__ == "__main__":
    cli()
