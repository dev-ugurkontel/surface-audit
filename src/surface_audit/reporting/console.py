"""Rich console rendering."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from surface_audit.models import ScanReport, Severity

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render_console(report: ScanReport, *, console: Console | None = None) -> None:
    """Pretty-print a scan report to the terminal."""
    out = console or Console()
    header = Text.assemble(
        ("surface-audit ", "bold"),
        (f"→ {report.target.url}\n", "cyan"),
        (f"duration: {report.duration_seconds:.2f}s  ", "dim"),
        (f"findings: {len(report.findings)}", "dim"),
    )
    out.print(Panel(header, border_style="cyan"))

    if not report.findings:
        out.print("[green]No findings.[/green]")
    else:
        table = Table(title="Findings", show_lines=True, expand=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Check", no_wrap=True)
        table.add_column("Title")
        table.add_column("Location", overflow="fold")
        for finding in sorted(
            report.findings, key=lambda f: (-f.severity.weight, f.check_id, f.title)
        ):
            table.add_row(
                Text(finding.severity.value, style=_SEVERITY_STYLES[finding.severity]),
                finding.check_id,
                finding.title,
                finding.location or "",
            )
        out.print(table)
        counts = report.severity_counts()
        summary_line = "  ".join(
            f"[{_SEVERITY_STYLES[s]}]{s.value}[/]: {counts[s]}"
            for s in (
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            )
        )
        out.print(Panel(summary_line, title="Summary", border_style="magenta"))

    if report.errors:
        out.print(Panel("\n".join(report.errors), title="Errors", border_style="red"))
