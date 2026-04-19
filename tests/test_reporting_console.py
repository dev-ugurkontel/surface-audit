"""Direct tests for the Rich console renderer."""

from __future__ import annotations

import io

from rich.console import Console

from surface_audit.models import Finding, FindingCategory, ScanReport, Severity
from surface_audit.reporting.console import render_console


def _buf() -> Console:
    return Console(file=io.StringIO(), width=120, force_terminal=False, record=True)


def test_empty_report_prints_no_findings_line(report: ScanReport) -> None:
    console = _buf()
    render_console(report, console=console)
    text = console.export_text()
    assert "No findings" in text


def test_report_with_findings_prints_table_and_summary(report: ScanReport) -> None:
    report.add(
        Finding(
            check_id="security-headers",
            title="Missing CSP",
            severity=Severity.HIGH,
            description="d",
            recommendation="r",
            category=FindingCategory.A05_SECURITY_MISCONFIGURATION,
            location="https://example.com/",
        )
    )
    console = _buf()
    render_console(report, console=console)
    text = console.export_text()
    assert "Missing CSP" in text
    assert "HIGH" in text
    assert "Summary" in text


def test_report_with_errors_prints_error_panel(report: ScanReport) -> None:
    report.record_error("check 'x' blew up")
    console = _buf()
    render_console(report, console=console)
    text = console.export_text()
    assert "check 'x' blew up" in text


def test_render_console_works_without_explicit_console(report: ScanReport, capsys) -> None:  # type: ignore[no-untyped-def]
    # Covers the `out = console or Console()` default branch.
    render_console(report)
    captured = capsys.readouterr()
    assert captured.out  # something was printed
