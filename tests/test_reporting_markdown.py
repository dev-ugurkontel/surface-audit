"""Tests for the Markdown renderer."""

from __future__ import annotations

from surface_audit.models import Finding, FindingCategory, ScanReport, Severity
from surface_audit.reporting.markdown import render_markdown


def test_renders_empty_report_with_ok_banner(report: ScanReport) -> None:
    md = render_markdown(report)
    assert md.startswith("## surface-audit —")
    assert "No findings" in md
    assert md.endswith("\n")


def test_renders_findings_with_table_and_details(report: ScanReport) -> None:
    report.add(
        Finding(
            check_id="auth-cookies",
            title="Cookie 'sid' missing hardening attributes",
            severity=Severity.HIGH,
            description="The cookie is set without Secure, HttpOnly.",
            recommendation="Set Secure and HttpOnly.",
            category=FindingCategory.A07_AUTH_FAILURES,
            location="https://example.com/",
            evidence="sid=<redacted>; Path=/",
        )
    )
    md = render_markdown(report)
    assert "| Severity | Check | Title | Location |" in md
    assert "auth-cookies" in md
    assert "Cookie 'sid' missing hardening attributes" in md
    assert "<details>" in md
    assert "**Fix:**" in md


def test_escapes_pipes_in_table_cells(report: ScanReport) -> None:
    report.add(
        Finding(
            check_id="x|y",
            title="Title with | pipe",
            severity=Severity.LOW,
            description="d",
            recommendation="r",
            category=FindingCategory.A05_SECURITY_MISCONFIGURATION,
            location="https://example.com/",
        )
    )
    md = render_markdown(report)
    # The escaped `\|` keeps the GitHub Markdown table structure intact.
    assert "x\\|y" in md
    assert "Title with \\| pipe" in md


def test_renderer_is_registered_under_markdown() -> None:
    from surface_audit.reporting import REGISTRY

    assert REGISTRY["markdown"] is render_markdown


def test_finding_without_location_or_evidence_is_rendered(report: ScanReport) -> None:
    report.add(
        Finding(
            check_id="x",
            title="T",
            severity=Severity.LOW,
            description="d",
            recommendation="r",
            category=FindingCategory.A05_SECURITY_MISCONFIGURATION,
        )
    )
    md = render_markdown(report)
    assert "Location:" not in md  # location block skipped when absent
    assert "Evidence:" not in md  # evidence block skipped when absent
    assert "**Fix:** r" in md
