"""Tests for report renderers and the renderer registry."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from surface_audit.exceptions import RendererError
from surface_audit.models import Finding, FindingCategory, ScanReport, Severity
from surface_audit.reporting import REGISTRY, register, render, write
from surface_audit.reporting.html import render_html
from surface_audit.reporting.json import render_json
from surface_audit.reporting.sarif import render_sarif

if TYPE_CHECKING:
    from pathlib import Path


def _populate(report: ScanReport) -> None:
    report.add(
        Finding(
            check_id="security-headers",
            title="Missing CSP",
            severity=Severity.HIGH,
            description="Content-Security-Policy is absent.",
            recommendation="Add a CSP header.",
            category=FindingCategory.A05_SECURITY_MISCONFIGURATION,
            location="https://example.com/",
            references=("https://example.com/docs",),
        )
    )


def test_json_round_trips(report: ScanReport) -> None:
    _populate(report)
    payload = json.loads(render_json(report))
    assert payload["findings"][0]["check_id"] == "security-headers"
    assert payload["summary"]["by_severity"]["HIGH"] == 1


def test_sarif_is_valid_json_and_has_rule(report: ScanReport) -> None:
    _populate(report)
    payload = json.loads(render_sarif(report))
    assert payload["version"] == "2.1.0"
    rules = payload["runs"][0]["tool"]["driver"]["rules"]
    assert rules[0]["id"].endswith("/security-headers")
    assert payload["runs"][0]["results"][0]["level"] == "error"


def test_html_escapes_content(report: ScanReport) -> None:
    report.add(
        Finding(
            check_id="xss-reflection",
            title="<script>alert(1)</script>",
            severity=Severity.MEDIUM,
            description="reflected",
            recommendation="encode",
            category=FindingCategory.A03_INJECTION,
        )
    )
    html = render_html(report)
    assert "&lt;script&gt;" in html
    assert "<script>alert" not in html


def test_write_creates_parent_directories(report: ScanReport, tmp_path: Path) -> None:
    _populate(report)
    destination = tmp_path / "nested" / "out.json"
    write(report, destination, "json")
    assert destination.is_file()
    assert json.loads(destination.read_text(encoding="utf-8"))["target"]["scheme"] == "https"


def test_registry_lookup(report: ScanReport) -> None:
    _populate(report)
    for fmt in ("json", "html", "sarif"):
        assert fmt in REGISTRY
        assert render(report, fmt)


def test_unknown_format_raises(report: ScanReport) -> None:
    with pytest.raises(RendererError):
        render(report, "nope")


def test_register_rejects_conflict() -> None:
    def fake(report: ScanReport) -> str:
        return ""

    register("custom-test", fake)
    with pytest.raises(RendererError):
        register("custom-test", lambda r: "other")
