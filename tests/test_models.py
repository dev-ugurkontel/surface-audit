"""Tests for domain models."""

from __future__ import annotations

import pytest

from surface_audit.models import Finding, FindingCategory, ScanReport, ScanTarget, Severity


def test_scan_target_normalizes_missing_scheme() -> None:
    target = ScanTarget.parse("example.com")
    assert target.url == "https://example.com/"
    assert target.scheme == "https"
    assert target.port == 443


def test_scan_target_respects_explicit_port() -> None:
    target = ScanTarget.parse("http://example.com:8080/api")
    assert target.port == 8080
    assert target.scheme == "http"


def test_scan_target_rejects_empty_url() -> None:
    with pytest.raises(ValueError):
        ScanTarget.parse("   ")


@pytest.mark.parametrize(
    "raw",
    [
        "ftp://example.com",
        "file:///etc/passwd",
        "gopher://example.com",
        "mailto:test@example.com",
        "javascript:alert(1)",
    ],
)
def test_scan_target_rejects_unsupported_schemes(raw: str) -> None:
    """Any non-http(s) input must be rejected, regardless of whether the
    rejection happens on scheme check, userinfo check, or port parsing."""
    with pytest.raises(ValueError):
        ScanTarget.parse(raw)


def test_scan_target_rejects_userinfo() -> None:
    """Credentials embedded in the target URL must be rejected, never flow into reports."""
    with pytest.raises(ValueError, match="credentials"):
        ScanTarget.parse("https://user:pass@example.com/")


def test_scan_target_preserves_ipv6() -> None:
    target = ScanTarget.parse("https://[::1]:8080/api")
    assert target.hostname == "::1"
    assert target.port == 8080
    assert "[::1]" in target.url


def test_scan_target_strips_default_port_in_canonical_url() -> None:
    target = ScanTarget.parse("https://example.com:443/")
    assert target.url == "https://example.com/"


def test_scan_target_rejects_non_string_input() -> None:
    with pytest.raises(ValueError, match="string"):
        ScanTarget.parse(123)  # type: ignore[arg-type]


def test_scan_target_rejects_invalid_port() -> None:
    with pytest.raises(ValueError, match="invalid"):
        # urlparse flags ``:abc`` as an invalid port value.
        ScanTarget.parse("https://example.com:abc/")


def test_scan_target_rejects_malformed_ipv6() -> None:
    with pytest.raises(ValueError):
        ScanTarget.parse("https://[::1")


def test_scan_target_rejects_empty_hostname() -> None:
    with pytest.raises(ValueError):
        ScanTarget.parse("https:///path")


def test_empty_report_has_no_max_severity(report: ScanReport) -> None:
    assert report.max_severity() is None
    payload = report.to_dict()
    assert payload["summary"]["max_severity"] is None
    assert payload["finished_at"] is None
    assert payload["duration_seconds"] == 0.0


def test_scan_target_preserves_query_string() -> None:
    target = ScanTarget.parse("https://example.com/search?q=hello&page=2")
    assert target.url == "https://example.com/search?q=hello&page=2"


def test_severity_weight_ordering() -> None:
    ordered = sorted(Severity, key=lambda s: s.weight)
    assert ordered == [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]


def test_report_summary_and_serialization(report: ScanReport) -> None:
    report.add(
        Finding(
            check_id="x",
            title="X",
            severity=Severity.HIGH,
            description="d",
            recommendation="r",
            category=FindingCategory.A03_INJECTION,
        )
    )
    report.add(
        Finding(
            check_id="y",
            title="Y",
            severity=Severity.LOW,
            description="d",
            recommendation="r",
            category=FindingCategory.A05_SECURITY_MISCONFIGURATION,
        )
    )
    assert report.max_severity() is Severity.HIGH
    counts = report.severity_counts()
    assert counts[Severity.HIGH] == 1
    assert counts[Severity.LOW] == 1

    payload = report.to_dict()
    assert payload["summary"]["total"] == 2
    assert payload["summary"]["max_severity"] == "HIGH"
    assert {f["check_id"] for f in payload["findings"]} == {"x", "y"}
