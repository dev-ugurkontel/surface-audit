"""Tests for scanner orchestration."""

from __future__ import annotations

import pytest

from surface_audit.checks.base import Check, CheckContext
from surface_audit.exceptions import ConfigError
from surface_audit.models import Finding, FindingCategory, Severity
from surface_audit.scanner import Scanner, ScannerConfig


class _OKCheck(Check):
    check_id = "ok-check"
    description = "Always emits one finding."
    category = FindingCategory.A05_SECURITY_MISCONFIGURATION

    async def run(self, ctx: CheckContext) -> list[Finding]:
        return [
            Finding(
                check_id=self.check_id,
                title="ok",
                severity=Severity.LOW,
                description="ok",
                recommendation="ok",
                category=self.category,
            )
        ]


class _BoomCheck(Check):
    check_id = "boom-check"
    description = "Always raises."
    category = FindingCategory.A05_SECURITY_MISCONFIGURATION

    async def run(self, ctx: CheckContext) -> list[Finding]:
        raise RuntimeError("deliberate")


async def test_scanner_collects_findings_and_captures_errors() -> None:
    scanner = Scanner(
        "https://example.com",
        config=ScannerConfig(timeout=2.0, max_concurrency=2),
        checks=[_OKCheck(), _BoomCheck()],
    )
    report = await scanner.run()
    assert [f.check_id for f in report.findings] == ["ok-check"]
    assert len(report.errors) == 1
    assert "boom-check" in report.errors[0]


async def test_scanner_respects_disabled_filter() -> None:
    scanner = Scanner(
        "https://example.com",
        config=ScannerConfig(
            timeout=2.0,
            max_concurrency=2,
            disabled_checks=frozenset({"ok-check"}),
        ),
        checks=[_OKCheck()],
    )
    report = await scanner.run()
    assert report.findings == []


async def test_scanner_enabled_allowlist() -> None:
    scanner = Scanner(
        "https://example.com",
        config=ScannerConfig(
            timeout=2.0,
            max_concurrency=2,
            enabled_checks=frozenset({"ok-check"}),
        ),
        checks=[_OKCheck(), _BoomCheck()],
    )
    report = await scanner.run()
    assert len(report.findings) == 1
    assert report.errors == []


def test_scanner_rejects_unknown_enabled_check_id() -> None:
    """Typos in --enable must fail fast, not silently scan nothing."""
    with pytest.raises(ConfigError, match="unknown check id"):
        Scanner(
            "https://example.com",
            config=ScannerConfig(enabled_checks=frozenset({"typo-name"})),
            checks=[_OKCheck()],
        )


def test_scanner_rejects_unknown_disabled_check_id() -> None:
    with pytest.raises(ConfigError, match="unknown check id"):
        Scanner(
            "https://example.com",
            config=ScannerConfig(disabled_checks=frozenset({"typo-name"})),
            checks=[_OKCheck()],
        )


def test_discover_checks_returns_builtins_without_entry_points() -> None:
    checks = Scanner.discover_checks()
    ids = {c.check_id for c in checks}
    assert {"security-headers", "csrf", "ssl-tls"}.issubset(ids)


def test_scanner_checks_property_returns_immutable_copy() -> None:
    scanner = Scanner("https://example.com", checks=[_OKCheck()])
    view = scanner.checks
    assert [c.check_id for c in view] == ["ok-check"]
    # Mutating the returned list must not affect the scanner's internal state.
    view.clear()
    assert [c.check_id for c in scanner.checks] == ["ok-check"]
