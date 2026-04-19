"""Tests for Scanner's entry-point plugin loading behavior."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from surface_audit.checks.base import Check, CheckContext
from surface_audit.exceptions import CheckRegistrationError
from surface_audit.models import Finding, FindingCategory, Severity
from surface_audit.scanner import Scanner


class _PluginA(Check):
    check_id = "plugin-a"
    description = "Plugin A."
    category = FindingCategory.A05_SECURITY_MISCONFIGURATION

    async def run(self, ctx: CheckContext) -> list[Finding]:  # pragma: no cover
        return [
            Finding(
                check_id=self.check_id,
                title="a",
                severity=Severity.LOW,
                description="d",
                recommendation="r",
                category=self.category,
            )
        ]


class _PluginADup(_PluginA):
    """Different class, same check_id — triggers CheckRegistrationError."""


class _NotACheck:
    """Duck-typed object that doesn't subclass Check."""

    check_id = "not-a-check"


def _fake_ep(name: str, loaded: object, *, raises: BaseException | None = None) -> MagicMock:
    ep = MagicMock()
    ep.name = name
    if raises is not None:
        ep.load.side_effect = raises
    else:
        ep.load.return_value = loaded
    return ep


def test_plugin_with_duplicate_check_id_raises() -> None:
    with (
        patch(
            "surface_audit.scanner.entry_points",
            return_value=[_fake_ep("a", _PluginA), _fake_ep("a2", _PluginADup)],
        ),
        pytest.raises(CheckRegistrationError, match="duplicate"),
    ):
        Scanner.discover_checks()


def test_plugin_loading_continues_after_one_fails() -> None:
    with patch(
        "surface_audit.scanner.entry_points",
        return_value=[
            _fake_ep("bad", None, raises=RuntimeError("boom")),
            _fake_ep("good", _PluginA),
        ],
    ):
        checks = Scanner.discover_checks()
    assert {c.check_id for c in checks} == {"plugin-a"}


def test_plugin_that_is_not_a_check_is_skipped() -> None:
    with patch(
        "surface_audit.scanner.entry_points",
        return_value=[_fake_ep("fake", _NotACheck)],
    ):
        checks = Scanner.discover_checks()
    # No valid plugin → built-in fallback fires.
    assert all(c.check_id != "not-a-check" for c in checks)
    assert len(checks) > 0


def test_discover_falls_back_to_builtins_when_no_entry_points() -> None:
    with patch("surface_audit.scanner.entry_points", return_value=[]):
        checks = Scanner.discover_checks()
    ids = {c.check_id for c in checks}
    assert {"csrf", "ssl-tls", "cors"}.issubset(ids)
