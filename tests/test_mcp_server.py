"""Tests for the MCP server wrappers.

We exercise the scan/list tools directly rather than through FastMCP so
the test suite does not depend on the MCP wire protocol. FastMCP's
decorators preserve the underlying callables at ``tool.fn``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from surface_audit.mcp_server import build_app, build_policy, run
from surface_audit.models import ScanTarget
from surface_audit.scope import ScopeError, ScopePolicy


def test_policy_denies_when_no_allowlist_configured() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset(), allow_any=False)
    with pytest.raises(ScopeError, match="allow-list"):
        policy.enforce(ScanTarget.parse("https://example.com"))


def test_policy_denies_host_not_on_allowlist() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset({"ok.example"}), allow_any=False)
    with pytest.raises(ScopeError, match="not on the allow-list"):
        policy.enforce(ScanTarget.parse("https://evil.example"))


def test_policy_allows_host_on_allowlist_case_insensitive() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset({"ok.example"}), allow_any=False)
    policy.enforce(ScanTarget.parse("https://OK.example"))  # no raise


def test_policy_allows_any_host_when_escape_hatch_set() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset(), allow_any=True)
    policy.enforce(ScanTarget.parse("https://anywhere.example"))  # no raise


def test_build_policy_merges_env_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SURFACE_AUDIT_ALLOWED_HOSTS", "a.example, B.example ")
    policy = build_policy(frozenset({"c.example"}), allow_any=False)
    assert policy.allowed_hosts == frozenset({"a.example", "b.example", "c.example"})


async def test_scan_tool_rejects_invalid_url() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset(), allow_any=True)
    app = build_app(policy)
    scan_fn = _tool_fn(app, "scan")
    result = await scan_fn(url="ftp://example.com")
    assert result["reason"] == "invalid_target"


async def test_scan_tool_denies_out_of_scope_host() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset({"allowed.example"}), allow_any=False)
    app = build_app(policy)
    scan_fn = _tool_fn(app, "scan")
    result = await scan_fn(url="https://blocked.example")
    assert result["reason"] == "scope_denied"


async def test_scan_tool_returns_report_dict_on_success() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset({"example.com"}), allow_any=False)
    app = build_app(policy)
    scan_fn = _tool_fn(app, "scan")

    fake_report = MagicMock()
    fake_report.to_dict.return_value = {"summary": {"total": 0}}

    with patch(
        "surface_audit.mcp_server.Scanner",
        return_value=MagicMock(run=AsyncMock(return_value=fake_report)),
    ):
        result = await scan_fn(
            url="https://example.com",
            enabled_checks=["security-headers"],
            disabled_checks=["ssl-tls"],
        )
    assert result == {"summary": {"total": 0}}


async def test_scan_tool_returns_error_dict_on_scanner_exception() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset({"example.com"}), allow_any=False)
    app = build_app(policy)
    scan_fn = _tool_fn(app, "scan")

    from surface_audit.exceptions import ConfigError

    async def boom() -> None:
        raise ConfigError("bad")

    with patch(
        "surface_audit.mcp_server.Scanner",
        return_value=MagicMock(run=AsyncMock(side_effect=ConfigError("bad"))),
    ):
        result = await scan_fn(url="https://example.com")
    assert result == {"error": "bad", "reason": "ConfigError"}


async def test_list_checks_tool_returns_structured_catalog() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset(), allow_any=True)
    app = build_app(policy)
    list_fn = _tool_fn(app, "list_checks")
    items = await list_fn()
    assert isinstance(items, list)
    ids = {item["id"] for item in items}
    assert {"csrf", "ssl-tls", "cors"}.issubset(ids)


async def test_list_formats_tool_includes_builtins() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset(), allow_any=True)
    app = build_app(policy)
    list_fn = _tool_fn(app, "list_formats")
    formats = await list_fn()
    assert {"json", "html", "sarif", "markdown"}.issubset(set(formats))


async def test_render_report_tool_roundtrips_report() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset(), allow_any=True)
    app = build_app(policy)
    render_fn = _tool_fn(app, "render_report")

    report = {
        "target": {
            "url": "https://example.com/",
            "hostname": "example.com",
            "port": 443,
            "scheme": "https",
        },
        "findings": [
            {
                "check_id": "csrf",
                "title": "t",
                "severity": "MEDIUM",
                "description": "d",
                "recommendation": "r",
                "category": "A01:2021 - Broken Access Control",
                "location": "https://example.com/",
                "references": [],
            }
        ],
    }
    md = await render_fn(report=report, fmt="markdown")
    assert "surface-audit" in md
    assert "csrf" in md


async def test_render_report_tool_rejects_missing_target() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset(), allow_any=True)
    app = build_app(policy)
    render_fn = _tool_fn(app, "render_report")

    assert "malformed" in await render_fn(report={"target": "not-a-dict"}, fmt="json")
    assert "malformed" in await render_fn(report={"target": {}}, fmt="json")


async def test_render_report_tool_skips_bad_finding_entries() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset(), allow_any=True)
    app = build_app(policy)
    render_fn = _tool_fn(app, "render_report")

    out = await render_fn(
        report={
            "target": {
                "url": "https://example.com/",
                "hostname": "example.com",
                "port": 443,
                "scheme": "https",
            },
            "findings": [
                "not-a-dict",
                {"check_id": "x"},  # missing required keys
            ],
        },
        fmt="json",
    )
    # Missing keys are silently dropped; the rebuilt report has zero findings.
    import json as _json

    payload = _json.loads(out)
    assert payload["summary"]["total"] == 0


def test_run_delegates_to_fastmcp() -> None:
    """Smoke-test the CLI entry point without actually starting stdio."""
    fake_app = MagicMock()
    with patch("surface_audit.mcp_server.build_app", return_value=fake_app):
        run(allowed_hosts=frozenset({"example.com"}), allow_any_host=False)
    fake_app.run.assert_called_once_with()


async def test_render_report_tool_accepts_report_without_findings_key() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset(), allow_any=True)
    app = build_app(policy)
    render_fn = _tool_fn(app, "render_report")

    out = await render_fn(
        report={
            "target": {
                "url": "https://example.com/",
                "hostname": "example.com",
                "port": 443,
                "scheme": "https",
            },
            # findings key entirely absent → `report.get("findings") or []` path.
        },
        fmt="json",
    )
    import json as _json

    payload = _json.loads(out)
    assert payload["summary"]["total"] == 0


async def test_render_report_tool_handles_non_list_findings() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset(), allow_any=True)
    app = build_app(policy)
    render_fn = _tool_fn(app, "render_report")

    out = await render_fn(
        report={
            "target": {
                "url": "https://example.com/",
                "hostname": "example.com",
                "port": 443,
                "scheme": "https",
            },
            "findings": "not-a-list",  # covers the `isinstance(..., list)` branch
        },
        fmt="json",
    )
    import json as _json

    payload = _json.loads(out)
    assert payload["summary"]["total"] == 0


def _tool_fn(app: object, name: str):  # type: ignore[no-untyped-def]
    """Extract the raw async callable from a FastMCP-decorated tool."""
    # FastMCP>=1.12 exposes registered tools under ``_tool_manager._tools``
    # and each Tool stores the original function as ``.fn``.
    tools = app._tool_manager._tools  # type: ignore[attr-defined]
    return tools[name].fn
