"""Tests for misconfiguration check."""

from __future__ import annotations

import httpx
import respx

from surface_audit.checks.base import CheckContext
from surface_audit.checks.misconfiguration import MisconfigurationCheck
from surface_audit.client import HTTPClient
from surface_audit.models import ScanTarget, Severity
from surface_audit.scanner import ScannerConfig


def _all_other_paths_404() -> None:
    """Mock every sensitive path to 404 so only the one under test lights up."""
    for path in (
        "/.env",
        "/.git/config",
        "/.git/HEAD",
        "/.aws/credentials",
        "/admin",
        "/phpmyadmin/",
        "/server-status",
        "/actuator/env",
    ):
        respx.head(f"https://example.com{path}").mock(return_value=httpx.Response(404))


async def _run() -> list:
    target = ScanTarget.parse("https://example.com")
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        return await MisconfigurationCheck().run(ctx)


@respx.mock
async def test_flags_reachable_env_file() -> None:
    _all_other_paths_404()
    respx.head("https://example.com/.env").mock(return_value=httpx.Response(200))
    findings = await _run()
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert "reachable" in findings[0].title.lower()


@respx.mock
async def test_downgrades_gated_env_file() -> None:
    _all_other_paths_404()
    respx.head("https://example.com/.env").mock(return_value=httpx.Response(403))
    findings = await _run()
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert "denies access" in findings[0].title.lower()


@respx.mock
async def test_same_origin_redirect_is_not_flagged_as_exposure() -> None:
    _all_other_paths_404()
    # /admin → /admin/login on the same origin is ordinary routing.
    respx.head("https://example.com/admin").mock(
        return_value=httpx.Response(301, headers={"Location": "/admin/login"})
    )
    findings = await _run()
    assert findings == []


@respx.mock
async def test_cross_origin_redirect_is_still_flagged() -> None:
    _all_other_paths_404()
    respx.head("https://example.com/admin").mock(
        return_value=httpx.Response(302, headers={"Location": "https://evil.example/"})
    )
    findings = await _run()
    assert len(findings) == 1


@respx.mock
async def test_head_405_falls_back_to_get() -> None:
    _all_other_paths_404()
    respx.head("https://example.com/.env").mock(return_value=httpx.Response(405))
    respx.get("https://example.com/.env").mock(return_value=httpx.Response(200))
    findings = await _run()
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL


@respx.mock
async def test_redirect_without_location_header_is_flagged() -> None:
    _all_other_paths_404()
    respx.head("https://example.com/admin").mock(
        return_value=httpx.Response(301)  # no Location header
    )
    findings = await _run()
    assert len(findings) == 1


@respx.mock
async def test_cross_origin_absolute_redirect_is_flagged() -> None:
    _all_other_paths_404()
    respx.head("https://example.com/admin").mock(
        return_value=httpx.Response(302, headers={"Location": "https://other.example/"})
    )
    findings = await _run()
    assert len(findings) == 1


@respx.mock
async def test_same_origin_absolute_redirect_is_not_flagged() -> None:
    _all_other_paths_404()
    respx.head("https://example.com/admin").mock(
        return_value=httpx.Response(301, headers={"Location": "https://example.com/admin/"})
    )
    findings = await _run()
    assert findings == []


@respx.mock
async def test_status_404_is_ignored() -> None:
    _all_other_paths_404()  # every path → 404 → no findings
    findings = await _run()
    assert findings == []


async def test_status_helper_returns_none_when_get_fallback_errors() -> None:
    """Covers the GET-fallback network-error branch in _status()."""
    from unittest.mock import AsyncMock

    from surface_audit.checks.base import CheckContext
    from surface_audit.checks.misconfiguration import _status
    from surface_audit.client import HTTPClient
    from surface_audit.models import ScanTarget
    from surface_audit.scanner import ScannerConfig

    target = ScanTarget.parse("https://example.com")
    async with HTTPClient(timeout=1.0, max_concurrency=2) as client:
        client.head = AsyncMock(return_value=httpx.Response(405))  # type: ignore[method-assign]
        client.get = AsyncMock(side_effect=httpx.ConnectError("boom"))  # type: ignore[method-assign]
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        assert await _status(ctx, "https://example.com/x") is None


async def test_redirect_host_helper_returns_none_on_network_error() -> None:
    """Covers the NETWORK_ERRORS branch in _redirect_host()."""
    from unittest.mock import AsyncMock

    from surface_audit.checks.base import CheckContext
    from surface_audit.checks.misconfiguration import _redirect_host
    from surface_audit.client import HTTPClient
    from surface_audit.models import ScanTarget
    from surface_audit.scanner import ScannerConfig

    target = ScanTarget.parse("https://example.com")
    async with HTTPClient(timeout=1.0, max_concurrency=2) as client:
        client.head = AsyncMock(side_effect=httpx.ConnectError("boom"))  # type: ignore[method-assign]
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        assert await _redirect_host(ctx, "https://example.com/x") is None


async def test_redirect_host_helper_returns_none_when_no_location_header() -> None:
    """Covers the `if not location: return None` branch in _redirect_host()."""
    from unittest.mock import AsyncMock

    from surface_audit.checks.base import CheckContext
    from surface_audit.checks.misconfiguration import _redirect_host
    from surface_audit.client import HTTPClient
    from surface_audit.models import ScanTarget
    from surface_audit.scanner import ScannerConfig

    target = ScanTarget.parse("https://example.com")
    async with HTTPClient(timeout=1.0, max_concurrency=2) as client:
        client.head = AsyncMock(return_value=httpx.Response(301))  # type: ignore[method-assign]
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        assert await _redirect_host(ctx, "https://example.com/x") is None
