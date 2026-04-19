"""Tests for the open-redirect check."""

from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import respx

from surface_audit.checks.base import CheckContext
from surface_audit.checks.open_redirect import OpenRedirectCheck
from surface_audit.client import HTTPClient
from surface_audit.models import ScanTarget, Severity
from surface_audit.scanner import ScannerConfig

CANARY = "scanner-canary.invalid"


async def _run(handler) -> list:  # type: ignore[no-untyped-def]
    target = ScanTarget.parse("https://example.com")
    respx.get(url__regex=r"https://example\.com/.*").mock(side_effect=handler)
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        return await OpenRedirectCheck().run(ctx)


@respx.mock
async def test_flags_redirect_to_canary_host() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        params = parse_qs(request.url.query.decode())
        target_value = params.get("next", [""])[0]
        if CANARY in target_value:
            return httpx.Response(302, headers={"Location": target_value})
        return httpx.Response(200)

    findings = await _run(handler)
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "next" in findings[0].title


@respx.mock
async def test_does_not_flag_redirect_to_own_origin() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # Redirect every request back to the homepage — not an open redirect.
        return httpx.Response(302, headers={"Location": "https://example.com/"})

    findings = await _run(handler)
    assert findings == []


@respx.mock
async def test_does_not_flag_reflection_without_redirect() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # 200 response — reflecting the param into the body is not a redirect.
        return httpx.Response(200, text=request.url.query.decode())

    findings = await _run(handler)
    assert findings == []


@respx.mock
async def test_ignores_redirect_without_location_header() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302)  # no Location

    findings = await _run(handler)
    assert findings == []
