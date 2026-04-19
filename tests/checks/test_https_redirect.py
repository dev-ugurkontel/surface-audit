"""Tests for https-redirect check."""

from __future__ import annotations

import httpx
import respx

from surface_audit.checks.base import CheckContext
from surface_audit.checks.https_redirect import HTTPSRedirectCheck
from surface_audit.client import HTTPClient
from surface_audit.models import ScanTarget
from surface_audit.scanner import ScannerConfig


async def _run_for_https(http_responder: respx.Route) -> list:
    target = ScanTarget.parse("https://example.com")
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        return await HTTPSRedirectCheck().run(ctx)


@respx.mock
async def test_flags_http_that_does_not_redirect() -> None:
    respx.get("http://example.com/").mock(return_value=httpx.Response(200, text="hi"))
    findings = await _run_for_https(None)  # type: ignore[arg-type]
    assert len(findings) == 1
    assert "does not redirect" in findings[0].title.lower()


@respx.mock
async def test_flags_http_redirect_to_non_https() -> None:
    respx.get("http://example.com/").mock(
        return_value=httpx.Response(301, headers={"Location": "http://other.example/"})
    )
    findings = await _run_for_https(None)  # type: ignore[arg-type]
    assert len(findings) == 1
    assert (
        "not upgrade" in findings[0].title.lower()
        or "not-https" in findings[0].title.lower()
        or "upgrade" in findings[0].title.lower()
    )


@respx.mock
async def test_accepts_http_to_https_redirect() -> None:
    respx.get("http://example.com/").mock(
        return_value=httpx.Response(301, headers={"Location": "https://example.com/"})
    )
    findings = await _run_for_https(None)  # type: ignore[arg-type]
    assert findings == []


async def test_skips_when_target_is_http() -> None:
    # No mocks needed — the check should short-circuit and never issue a request.
    target = ScanTarget.parse("http://example.com")
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await HTTPSRedirectCheck().run(ctx)
    assert findings == []


@respx.mock
async def test_custom_port_target_builds_http_url_with_port() -> None:
    target = ScanTarget.parse("https://example.com:8443/api")
    respx.get("http://example.com:8443/api").mock(return_value=httpx.Response(200))
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await HTTPSRedirectCheck().run(ctx)
    # HTTP on 8443 returning 200 → no redirect → finding emitted.
    assert len(findings) == 1
