"""HTTP-level tests for SecurityHeadersCheck via respx mocking."""

from __future__ import annotations

import httpx
import respx

from surface_audit.checks.base import CheckContext
from surface_audit.checks.security_headers import SecurityHeadersCheck
from surface_audit.client import HTTPClient
from surface_audit.models import ScanTarget, Severity
from surface_audit.scanner import ScannerConfig


@respx.mock
async def test_flags_missing_headers_and_server_banner() -> None:
    target = ScanTarget.parse("https://example.com")
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(200, headers={"Server": "nginx/1.18.0"})
    )
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await SecurityHeadersCheck().run(ctx)

    titles = {f.title for f in findings}
    assert "Missing security header: Content-Security-Policy" in titles
    assert "Server banner disclosed" in titles
    severities = {f.severity for f in findings}
    assert Severity.HIGH in severities


@respx.mock
async def test_flags_short_hsts_max_age() -> None:
    target = ScanTarget.parse("https://example.com")
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=60",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            },
        )
    )
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await SecurityHeadersCheck().run(ctx)
    titles = {f.title for f in findings}
    assert "HSTS max-age below recommended threshold" in titles


@respx.mock
async def test_flags_hsts_without_max_age_parameter() -> None:
    target = ScanTarget.parse("https://example.com")
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "includeSubDomains",  # no max-age at all
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            },
        )
    )
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await SecurityHeadersCheck().run(ctx)
    titles = {f.title for f in findings}
    assert "HSTS max-age below recommended threshold" in titles


@respx.mock
async def test_flags_unsafe_inline_in_csp() -> None:
    target = ScanTarget.parse("https://example.com")
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                "Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            },
        )
    )
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await SecurityHeadersCheck().run(ctx)
    titles = {f.title for f in findings}
    assert any("CSP contains" in t for t in titles)


@respx.mock
async def test_flags_x_content_type_options_wrong_value() -> None:
    target = ScanTarget.parse("https://example.com")
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "something-else",  # should be 'nosniff'
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            },
        )
    )
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await SecurityHeadersCheck().run(ctx)
    titles = {f.title for f in findings}
    assert "X-Content-Type-Options is not 'nosniff'" in titles


@respx.mock
async def test_no_findings_when_all_headers_present() -> None:
    target = ScanTarget.parse("https://example.com")
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            },
        )
    )
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await SecurityHeadersCheck().run(ctx)
    assert findings == []
