"""HTTP tests for the CORS check."""

from __future__ import annotations

import httpx
import respx

from surface_audit.checks.base import CheckContext
from surface_audit.checks.cors import CORSCheck
from surface_audit.client import HTTPClient
from surface_audit.models import ScanTarget, Severity
from surface_audit.scanner import ScannerConfig


@respx.mock
async def test_flags_wildcard_with_credentials() -> None:
    target = ScanTarget.parse("https://example.com")
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )
    )
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await CORSCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "wildcard" in findings[0].title.lower()


@respx.mock
async def test_flags_arbitrary_origin_reflection_with_credentials() -> None:
    target = ScanTarget.parse("https://example.com")

    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("Origin", "")
        return httpx.Response(
            200,
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            },
        )

    respx.get("https://example.com/").mock(side_effect=handler)
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await CORSCheck().run(ctx)
    assert len(findings) == 1
    assert "reflects" in findings[0].title.lower()


@respx.mock
async def test_no_finding_for_sane_config() -> None:
    target = ScanTarget.parse("https://example.com")
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            200,
            headers={"Access-Control-Allow-Origin": "https://trusted.example"},
        )
    )
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await CORSCheck().run(ctx)
    assert findings == []
