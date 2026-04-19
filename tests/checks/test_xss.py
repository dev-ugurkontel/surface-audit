"""Tests for the reflected XSS check."""

from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import respx

from surface_audit.checks.base import CheckContext
from surface_audit.checks.xss import ReflectedXSSCheck
from surface_audit.client import HTTPClient
from surface_audit.models import ScanTarget
from surface_audit.scanner import ScannerConfig


async def _run(body_template: str, content_type: str = "text/html") -> list:
    target = ScanTarget.parse("https://example.com")

    def handler(request: httpx.Request) -> httpx.Response:
        params = parse_qs(request.url.query.decode())
        reflected = params.get("q", [""])[0]
        body = body_template.replace("__Q__", reflected)
        return httpx.Response(200, text=body, headers={"Content-Type": content_type})

    respx.get(url__regex=r"https://example.com/\?.*").mock(side_effect=handler)
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        return await ReflectedXSSCheck().run(ctx)


@respx.mock
async def test_flags_reflected_payload_in_html_response() -> None:
    findings = await _run("<html><body>__Q__</body></html>")
    assert len(findings) == 1


@respx.mock
async def test_skips_reflection_in_non_html_response() -> None:
    # Reflected input in a JSON response body cannot be rendered as HTML by a
    # browser, so it is not an XSS signal and the check must stay silent.
    findings = await _run('{"echo": "__Q__"}', content_type="application/json")
    assert findings == []


@respx.mock
async def test_skips_when_no_reflection() -> None:
    findings = await _run("<html><body>static</body></html>")
    assert findings == []
