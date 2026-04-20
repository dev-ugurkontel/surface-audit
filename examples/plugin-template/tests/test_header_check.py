"""Tests for the example X-Powered-By plugin check."""

from __future__ import annotations

import httpx
import respx
from surface_audit_header_check.checks import PoweredByHeaderCheck

from surface_audit.checks.base import CheckContext
from surface_audit.client import HTTPClient
from surface_audit.models import ScanTarget
from surface_audit.scanner import ScannerConfig


@respx.mock
async def test_flags_x_powered_by_header() -> None:
    target = ScanTarget.parse("https://example.com")
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(200, headers={"X-Powered-By": "Express"})
    )

    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await PoweredByHeaderCheck().run(ctx)

    assert len(findings) == 1
    assert findings[0].check_id == "x-powered-by"
    assert "Express" in findings[0].evidence


@respx.mock
async def test_is_silent_when_header_is_absent() -> None:
    target = ScanTarget.parse("https://example.com")
    respx.get("https://example.com/").mock(return_value=httpx.Response(200))

    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await PoweredByHeaderCheck().run(ctx)

    assert findings == []
