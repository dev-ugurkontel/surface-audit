"""HTTP tests for security.txt presence check."""

from __future__ import annotations

import httpx
import respx

from surface_audit.checks.base import CheckContext
from surface_audit.checks.security_txt import SecurityTxtCheck
from surface_audit.client import HTTPClient
from surface_audit.models import ScanTarget
from surface_audit.scanner import ScannerConfig


@respx.mock
async def test_flags_missing_security_txt() -> None:
    target = ScanTarget.parse("https://example.com")
    respx.get("https://example.com/.well-known/security.txt").mock(return_value=httpx.Response(404))
    respx.get("https://example.com/security.txt").mock(return_value=httpx.Response(404))
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await SecurityTxtCheck().run(ctx)
    assert len(findings) == 1
    assert "security.txt" in findings[0].title.lower()


@respx.mock
async def test_silent_when_security_txt_exists() -> None:
    target = ScanTarget.parse("https://example.com")
    respx.get("https://example.com/.well-known/security.txt").mock(
        return_value=httpx.Response(
            200,
            text="Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n",
        )
    )
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await SecurityTxtCheck().run(ctx)
    assert findings == []
