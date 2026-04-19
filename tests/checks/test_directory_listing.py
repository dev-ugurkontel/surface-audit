"""Tests for directory-listing check."""

from __future__ import annotations

import httpx
import respx

from surface_audit.checks.base import CheckContext
from surface_audit.checks.directory_listing import DirectoryListingCheck
from surface_audit.client import HTTPClient
from surface_audit.models import ScanTarget
from surface_audit.scanner import ScannerConfig


async def _run(body: str) -> list:
    target = ScanTarget.parse("https://example.com")
    respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=body))
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        return await DirectoryListingCheck().run(ctx)


@respx.mock
async def test_flags_apache_style_index() -> None:
    findings = await _run("<html><title>Index of /</title></html>")
    assert len(findings) == 1


@respx.mock
async def test_flags_directory_listing_phrase() -> None:
    findings = await _run("<body>Directory listing for /public</body>")
    assert len(findings) == 1


@respx.mock
async def test_ignores_ordinary_content() -> None:
    findings = await _run("<html><body>Welcome home</body></html>")
    assert findings == []
