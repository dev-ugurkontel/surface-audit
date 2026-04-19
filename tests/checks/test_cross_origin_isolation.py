"""Tests for the cross-origin isolation (COOP/COEP/CORP) check."""

from __future__ import annotations

import httpx
import respx

from surface_audit.checks.base import CheckContext
from surface_audit.checks.cross_origin_isolation import CrossOriginIsolationCheck
from surface_audit.client import HTTPClient
from surface_audit.models import ScanTarget, Severity
from surface_audit.scanner import ScannerConfig


async def _run(headers: dict[str, str]) -> list:
    target = ScanTarget.parse("https://example.com")
    respx.get("https://example.com/").mock(return_value=httpx.Response(200, headers=headers))
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        return await CrossOriginIsolationCheck().run(ctx)


@respx.mock
async def test_flags_all_three_headers_missing() -> None:
    findings = await _run({})
    assert len(findings) == 3
    titles = {f.title for f in findings}
    assert any("Opener-Policy" in t for t in titles)
    assert any("Embedder-Policy" in t for t in titles)
    assert any("Resource-Policy" in t for t in titles)
    assert all(f.severity is Severity.LOW for f in findings)


@respx.mock
async def test_accepts_fully_isolated_response() -> None:
    findings = await _run(
        {
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Resource-Policy": "same-origin",
        }
    )
    assert findings == []


@respx.mock
async def test_partial_coverage_flags_only_missing_one() -> None:
    findings = await _run(
        {
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
        }
    )
    assert len(findings) == 1
    assert "Resource-Policy" in findings[0].title
