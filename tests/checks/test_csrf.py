"""Tests for the CSRF check."""

from __future__ import annotations

import httpx
import respx

from surface_audit.checks.base import CheckContext
from surface_audit.checks.csrf import CSRFCheck
from surface_audit.client import HTTPClient
from surface_audit.models import ScanTarget
from surface_audit.scanner import ScannerConfig


async def _run(html: str) -> list:
    target = ScanTarget.parse("https://example.com")
    respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        return await CSRFCheck().run(ctx)


@respx.mock
async def test_flags_post_form_without_token() -> None:
    findings = await _run('<form method="post"><input name="x"></form>')
    assert len(findings) == 1
    assert "POST" in findings[0].title


@respx.mock
async def test_flags_post_form_with_uppercase_method() -> None:
    findings = await _run("<form method='POST' action='/a'><input></form>")
    assert len(findings) == 1


@respx.mock
async def test_flags_post_form_with_trailing_attribute() -> None:
    findings = await _run('<form action="/x" method="post" class="y"><input></form>')
    assert len(findings) == 1


@respx.mock
async def test_skips_form_without_method_attribute() -> None:
    # Default form method is GET per HTML spec.
    findings = await _run("<form><button>go</button></form>")
    assert findings == []


@respx.mock
async def test_skips_get_form() -> None:
    findings = await _run('<form method="get"><input></form>')
    assert findings == []


@respx.mock
async def test_accepts_form_with_csrf_token() -> None:
    findings = await _run('<form method="post"><input name="csrf_token" value="abc"><input></form>')
    assert findings == []


@respx.mock
async def test_accepts_form_with_authenticity_token() -> None:
    findings = await _run(
        '<form method="post"><input name="authenticity_token" value="abc"></form>'
    )
    assert findings == []


@respx.mock
async def test_flags_put_form_without_token() -> None:
    findings = await _run('<form method="put"><input></form>')
    assert len(findings) == 1
    assert "PUT" in findings[0].title


@respx.mock
async def test_emits_at_most_one_finding_per_page() -> None:
    html = '<form method="post"><input></form><form method="post" action="/b"><input></form>'
    findings = await _run(html)
    assert len(findings) == 1
