"""Tests for sql-injection check."""

from __future__ import annotations

import httpx
import respx

from surface_audit.checks.base import CheckContext
from surface_audit.checks.sql_injection import SQLInjectionCheck
from surface_audit.client import HTTPClient
from surface_audit.models import ScanTarget, Severity
from surface_audit.scanner import ScannerConfig


async def _run(body: str) -> list:
    target = ScanTarget.parse("https://example.com")
    respx.get(url__regex=r"https://example.com/\?.*").mock(
        return_value=httpx.Response(200, text=body)
    )
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        return await SQLInjectionCheck().run(ctx)


@respx.mock
async def test_flags_mysql_error_leak() -> None:
    findings = await _run("You have an error in your SQL syntax near '''")
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL


@respx.mock
async def test_flags_mssql_error_leak() -> None:
    findings = await _run("Microsoft OLE DB Provider for ODBC Drivers error '80040e14'")
    assert len(findings) == 1


@respx.mock
async def test_ignores_clean_response() -> None:
    findings = await _run("<html>ok</html>")
    assert findings == []
