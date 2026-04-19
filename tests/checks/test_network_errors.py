"""Each HTTP-based check must swallow network errors and emit no findings.

This single parametrized test exercises the common error path for every
HTTP-based check. It is the coverage guard for the NETWORK_ERRORS branch
in each file.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest

from surface_audit.checks.authentication import AuthenticationCheck
from surface_audit.checks.base import Check, CheckContext
from surface_audit.checks.cors import CORSCheck
from surface_audit.checks.cross_origin_isolation import CrossOriginIsolationCheck
from surface_audit.checks.csrf import CSRFCheck
from surface_audit.checks.directory_listing import DirectoryListingCheck
from surface_audit.checks.https_redirect import HTTPSRedirectCheck
from surface_audit.checks.misconfiguration import MisconfigurationCheck
from surface_audit.checks.open_redirect import OpenRedirectCheck
from surface_audit.checks.security_headers import SecurityHeadersCheck
from surface_audit.checks.security_txt import SecurityTxtCheck
from surface_audit.checks.sql_injection import SQLInjectionCheck
from surface_audit.checks.xss import ReflectedXSSCheck
from surface_audit.client import HTTPClient
from surface_audit.models import ScanTarget
from surface_audit.scanner import ScannerConfig


@pytest.mark.parametrize(
    "check_cls",
    [
        AuthenticationCheck,
        CORSCheck,
        CrossOriginIsolationCheck,
        CSRFCheck,
        DirectoryListingCheck,
        HTTPSRedirectCheck,
        MisconfigurationCheck,
        OpenRedirectCheck,
        SecurityHeadersCheck,
        SQLInjectionCheck,
        ReflectedXSSCheck,
    ],
)
async def test_check_swallows_network_errors(check_cls: type[Check]) -> None:
    """Checks that depend purely on HTTP responses must emit [] on transport
    failure instead of propagating the exception."""
    target = ScanTarget.parse("https://example.com")
    async with HTTPClient(timeout=1.0, max_concurrency=2) as client:
        exc = httpx.ConnectError("boom")
        client.get = AsyncMock(side_effect=exc)  # type: ignore[method-assign]
        client.head = AsyncMock(side_effect=exc)  # type: ignore[method-assign]
        client.request = AsyncMock(side_effect=exc)  # type: ignore[method-assign]

        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await check_cls().run(ctx)
    assert findings == []


async def test_security_txt_emits_finding_when_all_candidates_error() -> None:
    """SecurityTxtCheck's documented behavior: if no candidate succeeds, the
    check reports the file as missing rather than silently passing."""
    target = ScanTarget.parse("https://example.com")
    async with HTTPClient(timeout=1.0, max_concurrency=2) as client:
        client.get = AsyncMock(side_effect=httpx.ConnectError("boom"))  # type: ignore[method-assign]
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await SecurityTxtCheck().run(ctx)
    assert len(findings) == 1
    assert "security.txt" in findings[0].title.lower()
