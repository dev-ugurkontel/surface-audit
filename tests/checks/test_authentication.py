"""Tests for auth-cookies check."""

from __future__ import annotations

import httpx
import respx

from surface_audit.checks.authentication import AuthenticationCheck, _parse_cookie
from surface_audit.checks.base import CheckContext
from surface_audit.client import HTTPClient
from surface_audit.models import ScanTarget, Severity
from surface_audit.scanner import ScannerConfig


def test_parse_cookie_extracts_attributes() -> None:
    name, attrs = _parse_cookie("sid=abc; Secure; HttpOnly; SameSite=Lax")
    assert name == "sid"
    assert attrs == {"secure", "httponly", "samesite"}


def test_parse_cookie_does_not_confuse_value_with_attribute() -> None:
    # 'secure' appears inside the value — must not be treated as the Secure attribute.
    _, attrs = _parse_cookie("session=securevalue; HttpOnly")
    assert "secure" not in attrs
    assert attrs == {"httponly"}


def test_parse_cookie_does_not_confuse_name_with_attribute() -> None:
    # Cookie name is 'samesite-cookie' — must not satisfy SameSite attribute.
    name, attrs = _parse_cookie("samesite-cookie=abc; Secure; HttpOnly")
    assert name == "samesite-cookie"
    assert "samesite" not in attrs


async def _run(cookie: str, *, scheme: str = "https") -> list:
    url = f"{scheme}://example.com"
    target = ScanTarget.parse(url)
    route = respx.get(f"{url}/").mock(
        return_value=httpx.Response(200, headers={"Set-Cookie": cookie})
    )
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await AuthenticationCheck().run(ctx)
    assert route.called
    return findings


@respx.mock
async def test_flags_substring_false_negative_regression() -> None:
    # A cookie value containing the substring "secure" must not satisfy the
    # Secure attribute check — the check must parse attributes structurally.
    findings = await _run("session=securevalue; HttpOnly")
    assert len(findings) == 1
    assert "Secure" in findings[0].description
    assert findings[0].severity is Severity.HIGH


@respx.mock
async def test_flags_cookie_name_substring_regression() -> None:
    findings = await _run("samesite-cookie=abc; Secure; HttpOnly")
    assert len(findings) == 1
    assert "SameSite" in findings[0].description


@respx.mock
async def test_accepts_fully_hardened_cookie() -> None:
    findings = await _run("sid=abc; Secure; HttpOnly; SameSite=Lax")
    assert findings == []


@respx.mock
async def test_does_not_require_secure_on_http_origin() -> None:
    # On plaintext HTTP, marking Secure is useless; the check should still
    # require HttpOnly and SameSite, but not Secure.
    findings = await _run("sid=abc; HttpOnly; SameSite=Lax", scheme="http")
    assert findings == []


@respx.mock
async def test_evidence_redacts_cookie_value() -> None:
    findings = await _run("sid=super-secret; HttpOnly; SameSite=Lax")
    assert len(findings) == 1
    assert "super-secret" not in (findings[0].evidence or "")
    assert "<redacted>" in (findings[0].evidence or "")


@respx.mock
async def test_missing_only_samesite_is_medium() -> None:
    findings = await _run("sid=abc; Secure; HttpOnly")
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM


def test_parse_cookie_handles_empty_header() -> None:
    name, attrs = _parse_cookie("")
    assert name == ""
    assert attrs == set()


def test_parse_cookie_handles_valueless_attribute() -> None:
    name, attrs = _parse_cookie("sid=abc; ; HttpOnly")
    assert name == "sid"
    assert attrs == {"httponly"}


def test_parse_cookie_ignores_empty_attribute_key() -> None:
    # `=value` fragment has an empty key; must be ignored structurally
    # rather than silently registered.
    _, attrs = _parse_cookie("sid=abc; =orphan; HttpOnly")
    assert attrs == {"httponly"}


@respx.mock
async def test_anonymous_cookie_without_name_is_skipped() -> None:
    # Some servers send Set-Cookie with a leading '=' which has no name.
    findings = await _run("=value; HttpOnly")
    # The anonymous cookie is skipped (guard in the check), so no finding.
    assert findings == []
