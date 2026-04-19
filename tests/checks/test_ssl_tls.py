"""Tests for ssl-tls check."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from surface_audit.checks.base import CheckContext
from surface_audit.checks.ssl_tls import SSLTLSCheck
from surface_audit.client import HTTPClient
from surface_audit.models import ScanTarget, Severity
from surface_audit.scanner import ScannerConfig


async def test_flags_http_target_as_plaintext() -> None:
    target = ScanTarget.parse("http://example.com")
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        findings = await SSLTLSCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "plaintext" in findings[0].title.lower()


async def test_probe_honors_verify_tls_and_timeout() -> None:
    """Regression for verify_tls and timeout must reach _probe_tls."""
    captured: dict = {}

    def fake_probe(hostname, port, timeout, verify_tls):  # type: ignore[no-untyped-def]
        captured["hostname"] = hostname
        captured["port"] = port
        captured["timeout"] = timeout
        captured["verify_tls"] = verify_tls
        return "TLS_AES_256_GCM_SHA384", "TLSv1.3", 256

    target = ScanTarget.parse("https://example.com")
    config = ScannerConfig(timeout=7.5, verify_tls=False)
    async with HTTPClient(timeout=7.5, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=config)
        with patch("surface_audit.checks.ssl_tls._probe_tls", side_effect=fake_probe):
            findings = await SSLTLSCheck().run(ctx)

    assert captured == {
        "hostname": "example.com",
        "port": 443,
        "timeout": 7.5,
        "verify_tls": False,
    }
    assert findings == []  # TLS 1.3 + 256-bit cipher is clean


async def test_reports_weak_protocol_and_cipher() -> None:
    def fake_probe(hostname, port, timeout, verify_tls):  # type: ignore[no-untyped-def]
        return "DES-CBC-SHA", "TLSv1.0", 56

    target = ScanTarget.parse("https://example.com")
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        with patch("surface_audit.checks.ssl_tls._probe_tls", side_effect=fake_probe):
            findings = await SSLTLSCheck().run(ctx)

    titles = {f.title for f in findings}
    assert "Weak TLS cipher negotiated" in titles
    assert "Obsolete TLS protocol version" in titles


@pytest.mark.parametrize(
    "exc_type",
    [TimeoutError, ConnectionError],
)
async def test_handshake_failure_maps_to_finding(exc_type: type[BaseException]) -> None:
    def fake_probe(hostname, port, timeout, verify_tls):  # type: ignore[no-untyped-def]
        raise exc_type("boom")

    target = ScanTarget.parse("https://example.com")
    async with HTTPClient(timeout=2.0, max_concurrency=2) as client:
        ctx = CheckContext(target=target, client=client, config=ScannerConfig())
        with patch("surface_audit.checks.ssl_tls._probe_tls", side_effect=fake_probe):
            findings = await SSLTLSCheck().run(ctx)
    assert len(findings) == 1
    assert "handshake failed" in findings[0].title.lower()


def test_probe_tls_returns_negotiated_info_when_socket_mocked() -> None:
    """Exercise the real _probe_tls body against a fully-mocked socket stack."""
    from unittest.mock import MagicMock

    import surface_audit.checks.ssl_tls as ssl_mod

    fake_ssock = MagicMock()
    fake_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    fake_ssock.version.return_value = "TLSv1.3"
    fake_ssock.__enter__.return_value = fake_ssock
    fake_ssock.__exit__.return_value = False

    fake_context = MagicMock()
    fake_context.wrap_socket.return_value = fake_ssock

    fake_sock = MagicMock()
    fake_sock.__enter__.return_value = fake_sock
    fake_sock.__exit__.return_value = False

    with (
        patch.object(ssl_mod.ssl, "create_default_context", return_value=fake_context),
        patch.object(ssl_mod.socket, "create_connection", return_value=fake_sock),
    ):
        result = ssl_mod._probe_tls("example.com", 443, 5.0, verify_tls=True)
    assert result == ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)


def test_probe_tls_returns_none_cipher_when_not_negotiated() -> None:
    """cipher() can return None — covers the early-return branch in _probe_tls."""
    from unittest.mock import MagicMock

    import surface_audit.checks.ssl_tls as ssl_mod

    fake_ssock = MagicMock()
    fake_ssock.cipher.return_value = None
    fake_ssock.version.return_value = None
    fake_ssock.__enter__.return_value = fake_ssock
    fake_ssock.__exit__.return_value = False

    fake_context = MagicMock()
    fake_context.wrap_socket.return_value = fake_ssock

    fake_sock = MagicMock()
    fake_sock.__enter__.return_value = fake_sock
    fake_sock.__exit__.return_value = False

    with (
        patch.object(ssl_mod.ssl, "create_default_context", return_value=fake_context),
        patch.object(ssl_mod.socket, "create_connection", return_value=fake_sock),
    ):
        result = ssl_mod._probe_tls("example.com", 443, 5.0, verify_tls=False)
    assert result == (None, None, None)
    fake_context.check_hostname = False


def test_parse_tls_version_variants() -> None:
    from surface_audit.checks.ssl_tls import _parse_tls_version

    assert _parse_tls_version("TLSv1.2") == (1, 2)
    assert _parse_tls_version("TLSv1.3") == (1, 3)
    assert _parse_tls_version(None) is None
    assert _parse_tls_version("SSLv3") is None
    assert _parse_tls_version("TLSv?") is None
