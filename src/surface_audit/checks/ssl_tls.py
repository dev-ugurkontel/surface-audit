"""TLS posture check: protocol version and cipher strength.

Limitations to be aware of:

- This check opens a direct TCP socket and does **not** route through
  ``--proxy``. If you need proxy coverage, rely on your proxy's own TLS
  inspection or disable this check.
- Only the negotiated protocol/cipher is observed, so a server that
  still accepts legacy protocols but prefers modern ones will not be
  flagged. Call out this property in the finding description below.
"""

from __future__ import annotations

import asyncio
import socket
import ssl

from surface_audit.checks.base import Check, CheckContext
from surface_audit.models import Finding, FindingCategory, Severity

MIN_CIPHER_BITS = 128
MIN_SAFE_TLS = (1, 2)  # TLS 1.2+


class SSLTLSCheck(Check):
    check_id = "ssl-tls"
    description = "Inspects the TLS negotiation for weak protocol versions or ciphers."
    category = FindingCategory.A02_CRYPTOGRAPHIC_FAILURES

    async def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.target.scheme != "https":
            return [
                Finding(
                    check_id=self.check_id,
                    title="Target served over plaintext HTTP",
                    severity=Severity.HIGH,
                    description=(
                        "The target URL uses HTTP. Traffic and credentials are exposed "
                        "in cleartext."
                    ),
                    recommendation="Serve the application exclusively over HTTPS and enforce HSTS.",
                    category=self.category,
                    location=ctx.target.url,
                )
            ]

        loop = asyncio.get_running_loop()
        try:
            info = await loop.run_in_executor(
                None,
                _probe_tls,
                ctx.target.hostname,
                ctx.target.port,
                ctx.config.timeout,
                ctx.config.verify_tls,
            )
        except (socket.gaierror, TimeoutError, ConnectionError, ssl.SSLError) as exc:
            return [
                Finding(
                    check_id=self.check_id,
                    title="TLS handshake failed",
                    severity=Severity.MEDIUM,
                    description=f"Could not establish a TLS session with the host: {exc}.",
                    recommendation=(
                        "Verify the certificate chain and that the host is reachable "
                        "on the TLS port. For self-signed test environments, rerun with "
                        "--insecure."
                    ),
                    category=self.category,
                    location=f"{ctx.target.hostname}:{ctx.target.port}",
                )
            ]

        findings: list[Finding] = []
        cipher_name, tls_version, cipher_bits = info

        if cipher_bits is not None and cipher_bits < MIN_CIPHER_BITS:
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="Weak TLS cipher negotiated",
                    severity=Severity.HIGH,
                    description=(
                        f"Negotiated cipher '{cipher_name}' uses only {cipher_bits} bits "
                        "of key material. Note: this check sees only the negotiated "
                        "suite; servers that support legacy suites but prefer modern ones "
                        "will appear clean here."
                    ),
                    recommendation=(
                        "Disable legacy ciphers and require AES-GCM or ChaCha20-Poly1305 "
                        "with >=128-bit keys."
                    ),
                    category=self.category,
                    location=f"{ctx.target.hostname}:{ctx.target.port}",
                    evidence=f"cipher={cipher_name} bits={cipher_bits}",
                )
            )

        parsed_version = _parse_tls_version(tls_version)
        if parsed_version and parsed_version < MIN_SAFE_TLS:
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="Obsolete TLS protocol version",
                    severity=Severity.HIGH,
                    description=(
                        f"The server negotiated {tls_version}, which is considered insecure."
                    ),
                    recommendation="Require TLS 1.2 at minimum; prefer TLS 1.3.",
                    category=self.category,
                    location=f"{ctx.target.hostname}:{ctx.target.port}",
                    evidence=tls_version or "",
                )
            )

        return findings


def _probe_tls(
    hostname: str,
    port: int,
    timeout: float,
    verify_tls: bool,
) -> tuple[str | None, str | None, int | None]:
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((hostname, port), timeout=timeout) as sock,
        context.wrap_socket(sock, server_hostname=hostname) as ssock,
    ):
        cipher = ssock.cipher()
        version = ssock.version()
    if cipher is None:
        return None, version, None
    name, _protocol, bits = cipher
    return name, version, bits


def _parse_tls_version(raw: str | None) -> tuple[int, int] | None:
    if not raw or not raw.startswith("TLSv"):
        return None
    try:
        major, minor = raw.removeprefix("TLSv").split(".", 1)
        return int(major), int(minor)
    except ValueError:
        return None
