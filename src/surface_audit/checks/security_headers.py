"""Checks for missing *and* weakly-configured HTTP security headers.

The check emits three kinds of finding:

- Missing header (unchanged from earlier versions).
- Weak value for a present header (HSTS too short, CSP permits unsafe
  script sources, X-Content-Type-Options != nosniff).
- Server-banner disclosure.

The value-aware rules are intentionally conservative: they flag the
well-known bad cases rather than trying to replicate a full CSP parser.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from surface_audit.checks.base import NETWORK_ERRORS, Check, CheckContext
from surface_audit.models import Finding, FindingCategory, Severity

if TYPE_CHECKING:
    import httpx

REQUIRED_HEADERS: tuple[tuple[str, Severity, str], ...] = (
    (
        "Strict-Transport-Security",
        Severity.HIGH,
        "HSTS forces browsers to use HTTPS and mitigates protocol downgrade attacks.",
    ),
    (
        "Content-Security-Policy",
        Severity.HIGH,
        "CSP restricts the sources from which scripts and other assets may load.",
    ),
    (
        "X-Content-Type-Options",
        Severity.MEDIUM,
        "Prevents MIME-type sniffing that can lead to script execution on uploaded files.",
    ),
    (
        "X-Frame-Options",
        Severity.MEDIUM,
        "Prevents clickjacking by disallowing the page from being framed.",
    ),
    (
        "Referrer-Policy",
        Severity.LOW,
        "Controls how much referrer information is leaked on outbound navigation.",
    ),
    (
        "Permissions-Policy",
        Severity.LOW,
        "Limits which powerful browser features (camera, geolocation, etc.) the page may use.",
    ),
)

# HSTS minimum: six months. Shorter values are below the browser preload
# list threshold and provide limited protection.
_HSTS_MIN_MAX_AGE = 15_552_000
_HSTS_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)

# CSP directives we consider directly dangerous in script context.
_CSP_DANGEROUS_TOKENS: tuple[str, ...] = ("'unsafe-inline'", "'unsafe-eval'")


class SecurityHeadersCheck(Check):
    check_id = "security-headers"
    description = (
        "Verifies presence and configuration of recommended HTTP security response headers."
    )
    category = FindingCategory.A05_SECURITY_MISCONFIGURATION

    async def run(self, ctx: CheckContext) -> list[Finding]:
        try:
            response = await ctx.client.get(ctx.target.url)
        except NETWORK_ERRORS:
            return []

        findings: list[Finding] = []
        headers = response.headers

        csp_raw = headers.get("Content-Security-Policy", "")
        csp_lower = csp_raw.lower()
        has_frame_ancestors = "frame-ancestors" in csp_lower

        findings.extend(self._missing_header_findings(ctx, headers, has_frame_ancestors))
        findings.extend(self._weak_value_findings(ctx, headers, csp_raw, csp_lower))

        server_header = headers.get("Server")
        if server_header:
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="Server banner disclosed",
                    severity=Severity.LOW,
                    description=(
                        f"The server discloses its software and version via the 'Server' "
                        f"header: {server_header!r}."
                    ),
                    recommendation="Suppress or minimize the 'Server' header at the reverse proxy.",
                    category=self.category,
                    location=ctx.target.url,
                    evidence=f"Server: {server_header}",
                )
            )
        return findings

    def _missing_header_findings(
        self,
        ctx: CheckContext,
        headers: httpx.Headers,
        has_frame_ancestors: bool,
    ) -> list[Finding]:
        out: list[Finding] = []
        for header, severity, description in REQUIRED_HEADERS:
            if header in headers:
                continue
            # CSP frame-ancestors supersedes X-Frame-Options per the CSP3 spec.
            if header == "X-Frame-Options" and has_frame_ancestors:
                continue
            out.append(
                Finding(
                    check_id=self.check_id,
                    title=f"Missing security header: {header}",
                    severity=severity,
                    description=description,
                    recommendation=f"Configure the server to emit the '{header}' response header.",
                    category=self.category,
                    location=ctx.target.url,
                    references=(f"https://developer.mozilla.org/docs/Web/HTTP/Headers/{header}",),
                )
            )
        return out

    def _weak_value_findings(
        self,
        ctx: CheckContext,
        headers: httpx.Headers,
        csp_raw: str,
        csp_lower: str,
    ) -> list[Finding]:
        out: list[Finding] = []

        hsts_raw = headers.get("Strict-Transport-Security")
        if hsts_raw:
            match = _HSTS_MAX_AGE_RE.search(hsts_raw)
            max_age = int(match.group(1)) if match else 0
            if max_age < _HSTS_MIN_MAX_AGE:
                out.append(
                    Finding(
                        check_id=self.check_id,
                        title="HSTS max-age below recommended threshold",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Strict-Transport-Security max-age is {max_age}s; browsers require "
                            f"at least {_HSTS_MIN_MAX_AGE}s (six months) for preload eligibility."
                        ),
                        recommendation=(
                            "Set max-age to 31536000 (1 year) with includeSubDomains and preload."
                        ),
                        category=self.category,
                        location=ctx.target.url,
                        evidence=f"Strict-Transport-Security: {hsts_raw}",
                    )
                )

        if csp_lower:
            dangerous = [tok for tok in _CSP_DANGEROUS_TOKENS if tok in csp_lower]
            if dangerous:
                out.append(
                    Finding(
                        check_id=self.check_id,
                        title=f"CSP contains {', '.join(dangerous)}",
                        severity=Severity.MEDIUM,
                        description=(
                            "Content-Security-Policy permits script sources that defeat most of "
                            "its XSS protection. These tokens allow inline script execution and "
                            "dynamic code-string execution, both of which CSP is meant to block."
                        ),
                        recommendation=(
                            "Remove the unsafe tokens; migrate to nonces or hashes for inline scripts."
                        ),
                        category=self.category,
                        location=ctx.target.url,
                        evidence=f"Content-Security-Policy: {csp_raw}",
                    )
                )

        xcto = headers.get("X-Content-Type-Options")
        if xcto is not None and xcto.strip().lower() != "nosniff":
            out.append(
                Finding(
                    check_id=self.check_id,
                    title="X-Content-Type-Options is not 'nosniff'",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The header is present but set to {xcto!r}; only 'nosniff' disables "
                        "MIME-type sniffing."
                    ),
                    recommendation="Set X-Content-Type-Options: nosniff (the only valid value).",
                    category=self.category,
                    location=ctx.target.url,
                    evidence=f"X-Content-Type-Options: {xcto}",
                )
            )

        return out
