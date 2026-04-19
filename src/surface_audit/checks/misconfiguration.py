"""Probe a small list of well-known paths for exposed admin or secret surfaces.

The check is deliberately conservative. We emit the finding severity that
matches the **observed HTTP evidence** rather than the pessimistic
configuration severity for the path: a 200 or a redirect that stays on the
same origin is treated as "reachable" (severity as declared), while 401/403
responses downgrade to LOW. This prevents the scanner from claiming that an
endpoint is unauthenticated when the evidence is only a 403.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urljoin, urlparse

from surface_audit.checks.base import NETWORK_ERRORS, Check, CheckContext
from surface_audit.models import Finding, FindingCategory, Severity

SENSITIVE_PATHS: tuple[tuple[str, Severity, str], ...] = (
    ("/.env", Severity.CRITICAL, "Application .env file likely contains secrets."),
    ("/.git/config", Severity.CRITICAL, "Exposed git config leaks repository metadata."),
    ("/.git/HEAD", Severity.CRITICAL, "Exposed git repository allows source reconstruction."),
    ("/.aws/credentials", Severity.CRITICAL, "Exposed AWS credentials file."),
    ("/admin", Severity.HIGH, "Admin interface path is reachable."),
    ("/phpmyadmin/", Severity.HIGH, "phpMyAdmin console is reachable."),
    ("/server-status", Severity.MEDIUM, "Apache mod_status page leaks internal metrics."),
    ("/actuator/env", Severity.HIGH, "Spring Boot actuator /env endpoint is reachable."),
)

_REACHABLE_CODES: frozenset[int] = frozenset({200, 301, 302, 303, 307, 308})
_AUTH_GATED_CODES: frozenset[int] = frozenset({401, 403})
_METHOD_NOT_ALLOWED = 405


class MisconfigurationCheck(Check):
    check_id = "misconfiguration"
    description = "Probes a small set of well-known paths for exposed admin or secret files."
    category = FindingCategory.A05_SECURITY_MISCONFIGURATION

    async def run(self, ctx: CheckContext) -> list[Finding]:
        target_host = urlparse(ctx.target.url).netloc.lower()

        async def probe(path: str, severity: Severity, reason: str) -> Finding | None:
            url = urljoin(ctx.target.url, path)

            status = await _status(ctx, url)
            if status is None:
                return None

            if status in _AUTH_GATED_CODES:
                return Finding(
                    check_id=self.check_id,
                    title=f"Sensitive path exists but denies access: {path}",
                    severity=Severity.LOW,
                    description=(
                        f"{reason} Server responded with HTTP {status}, which indicates the "
                        "endpoint is present but access is gated. Ensure the file is not "
                        "deployed to the document root at all."
                    ),
                    recommendation=(
                        "Remove VCS metadata, dotfiles, and admin consoles from the web "
                        "root rather than relying on access control alone."
                    ),
                    category=self.category,
                    location=url,
                    evidence=f"HTTP {status}",
                )

            if status not in _REACHABLE_CODES:
                return None

            # For redirects, only flag when the target leaves the origin — a
            # same-origin 301 for /admin → /admin/login is routing, not exposure.
            if 300 <= status < 400:
                redirect_host = await _redirect_host(ctx, url)
                if redirect_host and redirect_host == target_host:
                    return None

            return Finding(
                check_id=self.check_id,
                title=f"Sensitive path reachable: {path}",
                severity=severity,
                description=(f"{reason} Server responded with HTTP {status} for {path!r}."),
                recommendation=(
                    "Restrict access to administrative surfaces, remove dotfiles from the "
                    "document root, and deploy through artifacts that exclude VCS metadata."
                ),
                category=self.category,
                location=url,
                evidence=f"HTTP {status}",
            )

        results = await asyncio.gather(
            *(probe(path, sev, reason) for path, sev, reason in SENSITIVE_PATHS)
        )
        return [finding for finding in results if finding is not None]


async def _status(ctx: CheckContext, url: str) -> int | None:
    """Probe ``url`` with HEAD, falling back to a bounded GET for servers
    that reject HEAD with 405 Method Not Allowed."""
    try:
        response = await ctx.client.head(url, follow_redirects=False)
    except NETWORK_ERRORS:
        return None

    if response.status_code != _METHOD_NOT_ALLOWED:
        return response.status_code

    # HEAD rejected — retry with GET. We still use the shared client but
    # cap the response body at 4 KiB via the Range header for politeness.
    try:
        response = await ctx.client.get(
            url, follow_redirects=False, headers={"Range": "bytes=0-4095"}
        )
    except NETWORK_ERRORS:
        return None
    return response.status_code


async def _redirect_host(ctx: CheckContext, url: str) -> str | None:
    """Return the lowercased ``netloc`` of the ``Location`` header, if any."""
    try:
        response = await ctx.client.head(url, follow_redirects=False)
    except NETWORK_ERRORS:
        return None
    location = response.headers.get("Location")
    if not location:
        return None
    if location.startswith("/"):  # relative → same origin
        return urlparse(url).netloc.lower()
    return urlparse(location).netloc.lower() or None
