"""Check whether an HTTP request to the same origin redirects to HTTPS."""

from __future__ import annotations

from urllib.parse import urlparse

from surface_audit.checks.base import NETWORK_ERRORS, Check, CheckContext
from surface_audit.models import Finding, FindingCategory, Severity

REDIRECT_CODES = frozenset({301, 302, 307, 308})


class HTTPSRedirectCheck(Check):
    check_id = "https-redirect"
    description = "Ensures plaintext HTTP requests are redirected to HTTPS."
    category = FindingCategory.A02_CRYPTOGRAPHIC_FAILURES

    async def run(self, ctx: CheckContext) -> list[Finding]:
        if ctx.target.scheme != "https":
            return []

        http_url = (
            urlparse(ctx.target.url)
            ._replace(scheme="http", netloc=_with_http_port(ctx.target))
            .geturl()
        )

        try:
            response = await ctx.client.request("GET", http_url, follow_redirects=False)
        except NETWORK_ERRORS:
            return []

        if response.status_code in REDIRECT_CODES:
            location = response.headers.get("Location", "")
            if location.startswith("https://"):
                return []
            return [
                Finding(
                    check_id=self.check_id,
                    title="HTTP redirect does not upgrade to HTTPS",
                    severity=Severity.HIGH,
                    description=f"Plain-HTTP request redirected to a non-HTTPS location: {location!r}.",
                    recommendation="Always redirect HTTP to the equivalent HTTPS URL.",
                    category=self.category,
                    location=http_url,
                )
            ]
        return [
            Finding(
                check_id=self.check_id,
                title="HTTP endpoint does not redirect to HTTPS",
                severity=Severity.HIGH,
                description=f"HTTP request to {http_url} returned {response.status_code} instead of redirecting.",
                recommendation="Configure the server or edge to 301 redirect HTTP → HTTPS for all paths.",
                category=self.category,
                location=http_url,
                evidence=f"status={response.status_code}",
            )
        ]


def _with_http_port(target: object) -> str:
    """Rewrite the netloc so a :443 hint is not carried into the HTTP probe."""
    # ScanTarget is passed via duck-typing; avoid importing to prevent cycles.
    hostname = getattr(target, "hostname", "")
    port = getattr(target, "port", 443)
    if port in (80, 443):
        return hostname
    return f"{hostname}:{port}"
