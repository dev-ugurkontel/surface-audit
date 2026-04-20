"""Example plugin check for surface-audit."""

from __future__ import annotations

from surface_audit.checks.base import NETWORK_ERRORS, Check, CheckContext
from surface_audit.models import Finding, FindingCategory, Severity


class PoweredByHeaderCheck(Check):
    """Flags responses that disclose an X-Powered-By header."""

    check_id = "x-powered-by"
    description = "Checks whether the response discloses an X-Powered-By header."
    category = FindingCategory.A05_SECURITY_MISCONFIGURATION

    async def run(self, ctx: CheckContext) -> list[Finding]:
        try:
            response = await ctx.client.get(ctx.target.url)
        except NETWORK_ERRORS:
            return []

        powered_by = response.headers.get("X-Powered-By")
        if not powered_by:
            return []

        return [
            Finding(
                check_id=self.check_id,
                title="X-Powered-By header is exposed",
                severity=Severity.LOW,
                description=(
                    "The response includes an X-Powered-By header, which can disclose "
                    "implementation details to unauthenticated clients."
                ),
                recommendation=(
                    "Remove the X-Powered-By header or replace it with a neutral value "
                    "at the application or reverse-proxy layer."
                ),
                category=self.category,
                location=ctx.target.url,
                evidence=f"X-Powered-By: {powered_by}",
            )
        ]
