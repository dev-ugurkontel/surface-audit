"""Check for overly permissive CORS configuration."""

from __future__ import annotations

import secrets

from surface_audit.checks.base import NETWORK_ERRORS, Check, CheckContext
from surface_audit.models import Finding, FindingCategory, Severity


class CORSCheck(Check):
    check_id = "cors"
    description = "Detects Access-Control-Allow-Origin reflections and wildcards with credentials."
    category = FindingCategory.A05_SECURITY_MISCONFIGURATION

    async def run(self, ctx: CheckContext) -> list[Finding]:
        probe_origin = f"https://{secrets.token_hex(6)}.example"
        try:
            response = await ctx.client.get(ctx.target.url, headers={"Origin": probe_origin})
        except NETWORK_ERRORS:
            return []

        allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
        allow_credentials = (
            response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        )

        if allow_origin == "*" and allow_credentials:
            return [
                Finding(
                    check_id=self.check_id,
                    title="CORS wildcard combined with credentials",
                    severity=Severity.HIGH,
                    description=(
                        "Access-Control-Allow-Origin: * is returned together with "
                        "Allow-Credentials: true. Browsers will reject this combination, but the "
                        "intent indicates a misconfiguration that may leak credentials under "
                        "certain framework behaviors."
                    ),
                    recommendation=(
                        "Reflect a trusted, allow-listed origin and only enable credentials for "
                        "that specific origin."
                    ),
                    category=self.category,
                    location=ctx.target.url,
                    evidence=f"Access-Control-Allow-Origin: {allow_origin}",
                )
            ]

        if allow_origin == probe_origin and allow_credentials:
            return [
                Finding(
                    check_id=self.check_id,
                    title="CORS reflects arbitrary origin with credentials",
                    severity=Severity.HIGH,
                    description=(
                        "The server echoed an arbitrary attacker-controlled Origin header and "
                        "set Allow-Credentials: true. Any site can now read authenticated "
                        "responses from this endpoint."
                    ),
                    recommendation="Validate the Origin against a static allow-list before reflecting it.",
                    category=self.category,
                    location=ctx.target.url,
                    evidence=f"Origin {probe_origin} → Access-Control-Allow-Origin {allow_origin}",
                )
            ]

        return []
