"""Check for the modern cross-origin isolation headers (COOP/COEP/CORP).

These are defense-in-depth headers — missing them is not an exploitable
vulnerability, but their absence removes a layer of protection against
Spectre-class side-channel attacks and cross-origin leaks.
"""

from __future__ import annotations

from surface_audit.checks.base import NETWORK_ERRORS, Check, CheckContext
from surface_audit.models import Finding, FindingCategory, Severity

_HEADERS: tuple[tuple[str, str, str], ...] = (
    (
        "Cross-Origin-Opener-Policy",
        "Prevents other origins from sharing a browsing context group with this document.",
        "same-origin",
    ),
    (
        "Cross-Origin-Embedder-Policy",
        "Requires explicit opt-in from cross-origin resources before the page may embed them.",
        "require-corp",
    ),
    (
        "Cross-Origin-Resource-Policy",
        "Allow-lists which origins may fetch this resource.",
        "same-origin",
    ),
)


class CrossOriginIsolationCheck(Check):
    check_id = "cross-origin-isolation"
    description = "Verifies COOP / COEP / CORP headers for defense-in-depth isolation."
    category = FindingCategory.A05_SECURITY_MISCONFIGURATION

    async def run(self, ctx: CheckContext) -> list[Finding]:
        try:
            response = await ctx.client.get(ctx.target.url)
        except NETWORK_ERRORS:
            return []

        findings: list[Finding] = []
        for header, description, recommended_value in _HEADERS:
            if header in response.headers:
                continue
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title=f"Missing cross-origin isolation header: {header}",
                    severity=Severity.LOW,
                    description=description,
                    recommendation=f"Set '{header}: {recommended_value}' or an equivalent policy.",
                    category=self.category,
                    location=ctx.target.url,
                    references=(f"https://developer.mozilla.org/docs/Web/HTTP/Headers/{header}",),
                )
            )
        return findings
