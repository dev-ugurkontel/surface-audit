"""Flag session cookies that lack hardening attributes.

The check parses every ``Set-Cookie`` header structurally so that cookie
names or values containing substrings like ``secure`` or ``samesite``
do not mask genuinely missing attributes.
"""

from __future__ import annotations

from surface_audit.checks.base import NETWORK_ERRORS, Check, CheckContext
from surface_audit.models import Finding, FindingCategory, Severity


def _parse_cookie(raw: str) -> tuple[str, set[str]]:
    """Return ``(cookie_name, set_of_lowercased_attribute_keys)``.

    The cookie value is intentionally discarded — we only care about
    attribute presence, never the secret content.
    """
    name_part, _, attr_part = raw.partition(";")
    name = name_part.split("=", 1)[0].strip()
    attrs: set[str] = set()
    for fragment in attr_part.split(";"):
        fragment = fragment.strip()
        if not fragment:
            continue
        key = fragment.split("=", 1)[0].strip().lower()
        if key:
            attrs.add(key)
    return name, attrs


class AuthenticationCheck(Check):
    check_id = "auth-cookies"
    description = "Inspects Set-Cookie headers for Secure, HttpOnly, and SameSite attributes."
    category = FindingCategory.A07_AUTH_FAILURES

    async def run(self, ctx: CheckContext) -> list[Finding]:
        try:
            response = await ctx.client.get(ctx.target.url)
        except NETWORK_ERRORS:
            return []

        findings: list[Finding] = []
        for raw in response.headers.get_list("set-cookie"):
            name, attrs = _parse_cookie(raw)
            if not name:
                continue

            missing: list[str] = []
            if "secure" not in attrs and ctx.target.scheme == "https":
                missing.append("Secure")
            if "httponly" not in attrs:
                missing.append("HttpOnly")
            if "samesite" not in attrs:
                missing.append("SameSite")
            if not missing:
                continue

            severity = Severity.HIGH if "Secure" in missing else Severity.MEDIUM
            # Redact the cookie value from evidence to avoid leaking secrets.
            redacted = raw.split("=", 1)
            evidence_header = f"{redacted[0]}=<redacted>" + (
                ";" + redacted[1].split(";", 1)[1]
                if len(redacted) == 2 and ";" in redacted[1]
                else ""
            )
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title=f"Cookie {name!r} missing hardening attributes",
                    severity=severity,
                    description=(
                        f"The cookie is set without the following attributes: {', '.join(missing)}."
                    ),
                    recommendation=(
                        "Set Secure, HttpOnly and SameSite=Lax (or Strict) on every "
                        "session cookie and any cookie holding authentication state."
                    ),
                    category=self.category,
                    location=ctx.target.url,
                    evidence=evidence_header,
                )
            )
        return findings
