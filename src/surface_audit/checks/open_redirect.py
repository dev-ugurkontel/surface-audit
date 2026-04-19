"""Heuristic open-redirect probe.

The check sends a canary attacker-controlled URL as each of a small set
of well-known redirect parameter names and looks for a 30x response
whose Location header points to the canary host. It is deliberately
conservative: only flags when the server actually redirects us off-origin
to the supplied value, not merely when it reflects the parameter.
"""

from __future__ import annotations

from urllib.parse import urlencode, urlparse, urlunparse

from surface_audit.checks.base import NETWORK_ERRORS, Check, CheckContext
from surface_audit.models import Finding, FindingCategory, Severity

_REDIRECT_PARAMS: tuple[str, ...] = (
    "next",
    "url",
    "redirect",
    "redirect_uri",
    "return",
    "returnUrl",
    "return_to",
    "dest",
    "destination",
    "continue",
)

_CANARY_HOST = "scanner-canary.invalid"
_CANARY_URL = f"https://{_CANARY_HOST}/surface-audit-probe"
_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})


def _with_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    extra = urlencode({name: value})
    query = f"{parsed.query}&{extra}" if parsed.query else extra
    return urlunparse(parsed._replace(query=query))


class OpenRedirectCheck(Check):
    check_id = "open-redirect"
    description = "Detects query parameters that let an attacker redirect the user off-origin."
    category = FindingCategory.A01_BROKEN_ACCESS_CONTROL

    async def run(self, ctx: CheckContext) -> list[Finding]:
        for param in _REDIRECT_PARAMS:
            test_url = _with_param(ctx.target.url, param, _CANARY_URL)
            try:
                response = await ctx.client.request("GET", test_url, follow_redirects=False)
            except NETWORK_ERRORS:
                continue

            if response.status_code not in _REDIRECT_STATUS:
                continue

            location = response.headers.get("Location", "")
            if not location:
                continue

            location_host = urlparse(location).hostname
            if location_host and location_host.lower() == _CANARY_HOST:
                return [
                    Finding(
                        check_id=self.check_id,
                        title=f"Open redirect via {param!r} parameter",
                        severity=Severity.MEDIUM,
                        description=(
                            f"The server redirected to an attacker-controlled URL supplied via "
                            f"the {param!r} query parameter. Attackers can use this to phish or "
                            "bypass trust boundaries."
                        ),
                        recommendation=(
                            "Validate redirect targets against an allow-list of same-origin paths "
                            "(not hosts), and reject anything else with 400."
                        ),
                        category=self.category,
                        location=test_url,
                        evidence=f"HTTP {response.status_code} Location: {location}",
                        references=(
                            "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards",
                        ),
                    )
                ]
        return []
