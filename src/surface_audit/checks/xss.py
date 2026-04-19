"""Heuristic reflected XSS probe.

This is a surface-level check — it proves that *some* payload is reflected
verbatim into the response body, which is a strong indicator of a missing
output-encoding step. It is intentionally conservative and will neither
attempt to bypass WAFs nor explore the DOM.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlencode, urlparse, urlunparse

from surface_audit.checks.base import NETWORK_ERRORS, Check, CheckContext
from surface_audit.models import Finding, FindingCategory, Severity


class ReflectedXSSCheck(Check):
    check_id = "xss-reflection"
    description = "Detects reflected input that could enable cross-site scripting."
    category = FindingCategory.A03_INJECTION

    async def run(self, ctx: CheckContext) -> list[Finding]:
        marker = f"xss{secrets.token_hex(6)}"
        payload = f'"><script>{marker}</script>'
        test_url = _with_query(ctx.target.url, {"q": payload})

        try:
            response = await ctx.client.get(test_url)
        except NETWORK_ERRORS:
            return []

        # Reflection in non-HTML contexts (JSON APIs, plaintext) cannot be
        # rendered as script by a browser, so it is not an XSS signal here.
        content_type = response.headers.get("Content-Type", "").lower()
        if "html" not in content_type:
            return []

        if payload in response.text:
            return [
                Finding(
                    check_id=self.check_id,
                    title="Reflected input without encoding",
                    severity=Severity.HIGH,
                    description=(
                        "A unique script payload submitted via a query string was reflected verbatim "
                        "into the response body without HTML encoding."
                    ),
                    recommendation=(
                        "Context-aware output encoding (HTML, attribute, JS) for any user-supplied "
                        "data and a strict Content-Security-Policy."
                    ),
                    category=self.category,
                    location=test_url,
                    evidence=payload,
                    references=("https://owasp.org/www-community/attacks/xss/",),
                )
            ]
        return []


def _with_query(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    merged = urlencode(params)
    new_query = f"{parsed.query}&{merged}" if parsed.query else merged
    return urlunparse(parsed._replace(query=new_query))
