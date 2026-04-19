"""Look for HTML forms that lack an anti-CSRF token or hidden challenge.

The check walks every ``<form>`` element on the landing page, reads
the ``method`` attribute from its opening tag, and — for mutating
forms (POST/PUT/PATCH/DELETE) — looks for common token field names in
the full form markup. It is a conservative heuristic: it does not
catch JS-only forms, does not follow crawl targets, and assumes a
framework that names its CSRF field recognizably.
"""

from __future__ import annotations

import re

from surface_audit.checks.base import NETWORK_ERRORS, Check, CheckContext
from surface_audit.models import Finding, FindingCategory, Severity

# Capture both the opening tag and body so we can inspect attributes on the
# tag itself. The prior implementation dropped the opening tag entirely,
# which meant method="post" was never observed.
_FORM_RE = re.compile(r"(<form\b[^>]*>)(.*?)</form>", re.IGNORECASE | re.DOTALL)
_METHOD_ATTR_RE = re.compile(
    r"""method\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""",
    re.IGNORECASE,
)

_MUTATING_METHODS: frozenset[str] = frozenset({"post", "put", "patch", "delete"})
_TOKEN_HINTS: tuple[str, ...] = (
    "csrf",
    "_token",
    "authenticity_token",
    "__requestverificationtoken",
    "xsrf",
)


def _form_method(opening_tag: str) -> str:
    """Return the lowercased ``method`` attribute, or the HTML default."""
    match = _METHOD_ATTR_RE.search(opening_tag)
    if match is None:
        return "get"  # HTML spec default
    value = next((g for g in match.groups() if g is not None), "")
    return value.strip().lower() or "get"


class CSRFCheck(Check):
    check_id = "csrf"
    description = "Detects mutating HTML forms that lack an obvious anti-CSRF token."
    category = FindingCategory.A01_BROKEN_ACCESS_CONTROL

    async def run(self, ctx: CheckContext) -> list[Finding]:
        try:
            response = await ctx.client.get(ctx.target.url)
        except NETWORK_ERRORS:
            return []

        forms = _FORM_RE.findall(response.text)
        if not forms:
            return []

        findings: list[Finding] = []
        for opening_tag, body in forms:
            method = _form_method(opening_tag)
            if method not in _MUTATING_METHODS:
                continue
            haystack = (opening_tag + body).lower()
            if any(hint in haystack for hint in _TOKEN_HINTS):
                continue
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title=f"{method.upper()} form without anti-CSRF token",
                    severity=Severity.MEDIUM,
                    description=(
                        f"A {method.upper()} form on the page does not include a recognized "
                        "anti-CSRF token field. State-changing requests should carry a "
                        "per-session, unpredictable token or rely on the SameSite cookie "
                        "attribute to prevent cross-site forgery."
                    ),
                    recommendation=(
                        "Add a framework-generated CSRF token to every mutating form and "
                        "verify it server-side, or set SameSite=Strict on session cookies "
                        "and audit all state-changing endpoints."
                    ),
                    category=self.category,
                    location=ctx.target.url,
                    references=("https://owasp.org/www-community/attacks/csrf",),
                )
            )
            # One finding per page is enough — the user will fix the pattern.
            break
        return findings
