"""RFC 9116: /.well-known/security.txt presence check."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from surface_audit.checks.base import NETWORK_ERRORS, Check, CheckContext
from surface_audit.models import Finding, FindingCategory, Severity

_CANDIDATES = ("/.well-known/security.txt", "/security.txt")
# RFC 9116 field names are case-insensitive (ABNF is case-insensitive).
_CONTACT_RE = re.compile(r"(?mi)^\s*contact\s*:")


class SecurityTxtCheck(Check):
    check_id = "security-txt"
    description = "Checks whether the site publishes a security.txt per RFC 9116."
    category = FindingCategory.A09_LOGGING_FAILURES

    async def run(self, ctx: CheckContext) -> list[Finding]:
        for path in _CANDIDATES:
            url = urljoin(ctx.target.url, path)
            try:
                response = await ctx.client.get(url)
            except NETWORK_ERRORS:
                continue
            if response.status_code == 200 and _CONTACT_RE.search(response.text):
                return []
        return [
            Finding(
                check_id=self.check_id,
                title="No security.txt published",
                severity=Severity.LOW,
                description=(
                    "The site does not publish a security.txt file. RFC 9116 defines this "
                    "standard location for vulnerability-disclosure contact details so that "
                    "researchers can reach the right team quickly."
                ),
                recommendation=(
                    "Publish /.well-known/security.txt with at least a Contact: field and a "
                    "signed Expires: date."
                ),
                category=self.category,
                location=urljoin(ctx.target.url, _CANDIDATES[0]),
                references=("https://www.rfc-editor.org/rfc/rfc9116",),
            )
        ]
