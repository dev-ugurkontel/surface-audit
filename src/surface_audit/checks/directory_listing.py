"""Detect servers that return directory index pages."""

from __future__ import annotations

import re

from surface_audit.checks.base import NETWORK_ERRORS, Check, CheckContext
from surface_audit.models import Finding, FindingCategory, Severity

INDICATORS = (
    re.compile(r"<title>\s*Index of\s*/", re.IGNORECASE),
    re.compile(r"<h1>\s*Index of\s*/", re.IGNORECASE),
    re.compile(r"directory listing for", re.IGNORECASE),
)


class DirectoryListingCheck(Check):
    check_id = "directory-listing"
    description = "Looks for auto-generated index pages that enumerate files on the server."
    category = FindingCategory.A05_SECURITY_MISCONFIGURATION

    async def run(self, ctx: CheckContext) -> list[Finding]:
        try:
            response = await ctx.client.get(ctx.target.url)
        except NETWORK_ERRORS:
            return []

        body = response.text
        if any(pattern.search(body) for pattern in INDICATORS):
            return [
                Finding(
                    check_id=self.check_id,
                    title="Directory listing enabled",
                    severity=Severity.MEDIUM,
                    description="The server returns an auto-generated index page, revealing file names.",
                    recommendation="Disable autoindex (Apache `Options -Indexes`, Nginx `autoindex off`).",
                    category=self.category,
                    location=ctx.target.url,
                )
            ]
        return []
