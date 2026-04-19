"""Heuristic SQL injection probe looking for error-based signatures."""

from __future__ import annotations

import re
from urllib.parse import urlencode, urlparse, urlunparse

from surface_audit.checks.base import NETWORK_ERRORS, Check, CheckContext
from surface_audit.models import Finding, FindingCategory, Severity

PAYLOADS = (
    "'",
    '"',
    "') OR ('1'='1",
    "' OR 1=1-- -",
)

ERROR_SIGNATURES = (
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"pg_query\(\)", re.I),
    re.compile(r"sqlite3\.OperationalError", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"SQLServer JDBC Driver", re.I),
    re.compile(r"Microsoft OLE DB Provider for", re.I),
)


class SQLInjectionCheck(Check):
    check_id = "sql-injection"
    description = "Sends benign SQL meta-characters and looks for database error strings."
    category = FindingCategory.A03_INJECTION

    async def run(self, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        for payload in PAYLOADS:
            test_url = _with_query(ctx.target.url, {"id": payload})
            try:
                response = await ctx.client.get(test_url)
            except NETWORK_ERRORS:
                continue

            match = _first_signature(response.text)
            if match is not None:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Database error message reflected in response",
                        severity=Severity.CRITICAL,
                        description=(
                            "A query parameter containing a SQL meta-character caused the server to leak "
                            "a database error. This strongly suggests unparameterized query construction."
                        ),
                        recommendation=(
                            "Use parameterized queries / prepared statements and suppress raw database "
                            "errors from HTTP responses."
                        ),
                        category=self.category,
                        location=test_url,
                        evidence=match[:200],
                        references=("https://owasp.org/www-community/attacks/SQL_Injection",),
                    )
                )
                break  # one finding is enough; stop hammering the endpoint
        return findings


def _with_query(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    merged = urlencode(params)
    new_query = f"{parsed.query}&{merged}" if parsed.query else merged
    return urlunparse(parsed._replace(query=new_query))


def _first_signature(body: str) -> str | None:
    for pattern in ERROR_SIGNATURES:
        match = pattern.search(body)
        if match is not None:
            return match.group(0)
    return None
