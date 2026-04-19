"""Model Context Protocol server exposing the scanner to LLM agents.

Install with the ``mcp`` extra::

    pip install "surface-audit[mcp]"

Run::

    surface-audit mcp-serve --allow-host staging.example.com

The server speaks stdio and therefore works out of the box with Claude
Desktop, Cursor, and any other MCP client that launches local servers.

Safety model
------------
The scanner issues real HTTP requests to whatever target it is handed.
Exposing it to an LLM without guard-rails would let an attacker (or a
confused agent) direct traffic at arbitrary hosts. This module enforces
a strict host allow-list:

- ``--allow-host`` (repeatable) or the ``SURFACE_AUDIT_ALLOWED_HOSTS``
  env var (comma-separated) sets the allow-list.
- ``--allow-any-host`` disables the allow-list. Refuse this flag in
  production.
- With no allow-list and no escape hatch, every scan request is denied.

Denied requests return a plain error so the LLM can explain the
restriction instead of retrying endlessly.
"""

from __future__ import annotations

import logging

from surface_audit.exceptions import SurfaceAuditError
from surface_audit.models import ScanTarget
from surface_audit.reporting import REGISTRY, render
from surface_audit.scanner import Scanner, ScannerConfig
from surface_audit.scope import ScopeError, ScopePolicy

_logger = logging.getLogger(__name__)

ENV_ALLOWED_HOSTS = "SURFACE_AUDIT_ALLOWED_HOSTS"


def build_policy(allowed_hosts: frozenset[str], allow_any: bool) -> ScopePolicy:
    """Merge MCP-server CLI flags with the allow-list env var."""
    return ScopePolicy.from_sources(allowed_hosts, env_var=ENV_ALLOWED_HOSTS, allow_any=allow_any)


def build_app(policy: ScopePolicy):  # type: ignore[no-untyped-def]
    """Construct the FastMCP app. Imported lazily so the core package
    does not require ``mcp`` at runtime."""
    from mcp.server.fastmcp import FastMCP

    app = FastMCP("surface-audit")

    @app.tool()
    async def scan(
        url: str,
        enabled_checks: list[str] | None = None,
        disabled_checks: list[str] | None = None,
        timeout: float = 10.0,
        max_concurrency: int = 8,
    ) -> dict[str, object]:
        """Run a surface-audit scan against ``url`` and return the report.

        Findings map to OWASP Top 10 (2021) categories where applicable.

        Args:
            url: Target URL. Must resolve to a hostname on the server's allow-list.
            enabled_checks: Optional list of check IDs; when set, only these run.
            disabled_checks: Optional list of check IDs to skip.
            timeout: Per-request timeout in seconds.
            max_concurrency: Maximum number of concurrent HTTP requests.

        Returns:
            A JSON-serializable ``ScanReport.to_dict()`` payload, or an
            ``{"error": ...}`` object if the request was denied.
        """
        try:
            target = ScanTarget.parse(url)
        except ValueError as exc:
            return {"error": str(exc), "reason": "invalid_target"}

        try:
            policy.enforce(target)
        except ScopeError as exc:
            return {"error": str(exc), "reason": "scope_denied"}

        config = ScannerConfig(
            timeout=timeout,
            max_concurrency=max_concurrency,
            enabled_checks=frozenset(enabled_checks) if enabled_checks else None,
            disabled_checks=frozenset(disabled_checks or ()),
        )

        try:
            report = await Scanner(target, config=config).run()
        except SurfaceAuditError as exc:
            return {"error": str(exc), "reason": type(exc).__name__}

        return report.to_dict()

    @app.tool()
    async def list_checks() -> list[dict[str, str]]:
        """List every check registered in this environment."""
        return [
            {
                "id": c.check_id,
                "description": c.description,
                "category": c.category.value,
            }
            for c in Scanner.discover_checks()
        ]

    @app.tool()
    async def list_formats() -> list[str]:
        """List every report format registered in this environment."""
        return sorted(REGISTRY)

    @app.tool()
    async def render_report(report: dict[str, object], fmt: str) -> str:
        """Render an existing scan-report dict in the requested format.

        Useful when the LLM has the scan JSON and wants Markdown/SARIF/HTML
        output without re-running the scan.
        """
        from datetime import datetime, timezone

        from surface_audit.models import (
            Finding,
            FindingCategory,
            ScanReport,
            ScanTarget,
            Severity,
        )

        target_raw = report.get("target") or {}
        if not isinstance(target_raw, dict):
            return "error: target missing or malformed"
        try:
            target = ScanTarget(
                url=str(target_raw["url"]),
                hostname=str(target_raw["hostname"]),
                port=int(target_raw["port"]),
                scheme=str(target_raw["scheme"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            return f"error: malformed target ({exc})"

        now = datetime.now(timezone.utc)
        rebuilt = ScanReport(target=target, started_at=now, finished_at=now)
        findings_raw = report.get("findings") or []
        if isinstance(findings_raw, list):
            for f in findings_raw:
                if not isinstance(f, dict):
                    continue
                try:
                    rebuilt.add(
                        Finding(
                            check_id=str(f["check_id"]),
                            title=str(f["title"]),
                            severity=Severity(str(f["severity"])),
                            description=str(f["description"]),
                            recommendation=str(f["recommendation"]),
                            category=FindingCategory(str(f["category"])),
                            location=f.get("location"),
                            evidence=f.get("evidence"),
                            references=tuple(f.get("references") or ()),
                        )
                    )
                except (KeyError, ValueError):
                    continue
        return render(rebuilt, fmt)

    return app


def run(*, allowed_hosts: frozenset[str], allow_any_host: bool) -> None:
    """Entry point used by the CLI. Blocks until stdio is closed."""
    policy = build_policy(allowed_hosts, allow_any_host)
    _logger.info(
        "MCP server starting: allow_any=%s allowed_hosts=%s",
        policy.allow_any,
        sorted(policy.allowed_hosts) if not policy.allow_any else "*",
    )
    app = build_app(policy)
    app.run()  # FastMCP defaults to stdio when not given a transport.
