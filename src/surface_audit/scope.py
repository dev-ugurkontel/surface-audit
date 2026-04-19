"""Host allow-list primitives shared by the CLI and the MCP server.

Both entry points converge on :class:`ScopePolicy` so that the safety
contract is identical regardless of how a scan was triggered.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from surface_audit.exceptions import SurfaceAuditError

if TYPE_CHECKING:
    from surface_audit.models import ScanTarget


class ScopeError(SurfaceAuditError):
    """Raised when a target falls outside the allow-list."""


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    """Run-time guard-rails for scan targets.

    An empty allow-list with ``allow_any=False`` means *nothing* is
    permitted — the operator must opt in deliberately.
    """

    allowed_hosts: frozenset[str]
    allow_any: bool = False

    @classmethod
    def from_sources(
        cls,
        cli_hosts: frozenset[str] | None,
        *,
        env_var: str,
        allow_any: bool,
    ) -> ScopePolicy:
        """Merge an explicit CLI/API set with a comma-separated env var."""
        env_hosts = {h.strip().lower() for h in os.environ.get(env_var, "").split(",") if h.strip()}
        cli_hosts_lower = {h.lower() for h in (cli_hosts or frozenset())}
        return cls(
            allowed_hosts=frozenset(cli_hosts_lower | env_hosts),
            allow_any=allow_any,
        )

    @classmethod
    def unrestricted(cls) -> ScopePolicy:
        """Convenience helper for callers that explicitly want no scope check.

        Used by the default ``scan`` command when no allow-list or env var
        was supplied — the operator typed the URL themselves and is
        implicitly authorizing it.
        """
        return cls(allowed_hosts=frozenset(), allow_any=True)

    def enforce(self, target: ScanTarget) -> None:
        if self.allow_any:
            return
        if not self.allowed_hosts:
            raise ScopeError(
                "scope allow-list is empty; refusing to scan. "
                "Pass --scope-host or set SURFACE_AUDIT_SCOPE_HOSTS."
            )
        if target.hostname.lower() not in self.allowed_hosts:
            raise ScopeError(
                f"host {target.hostname!r} is not on the allow-list {sorted(self.allowed_hosts)}"
            )
