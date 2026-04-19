"""Check plugins. Each check subclasses :class:`surface_audit.checks.base.Check`."""

from __future__ import annotations

from surface_audit.checks.base import Check, CheckContext

__all__ = ["Check", "CheckContext"]
