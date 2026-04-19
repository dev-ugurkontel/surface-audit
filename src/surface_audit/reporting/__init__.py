"""Report rendering subsystem.

Usage::

    from surface_audit.reporting import render, write, render_console

New renderers register themselves against :data:`REGISTRY` by calling
:func:`register`. Third-party packages may contribute renderers via the
``surface_audit.renderers`` entry-point group; those are discovered the
first time this module is imported.
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points

# Side-effect import: registering the built-in renderers before we look
# for third-party ones so the built-in set is always available even if a
# plugin fails to load.
from surface_audit.reporting import html as _html  # noqa: F401
from surface_audit.reporting import json as _json  # noqa: F401
from surface_audit.reporting import markdown as _markdown  # noqa: F401
from surface_audit.reporting import sarif as _sarif  # noqa: F401
from surface_audit.reporting.base import REGISTRY, Renderer, register, render, write
from surface_audit.reporting.console import render_console

_logger = logging.getLogger(__name__)

_ENTRY_POINT_GROUP = "surface_audit.renderers"


def _discover_plugin_renderers() -> None:
    """Load any ``surface_audit.renderers`` entry points.

    A broken plugin must not mask the built-in set, so we catch and log
    rather than propagating.
    """
    for ep in entry_points(group=_ENTRY_POINT_GROUP):
        try:
            renderer = ep.load()
        except Exception as exc:
            _logger.warning("failed to load renderer %s: %r", ep.name, exc)
            continue
        if not callable(renderer):
            _logger.warning("renderer plugin %s is not callable; ignoring", ep.name)
            continue
        try:
            register(ep.name, renderer)
        except Exception as exc:
            _logger.warning("failed to register renderer %s: %r", ep.name, exc)


_discover_plugin_renderers()


__all__ = [
    "REGISTRY",
    "Renderer",
    "register",
    "render",
    "render_console",
    "write",
]
