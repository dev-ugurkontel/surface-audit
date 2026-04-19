"""Renderer protocol and registry.

A renderer is any callable (typically a function) that takes a
:class:`ScanReport` and returns a ``str``. Rendering is a pure
transformation, so it is safely composable and easy to unit-test.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from surface_audit.exceptions import RendererError

if TYPE_CHECKING:
    from pathlib import Path

    from surface_audit.models import ScanReport


class Renderer(Protocol):
    """Structural type for report renderers."""

    def __call__(self, report: ScanReport, /) -> str: ...  # pragma: no cover - structural


REGISTRY: dict[str, Renderer] = {}


def register(name: str, renderer: Renderer) -> None:
    """Register ``renderer`` under ``name``. Idempotent for the same callable."""
    existing = REGISTRY.get(name)
    if existing is not None and existing is not renderer:
        raise RendererError(f"renderer {name!r} is already registered")
    REGISTRY[name] = renderer


def render(report: ScanReport, fmt: str) -> str:
    """Return a serialized report. ``fmt`` must match a registered renderer."""
    try:
        renderer = REGISTRY[fmt]
    except KeyError as exc:
        available = ", ".join(sorted(REGISTRY))
        raise RendererError(f"unknown format {fmt!r}; known: {available}") from exc
    return renderer(report)


def write(report: ScanReport, path: Path, fmt: str) -> None:
    """Serialize a report to ``path`` in the requested format."""
    content = render(report, fmt)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
