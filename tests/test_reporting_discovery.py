"""Cover the renderer plugin discovery branch in reporting/__init__.py."""

from __future__ import annotations

from collections.abc import Iterator  # noqa: TC003 — yielded by a pytest fixture at runtime
from unittest.mock import MagicMock, patch

import pytest

import surface_audit.reporting as reporting_pkg
from surface_audit.exceptions import RendererError
from surface_audit.reporting import REGISTRY
from surface_audit.reporting.base import register


def _fake_ep(name: str, loaded: object, *, raises: BaseException | None = None) -> MagicMock:
    ep = MagicMock()
    ep.name = name
    if raises is not None:
        ep.load.side_effect = raises
    else:
        ep.load.return_value = loaded
    return ep


@pytest.fixture(autouse=True)
def _restore_registry() -> Iterator[None]:
    snapshot = dict(REGISTRY)
    yield
    REGISTRY.clear()
    REGISTRY.update(snapshot)


def test_discover_registers_valid_plugin() -> None:
    def fake_render(_report):  # type: ignore[no-untyped-def]
        return "ok"

    with patch.object(
        reporting_pkg, "entry_points", return_value=[_fake_ep("ok-renderer", fake_render)]
    ):
        reporting_pkg._discover_plugin_renderers()
    assert REGISTRY.get("ok-renderer") is fake_render


def test_discover_skips_broken_plugin() -> None:
    with patch.object(
        reporting_pkg,
        "entry_points",
        return_value=[_fake_ep("broken", None, raises=RuntimeError("boom"))],
    ):
        reporting_pkg._discover_plugin_renderers()
    assert "broken" not in REGISTRY


def test_discover_skips_non_callable_plugin() -> None:
    with patch.object(
        reporting_pkg,
        "entry_points",
        return_value=[_fake_ep("not-callable", "not a function")],
    ):
        reporting_pkg._discover_plugin_renderers()
    assert "not-callable" not in REGISTRY


def test_discover_handles_register_conflict() -> None:
    def first(_report):  # type: ignore[no-untyped-def]
        return "1"

    def second(_report):  # type: ignore[no-untyped-def]
        return "2"

    register("dup-renderer", first)
    with patch.object(
        reporting_pkg, "entry_points", return_value=[_fake_ep("dup-renderer", second)]
    ):
        reporting_pkg._discover_plugin_renderers()
    assert REGISTRY["dup-renderer"] is first


def test_register_rejects_renamed_conflict_directly() -> None:
    def first(_report):  # type: ignore[no-untyped-def]
        return "1"

    def second(_report):  # type: ignore[no-untyped-def]
        return "2"

    register("explicit-conflict", first)
    with pytest.raises(RendererError):
        register("explicit-conflict", second)
