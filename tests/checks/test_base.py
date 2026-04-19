"""Tests for the Check ABC."""

from __future__ import annotations

import pytest

from surface_audit.checks.base import Check


def test_subclass_missing_required_attributes_raises() -> None:
    with pytest.raises(TypeError, match="missing required attributes"):

        class Incomplete(Check):  # type: ignore[misc]
            async def run(self, ctx):  # type: ignore[no-untyped-def]
                return []
