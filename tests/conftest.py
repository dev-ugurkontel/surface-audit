"""Shared pytest fixtures."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from surface_audit.models import ScanReport, ScanTarget


@pytest.fixture
def target() -> ScanTarget:
    return ScanTarget.parse("https://example.com")


@pytest.fixture
def report(target: ScanTarget) -> ScanReport:
    return ScanReport(target=target, started_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
