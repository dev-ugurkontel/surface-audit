"""JSON renderer — deterministic, pretty, UTF-8 safe."""

from __future__ import annotations

import json as _json
from typing import TYPE_CHECKING

from surface_audit.reporting.base import register

if TYPE_CHECKING:
    from surface_audit.models import ScanReport


def render_json(report: ScanReport) -> str:
    return _json.dumps(report.to_dict(), indent=2, sort_keys=True, ensure_ascii=False)


register("json", render_json)
