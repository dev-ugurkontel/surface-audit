"""Finding-level diff and baseline helpers.

Two findings are considered equivalent when their ``(check_id, title,
location, severity)`` tuple matches. That is stable across time: the
same underlying issue produces the same fingerprint on every scan, so
a baseline file captured today can be used to suppress pre-existing
findings on tomorrow's run without hiding genuinely new regressions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from surface_audit.exceptions import ConfigError
from surface_audit.models import Finding, FindingCategory, Severity

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

FindingKey = tuple[str, str, str, str]


def finding_key(finding: Finding) -> FindingKey:
    """Fingerprint used for baseline/diff comparison."""
    return (
        finding.check_id,
        finding.title,
        finding.location or "",
        finding.severity.value,
    )


def load_baseline(path: Path) -> set[FindingKey]:
    """Load a previously-saved JSON report and return finding fingerprints."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"baseline not found: {path}") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"baseline is not valid JSON ({path}): {exc}") from exc
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise ConfigError(f"baseline missing a 'findings' list: {path}")
    keys: set[FindingKey] = set()
    for item in findings:
        if not isinstance(item, dict):
            continue
        try:
            keys.add(
                (
                    str(item["check_id"]),
                    str(item["title"]),
                    str(item.get("location") or ""),
                    str(item["severity"]),
                )
            )
        except KeyError:
            # Silently skip malformed entries — baseline tolerance is
            # better than refusing a slightly-older report format.
            continue
    return keys


def new_findings(current: Iterable[Finding], baseline: set[FindingKey]) -> list[Finding]:
    """Return only findings that are not present in the baseline."""
    return [f for f in current if finding_key(f) not in baseline]


@dataclass(frozen=True, slots=True)
class DiffResult:
    """Structured diff between two reports."""

    added: list[Finding]
    removed: list[Finding]
    unchanged: list[Finding]

    def to_dict(self) -> dict[str, object]:
        return {
            "added": [f.to_dict() for f in self.added],
            "removed": [f.to_dict() for f in self.removed],
            "unchanged": [f.to_dict() for f in self.unchanged],
            "summary": {
                "added": len(self.added),
                "removed": len(self.removed),
                "unchanged": len(self.unchanged),
            },
        }


def diff_findings(before: list[Finding], after: list[Finding]) -> DiffResult:
    """Compute the added/removed/unchanged sets between two finding lists."""
    before_keys = {finding_key(f): f for f in before}
    after_keys = {finding_key(f): f for f in after}
    added = [f for k, f in after_keys.items() if k not in before_keys]
    removed = [f for k, f in before_keys.items() if k not in after_keys]
    unchanged = [f for k, f in after_keys.items() if k in before_keys]
    return DiffResult(added=added, removed=removed, unchanged=unchanged)


def _finding_from_dict(raw: dict[str, object]) -> Finding | None:
    try:
        return Finding(
            check_id=str(raw["check_id"]),
            title=str(raw["title"]),
            severity=Severity(str(raw["severity"])),
            description=str(raw["description"]),
            recommendation=str(raw["recommendation"]),
            category=FindingCategory(str(raw["category"])),
            location=raw.get("location"),  # type: ignore[arg-type]
            evidence=raw.get("evidence"),  # type: ignore[arg-type]
            references=tuple(raw.get("references") or ()),  # type: ignore[arg-type]
        )
    except (KeyError, ValueError):
        return None


def load_findings(path: Path) -> list[Finding]:
    """Load a saved JSON report and rebuild its findings list.

    Used by the ``diff`` CLI command. Malformed entries are dropped.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"report not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"report is not valid JSON ({path}): {exc}") from exc
    raw = payload.get("findings")
    if not isinstance(raw, list):
        raise ConfigError(f"report missing a 'findings' list: {path}")
    out: list[Finding] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        finding = _finding_from_dict(item)
        if finding is not None:
            out.append(finding)
    return out
