"""Tests for the baseline / diff module."""

from __future__ import annotations

import json
from pathlib import Path  # noqa: TC003 — pytest tmp_path annotation needs runtime access

import pytest

from surface_audit.diff import (
    diff_findings,
    finding_key,
    load_baseline,
    load_findings,
    new_findings,
)
from surface_audit.exceptions import ConfigError
from surface_audit.models import Finding, FindingCategory, Severity


def _finding(**kw) -> Finding:  # type: ignore[no-untyped-def]
    defaults = {
        "check_id": "x",
        "title": "T",
        "severity": Severity.LOW,
        "description": "d",
        "recommendation": "r",
        "category": FindingCategory.A05_SECURITY_MISCONFIGURATION,
        "location": "https://example.com/",
        "references": (),
    }
    defaults.update(kw)
    return Finding(**defaults)  # type: ignore[arg-type]


def _write_report(path: Path, findings: list[Finding]) -> None:
    payload = {
        "target": {
            "url": "https://example.com/",
            "hostname": "example.com",
            "port": 443,
            "scheme": "https",
        },
        "findings": [f.to_dict() for f in findings],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_finding_key_uses_stable_fields() -> None:
    f = _finding(check_id="csrf", title="t", location="loc", severity=Severity.HIGH)
    assert finding_key(f) == ("csrf", "t", "loc", "HIGH")


def test_finding_key_handles_missing_location() -> None:
    f = _finding(location=None)
    assert finding_key(f)[2] == ""


def test_new_findings_subtracts_baseline() -> None:
    a = _finding(title="A")
    b = _finding(title="B")
    baseline = {finding_key(a)}
    result = new_findings([a, b], baseline)
    assert [f.title for f in result] == ["B"]


def test_diff_categorizes_findings() -> None:
    a = _finding(title="A")
    b = _finding(title="B")
    c = _finding(title="C")
    result = diff_findings([a, b], [b, c])
    assert [f.title for f in result.added] == ["C"]
    assert [f.title for f in result.removed] == ["A"]
    assert [f.title for f in result.unchanged] == ["B"]


def test_diff_result_to_dict_has_summary() -> None:
    a = _finding(title="A")
    result = diff_findings([], [a])
    payload = result.to_dict()
    assert payload["summary"] == {"added": 1, "removed": 0, "unchanged": 0}
    assert payload["added"][0]["title"] == "A"


def test_load_baseline_reads_fingerprints(tmp_path: Path) -> None:
    f = _finding(check_id="csrf", title="t", location="loc", severity=Severity.HIGH)
    path = tmp_path / "baseline.json"
    _write_report(path, [f])
    keys = load_baseline(path)
    assert keys == {("csrf", "t", "loc", "HIGH")}


def test_load_baseline_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_baseline(tmp_path / "nope.json")


def test_load_baseline_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(ConfigError, match="valid JSON"):
        load_baseline(path)


def test_load_baseline_rejects_missing_findings_key(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"no": "findings"}), encoding="utf-8")
    with pytest.raises(ConfigError, match="findings"):
        load_baseline(path)


def test_load_baseline_tolerates_malformed_entries(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    # One good, one not-a-dict, one missing check_id — loader must tolerate.
    payload = {
        "findings": [
            {
                "check_id": "csrf",
                "title": "t",
                "location": "loc",
                "severity": "HIGH",
            },
            "not-a-dict",
            {"title": "no check_id"},
        ]
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    keys = load_baseline(path)
    assert keys == {("csrf", "t", "loc", "HIGH")}


def test_load_findings_rebuilds_findings(tmp_path: Path) -> None:
    a = _finding(title="A")
    path = tmp_path / "r.json"
    _write_report(path, [a])
    loaded = load_findings(path)
    assert len(loaded) == 1
    assert loaded[0].title == "A"


def test_load_findings_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_findings(tmp_path / "nope.json")


def test_load_findings_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(ConfigError, match="valid JSON"):
        load_findings(path)


def test_load_findings_rejects_missing_findings_key(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"foo": 1}), encoding="utf-8")
    with pytest.raises(ConfigError, match="findings"):
        load_findings(path)


def test_load_findings_skips_malformed_entries(tmp_path: Path) -> None:
    path = tmp_path / "r.json"
    path.write_text(
        json.dumps(
            {
                "findings": [
                    "not-a-dict",
                    {"check_id": "x"},  # missing required keys
                    {
                        "check_id": "csrf",
                        "title": "t",
                        "severity": "HIGH",
                        "description": "d",
                        "recommendation": "r",
                        "category": "A01:2021 - Broken Access Control",
                        "location": None,
                        "references": [],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    loaded = load_findings(path)
    assert len(loaded) == 1
    assert loaded[0].check_id == "csrf"
