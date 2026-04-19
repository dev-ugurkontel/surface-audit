"""SARIF 2.1.0 renderer suitable for GitHub Code Scanning."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from surface_audit.models import Finding, ScanReport, Severity
from surface_audit.reporting.base import register


def render_sarif(report: ScanReport) -> str:
    sarif: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "surface-audit",
                        "informationUri": "https://github.com/dev-ugurkontel/surface-audit",
                        "rules": _rules(report),
                    }
                },
                "results": [_result(f, report) for f in report.findings],
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True, ensure_ascii=False)


def _rule_id(check_id: str) -> str:
    return f"surface-audit/{check_id}"


def _level(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }[severity]


def _rules(report: ScanReport) -> list[dict[str, Any]]:
    seen: dict[str, Finding] = {}
    for finding in report.findings:
        seen.setdefault(finding.check_id, finding)
    return [
        {
            "id": _rule_id(finding.check_id),
            "name": finding.check_id,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "helpUri": (finding.references[0] if finding.references else ""),
            "properties": {"category": finding.category.value},
        }
        for finding in seen.values()
    ]


def _result(finding: Finding, report: ScanReport) -> dict[str, Any]:
    fingerprint = hashlib.sha256(
        f"{finding.check_id}|{finding.title}|{finding.location or ''}".encode()
    ).hexdigest()
    location = finding.location or report.target.url
    return {
        "ruleId": _rule_id(finding.check_id),
        "level": _level(finding.severity),
        "message": {"text": finding.description},
        "partialFingerprints": {"primaryLocationLineHash": fingerprint},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": location}}}],
        "properties": {
            "severity": finding.severity.value,
            "owaspCategory": finding.category.value,
            "recommendation": finding.recommendation,
        },
    }


register("sarif", render_sarif)
