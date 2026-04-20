"""Schema validation tests for the JSON report contract."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from surface_audit.models import Finding, FindingCategory, ScanReport, Severity


def _validator() -> Draft202012Validator:
    schema = json.loads(Path("schemas/report.schema.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def test_empty_report_matches_json_schema(report: ScanReport) -> None:
    _validator().validate(report.to_dict())


def test_non_empty_report_matches_json_schema(report: ScanReport) -> None:
    report.add(
        Finding(
            check_id="security-headers",
            title="Missing Content-Security-Policy header",
            severity=Severity.HIGH,
            description="The response does not define a CSP.",
            recommendation="Set a strict Content-Security-Policy header.",
            category=FindingCategory.A05_SECURITY_MISCONFIGURATION,
            location=report.target.url,
            evidence="content-security-policy: <missing>",
            references=(
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            ),
        )
    )
    _validator().validate(report.to_dict())
