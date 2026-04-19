"""GitHub-Flavored-Markdown renderer suitable for PR comments."""

from __future__ import annotations

from typing import TYPE_CHECKING

from surface_audit.models import Severity
from surface_audit.reporting.base import register

if TYPE_CHECKING:
    from surface_audit.models import ScanReport


_SEVERITY_ICONS: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def _escape(text: str) -> str:
    """Escape pipe characters so they do not break the Markdown table."""
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: ScanReport) -> str:
    lines: list[str] = []
    lines.append(f"## surface-audit — `{report.target.url}`")
    lines.append("")
    counts = report.severity_counts()
    summary = " · ".join(
        f"{_SEVERITY_ICONS[s]} **{s.value}**: {counts[s]}"
        for s in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        )
    )
    lines.append(
        f"_{len(report.findings)} finding(s) in {report.duration_seconds:.2f}s_ — {summary}"
    )
    lines.append("")

    if not report.findings:
        lines.append("> ✅ No findings.")
        return "\n".join(lines) + "\n"

    lines.append("| Severity | Check | Title | Location |")
    lines.append("| --- | --- | --- | --- |")
    for f in sorted(report.findings, key=lambda x: (-x.severity.weight, x.check_id)):
        icon = _SEVERITY_ICONS[f.severity]
        lines.append(
            f"| {icon} {f.severity.value} | `{_escape(f.check_id)}` | "
            f"{_escape(f.title)} | {_escape(f.location or '')} |"
        )

    lines.append("")
    lines.append("<details><summary>Details</summary>")
    lines.append("")
    for f in sorted(report.findings, key=lambda x: (-x.severity.weight, x.check_id)):
        lines.append(f"### {_SEVERITY_ICONS[f.severity]} {_escape(f.title)}")
        lines.append("")
        lines.append(f"- **Check:** `{f.check_id}`")
        lines.append(f"- **Category:** {f.category.value}")
        if f.location:
            lines.append(f"- **Location:** `{f.location}`")
        if f.evidence:
            lines.append(f"- **Evidence:** `{_escape(f.evidence)}`")
        lines.append("")
        lines.append(f.description)
        lines.append("")
        lines.append(f"> **Fix:** {f.recommendation}")
        lines.append("")
    lines.append("</details>")
    return "\n".join(lines) + "\n"


register("markdown", render_markdown)
