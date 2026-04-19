"""Self-contained HTML renderer."""

from __future__ import annotations

import html

from surface_audit.models import ScanReport, Severity
from surface_audit.reporting.base import register


def render_html(report: ScanReport) -> str:
    rows: list[str] = []
    for finding in sorted(report.findings, key=lambda f: (-f.severity.weight, f.check_id)):
        rows.append(
            "<tr>"
            f"<td class='sev sev-{html.escape(finding.severity.value.lower())}'>"
            f"{html.escape(finding.severity.value)}</td>"
            f"<td>{html.escape(finding.check_id)}</td>"
            f"<td>{html.escape(finding.title)}</td>"
            f"<td>{html.escape(finding.category.value)}</td>"
            f"<td>{html.escape(finding.description)}</td>"
            f"<td>{html.escape(finding.recommendation)}</td>"
            "</tr>"
        )
    counts = report.severity_counts()
    chips = "".join(
        f"<div class='chip chip-{s.value.lower()}'><span>{s.value}</span>"
        f"<strong>{counts[s]}</strong></div>"
        for s in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        )
    )
    return _TEMPLATE.format(
        target=html.escape(report.target.url),
        duration=f"{report.duration_seconds:.2f}",
        finding_count=len(report.findings),
        started_at=html.escape(report.started_at.isoformat()),
        summary=chips,
        rows="".join(rows) or "<tr><td colspan='6'>No findings.</td></tr>",
    )


_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>surface-audit Report — {target}</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }}
  h1 {{ margin-bottom: 0.25rem; }}
  .meta {{ color: #666; font-size: 0.9rem; margin-bottom: 1.5rem; }}
  .chips {{ display: flex; gap: 0.5rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
  .chip {{ padding: 0.5rem 0.75rem; border-radius: 999px; background: #f4f4f5; display: flex; gap: 0.5rem; align-items: baseline; }}
  .chip strong {{ font-size: 1.1rem; }}
  .chip-critical {{ background: #fee2e2; color: #7f1d1d; }}
  .chip-high     {{ background: #fef3c7; color: #78350f; }}
  .chip-medium   {{ background: #fef9c3; color: #713f12; }}
  .chip-low      {{ background: #dbeafe; color: #1e3a8a; }}
  .chip-info     {{ background: #e5e7eb; color: #374151; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ text-align: left; padding: 0.6rem 0.75rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
  th {{ background: #fafafa; font-weight: 600; }}
  .sev {{ font-weight: 600; }}
  .sev-critical {{ color: #b91c1c; }}
  .sev-high     {{ color: #c2410c; }}
  .sev-medium   {{ color: #a16207; }}
  .sev-low      {{ color: #1d4ed8; }}
  .sev-info     {{ color: #4b5563; }}
</style></head>
<body>
  <h1>surface-audit Report</h1>
  <div class="meta">Target: <code>{target}</code> · Started: {started_at} · Duration: {duration}s · Findings: {finding_count}</div>
  <div class="chips">{summary}</div>
  <table>
    <thead><tr><th>Severity</th><th>Check</th><th>Title</th><th>Category</th><th>Description</th><th>Recommendation</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body></html>
"""


register("html", render_html)
