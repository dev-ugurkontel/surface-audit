"""Minimal library-usage example.

Run with::

    python examples/basic_usage.py https://example.com
"""

from __future__ import annotations

import asyncio
import sys

from surface_audit import Scanner, ScannerConfig


async def main(url: str) -> int:
    scanner = Scanner(url, config=ScannerConfig(max_concurrency=4, timeout=5.0))
    report = await scanner.run()

    print(f"Target:   {report.target.url}")
    print(f"Duration: {report.duration_seconds:.2f}s")
    print(f"Findings: {len(report.findings)}")
    for finding in sorted(report.findings, key=lambda f: -f.severity.weight):
        print(f"  [{finding.severity.value}] {finding.check_id} — {finding.title}")

    max_severity = report.max_severity()
    return 2 if max_severity and max_severity.weight >= 3 else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python basic_usage.py <url>", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(asyncio.run(main(sys.argv[1])))
