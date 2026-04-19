# Usage guide

A full tour of the CLI and Python library. For one-shot reference, run
`surface-audit --help` or `surface-audit scan --help`.

> ⚠️ **Only scan systems you own or are explicitly authorized to test.**
> The scanner sends real HTTP requests. See [`SECURITY.md`](../SECURITY.md).

## Quick start

```bash
surface-audit scan https://example.com
```

Prints a rich terminal report of findings sorted by severity.

## Common workflows

### Save a machine-readable report

```bash
surface-audit scan https://example.com -o reports/example.json     -f json
surface-audit scan https://example.com -o reports/example.html     -f html
surface-audit scan https://example.com -o reports/example.sarif    -f sarif
surface-audit scan https://example.com -o reports/example.md       -f markdown  # PR-ready
```

### Gate your CI on severity

```bash
surface-audit scan https://staging.example.com --fail-on HIGH --quiet
# exit 0 if no HIGH+ findings, exit 2 otherwise
```

### Run a subset of checks

```bash
surface-audit scan https://example.com \
    --enable security-headers \
    --enable ssl-tls \
    --enable https-redirect
```

### Disable noisy checks

```bash
surface-audit scan https://example.com --disable directory-listing
```

### Through a proxy (e.g. Burp / mitmproxy)

```bash
surface-audit scan https://staging.local \
    --proxy http://127.0.0.1:8080 \
    --insecure
```

### Custom User-Agent (bot detection bypass for your own origin)

```bash
surface-audit scan https://example.com --user-agent "acme-security-bot/1.0"
```

### Restrict which hosts the CLI may scan

```bash
surface-audit scan https://staging.example.com \
    --scope-host staging.example.com

# Also honored from the environment:
export SURFACE_AUDIT_SCOPE_HOSTS=staging.example.com,internal.example
surface-audit scan https://staging.example.com
```

A request to any host outside the allow-list exits `2` with an error.
Useful in shared CI runners where operators want to block accidental
scans of production or third-party origins.

### Suppress already-known findings (baseline mode)

```bash
# Capture the current state once:
surface-audit scan https://example.com -o baseline.json -f json

# Subsequent runs suppress those findings when evaluating --fail-on:
surface-audit scan https://example.com \
    --baseline baseline.json \
    --fail-on HIGH
```

Adopt the scanner in CI without remediating every pre-existing finding
first. Only new findings gate the build.

### Compare two scan reports

```bash
surface-audit diff reports/before.json reports/after.json \
    --output diff.json \
    --fail-on-new
```

Prints added / removed / unchanged findings and optionally exits non-zero
on any newly introduced finding.

### Run as an MCP server (optional, requires `[mcp]` extra)

```bash
pip install "surface-audit[mcp]"
surface-audit mcp-serve --allow-host staging.example.com
```

Exposes `scan`, `list_checks`, `list_formats`, and `render_report` tools
to any Model Context Protocol client (Claude Desktop, Cursor, custom
agents). Every scan is gated by the host allow-list.

### Structured logs

```bash
surface-audit scan https://example.com --log-format json -v
```

Emits JSON-per-line log records to stderr — friendly to log aggregators
like Datadog, Loki, and CloudWatch.

### List what's available

```bash
surface-audit list-checks     # registered checks (built-in + plugins)
surface-audit list-formats    # registered report renderers
```

## Configuration file

Keep flags out of your `make scan` commands by putting defaults in
either `surface-audit.toml` (dedicated) or `pyproject.toml`
(`[tool.surface-audit]`).

```toml
# surface-audit.toml
timeout = 15.0
max_concurrency = 16
verify_tls = true
follow_redirects = true
user_agent = "acme-security-bot/1.0"
retry_attempts = 3
retry_backoff = 0.5
enabled_checks = ["security-headers", "ssl-tls", "https-redirect"]
disabled_checks = ["xss-reflection"]
```

Override path:

```bash
surface-audit scan https://example.com --config ./custom.toml
```

Precedence: **CLI flag > file > built-in default**.

## Library usage

### Minimum viable scan

```python
import asyncio
from surface_audit import Scanner

async def main() -> None:
    report = await Scanner("https://example.com").run()
    print(len(report.findings), "findings")

asyncio.run(main())
```

### Customize the run

```python
from surface_audit import Scanner, ScannerConfig

config = ScannerConfig(
    timeout=5.0,
    max_concurrency=4,
    disabled_checks=frozenset({"sql-injection"}),
    retry_attempts=5,
)
report = await Scanner("https://example.com", config=config).run()
```

### Render to JSON or SARIF from code

```python
from pathlib import Path
from surface_audit.reporting import render, write

print(render(report, "json"))
write(report, Path("out.sarif"), "sarif")
```

### Iterate findings

```python
for finding in sorted(report.findings, key=lambda f: -f.severity.weight):
    print(f"{finding.severity.value:<9} {finding.check_id:<20} {finding.title}")
```

## Writing a custom check

1. Subclass `surface_audit.checks.base.Check`.
2. Return a list of `Finding` from `run()`.
3. Register via `pyproject.toml` entry point:

```toml
[project.entry-points."surface_audit.checks"]
my_check = "my_pkg.my_module:MyCheck"
```

See [`../examples`](../examples) and [`ARCHITECTURE.md`](ARCHITECTURE.md)
for more.

## Exit codes

| Code | Meaning                                                  |
| ---- | -------------------------------------------------------- |
| 0    | Scan completed. Either no findings or below `--fail-on`. |
| 1    | Unexpected runtime error.                                |
| 2    | Scan completed, findings at or above `--fail-on`.        |
| 130  | Interrupted (Ctrl-C).                                    |

## CI recipes

### GitHub Actions

```yaml
- name: Security scan
  run: |
    pipx install surface-audit
    surface-audit scan https://staging.example.com \
      --output scan.sarif --format sarif --fail-on HIGH --quiet
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: scan.sarif
```

### GitLab CI

```yaml
security:scan:
  image: python:3.12-slim
  script:
    - pip install surface-audit
    - surface-audit scan "$STAGING_URL" --fail-on HIGH --output scan.json
  artifacts:
    when: always
    paths: [scan.json]
```
