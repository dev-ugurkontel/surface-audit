# surface-audit

[![CI](https://github.com/dev-ugurkontel/surface-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/dev-ugurkontel/surface-audit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/surface-audit.svg)](https://pypi.org/project/surface-audit/)
[![Downloads](https://img.shields.io/pypi/dm/surface-audit.svg)](https://pypistats.org/packages/surface-audit)
[![Python](https://img.shields.io/pypi/pyversions/surface-audit.svg)](https://pypi.org/project/surface-audit/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-blue)](https://mypy.readthedocs.io/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Deterministic **security smoke tests** for staging, preview, and
pre-deploy web apps.

`surface-audit` sends a small, bounded set of safe probes at a **known
URL** and turns the result into CI-friendly findings, SARIF, Markdown,
HTML, and JSON reports. It is designed for teams that want to catch
security regressions in headers, TLS, redirects, cookies, CORS, exposed
files, and other surface-level mistakes **before** they promote a build.

> ⚠️ **Authorized use only.** This tool sends real HTTP requests to the
> target. Only run it against systems you own or have explicit written
> permission to test. See [`SECURITY.md`](SECURITY.md).

## Why Teams Use It

- **Safe by default** — bounded checks against a known URL, not a crawler
  and not an exploit framework.
- **Regression-oriented** — baseline suppression and report diff help
  answer "what got worse?" instead of just "what exists?"
- **CI-native** — `--fail-on`, SARIF, Markdown, HTML, and JSON all fit
  cleanly into pull requests, code scanning, and release gates.
- **LLM-safe MCP support** — the optional MCP server exposes only a
  host allow-listed interface.
- **Extensible** — checks and renderers are pluggable via entry points.
- **Supply-chain aware** — PyPI Trusted Publishing, Sigstore signatures,
  GitHub Releases, and CycloneDX SBOMs are built into the release flow.

## Use It When

- you have a staging, preview, or pre-production URL
- you want a deterministic security gate in CI
- you care about security regressions between two deployments
- you want machine-readable output for SARIF, dashboards, or PR comments

## Reach for Other Tools When

- you need full crawling or spidering
- you need authenticated scanning workflows
- you want exploit confirmation or a broad template corpus

That positioning is deliberate: `surface-audit` is strongest as a
**pre-deploy security smoke test**, not as a full DAST platform.

## Quick Start

```bash
pipx install surface-audit

surface-audit scan https://preview.example.com \
    --scope-host preview.example.com \
    --fail-on HIGH
```

Detailed installation: [`docs/INSTALL.md`](docs/INSTALL.md).

## Distribution Options

- **PyPI** — best when you want the CLI in `pipx`, a virtualenv, or
  your own Python-based tooling.
- **GHCR** — best when your CI prefers a prebuilt container image over
  installing Python dependencies at runtime.
- **GitHub Action** — best when a preview-environment workflow already
  lives in GitHub Actions and you want the shortest integration path.

Container-first teams can use the published GHCR image on tagged
releases:

```bash
docker run --rm ghcr.io/dev-ugurkontel/surface-audit:latest \
    scan https://preview.example.com --fail-on HIGH
```

Use the GitHub Action `@v1` tag for the stable major line, or pin an
exact action release such as `@v1.0.2` when you want fully reproducible
workflow inputs. Tagged releases also publish GitHub Release artifacts,
CycloneDX SBOMs, and Sigstore signatures.

More end-to-end patterns: [`docs/RECIPES.md`](docs/RECIPES.md). Release
and tag-management details: [`docs/RELEASE.md`](docs/RELEASE.md).

## Security Regression Diff

```bash
# Capture a baseline once
surface-audit scan https://preview.example.com \
    --output reports/baseline.json \
    --format json

# Gate only on newly introduced HIGH+ findings
surface-audit scan https://preview.example.com \
    --baseline reports/baseline.json \
    --fail-on HIGH

# Or diff two reports explicitly
surface-audit diff reports/before.json reports/after.json \
    --output reports/diff.json \
    --fail-on-new
```

## GitHub Action

The repository ships an action at the repo root so you can run the scan
in a preview-environment workflow without hand-rolling install steps:

```yaml
- name: Run surface-audit
  uses: dev-ugurkontel/surface-audit@v1
  with:
    target: ${{ steps.preview.outputs.url }}
    scope-hosts: preview.example.com
    output: reports/surface-audit.sarif
    format: sarif
    fail-on: HIGH

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: reports/surface-audit.sarif
```

More end-to-end patterns: [`docs/RECIPES.md`](docs/RECIPES.md).

## Sample Output

```text
Target: https://preview.example.com/
Summary: HIGH 1  MEDIUM 2  LOW 1

HIGH     security-headers        Missing Content-Security-Policy header
MEDIUM   auth-cookies            Cookie 'sessionid' missing SameSite
MEDIUM   security-txt            Missing /.well-known/security.txt
LOW      directory-listing       Auto-generated index page exposed
```

## Built-in checks

| Check ID                 | OWASP | Summary                                                                 |
| ------------------------ | ----- | ----------------------------------------------------------------------- |
| `security-headers`       | A05   | Missing and weakly-configured HSTS / CSP / XFO / Referrer / Permissions |
| `ssl-tls`                | A02   | Weak ciphers or obsolete TLS versions                                   |
| `https-redirect`         | A02   | Plain HTTP does not redirect to HTTPS                                   |
| `cross-origin-isolation` | A05   | Missing COOP / COEP / CORP isolation headers                            |
| `xss-reflection`         | A03   | Query-string input reflected without output encoding                    |
| `sql-injection`          | A03   | Database error messages leaked on meta-character input                  |
| `csrf`                   | A01   | Mutating HTML forms without a recognizable anti-CSRF token              |
| `auth-cookies`           | A07   | Cookies missing `Secure` / `HttpOnly` / `SameSite`                      |
| `open-redirect`          | A01   | Query parameters that allow off-origin 30x redirects                    |
| `misconfiguration`       | A05   | Well-known exposed paths (`.env`, `.git`, admin consoles)               |
| `directory-listing`      | A05   | Auto-generated directory index pages                                    |
| `cors`                   | A05   | Permissive CORS reflections and wildcard-with-credentials               |
| `security-txt`           | A09   | Missing `/.well-known/security.txt` (RFC 9116)                          |

Run `surface-audit list-checks` to see what is registered in your
environment (including any third-party plugins).

## Usage

```bash
# Save a JSON report and fail CI on HIGH+ findings
surface-audit scan https://example.com \
    --output reports/example.json --format json --fail-on HIGH

# Emit SARIF for GitHub Advanced Security
surface-audit scan https://example.com \
    --output reports/example.sarif --format sarif

# Run only a subset of checks
surface-audit scan https://example.com \
    --enable security-headers --enable ssl-tls
```

Full CLI and library reference: [`docs/USAGE.md`](docs/USAGE.md).

## MCP integration

```bash
pip install "surface-audit[mcp]"
surface-audit mcp-serve --allow-host staging.example.com
```

This exposes `scan`, `list_checks`, `list_formats`, and `render_report`
tools to local MCP clients while keeping scans gated behind an explicit
host allow-list.

## Project Site

The project site highlights the smoke-test workflow, GitHub Action,
sample artifacts, and core adoption patterns:

- [Project landing page](https://dev-ugurkontel.github.io/surface-audit/)
- [Console sample](https://dev-ugurkontel.github.io/surface-audit/samples/preview-report.console.txt)
- [HTML sample](https://dev-ugurkontel.github.io/surface-audit/samples/preview-report.html)
- [SARIF sample](https://dev-ugurkontel.github.io/surface-audit/samples/preview-report.sarif.json)

Download trends remain available via
[PyPI Stats](https://pypistats.org/packages/surface-audit).

## Library example

```python
import asyncio
from surface_audit import Scanner, ScannerConfig

async def main() -> None:
    report = await Scanner(
        "https://example.com",
        config=ScannerConfig(max_concurrency=4, timeout=5.0),
    ).run()
    for finding in report.findings:
        print(finding.severity.value, finding.check_id, finding.title)

asyncio.run(main())
```

## Extend it

Any package shipping an entry point under `surface_audit.checks` adds a
check. A starter template for third-party checks lives under
[`examples/plugin-template`](examples/plugin-template):

```toml
# your-plugin/pyproject.toml
[project.entry-points."surface_audit.checks"]
cors_wildcard = "my_checks.cors:PermissiveCORSCheck"
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for layering, SOLID
scorecard, and design patterns.

## Documentation

- [`docs/INSTALL.md`](docs/INSTALL.md) — per-platform installation
- [`docs/USAGE.md`](docs/USAGE.md) — CLI, library, and CI recipes
- [`docs/RECIPES.md`](docs/RECIPES.md) — preview, SARIF, baseline, MCP, and action recipes
- [`docs/RELEASE.md`](docs/RELEASE.md) — PyPI, GHCR, GitHub Release, and `v1` tag process
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — layering and extension points
- [`docs/SCHEMA.md`](docs/SCHEMA.md) — JSON report contract
- [`examples/plugin-template`](examples/plugin-template) — starter template for third-party checks
- [`SUPPORT.md`](SUPPORT.md) — where to ask questions and report the right thing
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — development workflow
- [`SECURITY.md`](SECURITY.md) — vulnerability disclosure
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — community expectations

## Development

```bash
make install   # set up .venv with dev extras
make all       # ruff + mypy + bandit + pytest
```

CI runs on every push across Python 3.10 – 3.13 — see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## License

[Apache License 2.0](LICENSE) — Copyright © 2026 Uğur Kontel. See also
[`NOTICE`](NOTICE) for attribution requirements that apply to
redistributions.

---

`surface-audit` is an open-source project from
[Fillbyte](https://fillbyte.com).
