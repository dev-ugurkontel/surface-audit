# surface-audit

[![CI](https://github.com/dev-ugurkontel/surface-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/dev-ugurkontel/surface-audit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/surface-audit.svg)](https://pypi.org/project/surface-audit/)
[![Python](https://img.shields.io/pypi/pyversions/surface-audit.svg)](https://pypi.org/project/surface-audit/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-blue)](https://mypy.readthedocs.io/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

A modular, asynchronous **web-application security surface auditor**.

`surface-audit` sends a small, configurable set of safe probes at a target
URL, mapping findings to the
[OWASP Top 10 (2021)](https://owasp.org/Top10/) categories where
applicable. It is designed for pre-deployment smoke testing, CI gates,
and as an embeddable Python library. The pluggable architecture
(`surface_audit.checks` entry points) keeps the tool catalog-agnostic —
third-party checks can target any standard (NIST, CIS, ASVS, internal
rules).

> ⚠️ **Authorized use only.** This tool sends real HTTP requests to the
> target. Only run it against systems you own or have explicit written
> permission to test. See [`SECURITY.md`](SECURITY.md).

---

## Highlights

- **Async by default** — checks run concurrently over a shared
  `httpx.AsyncClient` with a semaphore cap and exponential-backoff retries.
- **Plugin architecture** — every check is a class registered via
  Python entry points. Third-party packages add their own without forking.
- **Multiple output formats** — rich console, JSON, HTML, Markdown
  (PR-ready), and [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) for
  GitHub Code Scanning integration.
- **Configurable** — TOML config file (`surface-audit.toml` or
  `[tool.surface-audit]`) plus per-invocation CLI flags.
- **CI-friendly** — `--fail-on HIGH` gates builds on severity; SARIF
  uploads integrate natively with GitHub Advanced Security.
- **Typed, tested, safe** — `mypy --strict`, `ruff`, `bandit`, and a
  `pytest` suite with respx-mocked HTTP tests.

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

## Quick start

```bash
pipx install surface-audit
surface-audit scan https://example.com
```

Detailed per-platform setup: [`docs/INSTALL.md`](docs/INSTALL.md).

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
check:

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
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — layering and extension points
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
