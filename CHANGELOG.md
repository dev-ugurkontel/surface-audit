# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.2] - 2026-04-21

### Added

- A fuller `docs/RECIPES.md` preview-environment workflow showing how
  to keep a trusted baseline in the repository, diff against it in CI,
  upload SARIF, and preserve raw report artifacts for debugging.
- Representative sample artifacts on the project site for console, HTML,
  and SARIF output so visitors can inspect real report shapes quickly.
- A starter template under `examples/plugin-template` for authors who
  want to ship third-party `surface-audit` checks with entry-point
  wiring and tests already in place.
- A docs-link regression test so broken relative Markdown links are
  caught in CI instead of after release.

### Changed

- PyPI metadata and README positioning now describe `surface-audit`
  primarily as a deterministic preview/staging security smoke test.
- GitHub Action and SARIF examples now reference the current
  `github/codeql-action/upload-sarif@v4` line.
- Release automation now maintains the GitHub Action major tag `v1`
  alongside versioned tags so `uses: dev-ugurkontel/surface-audit@v1`
  stays valid after future releases.

### Fixed

- Reworked the README distribution section so GHCR, PyPI, and GitHub
  Action guidance reads as one coherent story instead of three
  disconnected notes.

## [1.0.1] - 2026-04-20

### Added

- `Changelog` and `Funding` URLs under `[project.urls]` so the PyPI
  project sidebar links to the release history and the GitHub
  Sponsors page directly.

### Changed

- **CI toolchain** bumped to current stable versions:
  `actions/checkout` v6.0.2, `actions/setup-python` v6.2.0,
  `actions/upload-artifact` v7.0.1, `actions/download-artifact` v8.0.1,
  `sigstore/gh-action-sigstore-python` v3.3.0.
- **Pre-commit hooks** refreshed: `ruff` v0.15.11, `mypy` v1.20.1,
  `bandit` 1.9.4, `gitleaks` v8.30.1, `pre-commit-hooks` v6.0.0.

### Fixed

- **Release workflow (publish)**: strip non-distribution files from
  the artifact before the PyPI upload. The CycloneDX SBOM under
  `dist/` was causing `twine` to reject the entire batch with
  `InvalidDistribution: Unknown distribution format: 'sbom.cdx.json'`.
- **Release workflow (idempotency)**: `publish-pypi` now uses
  `skip-existing: true`, and the GitHub Release step reuses the
  existing release via `gh release upload --clobber` when one is
  already present. Re-triggering a release for the same tag no
  longer requires manual cleanup.

## [1.0.0] - 2026-04-19

Initial public release.

### Added

- Modular asynchronous scanner core with 13 built-in checks covering
  OWASP Top 10 (2021) categories: security headers (presence and value
  analysis), TLS posture, HTTPS redirect, reflected XSS, error-based
  SQLi, CSRF, cookie hardening, misconfiguration probes, directory
  listing, CORS, security.txt, cross-origin isolation, and open
  redirect.
- Entry-point plugin architecture for checks and renderers.
- Five built-in report formats: Rich console, JSON, HTML, SARIF 2.1.0,
  and GitHub-flavored Markdown for PR comments.
- Typer-based CLI with `scan`, `diff`, `list-checks`, `list-formats`,
  and `mcp-serve` subcommands.
- TOML configuration (`surface-audit.toml` or `[tool.surface-audit]`
  in `pyproject.toml`) with strict schema validation.
- Baseline / diff mode for CI adoption: `--baseline PATH` suppresses
  known findings; `diff` compares two reports.
- Scope allow-list enforced at both CLI (`--scope-host`) and MCP
  server layers via shared `ScopePolicy`.
- Model Context Protocol server (`mcp-serve`) with host allow-list,
  shipped as the `[mcp]` extra.
- Structured JSON logging (`--log-format json`).
- Tag-triggered release pipeline: PyPI Trusted Publishing via OIDC,
  CycloneDX SBOM, sigstore artifact signing, GitHub Release.
- JSON Schema 2020-12 contract for the report format
  (`schemas/report.schema.json`, documented in `docs/SCHEMA.md`).
- 100 % line and branch coverage enforced in CI.
