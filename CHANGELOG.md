# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
