# Contributing to surface-audit

Thanks for your interest in improving `surface-audit`.

The project is intentionally narrow: it focuses on safe, deterministic
security smoke tests for known web URLs such as staging, preview, and
pre-deploy environments. Contributions are welcome when they make that
core story clearer, safer, easier to adopt, or easier to extend.

## The best kinds of contributions

- Bug fixes in existing checks, reports, CLI behavior, or MCP support.
- Documentation improvements, copy-paste fixes, recipes, and examples.
- CI / packaging / release hardening.
- Integrations such as GitHub Actions, SARIF workflows, Docker, and MCP.
- New checks or report formats that fit the project's scope, especially
  when they can be shipped as plugins.

## Before you open a PR

Small docs, typo, example, or tooling fixes can be opened directly.

For anything larger, please open an issue or discussion first so we can
confirm fit and avoid wasted work. This is especially helpful for:

- new built-in checks
- CLI or library API changes
- changes that expand scope
- large refactors

If a feature is valuable but too specific for the core project, a plugin
or companion repository is often the best path.

## Development workflow

```bash
git clone https://github.com/dev-ugurkontel/surface-audit.git
cd surface-audit
make install   # creates .venv, installs dev extras, sets up pre-commit
make all       # ruff + format check + mypy + bandit + pytest (100%)
```

## Quality expectations

Every PR should keep the repo's existing quality bar intact:

- `make all` passes locally
- tests remain at 100% line and branch coverage
- user-visible behavior changes are reflected in `README.md` and `docs/`
- new checks include tests and entry-point registration when relevant
- meaningful user-facing changes are noted in `CHANGELOG.md`

## Review expectations

`surface-audit` is maintained by one primary maintainer, so review and
merge timing is best-effort rather than guaranteed. Contributions are
welcome, but merges stay intentionally curated so the tool can remain
small, predictable, and safe by default.

## Support and security

- Usage questions: see [`SUPPORT.md`](SUPPORT.md) and GitHub Discussions.
- Security vulnerabilities in `surface-audit` itself: use the private
  reporting path in [`SECURITY.md`](SECURITY.md), not public issues.

## License

By submitting a contribution, you agree that it will be licensed under
the Apache License 2.0 terms already used by this repository.
