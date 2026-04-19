# Contributing to surface-audit

Thank you for reading this before opening an issue or PR. Please read
this whole file — it sets expectations that will save everyone time.

## Maintenance model

`surface-audit` is a **solo-maintained** project. One person (the
copyright holder) makes every merge decision and writes the release
notes. That has concrete consequences:

- **Bug reports are welcome.** If something is broken, file an issue
  using the bug-report template and include a minimal reproduction.
  Real bugs usually get fixed.
- **Feature requests are read but rarely accepted.** The project has a
  deliberate, narrow scope (see [`README.md`](README.md)). Requests that
  expand the scope will most likely be closed with a short explanation.
- **Pull requests are accepted at the maintainer's discretion.** There
  is no SLA, no guarantee of review, and no guarantee of merge — even
  for excellent code. Expect this and do not be offended if a PR is
  closed unmerged.
- **Forks are encouraged.** If your use case diverges from the project
  direction, fork it. That is what the Apache 2.0 license is for.

This is not a social project. If you prefer a community-driven model,
there are many excellent alternatives.

## What still belongs in issues

- Reproducible bugs in the existing checks, CLI, MCP server, or reports.
- Security vulnerabilities in `surface-audit` itself (see
  [`SECURITY.md`](SECURITY.md) — do **not** file these publicly).
- Documentation errors or copy-paste-broken examples.
- Regressions across supported Python versions (3.10 – 3.13).

## What does not belong in issues

- "Can you add a check for X?" — open it anyway, but expect a short
  answer. The scope is set; the roadmap is in GitHub Milestones.
- Support questions about your specific deployment. Use
  [GitHub Discussions](https://github.com/dev-ugurkontel/surface-audit/discussions)
  instead.
- Marketing, partnerships, sponsorship pitches by email.

## If you still want to send a PR

Read this before writing code:

1. Open an issue first and wait for an explicit "please send a PR" reply.
   Unsolicited PRs will usually be closed.
2. Branch names: `fix/<short-slug>`, `docs/<slug>`, or `feat/<slug>`.
3. The PR must pass the full quality gate: `make all` (ruff + format
   check + mypy `--strict` + bandit + pytest with 100 % line+branch
   coverage). CI will enforce this.
4. Keep the change surgical. Refactors that touch unrelated code will
   be closed without review.
5. By submitting a Contribution, you license it under the Apache
   License 2.0 (Section 5 of `LICENSE`) — that is automatic and
   non-negotiable.

## Development setup

```bash
git clone https://github.com/dev-ugurkontel/surface-audit.git
cd surface-audit
make install   # creates .venv, installs dev extras, sets up pre-commit
make all       # ruff + ruff format --check + mypy + bandit + pytest (100%)
```

## Tooling

- **Formatter / linter:** `ruff format` + `ruff check`
- **Type checker:** `mypy --strict`
- **Security linter:** `bandit`
- **Tests:** `pytest` with 100 % coverage gate
- **Pre-commit:** gitleaks + bandit + ruff + mypy

## One-line summary

**Open an issue, expect a short answer, fork if needed.**
