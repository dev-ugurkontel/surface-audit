# Support

Use the right channel so questions and fixes land in the right place.

## Q&A and usage help

Use GitHub Discussions for:

- installation help
- CI and GitHub Actions setup
- MCP configuration questions
- interpreting findings
- choosing flags such as `--fail-on`, `--baseline`, or `--scope-host`

Start here:

- Q&A: <https://github.com/dev-ugurkontel/surface-audit/discussions/categories/q-a>
- Ideas: <https://github.com/dev-ugurkontel/surface-audit/discussions/categories/ideas>
- Show and tell: <https://github.com/dev-ugurkontel/surface-audit/discussions/categories/show-and-tell>

## Open an issue when

- a documented command does not work as described
- a built-in check is producing a false positive or false negative
- a report renderer emits malformed output
- a supported Python version regressed
- documentation contains copy-paste-broken or misleading examples

## Do not open a public issue for

- vulnerabilities in `surface-audit` itself
- secrets, tokens, or private target URLs

Use the private security reporting flow instead:

- [`SECURITY.md`](SECURITY.md)
- <https://github.com/dev-ugurkontel/surface-audit/security/advisories/new>

## Contribution fit

If your idea changes the project's scope substantially, open a
discussion first. `surface-audit` aims to stay focused on safe,
deterministic security smoke tests for known URLs rather than broad
crawling or exploit automation.
