# Security Policy

## Reporting a vulnerability in `surface-audit`

If you discover a security issue in the scanner itself — for example, a
way the tool could be tricked into attacking an unintended host, leaking
secrets from the environment, or silently skipping findings —
**do not open a public issue**.

### Preferred channel

Open a private advisory on GitHub:

> **[github.com/dev-ugurkontel/surface-audit/security/advisories/new](https://github.com/dev-ugurkontel/surface-audit/security/advisories/new)**

GitHub Security Advisories keep the report private, track the fix
through a CVE if one is warranted, and coordinate disclosure.

Include:

- a concise description of the issue,
- reproduction steps or a minimal proof of concept,
- the affected version (from `surface-audit --version`) and OS / Python.

### Response time

- Acknowledgement: within **3 working days**.
- Mitigation plan or fix for confirmed issues: within **30 days**.

## Supported versions

Only the latest `1.x` release receives security fixes. Pin to a specific
version in CI and update regularly.

## Responsible use

`surface-audit` sends real HTTP requests to the target URL. Running it
against a system you do not own or have written authorization to test
is likely illegal in your jurisdiction. The maintainer accepts no
liability for misuse.
