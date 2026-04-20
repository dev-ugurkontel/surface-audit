# surface-audit plugin template

This starter gives third-party authors a minimal, tested layout for a
custom `surface-audit` check package.

## What is included

- a tiny `X-Powered-By` check under `src/`
- entry-point wiring in `pyproject.toml`
- an async `respx`-based test
- a package layout you can rename and publish

## How to adapt it

1. Rename the package directory under `src/`.
2. Change the distribution name in `pyproject.toml`.
3. Replace `PoweredByHeaderCheck` with your own check class.
4. Update the entry point under `[project.entry-points."surface_audit.checks"]`.
5. Expand the tests to cover your check's success and failure paths.

## Local development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Install into a host project

```bash
pip install surface-audit /path/to/your-plugin
surface-audit list-checks
```

The new check should appear alongside the built-in ones.
