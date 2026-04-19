# Installation

`surface-audit` requires **Python 3.10 or newer**. Pick the path that
matches how you will use it.

## 1. End-user (CLI only)

The recommended tool is [pipx](https://pipx.pypa.io/), which installs
the CLI into its own isolated environment:

```bash
# macOS / Linux
brew install pipx    # or: python3 -m pip install --user pipx
pipx ensurepath
pipx install surface-audit

# Windows (PowerShell)
scoop install pipx   # or: py -m pip install --user pipx
pipx ensurepath
pipx install surface-audit
```

Verify:

```bash
surface-audit --version
```

## 2. Inside a Python project

```bash
python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install surface-audit
```

## 3. From source (for contributors)

```bash
git clone https://github.com/dev-ugurkontel/surface-audit.git
cd surface-audit
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

Run the full quality gate:

```bash
make all   # lint + typecheck + security + tests
```

## 4. Docker

```bash
docker build -t surface-audit:local .
docker run --rm surface-audit:local scan https://example.com
```

The image uses a non-root user (UID 10001) and contains only the
packaged wheel — no build tools or test artifacts.

## Platform notes

### macOS

The system Python at `/usr/bin/python3` is **3.9** on macOS 14+ and is
too old. Use Homebrew:

```bash
brew install python@3.12
/opt/homebrew/bin/python3.12 -m venv .venv
```

### Linux (Debian / Ubuntu)

```bash
sudo apt-get install -y python3.12 python3.12-venv
python3.12 -m venv .venv
```

### Windows

Install Python 3.12 from [python.org](https://www.python.org/downloads/)
or via the Microsoft Store, then use `py -3.12 -m venv .venv`.

## Upgrading

```bash
pipx upgrade surface-audit          # if installed via pipx
pip install --upgrade surface-audit # if installed into a venv
```

## Uninstalling

```bash
pipx uninstall surface-audit
```

## Troubleshooting

| Symptom                                    | Cause                                | Fix                                                           |
| ------------------------------------------ | ------------------------------------ | ------------------------------------------------------------- |
| `zsh: command not found: python`           | macOS has no `python` alias          | Use `python3` or create a venv                                |
| `ModuleNotFoundError: No module named ...` | Package not installed into this venv | `pip install -e .` in the project dir                         |
| `surface-audit: command not found`         | `~/.local/bin` not in `PATH`         | `pipx ensurepath` then re-open the terminal                   |
| SSL handshake errors                       | Corporate proxy or MITM              | Use `--insecure` for lab testing, or set `REQUESTS_CA_BUNDLE` |
