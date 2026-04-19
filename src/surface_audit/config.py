"""Loading of user configuration from TOML files.

The configuration precedence is (highest to lowest):

1. Arguments passed to the CLI.
2. A file passed via ``--config PATH``.
3. ``./surface-audit.toml`` in the current working directory.
4. ``[tool.surface-audit]`` section inside ``./pyproject.toml``.
5. Hard-coded defaults in :class:`ScannerConfig`.

Only documented keys are accepted; unknown keys raise :class:`ConfigError`
so typos surface immediately instead of silently doing nothing.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):  # pragma: no cover
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

from surface_audit.exceptions import ConfigError

_TableExtractor = Callable[[dict[str, Any]], dict[str, Any] | None]

_VALID_KEYS: frozenset[str] = frozenset(
    {
        "timeout",
        "max_concurrency",
        "verify_tls",
        "follow_redirects",
        "user_agent",
        "proxy",
        "enabled_checks",
        "disabled_checks",
        "retry_attempts",
        "retry_backoff",
    }
)


def load(path: Path | None = None) -> dict[str, Any]:
    """Return a dict of scanner-config overrides found on disk.

    ``path`` is searched first; when missing, the default search path is
    ``./surface-audit.toml`` then ``./pyproject.toml`` (the
    ``[tool.surface-audit]`` table).
    """
    if path is not None:
        return _read_scanner_table(path, _top_level)

    dedicated = Path("surface-audit.toml")
    if dedicated.is_file():
        return _read_scanner_table(dedicated, _top_level)

    pyproject = Path("pyproject.toml")
    if pyproject.is_file():
        return _read_scanner_table(pyproject, _tool_table)

    return {}


def _read_scanner_table(path: Path, extract: _TableExtractor) -> dict[str, Any]:
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc

    table = extract(data)
    if table is None:
        return {}

    unknown = set(table) - _VALID_KEYS
    if unknown:
        raise ConfigError(f"unknown configuration keys in {path}: {', '.join(sorted(unknown))}")

    return {key: _coerce(key, value) for key, value in table.items()}


_BOOL_KEYS: frozenset[str] = frozenset({"verify_tls", "follow_redirects"})
_INT_KEYS: frozenset[str] = frozenset({"max_concurrency", "retry_attempts"})
_FLOAT_KEYS: frozenset[str] = frozenset({"timeout", "retry_backoff"})
_STRING_KEYS: frozenset[str] = frozenset({"user_agent", "proxy"})
_SET_KEYS: frozenset[str] = frozenset({"enabled_checks", "disabled_checks"})


def _coerce(key: str, value: Any) -> Any:
    if key in _SET_KEYS:
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise ConfigError(f"{key!r} must be a list of strings")
        return frozenset(value)
    if key in _BOOL_KEYS:
        if not isinstance(value, bool):
            raise ConfigError(f"{key!r} must be a boolean, got {type(value).__name__}")
        return value
    if key in _INT_KEYS:
        # bool is a subclass of int; reject to catch True/False typos.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{key!r} must be an integer, got {type(value).__name__}")
        return value
    if key in _FLOAT_KEYS:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{key!r} must be a number, got {type(value).__name__}")
        return float(value)
    if key in _STRING_KEYS:
        if not isinstance(value, str):
            raise ConfigError(f"{key!r} must be a string, got {type(value).__name__}")
        return value
    return value  # pragma: no cover — _VALID_KEYS gates this path


def _top_level(data: dict[str, Any]) -> dict[str, Any] | None:
    return data or None


def _tool_table(data: dict[str, Any]) -> dict[str, Any] | None:
    tool = data.get("tool", {})
    if not isinstance(tool, dict):
        return None
    table = tool.get("surface-audit")
    return table if isinstance(table, dict) else None
