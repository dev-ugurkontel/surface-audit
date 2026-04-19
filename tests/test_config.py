"""Tests for the TOML config loader."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from surface_audit.config import load
from surface_audit.exceptions import ConfigError

if TYPE_CHECKING:
    from pathlib import Path


def test_loads_dedicated_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "surface-audit.toml").write_text(
        "timeout = 42.0\nmax_concurrency = 2\n", encoding="utf-8"
    )
    cfg = load()
    assert cfg == {"timeout": 42.0, "max_concurrency": 2}


def test_loads_pyproject_tool_table(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text(
        '[tool.surface-audit]\nuser_agent = "acme-bot"\n', encoding="utf-8"
    )
    cfg = load()
    assert cfg == {"user_agent": "acme-bot"}


def test_explicit_path_wins(tmp_path: Path) -> None:
    path = tmp_path / "custom.toml"
    path.write_text('disabled_checks = ["xss-reflection"]\n', encoding="utf-8")
    cfg = load(path)
    assert cfg == {"disabled_checks": frozenset({"xss-reflection"})}


def test_unknown_keys_fail(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text("what_is_this = 1\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load(path)


def test_malformed_list_fails(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text("enabled_checks = [1, 2]\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load(path)


def test_missing_returns_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert load() == {}


@pytest.mark.parametrize(
    "snippet, match",
    [
        ('timeout = "fast"\n', "timeout"),
        ("max_concurrency = true\n", "max_concurrency"),
        ('verify_tls = "yes"\n', "verify_tls"),
        ("retry_attempts = 1.5\n", "retry_attempts"),
        ('retry_backoff = "slow"\n', "retry_backoff"),
        ("user_agent = 42\n", "user_agent"),
        ("proxy = 123\n", "proxy"),
    ],
)
def test_loader_rejects_wrong_types(tmp_path: Path, snippet: str, match: str) -> None:
    """Regression for loader-side validation."""
    path = tmp_path / "config.toml"
    path.write_text(snippet, encoding="utf-8")
    with pytest.raises(ConfigError, match=match):
        load(path)


def test_loader_rejects_malformed_toml(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text("timeout = [[[\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load(path)


def test_loader_handles_non_dict_tool_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text(
        '[tool]\nsurface-audit = "not-a-table"\n', encoding="utf-8"
    )
    assert load() == {}


def test_loader_handles_missing_owasp_table_in_pyproject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("[tool.black]\n", encoding="utf-8")
    assert load() == {}


def test_loader_rejects_non_string_in_disabled_checks(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text("disabled_checks = [1, 2]\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load(path)


def test_loader_raises_for_explicit_missing_path(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load(tmp_path / "does-not-exist.toml")


def test_loader_accepts_bool(tmp_path: Path) -> None:
    path = tmp_path / "ok.toml"
    path.write_text("verify_tls = true\nfollow_redirects = false\n", encoding="utf-8")
    cfg = load(path)
    assert cfg == {"verify_tls": True, "follow_redirects": False}


def test_loader_handles_scalar_tool_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Covers the `not isinstance(tool, dict)` branch in _tool_table."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text('tool = "scalar"\n', encoding="utf-8")
    assert load() == {}
