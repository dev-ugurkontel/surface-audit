"""Tests for the shared scope-allow-list primitives."""

from __future__ import annotations

import pytest

from surface_audit.models import ScanTarget
from surface_audit.scope import ScopeError, ScopePolicy


def test_unrestricted_factory_allows_anything() -> None:
    policy = ScopePolicy.unrestricted()
    policy.enforce(ScanTarget.parse("https://anywhere.example"))


def test_allow_any_short_circuits() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset(), allow_any=True)
    policy.enforce(ScanTarget.parse("https://anywhere.example"))


def test_empty_allowlist_without_allow_any_denies() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset(), allow_any=False)
    with pytest.raises(ScopeError, match="allow-list is empty"):
        policy.enforce(ScanTarget.parse("https://example.com"))


def test_allowed_host_is_case_insensitive() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset({"example.com"}), allow_any=False)
    policy.enforce(ScanTarget.parse("https://EXAMPLE.com"))


def test_not_on_allowlist_raises() -> None:
    policy = ScopePolicy(allowed_hosts=frozenset({"good.example"}), allow_any=False)
    with pytest.raises(ScopeError, match="not on the allow-list"):
        policy.enforce(ScanTarget.parse("https://bad.example"))


def test_from_sources_merges_cli_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_ENV", "a.example, B.example ")
    policy = ScopePolicy.from_sources(frozenset({"c.example"}), env_var="MY_ENV", allow_any=False)
    assert policy.allowed_hosts == frozenset({"a.example", "b.example", "c.example"})
    assert policy.allow_any is False


def test_from_sources_handles_missing_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MY_ENV", raising=False)
    policy = ScopePolicy.from_sources(frozenset({"a.example"}), env_var="MY_ENV", allow_any=False)
    assert policy.allowed_hosts == frozenset({"a.example"})


def test_from_sources_handles_none_cli_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_ENV", "only.example")
    policy = ScopePolicy.from_sources(None, env_var="MY_ENV", allow_any=False)
    assert policy.allowed_hosts == frozenset({"only.example"})
