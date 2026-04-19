"""Tests for ScannerConfig.__post_init__ validation."""

from __future__ import annotations

import pytest

from surface_audit.exceptions import ConfigError
from surface_audit.scanner import ScannerConfig


@pytest.mark.parametrize(
    "kwargs, match",
    [
        ({"timeout": 0}, "timeout"),
        ({"timeout": -1}, "timeout"),
        ({"timeout": "fast"}, "timeout"),
        ({"timeout": True}, "timeout"),
        ({"max_concurrency": 0}, "max_concurrency"),
        ({"max_concurrency": -3}, "max_concurrency"),
        ({"max_concurrency": True}, "max_concurrency"),
        ({"max_concurrency": 1.5}, "max_concurrency"),
        ({"verify_tls": "yes"}, "verify_tls"),
        ({"follow_redirects": "yes"}, "follow_redirects"),
        ({"user_agent": ""}, "user_agent"),
        ({"user_agent": "   "}, "user_agent"),
        ({"proxy": ""}, "proxy"),
        ({"retry_attempts": 0}, "retry_attempts"),
        ({"retry_attempts": -5}, "retry_attempts"),
        ({"retry_attempts": True}, "retry_attempts"),
        ({"retry_backoff": -0.1}, "retry_backoff"),
        ({"retry_backoff": "slow"}, "retry_backoff"),
    ],
)
def test_invalid_values_raise_config_error(kwargs: dict, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        ScannerConfig(**kwargs)


def test_valid_defaults_construct_cleanly() -> None:
    cfg = ScannerConfig()
    assert cfg.timeout == 10.0
    assert cfg.retry_attempts == 3


def test_enabled_checks_must_contain_strings() -> None:
    with pytest.raises(ConfigError, match="enabled_checks"):
        ScannerConfig(enabled_checks=frozenset({1, 2}))  # type: ignore[arg-type]


def test_disabled_checks_must_contain_strings() -> None:
    with pytest.raises(ConfigError, match="disabled_checks"):
        ScannerConfig(disabled_checks=frozenset({1, 2}))  # type: ignore[arg-type]


def test_valid_override_accepts_everything() -> None:
    cfg = ScannerConfig(
        timeout=5.5,
        max_concurrency=4,
        verify_tls=False,
        follow_redirects=False,
        user_agent="acme-bot/1.0",
        proxy="http://127.0.0.1:8080",
        retry_attempts=1,
        retry_backoff=0.0,
    )
    assert cfg.max_concurrency == 4
    assert cfg.verify_tls is False
