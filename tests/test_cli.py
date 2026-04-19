"""CLI tests via typer.testing.CliRunner."""

from __future__ import annotations

import json
from pathlib import Path  # noqa: TC003 — used at runtime by tmp_path typing
from unittest.mock import patch

import httpx
import pytest  # noqa: TC002 — used at runtime for monkeypatch fixtures
import respx
from typer.testing import CliRunner

from surface_audit.cli import app

runner = CliRunner()


def _mock_clean_target() -> None:
    """Serve a minimal, clean HTTPS response for every path under example.com."""
    headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
    respx.route(url__regex=r"https?://example\.com/.*").mock(
        return_value=httpx.Response(200, text="<html><body>ok</body></html>", headers=headers)
    )
    respx.route(url__regex=r"https?://example\.com").mock(
        return_value=httpx.Response(200, text="<html><body>ok</body></html>", headers=headers)
    )


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "surface-audit" in result.stdout


def test_list_formats_contains_builtins() -> None:
    result = runner.invoke(app, ["list-formats"])
    assert result.exit_code == 0
    assert "json" in result.stdout
    assert "html" in result.stdout
    assert "sarif" in result.stdout


def test_list_checks_includes_csrf() -> None:
    result = runner.invoke(app, ["list-checks"])
    assert result.exit_code == 0
    assert "csrf" in result.stdout


def test_bad_target_exits_cleanly() -> None:
    """Invalid targets must exit cleanly via BadParameter, not with a traceback."""
    result = runner.invoke(app, ["scan", "ftp://example.com"])
    assert result.exit_code == 2
    assert "Traceback" not in (result.stderr or "")


def test_unknown_format_rejected() -> None:
    result = runner.invoke(app, ["scan", "https://example.com", "--format", "xml"])
    assert result.exit_code == 2


@respx.mock
def test_scan_writes_json_report(tmp_path: Path) -> None:
    _mock_clean_target()
    out = tmp_path / "report.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.com",
            "--output",
            str(out),
            "--format",
            "json",
            "--disable",
            "ssl-tls",
            "--disable",
            "https-redirect",
            "--quiet",
        ],
    )
    assert result.exit_code in (0, 2), result.stdout + (result.stderr or "")
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["target"]["url"].startswith("https://example.com")


def test_unknown_enable_id_exits_with_config_error() -> None:
    """Unknown --enable IDs must fail fast rather than silently filter to zero."""
    result = runner.invoke(app, ["scan", "https://example.com", "--enable", "nope"])
    assert result.exit_code == 2
    assert "unknown check id" in (result.stderr or "")


def test_unknown_severity_in_fail_on_is_rejected() -> None:
    result = runner.invoke(app, ["scan", "https://example.com", "--fail-on", "TITANIUM"])
    assert result.exit_code == 2


@respx.mock
def test_fail_on_triggers_nonzero_exit_on_high_finding() -> None:
    # Any cookie without hardening flags raises a HIGH finding.
    respx.route(url__regex=r"https?://example\.com/.*").mock(
        return_value=httpx.Response(
            200,
            text="<html></html>",
            headers={"Set-Cookie": "sid=abc; Path=/"},
        )
    )
    respx.route(url__regex=r"https?://example\.com").mock(
        return_value=httpx.Response(
            200,
            text="<html></html>",
            headers={"Set-Cookie": "sid=abc; Path=/"},
        )
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.com",
            "--quiet",
            "--fail-on",
            "HIGH",
            "--disable",
            "ssl-tls",
            "--disable",
            "https-redirect",
        ],
    )
    assert result.exit_code == 2


def test_verbose_flag_sets_logging(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["scan", "https://example.com", "-vv", "--disable", "ssl-tls", "--quiet"],
    )
    # We don't assert on content, only that -vv doesn't crash the CLI.
    assert result.exit_code in (0, 2)


def test_malformed_config_file_exits_with_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text("timeout = [not a number]\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", "https://example.com", "--config", str(bad), "--quiet"])
    assert result.exit_code == 2


def test_keyboard_interrupt_is_caught() -> None:
    """Covers the KeyboardInterrupt branch in scan()."""
    import surface_audit.cli as cli_mod

    with patch.object(cli_mod.asyncio, "run", side_effect=KeyboardInterrupt):
        result = runner.invoke(app, ["scan", "https://example.com", "--quiet"])
    assert result.exit_code == 130


@respx.mock
def test_build_config_wires_every_cli_override() -> None:
    """Covers every optional branch in _build_config."""
    _mock_clean_target()
    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.com",
            "--timeout",
            "5",
            "--concurrency",
            "4",
            "--verify",
            "--enable",
            "security-headers",
            "--disable",
            "ssl-tls",
            "--proxy",
            "http://127.0.0.1:8080",
            "--user-agent",
            "bot/1.0",
            "--quiet",
        ],
    )
    assert result.exit_code in (0, 2), result.stderr


@respx.mock
def test_scan_renders_console_when_not_quiet() -> None:
    """Covers the `render_console(...)` branch when --quiet is absent."""
    _mock_clean_target()
    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.com",
            "--disable",
            "ssl-tls",
            "--disable",
            "https-redirect",
        ],
    )
    assert result.exit_code in (0, 2)
    # Rich's output lands on stdout in test mode.
    assert "surface-audit" in result.stdout or "findings" in result.stdout


def test_timeout_zero_exits_with_config_error() -> None:
    """Covers the ConfigError branch around _build_config in scan()."""
    result = runner.invoke(app, ["scan", "https://example.com", "--timeout", "0"])
    assert result.exit_code == 2


@respx.mock
def test_scope_host_denies_out_of_scope_target(tmp_path: Path) -> None:
    _mock_clean_target()
    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.com",
            "--scope-host",
            "only-this.example",
            "--quiet",
        ],
    )
    assert result.exit_code == 2
    assert "allow-list" in (result.stderr or "")


@respx.mock
def test_scope_env_var_is_honored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_clean_target()
    monkeypatch.setenv("SURFACE_AUDIT_SCOPE_HOSTS", "other.example")
    result = runner.invoke(app, ["scan", "https://example.com", "--quiet"])
    assert result.exit_code == 2
    assert "allow-list" in (result.stderr or "")


@respx.mock
def test_scope_host_allows_in_scope_target(tmp_path: Path) -> None:
    _mock_clean_target()
    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.com",
            "--scope-host",
            "example.com",
            "--disable",
            "ssl-tls",
            "--disable",
            "https-redirect",
            "--quiet",
        ],
    )
    assert result.exit_code in (0, 2)


@respx.mock
def test_baseline_suppresses_known_findings(tmp_path: Path) -> None:
    # Serve a response that will produce a HIGH cookie finding.
    respx.route(url__regex=r"https?://example\.com/.*").mock(
        return_value=httpx.Response(
            200,
            text="<html></html>",
            headers={"Set-Cookie": "sid=abc; Path=/"},
        )
    )
    respx.route(url__regex=r"https?://example\.com").mock(
        return_value=httpx.Response(
            200,
            text="<html></html>",
            headers={"Set-Cookie": "sid=abc; Path=/"},
        )
    )

    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "check_id": "auth-cookies",
                        "title": "Cookie 'sid' missing hardening attributes",
                        "location": "https://example.com/",
                        "severity": "HIGH",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.com",
            "--baseline",
            str(baseline),
            "--fail-on",
            "HIGH",
            # Only run the auth-cookies check so the HIGH cookie finding is
            # the only finding and the baseline suppresses it cleanly.
            "--enable",
            "auth-cookies",
            "--quiet",
        ],
    )
    assert result.exit_code == 0


def test_baseline_missing_file_exits_with_config_error(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.com",
            "--baseline",
            str(tmp_path / "nope.json"),
            "--disable",
            "ssl-tls",
            "--quiet",
        ],
    )
    assert result.exit_code == 2


def test_diff_command_emits_added_removed_unchanged(tmp_path: Path) -> None:
    base = tmp_path / "before.json"
    head = tmp_path / "after.json"
    base.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "check_id": "csrf",
                        "title": "T",
                        "severity": "HIGH",
                        "description": "d",
                        "recommendation": "r",
                        "category": "A01:2021 - Broken Access Control",
                        "location": "x",
                        "references": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    head.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "check_id": "cors",
                        "title": "new",
                        "severity": "MEDIUM",
                        "description": "d",
                        "recommendation": "r",
                        "category": "A05:2021 - Security Misconfiguration",
                        "location": "x",
                        "references": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "diff.json"
    result = runner.invoke(
        app,
        ["diff", str(base), str(head), "--output", str(out), "--fail-on-new"],
    )
    assert result.exit_code == 2  # new finding triggered the fail-on-new gate
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["summary"]["added"] == 1
    assert payload["summary"]["removed"] == 1
    assert payload["summary"]["unchanged"] == 0


def test_diff_command_missing_file_exits_cleanly(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path / "nope.json"),
            str(tmp_path / "also_nope.json"),
        ],
    )
    assert result.exit_code == 2


def test_diff_command_without_fail_on_new_exits_zero(tmp_path: Path) -> None:
    empty = tmp_path / "e.json"
    empty.write_text(json.dumps({"findings": []}), encoding="utf-8")
    result = runner.invoke(app, ["diff", str(empty), str(empty)])
    assert result.exit_code == 0


def test_json_log_format_smoke(tmp_path: Path) -> None:
    # Just assert that --log-format json doesn't crash the CLI.
    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.com",
            "--log-format",
            "json",
            "-v",
            "--disable",
            "ssl-tls",
            "--quiet",
        ],
    )
    assert result.exit_code in (0, 2)


def test_json_log_format_emits_valid_json_line() -> None:
    import io
    import logging

    from surface_audit.cli import LogFormat, _configure_logging

    _configure_logging(verbosity=2, fmt=LogFormat.json)
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(logging.getLogger().handlers[0].formatter)
    logging.getLogger().addHandler(handler)
    try:
        logging.getLogger("surface_audit.test").info("hello world")
    finally:
        logging.getLogger().removeHandler(handler)

    line = buf.getvalue().strip().splitlines()[-1]
    payload = json.loads(line)
    assert payload["message"] == "hello world"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "surface_audit.test"
    assert "ts" in payload


def test_json_log_format_includes_exception_info() -> None:
    import io
    import logging

    from surface_audit.cli import LogFormat, _configure_logging

    _configure_logging(verbosity=2, fmt=LogFormat.json)
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(logging.getLogger().handlers[0].formatter)
    logging.getLogger().addHandler(handler)
    try:
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            logging.getLogger("surface_audit.test").exception("bad thing")
    finally:
        logging.getLogger().removeHandler(handler)

    line = buf.getvalue().strip().splitlines()[-1]
    payload = json.loads(line)
    assert "exc_info" in payload
    assert "RuntimeError" in payload["exc_info"]


def test_mcp_serve_invokes_server_run() -> None:
    """``mcp-serve`` subcommand must delegate to the MCP server entry point."""
    with patch("surface_audit.mcp_server.run") as fake_run:
        result = runner.invoke(
            app,
            ["mcp-serve", "--allow-host", "example.com", "--allow-host", "other.example"],
        )
    assert result.exit_code == 0, result.stderr
    fake_run.assert_called_once()
    kwargs = fake_run.call_args.kwargs
    assert kwargs["allow_any_host"] is False
    assert kwargs["allowed_hosts"] == frozenset({"example.com", "other.example"})


@respx.mock
def test_renderer_error_on_output_exits_cleanly(tmp_path: Path) -> None:
    """Covers the RendererError branch in scan()."""
    import surface_audit.cli as cli_mod
    from surface_audit.exceptions import RendererError

    _mock_clean_target()
    with patch.object(cli_mod, "write", side_effect=RendererError("boom")):
        result = runner.invoke(
            app,
            [
                "scan",
                "https://example.com",
                "--output",
                str(tmp_path / "out.json"),
                "--disable",
                "ssl-tls",
                "--disable",
                "https-redirect",
                "--quiet",
            ],
        )
    assert result.exit_code == 2
