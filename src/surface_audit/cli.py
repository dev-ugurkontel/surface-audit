"""Command-line interface built with Typer.

Run ``surface-audit --help`` for usage. The CLI owns argument parsing,
logging setup, report persistence and exit-code policy; the actual
scanning logic lives in :mod:`surface_audit.scanner`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path  # noqa: TC003 — Typer needs this at runtime for type inference
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.logging import RichHandler

from surface_audit import __version__
from surface_audit import config as config_module
from surface_audit.diff import (
    DiffResult,
    diff_findings,
    load_baseline,
    load_findings,
    new_findings,
)
from surface_audit.exceptions import ConfigError, RendererError
from surface_audit.models import ScanTarget, Severity
from surface_audit.reporting import REGISTRY, render_console, write
from surface_audit.scanner import Scanner, ScannerConfig
from surface_audit.scope import ScopeError, ScopePolicy

ENV_SCOPE_HOSTS = "SURFACE_AUDIT_SCOPE_HOSTS"


class LogFormat(str, Enum):
    rich = "rich"
    json = "json"


app = typer.Typer(
    name="surface-audit",
    help="Modular async web-application security surface auditor.",
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"surface-audit {__version__}")
        raise typer.Exit()


class _JSONFormatter(logging.Formatter):
    """JSON-per-line log formatter for log aggregators."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _configure_logging(verbosity: int, fmt: LogFormat = LogFormat.rich) -> None:
    level = max(logging.DEBUG, logging.WARNING - (verbosity * 10))
    handler: logging.Handler
    if fmt is LogFormat.json:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(_JSONFormatter())
        log_format = "%(message)s"
    else:
        handler = RichHandler(show_path=False, rich_tracebacks=True, markup=True)
        log_format = "%(message)s"
    logging.basicConfig(
        level=level,
        format=log_format,
        datefmt="%H:%M:%S",
        handlers=[handler],
        force=True,  # replace any existing handlers so repeated CLI runs are clean
    )


def _severity_threshold(name: str | None) -> Severity | None:
    if name is None:
        return None
    try:
        return Severity(name.upper())
    except ValueError as exc:
        raise typer.BadParameter(
            f"unknown severity: {name!r}. choose from {[s.value for s in Severity]}"
        ) from exc


def _exceeded_threshold(findings: list, threshold: Severity | None) -> bool:  # type: ignore[type-arg]
    if threshold is None:
        return False
    return any(f.severity.weight >= threshold.weight for f in findings)


def _available_formats() -> list[str]:
    return sorted(REGISTRY)


@app.callback()
def _root(
    _version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = None,
) -> None:
    """Web-application security surface auditor."""


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Target URL (e.g. https://example.com).")],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write a report file. Format given by --format."),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Report format. See list-formats."),
    ] = "json",
    config_path: Annotated[
        Path | None,
        typer.Option("--config", help="Path to a TOML config file overriding defaults."),
    ] = None,
    baseline: Annotated[
        Path | None,
        typer.Option(
            "--baseline",
            help="Suppress findings already present in this prior JSON report "
            "when evaluating --fail-on.",
        ),
    ] = None,
    scope_host: Annotated[
        list[str] | None,
        typer.Option(
            "--scope-host",
            help="Only allow scans of these hostnames (repeatable). "
            "Also reads SURFACE_AUDIT_SCOPE_HOSTS (comma-separated).",
        ),
    ] = None,
    timeout: Annotated[float | None, typer.Option(help="Per-request timeout in seconds.")] = None,
    concurrency: Annotated[
        int | None,
        typer.Option("--concurrency", "-c", help="Maximum concurrent requests."),
    ] = None,
    insecure: Annotated[
        bool | None,
        typer.Option("--insecure/--verify", help="Skip TLS certificate verification."),
    ] = None,
    enable: Annotated[
        list[str] | None,
        typer.Option("--enable", help="Only run these check IDs (repeatable)."),
    ] = None,
    disable: Annotated[
        list[str] | None,
        typer.Option("--disable", help="Skip these check IDs (repeatable)."),
    ] = None,
    proxy: Annotated[
        str | None, typer.Option(help="HTTP(S) proxy, e.g. http://127.0.0.1:8080.")
    ] = None,
    user_agent: Annotated[
        str | None,
        typer.Option("--user-agent", help="Override the default User-Agent header."),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Exit non-zero if any new finding has severity >= this (e.g. HIGH).",
        ),
    ] = None,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Suppress console report output.")
    ] = False,
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase log verbosity (-v, -vv)."),
    ] = 0,
    log_format: Annotated[
        LogFormat, typer.Option("--log-format", help="Log output style.")
    ] = LogFormat.rich,
) -> None:
    """Run a scan against ``TARGET`` and emit findings."""
    _configure_logging(verbose, log_format)

    if fmt not in REGISTRY:
        raise typer.BadParameter(f"--format must be one of {_available_formats()}; got {fmt!r}")

    threshold = _severity_threshold(fail_on)

    try:
        parsed_target = ScanTarget.parse(target)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="TARGET") from exc

    if scope_host or _env_scope_hosts():
        policy = ScopePolicy.from_sources(
            frozenset(scope_host or ()),
            env_var=ENV_SCOPE_HOSTS,
            allow_any=False,
        )
        try:
            policy.enforce(parsed_target)
        except ScopeError as exc:
            typer.secho(str(exc), fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2) from None

    try:
        file_config = config_module.load(config_path)
    except ConfigError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from None

    try:
        config = _build_config(
            file_config,
            timeout=timeout,
            concurrency=concurrency,
            insecure=insecure,
            enable=enable,
            disable=disable,
            proxy=proxy,
            user_agent=user_agent,
        )
    except ConfigError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from None

    baseline_keys: set[tuple[str, str, str, str]] = set()
    if baseline is not None:
        try:
            baseline_keys = load_baseline(baseline)
        except ConfigError as exc:
            typer.secho(str(exc), fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2) from None

    try:
        scanner = Scanner(parsed_target, config=config)
    except ConfigError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from None

    try:
        report = asyncio.run(scanner.run())
    except KeyboardInterrupt:
        typer.secho("scan interrupted", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=130) from None

    if not quiet:
        render_console(report, console=Console())

    if output is not None:
        try:
            write(report, output, fmt)
        except RendererError as exc:
            typer.secho(str(exc), fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2) from None
        typer.secho(f"wrote {fmt.upper()} report → {output}", fg=typer.colors.GREEN, err=True)

    new = new_findings(report.findings, baseline_keys) if baseline_keys else report.findings
    if _exceeded_threshold(new, threshold):
        raise typer.Exit(code=2)


def _env_scope_hosts() -> bool:
    import os  # local import keeps module-scope lean

    return bool(os.environ.get(ENV_SCOPE_HOSTS, "").strip())


@app.command("list-checks")
def list_checks() -> None:
    """List every registered check."""
    console = Console()
    for check in Scanner.discover_checks():
        console.print(
            f"[bold]{check.check_id}[/] — {check.description} [dim]({check.category.value})[/]"
        )


@app.command("list-formats")
def list_formats() -> None:
    """List every registered report format."""
    console = Console()
    for name in _available_formats():
        console.print(name)


@app.command("diff")
def diff_cmd(
    before: Annotated[Path, typer.Argument(help="Previous JSON report.")],
    after: Annotated[Path, typer.Argument(help="Current JSON report.")],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the diff to this path as JSON."),
    ] = None,
    fail_on_new: Annotated[
        bool,
        typer.Option("--fail-on-new", help="Exit non-zero if the diff contains any added finding."),
    ] = False,
) -> None:
    """Diff two scan reports and emit added / removed / unchanged findings."""
    try:
        before_findings = load_findings(before)
        after_findings = load_findings(after)
    except ConfigError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from None

    result = diff_findings(before_findings, after_findings)
    _render_diff(result)

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result.to_dict(), indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
        typer.secho(f"wrote diff → {output}", fg=typer.colors.GREEN, err=True)

    if fail_on_new and result.added:
        raise typer.Exit(code=2)


def _render_diff(result: DiffResult) -> None:
    console = Console()
    console.print(
        f"[bold]added[/] {len(result.added)}  "
        f"[bold]removed[/] {len(result.removed)}  "
        f"[dim]unchanged {len(result.unchanged)}[/]"
    )
    for label, findings, style in (
        ("added", result.added, "red"),
        ("removed", result.removed, "green"),
    ):
        for f in sorted(findings, key=lambda x: (-x.severity.weight, x.check_id)):
            console.print(
                f"[{style}]{label:<7}[/] [bold]{f.severity.value:<8}[/] {f.check_id:<22} {f.title}"
            )


@app.command("mcp-serve")
def mcp_serve(
    allow_host: Annotated[
        list[str] | None,
        typer.Option(
            "--allow-host",
            help="Hostname permitted for scans (repeatable). "
            "Also reads SURFACE_AUDIT_ALLOWED_HOSTS (comma-separated).",
        ),
    ] = None,
    allow_any_host: Annotated[
        bool,
        typer.Option(
            "--allow-any-host",
            help="Disable the allow-list. Unsafe — do not enable in production.",
        ),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase log verbosity."),
    ] = 0,
    log_format: Annotated[
        LogFormat, typer.Option("--log-format", help="Log output style.")
    ] = LogFormat.rich,
) -> None:
    """Run the scanner as an MCP server over stdio.

    Requires the ``mcp`` extra::

        pip install "surface-audit[mcp]"
    """
    _configure_logging(verbose, log_format)
    try:
        from surface_audit.mcp_server import run as run_mcp
    except ImportError as exc:  # pragma: no cover — optional dep missing
        typer.secho(
            f"MCP support requires the 'mcp' extra. Install with: "
            f"pip install 'surface-audit[mcp]'. Original error: {exc}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2) from None

    run_mcp(
        allowed_hosts=frozenset(allow_host or ()),
        allow_any_host=allow_any_host,
    )


def _build_config(
    file_config: dict[str, Any],
    *,
    timeout: float | None,
    concurrency: int | None,
    insecure: bool | None,
    enable: list[str] | None,
    disable: list[str] | None,
    proxy: str | None,
    user_agent: str | None,
) -> ScannerConfig:
    """Merge file config with explicit CLI overrides (CLI wins)."""
    merged: dict[str, Any] = dict(file_config)
    if timeout is not None:
        merged["timeout"] = timeout
    if concurrency is not None:
        merged["max_concurrency"] = concurrency
    if insecure is not None:
        merged["verify_tls"] = not insecure
    if enable:
        merged["enabled_checks"] = frozenset(enable)
    if disable:
        merged["disabled_checks"] = frozenset(disable)
    if proxy is not None:
        merged["proxy"] = proxy
    if user_agent is not None:
        merged["user_agent"] = user_agent
    return ScannerConfig(**merged)


def main() -> None:  # pragma: no cover — shim for ``python -m`` usage
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
    sys.exit(0)
