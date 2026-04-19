"""Scan orchestrator that runs registered checks concurrently.

The scanner knows nothing about specific OWASP categories — it only runs
``Check`` plugins, collects their findings, and hands the aggregated
``ScanReport`` back. New checks are added by registering a class that
inherits from ``surface_audit.checks.base.Check``.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib.metadata import entry_points

from surface_audit.checks.base import Check, CheckContext
from surface_audit.client import DEFAULT_USER_AGENT, HTTPClient, RetryPolicy
from surface_audit.exceptions import CheckRegistrationError, ConfigError
from surface_audit.models import Finding, ScanReport, ScanTarget

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "surface_audit.checks"


@dataclass(slots=True)
class ScannerConfig:
    """Knobs that govern a scan. All fields have sane, polite defaults.

    All values are validated in :meth:`__post_init__`; invalid input raises
    :class:`ConfigError` at construction time rather than later, deep in the
    request path.
    """

    timeout: float = 10.0
    max_concurrency: int = 8
    verify_tls: bool = True
    follow_redirects: bool = True
    user_agent: str = DEFAULT_USER_AGENT
    proxy: str | None = None
    enabled_checks: frozenset[str] | None = None  # None → all
    disabled_checks: frozenset[str] = field(default_factory=frozenset)
    retry_attempts: int = 3
    retry_backoff: float = 0.25

    def __post_init__(self) -> None:
        if not isinstance(self.timeout, (int, float)) or isinstance(self.timeout, bool):
            raise ConfigError(f"timeout must be a positive number, got {self.timeout!r}")
        if self.timeout <= 0:
            raise ConfigError(f"timeout must be > 0, got {self.timeout!r}")

        if not isinstance(self.max_concurrency, int) or isinstance(self.max_concurrency, bool):
            raise ConfigError(f"max_concurrency must be an integer, got {self.max_concurrency!r}")
        if self.max_concurrency < 1:
            raise ConfigError(f"max_concurrency must be >= 1, got {self.max_concurrency!r}")

        if not isinstance(self.verify_tls, bool):
            raise ConfigError(f"verify_tls must be a bool, got {self.verify_tls!r}")
        if not isinstance(self.follow_redirects, bool):
            raise ConfigError(f"follow_redirects must be a bool, got {self.follow_redirects!r}")

        if not isinstance(self.user_agent, str) or not self.user_agent.strip():
            raise ConfigError("user_agent must be a non-empty string")

        if self.proxy is not None and (not isinstance(self.proxy, str) or not self.proxy.strip()):
            raise ConfigError(f"proxy must be a non-empty string or None, got {self.proxy!r}")

        if self.enabled_checks is not None and not all(
            isinstance(c, str) for c in self.enabled_checks
        ):
            raise ConfigError("enabled_checks must contain only strings")
        if not all(isinstance(c, str) for c in self.disabled_checks):
            raise ConfigError("disabled_checks must contain only strings")

        if not isinstance(self.retry_attempts, int) or isinstance(self.retry_attempts, bool):
            raise ConfigError(f"retry_attempts must be an integer, got {self.retry_attempts!r}")
        if self.retry_attempts < 1:
            raise ConfigError(
                f"retry_attempts must be >= 1 (set to 1 to disable retries), "
                f"got {self.retry_attempts!r}"
            )

        if not isinstance(self.retry_backoff, (int, float)) or isinstance(self.retry_backoff, bool):
            raise ConfigError(f"retry_backoff must be a number, got {self.retry_backoff!r}")
        if self.retry_backoff < 0:
            raise ConfigError(f"retry_backoff must be >= 0, got {self.retry_backoff!r}")


class Scanner:
    """Runs a set of checks against a single target and aggregates findings."""

    def __init__(
        self,
        target: ScanTarget | str,
        *,
        config: ScannerConfig | None = None,
        checks: list[Check] | None = None,
    ) -> None:
        self.target = target if isinstance(target, ScanTarget) else ScanTarget.parse(target)
        self.config = config or ScannerConfig()
        self._checks = checks if checks is not None else self._discover_checks()
        self._validate_selection()

    @property
    def checks(self) -> list[Check]:
        """Read-only view of the checks this scanner will consider."""
        return list(self._checks)

    def _validate_selection(self) -> None:
        """Fail fast when enabled/disabled reference unknown check IDs."""
        known = {c.check_id for c in self._checks}
        for label, ids in (
            ("enabled_checks", self.config.enabled_checks),
            ("disabled_checks", self.config.disabled_checks),
        ):
            if not ids:
                continue
            unknown = set(ids) - known
            if unknown:
                raise ConfigError(
                    f"unknown check id(s) for {label}: {sorted(unknown)}. "
                    f"Known ids: {sorted(known)}"
                )

    @classmethod
    def discover_checks(cls) -> list[Check]:
        """Public helper used by the CLI and library consumers to enumerate
        registered checks without constructing a full :class:`Scanner`."""
        return cls._discover_checks()

    @staticmethod
    def _discover_checks() -> list[Check]:
        """Load checks declared via the ``surface_audit.checks`` entry point.

        Failures are logged as warnings but do not abort discovery — one
        broken third-party plugin must not disable the scanner. Duplicate
        check IDs across entry points raise :class:`CheckRegistrationError`
        because silently dropping one would mask real misconfiguration.

        Falls back to the in-tree defaults when no entry points are
        present (typical during editable/dev installs).
        """
        discovered: dict[str, Check] = {}
        eps = entry_points(group=ENTRY_POINT_GROUP)
        for ep in eps:
            try:
                cls = ep.load()
                instance = cls()
            except Exception as exc:
                logger.warning("failed to load check %s: %r", ep.name, exc)
                continue
            if not isinstance(instance, Check):
                logger.warning("check plugin %s does not subclass Check; skipping", ep.name)
                continue
            if instance.check_id in discovered:
                raise CheckRegistrationError(
                    f"duplicate check_id {instance.check_id!r} registered by entry points"
                )
            discovered[instance.check_id] = instance
        if not discovered:
            discovered = {c.check_id: c for c in _builtin_checks()}
        return list(discovered.values())

    def _filter_checks(self) -> list[Check]:
        checks: list[Check] = []
        for check in self._checks:
            if check.check_id in self.config.disabled_checks:
                continue
            if (
                self.config.enabled_checks is not None
                and check.check_id not in self.config.enabled_checks
            ):
                continue
            checks.append(check)
        return checks

    async def run(self) -> ScanReport:
        report = ScanReport(target=self.target, started_at=datetime.now(timezone.utc))
        selected = self._filter_checks()
        logger.info("starting scan of %s with %d checks", self.target.url, len(selected))

        async with HTTPClient(
            timeout=self.config.timeout,
            verify_tls=self.config.verify_tls,
            max_concurrency=self.config.max_concurrency,
            user_agent=self.config.user_agent,
            follow_redirects=self.config.follow_redirects,
            proxy=self.config.proxy,
            retry=RetryPolicy(
                attempts=self.config.retry_attempts,
                backoff=self.config.retry_backoff,
            ),
        ) as client:
            context = CheckContext(target=self.target, client=client, config=self.config)
            tasks = [asyncio.create_task(self._run_one(check, context)) for check in selected]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for check, outcome in zip(selected, results, strict=True):
            if isinstance(outcome, BaseException):
                message = f"check {check.check_id!r} failed: {outcome!r}"
                logger.warning(message)
                report.record_error(message)
            else:
                report.extend(list(outcome))

        report.finished_at = datetime.now(timezone.utc)
        logger.info(
            "scan finished: %d findings in %.2fs",
            len(report.findings),
            report.duration_seconds,
        )
        return report

    @staticmethod
    async def _run_one(check: Check, context: CheckContext) -> list[Finding]:
        logger.debug("running check %s", check.check_id)
        return await check.run(context)


def _builtin_checks() -> list[Check]:
    """Import the bundled checks lazily to avoid circular imports."""
    from surface_audit.checks.authentication import AuthenticationCheck
    from surface_audit.checks.cors import CORSCheck
    from surface_audit.checks.cross_origin_isolation import CrossOriginIsolationCheck
    from surface_audit.checks.csrf import CSRFCheck
    from surface_audit.checks.directory_listing import DirectoryListingCheck
    from surface_audit.checks.https_redirect import HTTPSRedirectCheck
    from surface_audit.checks.misconfiguration import MisconfigurationCheck
    from surface_audit.checks.open_redirect import OpenRedirectCheck
    from surface_audit.checks.security_headers import SecurityHeadersCheck
    from surface_audit.checks.security_txt import SecurityTxtCheck
    from surface_audit.checks.sql_injection import SQLInjectionCheck
    from surface_audit.checks.ssl_tls import SSLTLSCheck
    from surface_audit.checks.xss import ReflectedXSSCheck

    return [
        SecurityHeadersCheck(),
        SSLTLSCheck(),
        HTTPSRedirectCheck(),
        ReflectedXSSCheck(),
        SQLInjectionCheck(),
        CSRFCheck(),
        AuthenticationCheck(),
        MisconfigurationCheck(),
        DirectoryListingCheck(),
        CORSCheck(),
        SecurityTxtCheck(),
        CrossOriginIsolationCheck(),
        OpenRedirectCheck(),
    ]
