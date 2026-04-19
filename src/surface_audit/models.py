"""Domain models for scan targets, findings, and reports.

All models are immutable dataclasses so that findings cannot be mutated
after a check emits them, and reports serialize deterministically.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import urlparse


class Severity(str, Enum):
    """CVSS-inspired severity levels. Ordered from least to most critical."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def weight(self) -> int:
        return _SEVERITY_WEIGHTS[self]


_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FindingCategory(str, Enum):
    """OWASP Top 10 (2021) categories referenced by findings."""

    A01_BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"
    A03_INJECTION = "A03:2021 - Injection"
    A04_INSECURE_DESIGN = "A04:2021 - Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021 - Identification and Authentication Failures"
    A08_SOFTWARE_INTEGRITY = "A08:2021 - Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021 - Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 - Server-Side Request Forgery"


_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """A validated scan target.

    Guarantees:
    - ``scheme`` is ``http`` or ``https``.
    - ``hostname`` is non-empty and the URL contains no userinfo.
    - ``url`` is a normalized, credential-free canonical form suitable for
      inclusion in logs and reports.

    Raises :class:`ValueError` for anything else; callers at the CLI boundary
    translate that into a user-facing error.
    """

    url: str
    hostname: str
    port: int
    scheme: str

    @classmethod
    def parse(cls, raw: str) -> ScanTarget:
        if not isinstance(raw, str):
            raise ValueError(f"target must be a string, got {type(raw).__name__}")

        candidate = raw.strip()
        if not candidate:
            raise ValueError(f"invalid target URL: {raw!r}")

        if "://" in candidate:
            declared_scheme = candidate.split("://", 1)[0].lower()
            if declared_scheme not in _ALLOWED_SCHEMES:
                raise ValueError(f"unsupported scheme {declared_scheme!r}; use http or https")
        else:
            candidate = f"https://{candidate}"

        try:
            parsed = urlparse(candidate)
        except ValueError as exc:  # urlparse raises on malformed IPv6 etc.
            raise ValueError(f"invalid target URL: {raw!r} ({exc})") from exc

        scheme = parsed.scheme.lower()
        # The pre-urlparse scheme check above already guarantees http/https.

        if parsed.username or parsed.password:
            raise ValueError(
                "target must not embed credentials (user:pass@); "
                "pass authentication via --user-agent/headers or a proxy instead"
            )

        hostname = parsed.hostname
        if not hostname:
            raise ValueError(f"invalid target URL: {raw!r}")

        try:
            port = parsed.port or (443 if scheme == "https" else 80)
        except ValueError as exc:
            raise ValueError(f"invalid port in {raw!r}: {exc}") from exc

        # Rebuild netloc without userinfo or default ports.
        is_default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
        host_for_netloc = f"[{hostname}]" if ":" in hostname else hostname
        netloc = host_for_netloc if is_default_port else f"{host_for_netloc}:{port}"

        path = parsed.path or "/"
        normalized = f"{scheme}://{netloc}{path}"
        if parsed.query:
            normalized = f"{normalized}?{parsed.query}"

        return cls(url=normalized, hostname=hostname, port=port, scheme=scheme)


@dataclass(frozen=True, slots=True)
class Finding:
    """A single vulnerability or weakness emitted by a check."""

    check_id: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    category: FindingCategory
    location: str | None = None
    evidence: str | None = None
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        payload["category"] = self.category.value
        payload["references"] = list(self.references)
        return payload


@dataclass(slots=True)
class ScanReport:
    """Aggregated result of a full scan."""

    target: ScanTarget
    started_at: datetime
    finished_at: datetime | None = None
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def record_error(self, message: str) -> None:
        self.errors.append(message)

    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    def severity_counts(self) -> dict[Severity, int]:
        counts = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.weight)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": {
                "url": self.target.url,
                "hostname": self.target.hostname,
                "port": self.target.port,
                "scheme": self.target.scheme,
            },
            "started_at": self.started_at.astimezone(timezone.utc).isoformat(),
            "finished_at": (
                self.finished_at.astimezone(timezone.utc).isoformat() if self.finished_at else None
            ),
            "duration_seconds": self.duration_seconds,
            "summary": {
                "total": len(self.findings),
                "by_severity": {
                    severity.value: count for severity, count in self.severity_counts().items()
                },
                "max_severity": (max_sev.value if (max_sev := self.max_severity()) else None),
            },
            "findings": [f.to_dict() for f in self.findings],
            "errors": list(self.errors),
        }
