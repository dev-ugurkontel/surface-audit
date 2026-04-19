"""surface-audit: modular async web-application security surface auditor.

The bundled check catalog maps findings to the OWASP Top 10 (2021)
categories, but the architecture is deliberately catalog-agnostic:
third-party plugins can contribute checks against any standard (NIST,
CIS, OWASP ASVS) through the ``surface_audit.checks`` entry-point group.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from surface_audit.exceptions import (
    CheckRegistrationError,
    ConfigError,
    HTTPTransportError,
    RendererError,
    SurfaceAuditError,
    TargetError,
)
from surface_audit.models import (
    Finding,
    FindingCategory,
    ScanReport,
    ScanTarget,
    Severity,
)
from surface_audit.scanner import Scanner, ScannerConfig

try:
    __version__ = version("surface-audit")
except PackageNotFoundError:  # pragma: no cover — source checkout without install
    __version__ = "0.0.0+unknown"

__all__ = [
    "CheckRegistrationError",
    "ConfigError",
    "Finding",
    "FindingCategory",
    "HTTPTransportError",
    "RendererError",
    "ScanReport",
    "ScanTarget",
    "Scanner",
    "ScannerConfig",
    "Severity",
    "SurfaceAuditError",
    "TargetError",
    "__version__",
]
