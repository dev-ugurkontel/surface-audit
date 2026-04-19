"""Typed exception hierarchy for ``surface-audit``.

Every error raised by the public API descends from :class:`SurfaceAuditError`
so that callers can ``except SurfaceAuditError:`` once and opt into finer
classes as needed.
"""

from __future__ import annotations


class SurfaceAuditError(Exception):
    """Base class for every error raised by this package."""


class TargetError(SurfaceAuditError, ValueError):
    """Raised when a scan target cannot be parsed or is not addressable."""


class ConfigError(SurfaceAuditError, ValueError):
    """Raised when a configuration file is malformed or references an unknown field."""


class CheckRegistrationError(SurfaceAuditError):
    """Raised when a check plugin fails validation during registration."""


class RendererError(SurfaceAuditError, LookupError):
    """Raised when an unknown report format is requested."""


class HTTPTransportError(SurfaceAuditError):
    """Raised when the HTTP client exhausts its retry budget."""

    def __init__(self, message: str, *, cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.__cause__ = cause
