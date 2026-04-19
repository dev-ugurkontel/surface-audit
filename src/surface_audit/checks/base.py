"""Base class for all scan checks.

A check is any class that implements :meth:`Check.run` returning a list of
``Finding`` instances. Checks are side-effect-free except for the HTTP
requests they issue through the shared :class:`HTTPClient`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx

from surface_audit.exceptions import HTTPTransportError

if TYPE_CHECKING:
    from surface_audit.client import HTTPClient
    from surface_audit.models import Finding, FindingCategory, ScanTarget
    from surface_audit.scanner import ScannerConfig

#: Exception tuple every check should catch around HTTP calls so that a
#: single transport failure never escapes into the scanner's error list.
NETWORK_ERRORS: tuple[type[BaseException], ...] = (httpx.HTTPError, HTTPTransportError)


@dataclass(frozen=True, slots=True)
class CheckContext:
    """Read-only dependencies handed to every check invocation."""

    target: ScanTarget
    client: HTTPClient
    config: ScannerConfig


class Check(ABC):
    """Abstract base class for a single security check.

    Subclasses declare the three class-level attributes below and implement
    :meth:`run`. They must not raise — use the framework's error recording
    via an empty return if they cannot run meaningfully in the current
    environment. Unhandled exceptions are caught by the scanner and turned
    into report-level errors.
    """

    check_id: str
    description: str
    category: FindingCategory

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        missing = [
            attr for attr in ("check_id", "description", "category") if not hasattr(cls, attr)
        ]
        if missing and not getattr(cls, "__abstract__", False):
            raise TypeError(f"{cls.__name__} is missing required attributes: {missing}")

    @abstractmethod
    async def run(self, ctx: CheckContext) -> list[Finding]:  # pragma: no cover - abstract
        ...
