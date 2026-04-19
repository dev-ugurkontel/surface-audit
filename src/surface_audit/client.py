"""Async HTTP client with concurrency caps and exponential-backoff retries.

All checks share a single :class:`HTTPClient` so that connection pooling,
retries, rate limiting and identity (User-Agent) are consistent across a
scan.
"""

from __future__ import annotations

import asyncio
import logging
import random
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx

from surface_audit.exceptions import HTTPTransportError

try:
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    _PKG_VERSION = _pkg_version("surface-audit")
except PackageNotFoundError:  # pragma: no cover — source checkout without install
    _PKG_VERSION = "0.0.0+unknown"

if sys.version_info >= (3, 11):  # pragma: no cover
    from typing import Self
else:  # pragma: no cover
    from typing_extensions import Self

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from types import TracebackType

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = (
    f"surface-audit/{_PKG_VERSION} (+https://github.com/dev-ugurkontel/surface-audit)"
)

_RETRY_STATUS: frozenset[int] = frozenset({408, 425, 429, 500, 502, 503, 504})


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Retry configuration. ``attempts=1`` disables retries."""

    attempts: int = 3
    backoff: float = 0.25  # seconds; grows as backoff * 2**i + jitter
    max_delay: float = 4.0

    def delay(self, attempt: int) -> float:
        base: float = self.backoff * (2**attempt)
        # retry jitter, not cryptography — random.uniform is fine here
        jitter: float = random.uniform(0, self.backoff)  # noqa: S311  # nosec B311
        return float(min(self.max_delay, base + jitter))


class HTTPClient:
    """Polite async HTTP client.

    The client is a thin wrapper around ``httpx.AsyncClient`` with two
    additions: a semaphore that caps concurrent requests, and an
    exponential-backoff retry loop for transient errors. Use it as an
    async context manager so connections are closed deterministically.
    """

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        verify_tls: bool = True,
        max_concurrency: int = 8,
        user_agent: str = DEFAULT_USER_AGENT,
        follow_redirects: bool = True,
        proxy: str | None = None,
        retry: RetryPolicy | None = None,
    ) -> None:
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._retry = retry or RetryPolicy()
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=min(timeout, 5.0)),
            verify=verify_tls,
            follow_redirects=follow_redirects,
            headers={"User-Agent": user_agent, "Accept": "*/*"},
            proxy=proxy,
        )
        self._closed = False

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if not self._closed:
            await self._client.aclose()
            self._closed = True

    @asynccontextmanager
    async def _slot(self) -> AsyncIterator[None]:
        async with self._semaphore:
            yield

    async def request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        """Issue an HTTP request, retrying transient failures with backoff."""
        last_exc: BaseException | None = None
        for attempt in range(self._retry.attempts):
            try:
                async with self._slot():
                    logger.debug("request %s %s (attempt %d)", method, url, attempt + 1)
                    response = await self._client.request(method, url, **kwargs)  # type: ignore[arg-type]
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                last_exc = exc
                logger.debug("transient error for %s %s: %r", method, url, exc)
            else:
                if response.status_code not in _RETRY_STATUS:
                    return response
                last_exc = httpx.HTTPStatusError(
                    f"retryable status {response.status_code}",
                    request=response.request,
                    response=response,
                )

            if attempt + 1 < self._retry.attempts:
                await asyncio.sleep(self._retry.delay(attempt))

        raise HTTPTransportError(
            f"request to {url!r} failed after {self._retry.attempts} attempts",
            cause=last_exc,
        )

    async def get(self, url: str, **kwargs: object) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: object) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)
