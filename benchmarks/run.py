"""Reproducible micro-benchmark for the full scan pipeline.

The benchmark uses ``respx`` to intercept every HTTP call locally, so the
numbers measure scanner orchestration overhead and in-process parsing —
not network latency. Run::

    python benchmarks/run.py

Output is deterministic given the same interpreter and machine; use it
as a regression guard rather than a marketing figure.
"""

from __future__ import annotations

import asyncio
import statistics
import time
from collections.abc import Callable  # noqa: TC003 — used at runtime below

import httpx
import respx

from surface_audit.models import ScanTarget
from surface_audit.scanner import Scanner, ScannerConfig

ITERATIONS = 20
WARMUP = 3


def _install_routes() -> None:
    """Install a minimal, clean response for every path under example.com."""
    headers = {
        "Strict-Transport-Security": ("max-age=63072000; includeSubDomains; preload"),
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Resource-Policy": "same-origin",
    }
    respx.route(url__regex=r"https?://example\.com(/.*)?").mock(
        return_value=httpx.Response(
            200,
            text="<html><body>ok</body></html>",
            headers=headers,
        )
    )


async def _one_scan() -> float:
    target = ScanTarget.parse("https://example.com")
    # Disable the TLS check (it opens a real socket that respx can't mock).
    config = ScannerConfig(disabled_checks=frozenset({"ssl-tls"}))
    start = time.perf_counter()
    await Scanner(target, config=config).run()
    return time.perf_counter() - start


async def _measure(runner: Callable[[], asyncio.Future[float] | object]) -> list[float]:
    # Warm-up runs amortize import/compile work.
    for _ in range(WARMUP):
        await runner()  # type: ignore[misc]
    samples: list[float] = []
    for _ in range(ITERATIONS):
        samples.append(await runner())  # type: ignore[arg-type, misc]
    return samples


@respx.mock
async def main() -> None:
    _install_routes()
    samples = await _measure(_one_scan)

    mean = statistics.mean(samples)
    median = statistics.median(samples)
    stdev = statistics.pstdev(samples)
    print(f"iterations: {ITERATIONS} (after {WARMUP} warmup)")
    print(f"mean:       {mean * 1000:6.1f} ms")
    print(f"median:     {median * 1000:6.1f} ms")
    print(f"stdev:      {stdev * 1000:6.1f} ms")
    print(f"min:        {min(samples) * 1000:6.1f} ms")
    print(f"max:        {max(samples) * 1000:6.1f} ms")


if __name__ == "__main__":
    asyncio.run(main())
