"""Tests for the HTTP client retry loop."""

from __future__ import annotations

import httpx
import pytest
import respx

from surface_audit.client import HTTPClient, RetryPolicy
from surface_audit.exceptions import HTTPTransportError


@respx.mock
async def test_retries_then_succeeds() -> None:
    route = respx.get("https://example.com/").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(503),
            httpx.Response(200, text="ok"),
        ]
    )
    async with HTTPClient(
        timeout=1.0, max_concurrency=2, retry=RetryPolicy(attempts=3, backoff=0.0)
    ) as client:
        response = await client.get("https://example.com/")
    assert response.status_code == 200
    assert route.call_count == 3


@respx.mock
async def test_gives_up_after_budget() -> None:
    respx.get("https://example.com/").mock(return_value=httpx.Response(502))
    async with HTTPClient(
        timeout=1.0, max_concurrency=2, retry=RetryPolicy(attempts=2, backoff=0.0)
    ) as client:
        with pytest.raises(HTTPTransportError):
            await client.get("https://example.com/")


@respx.mock
async def test_non_retryable_status_returned_immediately() -> None:
    route = respx.get("https://example.com/").mock(return_value=httpx.Response(404))
    async with HTTPClient(
        timeout=1.0, max_concurrency=2, retry=RetryPolicy(attempts=3, backoff=0.0)
    ) as client:
        response = await client.get("https://example.com/")
    assert response.status_code == 404
    assert route.call_count == 1


@respx.mock
async def test_transport_error_exhausts_budget() -> None:
    respx.get("https://example.com/").mock(side_effect=httpx.ConnectError("refused"))
    async with HTTPClient(
        timeout=1.0, max_concurrency=2, retry=RetryPolicy(attempts=2, backoff=0.0)
    ) as client:
        with pytest.raises(HTTPTransportError):
            await client.get("https://example.com/")


async def test_aclose_is_idempotent() -> None:
    client = HTTPClient(timeout=1.0, max_concurrency=2)
    await client.aclose()
    await client.aclose()  # second call is a no-op


@respx.mock
async def test_head_uses_request() -> None:
    route = respx.head("https://example.com/").mock(return_value=httpx.Response(200))
    async with HTTPClient(timeout=1.0, max_concurrency=2) as client:
        response = await client.head("https://example.com/")
    assert response.status_code == 200
    assert route.called


def test_retry_policy_delay_is_bounded() -> None:
    policy = RetryPolicy(attempts=5, backoff=0.5, max_delay=1.0)
    assert policy.delay(0) <= 1.0
    # attempt 10 would blow through max_delay without the clamp.
    assert policy.delay(10) == 1.0
