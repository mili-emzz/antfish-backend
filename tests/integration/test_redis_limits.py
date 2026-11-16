"""Integración con Redis real: atomicidad de rate limit y cuota dual (DP-04, P5).

Usa REDIS_TEST_URL (por defecto redis://localhost:6379/15) y se omite si no hay Redis.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
import pytest_asyncio
import redis.asyncio as redis

from app.repositories.redis.quota_repository import QuotaRepository
from app.repositories.redis.rate_limit_repository import RateLimitRepository

REDIS_URL = os.getenv("REDIS_TEST_URL", "redis://localhost:6379/15")


@pytest_asyncio.fixture
async def client():
    r = redis.from_url(REDIS_URL)
    try:
        await r.ping()
    except Exception as exc:
        pytest.skip(f"Redis no disponible: {type(exc).__name__}")
    yield r
    await r.aclose()


@pytest.mark.asyncio
async def test_hit_counts_sets_ttl_and_is_atomic_under_concurrency(client) -> None:
    repo = RateLimitRepository(client)
    key = f"rl:test:{uuid.uuid4()}"
    results = await asyncio.gather(*(repo.hit(key, 60) for _ in range(50)))
    assert sorted(c for c, _ in results) == list(range(1, 51))
    assert 0 < await client.ttl(key) <= 60
    await client.delete(key)


@pytest.mark.asyncio
async def test_quota_blocks_at_minute_limit_without_overconsuming(client) -> None:
    api = f"api_{uuid.uuid4().hex[:8]}"
    repo = QuotaRepository(client)
    outcomes = await asyncio.gather(*(repo.try_consume(api, 4, 500) for _ in range(20)))
    assert outcomes.count(True) == 4  # nunca más de la cuota, aun en concurrencia
    assert int(await client.get(f"cuota:{api}:pm")) == 4
    assert 0 < await client.ttl(f"cuota:{api}:pm") <= 60
    assert 0 < await client.ttl(f"cuota:{api}:daily") <= 86400
    await client.delete(f"cuota:{api}:pm", f"cuota:{api}:daily")


@pytest.mark.asyncio
async def test_quota_blocks_at_daily_limit(client) -> None:
    api = f"api_{uuid.uuid4().hex[:8]}"
    repo = QuotaRepository(client)
    assert [await repo.try_consume(api, 100, 2) for _ in range(3)] == [True, True, False]
    await client.delete(f"cuota:{api}:pm", f"cuota:{api}:daily")
