"""Integración con Redis real: caché de reputación (RF-04).

Usa REDIS_TEST_URL (por defecto redis://localhost:6379/15) y se omite si no hay Redis.
"""

from __future__ import annotations

import os
import uuid
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
import redis.asyncio as redis

from app.clients.base import ReputationResult
from app.engine.models import Reputation, SourceStatus
from app.repositories.redis.quota_repository import QuotaRepository
from app.repositories.redis.reputation_cache import ReputationCacheRepository
from app.services.analysis_service import AnalysisService

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
async def test_roundtrip_ttl_and_corrupt_entry(client) -> None:
    repo = ReputationCacheRepository(client)
    url = f"https://{uuid.uuid4().hex}.example/login"
    assert await repo.get(url) is None

    await repo.set(url, {"virustotal": {"positivo": True, "detecciones": 5}})
    assert await repo.get(url) == {"virustotal": {"positivo": True, "detecciones": 5}}
    assert 3590 <= await client.ttl(f"rep:{url}") <= 3600  # RF-04.1: TTL 3600 s

    await client.set(f"rep:{url}", "{no es json")  # entrada corrupta -> miss
    assert await repo.get(url) is None
    await client.delete(f"rep:{url}")


def _api(name: str) -> AsyncMock:
    m = AsyncMock()
    m.check_url.return_value = ReputationResult(
        reputation=Reputation(api=name, estado=SourceStatus.OK, positivo=False, detecciones=None)
    )
    return m


@pytest.mark.asyncio
async def test_cache_hit_end_to_end_skips_apis_and_quota(client) -> None:
    host = f"{uuid.uuid4().hex}.example"
    wr, vt = _api("google_web_risk"), _api("virustotal")
    service = AnalysisService(
        web_risk_client=wr,
        virustotal_client=vt,
        phishtank_client=None,
        quota_repository=QuotaRepository(client),
        reputation_cache=ReputationCacheRepository(client),
    )
    first = await service.analyze("url", f"https://{host}/a?token=secreto")
    second = await service.analyze("url", f"https://{host}/a?otro=1")  # misma URL normalizada

    assert wr.check_url.await_count == 1 and vt.check_url.await_count == 1
    assert [f["desde_cache"] for f in first["fuentes_consultadas"]] == [False, False]
    assert [f["desde_cache"] for f in second["fuentes_consultadas"]] == [True, True]

    keys = [k.decode() async for k in client.scan_iter(f"rep:*{host}*")]
    assert keys == [f"rep:https://{host}/a"]  # sin query string en la clave
    assert b"secreto" not in (await client.get(keys[0]))
    await client.delete(*keys)
