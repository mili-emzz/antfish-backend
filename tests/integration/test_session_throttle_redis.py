"""Integración con Redis real: scripts Lua de rotación de sesión, retroceso de login y intentos.

Usa REDIS_TEST_URL (por defecto redis://localhost:6379/15) y se omite si no hay Redis.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
import pytest_asyncio
import redis.asyncio as redis

from app.repositories.redis.rate_limit_repository import RateLimitRepository
from app.repositories.redis.session_repository import RefreshSessionRepository
from app.repositories.redis.verification_repository import VerificationRepository

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
async def test_session_rotation_is_atomic_and_single_use(client) -> None:
    repo = RefreshSessionRepository(client)
    fam = f"fam-{uuid.uuid4().hex}"
    await repo.start(fam, "j0", 60)
    results = await asyncio.gather(*(repo.rotate(fam, "j0", f"j{i}", 60) for i in range(1, 21)))
    assert results.count(True) == 1  # solo una rotación gana la carrera
    assert 0 < await client.ttl(f"rt:{fam}") <= 60
    await repo.revoke(fam)
    assert await repo.rotate(fam, "j0", "x", 60) is False
    await client.delete(f"rt:{fam}")


@pytest.mark.asyncio
async def test_login_backoff_script_doubles_sets_ttl_and_resets(client) -> None:
    repo = RateLimitRepository(client)
    acct = f"acct-{uuid.uuid4().hex}"
    delays = [await repo.record_login_failure(acct, 900, 5, 30, 900) for _ in range(9)]
    assert delays == [0, 0, 0, 0, 0, 30, 60, 120, 240]
    assert 0 < await repo.login_block_ttl(acct) <= 240
    await repo.clear_login_failures(acct)
    assert await repo.login_block_ttl(acct) == 0
    assert await client.exists(f"lf:{acct}") == 0


@pytest.mark.asyncio
async def test_verification_attempts_always_have_ttl(client) -> None:
    repo = VerificationRepository(client)
    user = f"u-{uuid.uuid4().hex}"
    assert [await repo.increment_attempts(user) for _ in range(3)] == [1, 2, 3]
    assert 0 < await client.ttl(f"verif_attempts:{user}") <= 600
    # repara una clave huérfana sin TTL (estado que dejaba el INCR + EXPIRE no atómico)
    await client.set(f"verif_attempts:{user}", 2)
    assert await client.ttl(f"verif_attempts:{user}") == -1
    assert await repo.increment_attempts(user) == 3
    assert 0 < await client.ttl(f"verif_attempts:{user}") <= 600
    await client.delete(f"verif_attempts:{user}")
