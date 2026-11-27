"""Integración con Redis real: sonda de /health (la de Mongo se cubre al correr la API completa).

Usa REDIS_TEST_URL (por defecto redis://localhost:6379/15; con contraseña: redis://:<REDIS_PASSWORD>@localhost:6379/15) y se omite si no hay Redis.
"""

from __future__ import annotations

import os

import pytest
import redis.asyncio as redis

from app.services.health_service import HealthService

REDIS_URL = os.getenv("REDIS_TEST_URL", "redis://localhost:6379/15")


async def _mongo_ok() -> bool:
    return True


@pytest.mark.asyncio
async def test_real_redis_up_then_unreachable_redis_is_degraded() -> None:
    live = redis.from_url(REDIS_URL)
    try:
        await live.ping()
    except Exception as exc:
        await live.aclose()
        pytest.skip(f"Redis no disponible: {type(exc).__name__}")
    try:
        assert (await HealthService(_mongo_ok, live.ping).check()).status == "ok"
    finally:
        await live.aclose()

    dead = redis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=1)
    try:
        report = await HealthService(_mongo_ok, dead.ping, timeout_seconds=2).check()
    finally:
        await dead.aclose()
    assert report.status == "degradado" and report.http_status == 200
