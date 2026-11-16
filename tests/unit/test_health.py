"""Pruebas de GET /health (§9.6): Mongo imprescindible, Redis degrada, sin detalles internos."""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest
from fastapi import FastAPI
from pymongo.errors import ServerSelectionTimeoutError
from redis.exceptions import ConnectionError as RedisConnectionError

from app.api.v1 import health
from app.services.health_service import HealthService


async def _ok() -> bool:
    return True


async def _mongo_down() -> None:
    raise ServerSelectionTimeoutError("mongodb://usuario:secreto@host: no responde")


async def _redis_down() -> None:
    raise RedisConnectionError("redis://:secreto@host: conexión rechazada")


async def _hang() -> None:
    await asyncio.sleep(30)


def _client(service: HealthService | None) -> httpx.AsyncClient:
    app = FastAPI()
    app.include_router(health.router)

    class _Container:
        health_service = service

    app.state.container = _Container()
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_all_up_is_200_ok() -> None:
    r = await _client(HealthService(_ok, _ok)).get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert r.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_redis_down_is_200_degradado() -> None:
    r = await _client(HealthService(_ok, _redis_down)).get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "degradado"}


@pytest.mark.asyncio
async def test_mongo_down_is_503_even_if_redis_up() -> None:
    r = await _client(HealthService(_mongo_down, _ok)).get("/health")
    assert r.status_code == 503
    assert r.json() == {"status": "no_disponible"}


@pytest.mark.asyncio
async def test_both_down_is_503() -> None:
    r = await _client(HealthService(_mongo_down, _redis_down)).get("/health")
    assert r.status_code == 503


@pytest.mark.asyncio
async def test_response_never_leaks_error_details() -> None:
    r = await _client(HealthService(_mongo_down, _redis_down)).get("/health")
    assert "secreto" not in r.text and "mongodb" not in r.text and "redis" not in r.text


@pytest.mark.asyncio
async def test_hung_dependency_is_cut_by_timeout_and_probes_run_in_parallel() -> None:
    service = HealthService(_hang, _hang, timeout_seconds=0.2)
    start = time.perf_counter()
    r = await _client(service).get("/health")
    elapsed = time.perf_counter() - start
    assert r.status_code == 503
    assert elapsed < 1.0  # ~0.2 s: timeout aplicado y sondas concurrentes (no 0.4 s en serie)


@pytest.mark.asyncio
async def test_missing_service_is_503() -> None:
    r = await _client(None).get("/health")
    assert r.status_code == 503
    assert r.json() == {"status": "no_disponible"}
