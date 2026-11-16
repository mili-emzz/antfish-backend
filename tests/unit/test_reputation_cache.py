"""Pruebas del caché de reputación (RF-04.1, RF-04.2, RF-04.3, RN-12, RN-13)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from app.clients.base import ReputationResult
from app.engine.models import Reputation, SourceStatus
from app.services.analysis_service import AnalysisService

URL = "https://example.com/login"


class FakeCache:
    def __init__(self, store: dict[str, dict[str, Any]] | None = None) -> None:
        self.store = store or {}
        self.sets: list[tuple[str, dict[str, Any]]] = []

    async def get(self, url: str) -> dict[str, Any] | None:
        return self.store.get(url)

    async def set(self, url: str, payload: dict[str, Any]) -> None:
        self.sets.append((url, payload))
        self.store[url] = payload


def _client(
    api: str,
    estado: SourceStatus = SourceStatus.OK,
    positivo: bool = False,
    detecciones: int | None = None,
) -> AsyncMock:
    m = AsyncMock()
    m.check_url.return_value = ReputationResult(
        reputation=Reputation(api=api, estado=estado, positivo=positivo, detecciones=detecciones),
        raw_response={"api": api},
    )
    return m


def _service(
    cache: Any,
    wr: AsyncMock | None = None,
    vt: AsyncMock | None = None,
    quota: Any = None,
    pt: AsyncMock | None = None,
) -> tuple[AnalysisService, AsyncMock, AsyncMock]:
    wr = wr or _client("google_web_risk")
    vt = vt or _client("virustotal", detecciones=0)
    service = AnalysisService(
        web_risk_client=wr,
        virustotal_client=vt,
        phishtank_client=pt,
        quota_repository=quota,
        reputation_cache=cache,
    )
    return service, wr, vt


@pytest.mark.asyncio
async def test_miss_with_full_success_stores_entry_without_raw_data() -> None:
    cache = FakeCache()
    service, wr, _ = _service(cache)
    result = await service.analyze("url", URL)

    wr.check_url.assert_awaited_once()
    assert len(cache.sets) == 1
    key, payload = cache.sets[0]
    assert key == "https://example.com/login"  # URL normalizada
    assert set(payload) == {"google_web_risk", "virustotal", "fecha_consulta"}
    assert "api" not in str(payload)  # no se guardan respuestas crudas
    assert all(f["desde_cache"] is False for f in result["fuentes_consultadas"])


@pytest.mark.asyncio
async def test_hit_returns_cached_reputation_without_apis_or_quota() -> None:
    cache = FakeCache(
        {
            URL: {
                "google_web_risk": {"positivo": True, "detecciones": 1},
                "virustotal": {"positivo": True, "detecciones": 5},
                "fecha_consulta": "2026-11-16T00:00:00+00:00",
            }
        }
    )
    quota = MagicMock()
    quota.try_consume = AsyncMock(return_value=True)
    service, wr, vt = _service(cache, quota=quota)
    result = await service.analyze("url", URL)

    wr.check_url.assert_not_awaited()
    vt.check_url.assert_not_awaited()
    quota.try_consume.assert_not_awaited()  # RF-04.2: sin consumir cuota
    assert result["analisis_parcial"] is False
    assert {f["api"]: f["desde_cache"] for f in result["fuentes_consultadas"]} == {
        "google_web_risk": True,
        "virustotal": True,
    }
    assert result["motivo_cortocircuito"] == "lista_negra"  # el positivo cacheado sí puntúa
    assert cache.sets == []  # un hit no reescribe


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_status", [SourceStatus.TIMEOUT, SourceStatus.RATE_LIMIT, SourceStatus.ERROR]
)
async def test_partial_result_is_never_cached(bad_status: SourceStatus) -> None:
    cache = FakeCache()
    service, _, _ = _service(cache, vt=_client("virustotal", estado=bad_status))
    result = await service.analyze("url", URL)
    assert result["analisis_parcial"] is True
    assert cache.sets == []


@pytest.mark.asyncio
async def test_quota_exhausted_result_is_not_cached() -> None:
    cache = FakeCache()
    quota = MagicMock()
    quota.try_consume = AsyncMock(side_effect=lambda api, pm, d: api != "virustotal")
    service, _, _ = _service(cache, quota=quota)
    await service.analyze("url", URL)
    assert cache.sets == []


@pytest.mark.asyncio
async def test_exception_in_one_api_is_not_cached() -> None:
    cache = FakeCache()
    vt = AsyncMock()
    vt.check_url.side_effect = RuntimeError("boom")
    service, _, _ = _service(cache, vt=vt)
    assert (await service.analyze("url", URL))["analisis_parcial"] is True
    assert cache.sets == []


@pytest.mark.asyncio
async def test_redis_failure_is_fail_open_on_read_and_write() -> None:
    cache = MagicMock()
    cache.get = AsyncMock(side_effect=RedisConnectionError("caído"))
    cache.set = AsyncMock(side_effect=RedisConnectionError("caído"))
    service, wr, vt = _service(cache)
    result = await service.analyze("url", URL)
    wr.check_url.assert_awaited_once()
    vt.check_url.assert_awaited_once()
    assert result["analisis_parcial"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "entry",
    [
        {"google_web_risk": {"positivo": False}},  # falta virustotal
        {"google_web_risk": {"positivo": "si"}, "virustotal": {"positivo": False}},
        {
            "google_web_risk": {"positivo": False},
            "virustotal": {"positivo": False, "detecciones": "5"},
        },
        {"google_web_risk": [], "virustotal": {"positivo": False}},
    ],
)
async def test_incomplete_or_corrupt_entry_is_a_miss(entry: dict[str, Any]) -> None:
    cache = FakeCache({URL: entry})
    service, wr, _ = _service(cache)
    await service.analyze("url", URL)
    wr.check_url.assert_awaited_once()  # se consultó de nuevo
    assert len(cache.sets) == 1  # y se reescribió con datos válidos


@pytest.mark.asyncio
async def test_enabling_phishtank_invalidates_entries_without_it() -> None:
    cache = FakeCache(
        {
            URL: {
                "google_web_risk": {"positivo": False},
                "virustotal": {"positivo": False, "detecciones": 0},
            }
        }
    )
    pt = _client("phishtank")
    service, wr, _ = _service(cache, pt=pt)
    await service.analyze("url", URL)
    pt.check_url.assert_awaited_once()
    wr.check_url.assert_awaited_once()
    assert "phishtank" in cache.sets[0][1]
