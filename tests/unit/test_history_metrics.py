"""Pruebas unitarias de RF-05: historial, detalle, borrado y métricas (sin red ni Mongo)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from bson import ObjectId
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.deps import get_current_user
from app.api.v1 import analysis as analysis_api
from app.api.v1 import metrics as metrics_api
from app.clients.base import ReputationResult
from app.core.exceptions import AnalysisNotFoundError, InvalidCursorError
from app.engine.models import Reputation, SourceStatus
from app.repositories.mongo.analysis_repository import (
    decode_cursor,
    encode_cursor,
)
from app.services.analysis_service import AnalysisService
from app.services.metrics_service import MetricsService

USER_ID = ObjectId()


class FakeUoW:
    def __init__(self) -> None:
        self.committed = 0
        self.failing = False

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[str]:
        yield "session"
        if self.failing:
            raise RuntimeError("boom")
        self.committed += 1


def _client(api: str, positivo: bool) -> AsyncMock:
    mock = AsyncMock()
    mock.check_url.return_value = ReputationResult(
        reputation=Reputation(
            api=api,
            estado=SourceStatus.OK,
            positivo=positivo,
            detecciones=5 if positivo else None,
        ),
        raw_response={"api": api},
    )
    return mock


def _service(
    positivo: bool = False,
) -> tuple[AnalysisService, MagicMock, MagicMock, FakeUoW]:
    analysis_repo = MagicMock()
    analysis_repo.insert_analysis = AsyncMock(return_value=ObjectId())
    analysis_repo.insert_api_responses = AsyncMock()
    metrics_repo = MagicMock()
    metrics_repo.increment = AsyncMock()
    uow = FakeUoW()
    service = AnalysisService(
        web_risk_client=_client("google_web_risk", positivo),
        virustotal_client=_client("virustotal", positivo),
        phishtank_client=_client("phishtank", positivo),
        analysis_repository=analysis_repo,
        metrics_repository=metrics_repo,
        unit_of_work=uow,  # type: ignore[arg-type]
    )
    return service, analysis_repo, metrics_repo, uow


def test_cursor_roundtrip_and_invalid() -> None:
    fecha = datetime(2026, 11, 1, 10, 30, tzinfo=UTC)
    oid = ObjectId()
    assert decode_cursor(encode_cursor(fecha, oid)) == (fecha, oid)
    with pytest.raises(InvalidCursorError):
        decode_cursor("no-es-un-cursor")


@pytest.mark.asyncio
async def test_analyze_persists_analysis_responses_and_metrics() -> None:
    service, analysis_repo, metrics_repo, uow = _service(positivo=True)
    result = await service.analyze("url", "https://phish-banco.xyz/login", str(USER_ID))

    assert result["id"] is not None
    assert uow.committed == 1
    doc = analysis_repo.insert_analysis.await_args.args[0]
    assert doc["user_id"] == USER_ID
    assert "contenido" not in doc  # nunca se persiste el contenido (privacidad)
    raw_docs = analysis_repo.insert_api_responses.await_args.args[0]
    assert len(raw_docs) == 3
    assert all(d["expira_en"] > d["fecha"] for d in raw_docs)
    metrics_repo.increment.assert_awaited_once()
    args = metrics_repo.increment.await_args.args
    assert args[1] == "url" and args[2] is True  # nivel alto/crítico -> amenaza


@pytest.mark.asyncio
async def test_analyze_without_user_does_not_persist() -> None:
    service, analysis_repo, _, uow = _service()
    result = await service.analyze("url", "https://example.com/")
    assert result["id"] is None
    assert uow.committed == 0
    analysis_repo.insert_analysis.assert_not_awaited()


@pytest.mark.asyncio
async def test_sms_without_urls_is_persisted_without_raw_responses() -> None:
    service, analysis_repo, metrics_repo, _ = _service()
    result = await service.analyze("sms", "Hola, nos vemos mañana", str(USER_ID))
    assert result["id"] is not None
    assert result["mensaje_hash"] is not None
    assert analysis_repo.insert_api_responses.await_args.args[0] == []
    assert metrics_repo.increment.await_args.args[1] == "sms"


@pytest.mark.asyncio
async def test_detail_and_delete_not_found() -> None:
    service, analysis_repo, _, uow = _service()
    analysis_repo.find_by_id_and_user = AsyncMock(return_value=None)
    with pytest.raises(AnalysisNotFoundError):
        await service.get_detail(str(USER_ID), str(ObjectId()))
    with pytest.raises(AnalysisNotFoundError):
        await service.delete_analysis(str(USER_ID), str(ObjectId()))
    assert uow.committed == 0


@pytest.mark.asyncio
async def test_delete_runs_in_transaction_without_touching_metrics() -> None:
    service, analysis_repo, metrics_repo, uow = _service()
    doc_id = ObjectId()
    analysis_repo.find_by_id_and_user = AsyncMock(return_value={"_id": doc_id})
    analysis_repo.delete_analysis = AsyncMock(return_value=True)
    await service.delete_analysis(str(USER_ID), str(doc_id))
    analysis_repo.delete_analysis.assert_awaited_once_with(doc_id, USER_ID, "session")
    assert uow.committed == 1
    metrics_repo.increment.assert_not_awaited()


@pytest.mark.asyncio
async def test_metrics_service_defaults_and_values() -> None:
    repo = MagicMock()
    repo.find_by_user = AsyncMock(return_value=None)
    data = await MetricsService(repo).get_user_metrics(str(USER_ID))
    assert data["total_escaneos"] == 0 and data["ultima_actualizacion"] is None

    now = datetime.now(UTC)
    repo.find_by_user = AsyncMock(
        return_value={
            "total_escaneos": 3,
            "total_url": 2,
            "total_sms": 1,
            "amenazas_bloqueadas": 1,
            "ultima_actualizacion": now,
        }
    )
    data = await MetricsService(repo).get_user_metrics(str(USER_ID))
    assert (data["total_url"], data["total_sms"], data["amenazas_bloqueadas"]) == (2, 1, 1)


def _app(analysis_service: Any, metrics_service: Any) -> TestClient:
    app = FastAPI()
    app.include_router(analysis_api.router, prefix="/api/v1")
    app.include_router(metrics_api.router, prefix="/api/v1")
    app.state.container = MagicMock(
        analysis_service=analysis_service,
        metrics_service=metrics_service,
        rate_limiter=AsyncMock(),
    )
    app.dependency_overrides[get_current_user] = lambda: {"_id": USER_ID}
    return TestClient(app)


def test_endpoints_history_detail_delete_metrics() -> None:
    analysis_service = MagicMock()
    analysis_service.list_history = AsyncMock(return_value=([], "abc"))
    analysis_service.get_detail = AsyncMock(side_effect=AnalysisNotFoundError())
    analysis_service.delete_analysis = AsyncMock(side_effect=AnalysisNotFoundError())
    metrics_service = MagicMock()
    metrics_service.get_user_metrics = AsyncMock(
        return_value={
            "total_escaneos": 2,
            "total_url": 1,
            "total_sms": 1,
            "amenazas_bloqueadas": 1,
            "ultima_actualizacion": None,
        }
    )
    client = _app(analysis_service, metrics_service)

    r = client.get("/api/v1/analysis")
    assert r.status_code == 200 and r.json() == {"items": [], "next_cursor": "abc"}
    assert client.get("/api/v1/analysis/xyz").status_code == 404
    assert client.delete("/api/v1/analysis/xyz").status_code == 404
    assert client.get("/api/v1/metrics/me").json()["total_escaneos"] == 2

    analysis_service.list_history = AsyncMock(side_effect=InvalidCursorError())
    assert client.get("/api/v1/analysis?cursor=bad").status_code == 400


def test_endpoints_require_authentication() -> None:
    app = FastAPI()
    app.include_router(analysis_api.router, prefix="/api/v1")
    app.include_router(metrics_api.router, prefix="/api/v1")
    app.state.container = MagicMock()
    client = TestClient(app)
    assert client.get("/api/v1/analysis").status_code == 401
    assert client.get("/api/v1/metrics/me").status_code == 401
    assert (
        client.post(
            "/api/v1/analysis", json={"tipo_entrada": "url", "contenido": "https://a.com"}
        ).status_code
        == 401
    )


@pytest.mark.asyncio
async def test_persistence_failure_raises_persistence_error_and_maps_to_503() -> None:
    from pymongo.errors import OperationFailure

    from app.api.errors import register_exception_handlers
    from app.core.exceptions import PersistenceError

    service, analysis_repo, _, _ = _service()
    analysis_repo.insert_analysis = AsyncMock(
        side_effect=OperationFailure("Transaction numbers are only allowed on a replica set")
    )
    with pytest.raises(PersistenceError):
        await service.analyze("url", "https://example.com/", str(USER_ID))

    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/boom")
    async def boom() -> None:
        raise PersistenceError()

    resp = TestClient(app).get("/boom")
    assert resp.status_code == 503
    assert "Transaction" not in resp.text  # sin detalles internos
