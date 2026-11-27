"""Pruebas de rate limiting y cuota dual (DP-04, D17, RF-04, RNF-02, RNF-03)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from redis.exceptions import ConnectionError as RedisConnectionError

from app.api.deps import rate_limit_read
from app.api.errors import register_exception_handlers
from app.api.v1 import analysis, auth, metrics
from app.clients.base import ReputationResult
from app.core.exceptions import RateLimitBackendError, RateLimitExceededError
from app.engine.models import Reputation, SourceStatus
from app.services.analysis_service import AnalysisService
from app.services.rate_limiter import RateLimiter
from app.services.verification_service import VerificationService


class FakeRepo:
    """Contador en memoria con la misma interfaz que RateLimitRepository."""

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    async def hit(self, key: str, window_seconds: int) -> tuple[int, int]:
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key], window_seconds


class BrokenRepo:
    async def hit(self, key: str, window_seconds: int) -> tuple[int, int]:
        raise RedisConnectionError("redis caído")


@pytest.mark.asyncio
async def test_auth_limit_is_5_per_ip_and_endpoint() -> None:
    limiter = RateLimiter(FakeRepo())  # type: ignore[arg-type]
    for _ in range(5):
        await limiter.check_auth("login", "1.2.3.4")
    with pytest.raises(RateLimitExceededError) as exc:
        await limiter.check_auth("login", "1.2.3.4")
    assert exc.value.retry_after == 60
    await limiter.check_auth("login", "5.6.7.8")  # otra IP no se ve afectada
    await limiter.check_auth("register", "1.2.3.4")  # otro endpoint, contador propio


@pytest.mark.asyncio
async def test_analysis_limit_is_20_per_user_and_fail_open() -> None:
    limiter = RateLimiter(FakeRepo())  # type: ignore[arg-type]
    for _ in range(20):
        await limiter.check_analysis("u1")
    with pytest.raises(RateLimitExceededError):
        await limiter.check_analysis("u1")
    await limiter.check_analysis("u2")

    # Redis caído: el análisis NO se bloquea (fail-open).
    await RateLimiter(BrokenRepo()).check_analysis("u1")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_auth_and_resend_are_fail_closed() -> None:
    limiter = RateLimiter(BrokenRepo())  # type: ignore[arg-type]
    with pytest.raises(RateLimitBackendError):
        await limiter.check_auth("login", "1.2.3.4")
    with pytest.raises(RateLimitBackendError):
        await limiter.check_resend("u1")


@pytest.mark.asyncio
async def test_resend_limit_is_3_per_hour_shared_key() -> None:
    repo = FakeRepo()
    limiter = RateLimiter(repo)  # type: ignore[arg-type]
    for _ in range(3):
        await limiter.check_resend("u1")
    with pytest.raises(RateLimitExceededError):
        await limiter.check_resend("u1")
    assert "reenvio:u1" in repo.counts


@pytest.mark.asyncio
async def test_no_email_is_sent_when_resend_limit_exceeded() -> None:
    email_client = AsyncMock()
    limiter = RateLimiter(FakeRepo())  # type: ignore[arg-type]
    service = VerificationService(
        verification_repo=AsyncMock(), email_client=email_client, rate_limiter=limiter
    )
    for _ in range(3):
        await service.generate_and_save_code("u1", "a@b.com")
    with pytest.raises(RateLimitExceededError):
        await service.generate_and_save_code("u1", "a@b.com")
    assert email_client.send_verification_code.await_count == 3


def _auth_app(rate_limiter: Any) -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(auth.router, prefix="/api/v1")
    container = MagicMock()
    container.rate_limiter = rate_limiter
    container.auth_service.authenticate_user = AsyncMock(side_effect=Exception("no debe llegar"))
    app.state.container = container
    return app


@pytest.mark.asyncio
async def test_login_endpoint_returns_429_with_retry_after() -> None:
    limiter = AsyncMock()
    limiter.check_auth.side_effect = RateLimitExceededError(retry_after=42)
    transport = httpx.ASGITransport(app=_auth_app(limiter))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.post("/api/v1/auth/login", json={"email": "a@b.com", "password": "x" * 12})
    assert r.status_code == 429
    assert r.headers["retry-after"] == "42"
    assert "Exception" not in r.text


@pytest.mark.asyncio
async def test_login_endpoint_returns_503_when_limiter_backend_down() -> None:
    limiter = AsyncMock()
    limiter.check_auth.side_effect = RateLimitBackendError()
    transport = httpx.ASGITransport(app=_auth_app(limiter))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.post("/api/v1/auth/login", json={"email": "a@b.com", "password": "x" * 12})
    assert r.status_code == 503


# ---------------- Cuota dual en el servicio de análisis ----------------


def _client(api: str) -> AsyncMock:
    mock = AsyncMock()
    mock.check_url.return_value = ReputationResult(
        reputation=Reputation(api=api, estado=SourceStatus.OK, positivo=False, detecciones=None),
        raw_response={"api": api},
    )
    return mock


def _service(quota: Any) -> tuple[AnalysisService, dict[str, AsyncMock]]:
    clients = {n: _client(n) for n in ("google_web_risk", "virustotal", "phishtank")}
    service = AnalysisService(
        web_risk_client=clients["google_web_risk"],
        virustotal_client=clients["virustotal"],
        phishtank_client=clients["phishtank"],
        quota_repository=quota,
    )
    return service, clients


@pytest.mark.asyncio
async def test_exhausted_quota_skips_api_and_marks_partial_analysis() -> None:
    quota = MagicMock()

    async def consume(api: str, pm: int, daily: int) -> bool:
        return api != "virustotal"

    quota.try_consume = consume
    service, clients = _service(quota)
    result = await service.analyze("url", "https://example.com/login")

    clients["virustotal"].check_url.assert_not_awaited()
    clients["google_web_risk"].check_url.assert_awaited_once()
    clients["phishtank"].check_url.assert_awaited_once()
    assert result["analisis_parcial"] is True
    estados = {f["api"]: f["estado"] for f in result["fuentes_consultadas"]}
    assert estados["virustotal"] == "rate_limit"


@pytest.mark.asyncio
async def test_quota_backend_failure_is_fail_open() -> None:
    quota = MagicMock()
    quota.try_consume = AsyncMock(side_effect=RedisConnectionError("caído"))
    service, clients = _service(quota)
    result = await service.analyze("url", "https://example.com/login")
    for c in clients.values():
        c.check_url.assert_awaited_once()
    assert result["analisis_parcial"] is False


@pytest.mark.asyncio
async def test_phishtank_disabled_is_not_queried_nor_counted_as_failure() -> None:
    web_risk, vt = _client("google_web_risk"), _client("virustotal")
    service = AnalysisService(web_risk_client=web_risk, virustotal_client=vt, phishtank_client=None)
    result = await service.analyze("url", "https://example.com/login")
    apis = {f["api"] for f in result["fuentes_consultadas"]}
    assert apis == {"google_web_risk", "virustotal"}
    assert result["analisis_parcial"] is False  # la ausencia de PhishTank no degrada el análisis


@pytest.mark.asyncio
async def test_check_auth_accepts_custom_limit() -> None:
    limiter = RateLimiter(FakeRepo())  # type: ignore[arg-type]
    for _ in range(20):
        await limiter.check_auth("refresh", "1.2.3.4", 20)
    with pytest.raises(RateLimitExceededError):
        await limiter.check_auth("refresh", "1.2.3.4", 20)


@pytest.mark.asyncio
async def test_read_limit_is_per_user_and_fail_open() -> None:
    limiter = RateLimiter(FakeRepo())  # type: ignore[arg-type]
    for _ in range(60):
        await limiter.check_read("u1")
    with pytest.raises(RateLimitExceededError):
        await limiter.check_read("u1")
    await limiter.check_read("u2")
    await RateLimiter(BrokenRepo()).check_read("u1")  # type: ignore[arg-type]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/v1/auth/verify-email", {"email": "a@b.com", "codigo": "123456"}),
        ("/api/v1/auth/refresh", {"refresh_token": "x"}),
    ],
)
async def test_verify_and_refresh_return_429(path: str, body: dict[str, str]) -> None:
    limiter = AsyncMock()
    limiter.check_auth.side_effect = RateLimitExceededError(retry_after=7)
    transport = httpx.ASGITransport(app=_auth_app(limiter))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.post(path, json=body)
    assert r.status_code == 429
    assert r.headers["retry-after"] == "7"


def test_every_authenticated_query_route_is_rate_limited() -> None:
    expected = {
        ("GET", "/analysis"),
        ("GET", "/analysis/{analysis_id}"),
        ("DELETE", "/analysis/{analysis_id}"),
        ("GET", "/metrics/me"),
    }
    found = {
        (method, route.path)
        for router in (analysis.router, metrics.router)
        for route in router.routes
        if isinstance(route, APIRoute)
        and any(d.call is rate_limit_read for d in route.dependant.dependencies)
        for method in route.methods
    }
    assert found == expected
