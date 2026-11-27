"""Contrato único de error: {"code", "detail"} en todas las respuestas de error."""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.api.errors import api_error, register_exception_handlers
from app.api.schemas.auth import DeleteAccountRequest, LoginRequest, UserRegisterRequest
from app.core.exceptions import PersistenceError, RateLimitExceededError


class _Body(BaseModel):
    n: int


def _client() -> httpx.AsyncClient:
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/plain")
    async def plain() -> None:
        raise HTTPException(status_code=404, detail="No existe")

    @app.get("/specific")
    async def specific() -> None:
        raise api_error(
            401, "INVALID_TOKEN", "Token inválido", headers={"WWW-Authenticate": "Bearer"}
        )

    @app.get("/limit")
    async def limit() -> None:
        raise RateLimitExceededError("Demasiadas solicitudes", retry_after=7)

    @app.get("/db")
    async def db() -> None:
        raise PersistenceError()

    @app.post("/validate")
    async def validate(body: _Body) -> None:
        return None

    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


@pytest.mark.asyncio
async def test_generic_http_error_gets_status_based_code() -> None:
    r = await _client().get("/plain")
    assert r.status_code == 404 and r.json() == {"code": "NOT_FOUND", "detail": "No existe"}


@pytest.mark.asyncio
async def test_unknown_route_has_code() -> None:
    r = await _client().get("/nada")
    assert r.status_code == 404 and r.json()["code"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_specific_code_and_headers_are_kept() -> None:
    r = await _client().get("/specific")
    assert r.status_code == 401
    assert r.json() == {"code": "INVALID_TOKEN", "detail": "Token inválido"}
    assert r.headers["www-authenticate"] == "Bearer"


@pytest.mark.asyncio
async def test_rate_limit_is_429_with_code_and_retry_after() -> None:
    r = await _client().get("/limit")
    assert r.status_code == 429 and r.json()["code"] == "RATE_LIMIT_EXCEEDED"
    assert r.headers["retry-after"] == "7"


@pytest.mark.asyncio
async def test_persistence_error_is_503_with_code() -> None:
    r = await _client().get("/db")
    assert r.status_code == 503 and r.json()["code"] == "SERVICE_UNAVAILABLE"


@pytest.mark.asyncio
async def test_validation_error_is_422_with_code_and_list_detail() -> None:
    r = await _client().post("/validate", json={"n": "abc"})
    assert r.status_code == 422 and r.json()["code"] == "VALIDATION_ERROR"
    assert isinstance(r.json()["detail"], list)


@pytest.mark.parametrize(
    ("content", "content_type"),
    [
        (b'{"email":"a@correo.com","password":"Secr3t!","nombre":"x"}', "application/json"),
        (b"\xff\xfe\x00", "text/plain"),
        (b'{"email":"a@correo.com","password":"\\ud800aaaaaaaa","nombre":"x"}', "application/json"),
        (
            b'{"email":"\\ud800@correo.com","password":"aaaaaaaaaa","nombre":"x"}',
            "application/json",
        ),
    ],
)
def test_validation_errors_never_echo_input_nor_crash(content: bytes, content_type: str) -> None:
    app = FastAPI()
    register_exception_handlers(app)

    @app.post("/r")
    def register(payload: UserRegisterRequest) -> None:
        return None

    client = TestClient(app, raise_server_exceptions=False)
    r = client.post("/r", content=content, headers={"content-type": content_type})
    assert r.status_code == 422
    assert "Secr3t!" not in r.text
    assert all(set(item) == {"type", "loc", "msg"} for item in r.json()["detail"])


def test_password_is_trimmed_the_same_in_register_login_and_delete() -> None:
    raw = "  clave1234  "
    register = UserRegisterRequest(email="a@correo.com", password=raw, nombre="n")
    login = LoginRequest(email="a@correo.com", password=raw)
    delete = DeleteAccountRequest(password=raw)
    assert register.password == login.password == delete.password == "clave1234"
