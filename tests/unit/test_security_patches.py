"""Pruebas de los parches de seguridad (ver parches-seguridad.md)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from bson import ObjectId
from fastapi import FastAPI, Response
from fastapi.testclient import TestClient
from pydantic import BaseModel, ValidationError

from app.api.errors import register_exception_handlers
from app.api.middleware import MAX_BODY_BYTES, BodySizeLimitMiddleware
from app.api.schemas.auth import LoginRequest, UserRegisterRequest
from app.core import security
from app.core.security import hash_password_async, verify_password, verify_password_async
from app.engine.url_extractor import extract_urls_from_text, normalize_url
from app.repositories.redis.verification_repository import VerificationRepository
from app.services.auth_service import AuthService

# --- 1. Pre-hijacking de cuenta pendiente -------------------------------------------------


@pytest.mark.asyncio
async def test_register_pending_account_keeps_original_password_and_resends_code() -> None:
    pending = {
        "_id": ObjectId(),
        "email": "victima@correo.com",
        "nombre": "Victima",
        "password_hash": "hash-original",
        "estado_cuenta": "pendiente_verificacion",
    }
    repo = MagicMock()
    repo.find_by_email = AsyncMock(return_value=pending)
    repo.create_user = AsyncMock()
    verification = MagicMock()
    verification.generate_and_save_code = AsyncMock()
    service = AuthService(user_repository=repo, verification_service=verification)

    result = await service.register_user("victima@correo.com", "ClaveDelAtacante1!", "Atacante")

    assert result["password_hash"] == "hash-original"
    assert result["nombre"] == "Victima"
    repo.create_user.assert_not_called()
    assert not hasattr(repo, "update_pending_user") or not repo.update_pending_user.called
    verification.generate_and_save_code.assert_awaited_once()


# --- 2. Argon2 fuera del event loop -------------------------------------------------------


@pytest.mark.asyncio
async def test_async_hashing_roundtrip() -> None:
    hashed = await hash_password_async("clave-correcta-1")
    assert verify_password("clave-correcta-1", hashed)
    assert await verify_password_async("clave-correcta-1", hashed) is True
    assert await verify_password_async("otra", hashed) is False


@pytest.mark.asyncio
async def test_hashing_does_not_block_event_loop() -> None:
    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(0.005)
            ticks += 1

    task = asyncio.create_task(ticker())
    await hash_password_async("clave-correcta-1")
    task.cancel()
    # Con hash síncrono el ticker no avanzaría durante los ~100 ms del hash.
    assert ticks >= 3


@pytest.mark.asyncio
async def test_hash_concurrency_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    active = 0
    peak = 0

    def fake_hash(_: str) -> str:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        import time

        time.sleep(0.02)
        active -= 1
        return "x"

    monkeypatch.setattr(security, "hash_password", fake_hash)
    await asyncio.gather(*(hash_password_async("p") for _ in range(12)))
    assert peak <= security._MAX_CONCURRENT_HASHES


# --- 3. Tamaño de contraseña y de cuerpo --------------------------------------------------


def test_password_max_length_enforced() -> None:
    long_password = "a" * 129
    with pytest.raises(ValidationError):
        UserRegisterRequest(email="a@b.com", password=long_password, nombre="Ana")
    with pytest.raises(ValidationError):
        LoginRequest(email="a@b.com", password=long_password)
    assert LoginRequest(email="a@b.com", password="a" * 128).password == "a" * 128


class _Payload(BaseModel):
    texto: str


def _app_with_limit() -> TestClient:
    app = FastAPI()
    register_exception_handlers(app)
    app.add_middleware(BodySizeLimitMiddleware)

    @app.post("/eco")
    async def eco(payload: _Payload) -> dict[str, int]:
        return {"n": len(payload.texto)}

    return TestClient(app)


def test_body_within_limit_is_accepted() -> None:
    response = _app_with_limit().post("/eco", json={"texto": "hola"})
    assert response.status_code == 200


def test_oversized_content_length_is_rejected_with_413() -> None:
    body = '{"texto": "' + "a" * MAX_BODY_BYTES + '"}'
    response = _app_with_limit().post(
        "/eco", content=body, headers={"content-type": "application/json"}
    )
    assert response.status_code == 413
    assert response.json()["code"] == "PAYLOAD_TOO_LARGE"


def test_oversized_chunked_body_is_rejected_with_413() -> None:
    def chunks():  # sin Content-Length: transferencia por fragmentos
        yield b'{"texto": "'
        for _ in range(MAX_BODY_BYTES // 1024 + 2):
            yield b"a" * 1024
        yield b'"}'

    response = _app_with_limit().post(
        "/eco", content=chunks(), headers={"content-type": "application/json"}
    )
    assert response.status_code == 413
    assert response.json()["code"] == "PAYLOAD_TOO_LARGE"


# --- 6. normalize_url con puerto o formato inválido ---------------------------------------


def test_normalize_url_invalid_port_does_not_raise() -> None:
    assert normalize_url("https://evil.com:99999/login") == "https://evil.com/login"
    assert normalize_url("evil.com:abc/x") == "https://evil.com/x"


def test_normalize_url_malformed_ipv6_returns_empty() -> None:
    assert normalize_url("https://[abc/x") == ""


def test_sms_with_invalid_port_is_still_analyzed() -> None:
    urls = extract_urls_from_text("Verifica en evil.com:99999/login ahora")
    assert urls == ["https://evil.com/login"]


# --- 8. Contador de intentos atómico ------------------------------------------------------


@pytest.mark.asyncio
async def test_increment_attempts_uses_atomic_script() -> None:
    redis = MagicMock()
    redis.eval = AsyncMock(return_value=3)
    redis.incr = AsyncMock()
    redis.expire = AsyncMock()
    repo = VerificationRepository(redis)

    assert await repo.increment_attempts("u1") == 3

    redis.eval.assert_awaited_once()
    args = redis.eval.await_args.args
    assert args[1:3] == (1, "verif_attempts:u1")
    assert "INCR" in args[0] and "EXPIRE" in args[0]
    redis.incr.assert_not_called()
    redis.expire.assert_not_called()


# --- 9. Cabeceras de seguridad ------------------------------------------------------------


def _headers_client(production: bool) -> TestClient:
    from app.api.middleware import SecurityHeadersMiddleware

    app = FastAPI()
    register_exception_handlers(app)
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware, production=production)

    @app.get("/ok")
    async def ok() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/propio")
    async def propio() -> Response:
        return Response("x", headers={"Cache-Control": "max-age=60"})

    @app.post("/eco")
    async def eco(payload: _Payload) -> dict[str, int]:
        return {"n": len(payload.texto)}

    return TestClient(app)


def test_security_headers_on_success_and_error_responses() -> None:
    client = _headers_client(production=False)
    for response in (
        client.get("/ok"),
        client.get("/no-existe"),  # 404 del manejador global
        client.post("/eco", content="x" * (MAX_BODY_BYTES + 1)),  # 413 del middleware interno
    ):
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "strict-transport-security" not in response.headers
        assert "content-security-policy" not in response.headers


def test_hsts_and_csp_only_in_production() -> None:
    response = _headers_client(production=True).get("/ok")
    assert "max-age=" in response.headers["strict-transport-security"]
    assert "default-src 'none'" in response.headers["content-security-policy"]


def test_security_headers_do_not_override_existing_ones() -> None:
    response = _headers_client(production=False).get("/propio")
    assert response.headers["cache-control"] == "max-age=60"


# --- 12. Log JSON con escape --------------------------------------------------------------


def test_json_log_escapes_quotes_and_newlines() -> None:
    import json
    import logging

    from app.core.logging import JsonFormatter

    record = logging.LogRecord(
        "antfish", logging.WARNING, __file__, 1, 'dato "malo"\n{"level": "CRITICAL"}', None, None
    )
    record.api = "virus\ntotal"  # campo extra
    line = JsonFormatter().format(record)

    assert "\n" not in line  # una sola línea: no se pueden inyectar registros falsos
    data = json.loads(line)
    assert data["level"] == "WARNING"
    assert data["message"] == 'dato "malo"\n{"level": "CRITICAL"}'
    assert data["api"] == "virus\ntotal"


# --- 13. Errores de Resend sin cuerpo de respuesta ----------------------------------------


@pytest.mark.asyncio
async def test_resend_error_message_does_not_leak_response_body() -> None:
    import httpx

    from app.clients.resend_email import ResendEmailClient
    from app.core.exceptions import EmailDeliveryError

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, text="destinatario secreto@correo.com inválido")

    client = ResendEmailClient(
        api_key="k", client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(EmailDeliveryError) as exc:
        await client.send_email("secreto@correo.com", "asunto", "<p>x</p>")
    assert "secreto" not in str(exc.value)
    assert "422" in str(exc.value)
