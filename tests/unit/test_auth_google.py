"""Pruebas de POST /auth/google (RF-06.4, RF-06.5, RN-18, RN-19, RN-24, D13).

La validación criptográfica del JWT (google-auth) no se ejecuta aquí: el decodificador se inyecta.
Se prueba todo lo que rodea a esa llamada: emisor, email_verificado, caché de certificados,
fallos de red, configuración y la lógica de alta/vinculación.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, ClassVar
from unittest.mock import AsyncMock

import httpx
import pytest
from bson import ObjectId
from fastapi import FastAPI
from pymongo.errors import DuplicateKeyError

from app.api.errors import register_exception_handlers
from app.api.v1 import auth
from app.clients.google_identity import (
    CERTS_URL,
    GoogleIdentity,
    GoogleIdentityClient,
)
from app.core.exceptions import GoogleTokenInvalidError, IdentityProviderUnavailableError
from app.core.security import decode_access_token, decode_refresh_token, hash_password
from app.services.auth_service import AuthService
from app.services.rate_limiter import RateLimiter

CLIENT_ID = "cliente-de-prueba.apps.googleusercontent.com"
SUB = "109876543210987654321"


# ----------------------------------------------------------------- cliente


def _claims(**over: Any) -> dict[str, Any]:
    base = {
        "iss": "https://accounts.google.com",
        "aud": CLIENT_ID,
        "sub": SUB,
        "email": "Ana@Correo.com",
        "email_verified": True,
        "name": "Ana Pérez",
    }
    base.update(over)
    return base


class CertsServer:
    """httpx.AsyncClient falso que cuenta las descargas de certificados."""

    def __init__(self, status: int = 200, cache_control: str = "public, max-age=3600") -> None:
        self.calls = 0
        self.status = status
        self.cache_control = cache_control

    def build(self) -> httpx.AsyncClient:
        def handler(request: httpx.Request) -> httpx.Response:
            assert str(request.url) == CERTS_URL
            self.calls += 1
            return httpx.Response(
                self.status, json={"kid1": "PEM"}, headers={"cache-control": self.cache_control}
            )

        return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _client(claims: dict[str, Any] | Exception, server: CertsServer | None = None, **kw: Any):
    seen: dict[str, Any] = {}

    def decoder(token: str, certs: Any, audience: str) -> Any:
        seen.update(token=token, certs=dict(certs), audience=audience)
        if isinstance(claims, Exception):
            raise claims
        return claims

    server = server or CertsServer()
    client = GoogleIdentityClient(
        client_id=kw.pop("client_id", CLIENT_ID),
        http_client=server.build(),
        decoder=decoder,
        **kw,
    )
    return client, server, seen


@pytest.mark.asyncio
async def test_client_returns_normalized_identity_and_passes_audience() -> None:
    client, _, seen = _client(_claims())
    identity = await client.verify_id_token("jwt")
    assert identity == GoogleIdentity(SUB, "ana@correo.com", True, "Ana Pérez")
    assert seen["audience"] == CLIENT_ID and seen["certs"] == {"kid1": "PEM"}


@pytest.mark.asyncio
@pytest.mark.parametrize("iss", ["https://evil.example", None, "accounts.google.com.evil"])
async def test_client_rejects_wrong_issuer(iss: str | None) -> None:
    client, _, _ = _client(_claims(iss=iss))
    with pytest.raises(GoogleTokenInvalidError):
        await client.verify_id_token("jwt")


@pytest.mark.asyncio
async def test_client_accepts_both_google_issuer_forms() -> None:
    client, _, _ = _client(_claims(iss="accounts.google.com"))
    assert (await client.verify_id_token("jwt")).sub == SUB


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["sub", "email"])
async def test_client_rejects_missing_sub_or_email(missing: str) -> None:
    claims = _claims()
    claims.pop(missing)
    client, _, _ = _client(claims)
    with pytest.raises(GoogleTokenInvalidError):
        await client.verify_id_token("jwt")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("raw", "expected"),
    [(True, True), ("true", True), (False, False), ("false", False), (None, False)],
)
async def test_client_email_verified_parsing(raw: Any, expected: bool) -> None:
    client, _, _ = _client(_claims(email_verified=raw))
    assert (await client.verify_id_token("jwt")).email_verified is expected


@pytest.mark.asyncio
async def test_client_propagates_invalid_token_from_decoder() -> None:
    client, _, _ = _client(GoogleTokenInvalidError())
    with pytest.raises(GoogleTokenInvalidError):
        await client.verify_id_token("jwt")


@pytest.mark.asyncio
async def test_client_without_client_id_is_unavailable_and_does_not_fetch_certs() -> None:
    client, server, _ = _client(_claims(), client_id="")
    with pytest.raises(IdentityProviderUnavailableError):
        await client.verify_id_token("jwt")
    assert server.calls == 0


@pytest.mark.asyncio
async def test_client_caches_certs_between_calls() -> None:
    client, server, _ = _client(_claims())
    await client.verify_id_token("a")
    await client.verify_id_token("b")
    assert server.calls == 1


@pytest.mark.asyncio
async def test_client_certs_fetch_failure_is_unavailable_not_invalid() -> None:
    client, _, _ = _client(_claims(), CertsServer(status=500))
    with pytest.raises(IdentityProviderUnavailableError):
        await client.verify_id_token("jwt")


@pytest.mark.asyncio
async def test_client_network_error_is_unavailable() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sin red")

    client = GoogleIdentityClient(
        client_id=CLIENT_ID,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(boom)),
        decoder=lambda *_: _claims(),
    )
    with pytest.raises(IdentityProviderUnavailableError):
        await client.verify_id_token("jwt")


# ---------------------------------------------------------------- servicio


class FakeUserRepo:
    def __init__(self, *users: dict[str, Any]) -> None:
        self.users: dict[ObjectId, dict[str, Any]] = {u["_id"]: u for u in users}
        self.duplicate_once = False

    async def find_by_google_sub(self, sub: str) -> dict[str, Any] | None:
        return next((u for u in self.users.values() if u.get("google_sub") == sub), None)

    async def find_by_email(self, email: str) -> dict[str, Any] | None:
        return next((u for u in self.users.values() if u["email"] == email), None)

    async def create_user(self, doc: dict[str, Any]) -> dict[str, Any]:
        if self.duplicate_once:
            self.duplicate_once = False
            raise DuplicateKeyError("dup")
        doc["_id"] = ObjectId()
        self.users[doc["_id"]] = doc
        return doc

    async def link_google_sub(self, user_id: ObjectId, sub: str) -> bool:
        u = self.users[user_id]
        if u["estado_cuenta"] != "activa" or u.get("google_sub") is not None:
            return False
        u["google_sub"] = sub
        return True

    async def activate_pending_with_google(self, user_id: ObjectId, sub: str) -> bool:
        u = self.users[user_id]
        if u["estado_cuenta"] != "pendiente_verificacion":
            return False
        now = datetime.now(UTC)
        u.update(
            proveedor_auth="google",
            google_sub=sub,
            password_hash=None,
            estado_cuenta="activa",
            email_verificado=True,
            fecha_verificacion=now,
            password_changed_at=now,
        )
        return True


def _local(estado: str = "activa", **extra: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "_id": ObjectId(),
        "email": "ana@correo.com",
        "nombre": "Ana",
        "proveedor_auth": "local",
        "google_sub": None,
        "password_hash": hash_password("PasswordSeguro123!"),
        "estado_cuenta": estado,
        "email_verificado": estado == "activa",
        "password_changed_at": None,
    }
    doc.update(extra)
    return doc


class Env:
    def __init__(
        self, *users: dict[str, Any], identity: GoogleIdentity | Exception | None = None
    ) -> None:
        self.repo = FakeUserRepo(*users)
        self.google = AsyncMock()
        if isinstance(identity, Exception):
            self.google.verify_id_token.side_effect = identity
        else:
            self.google.verify_id_token.return_value = identity or GoogleIdentity(
                SUB, "ana@correo.com", True, "Ana Pérez"
            )
        self.service = AuthService(self.repo, AsyncMock(), google_client=self.google)  # type: ignore[arg-type]

        class _Repo:
            counts: ClassVar[dict[str, int]] = {}

            async def hit(self, key: str, window: int) -> tuple[int, int]:
                self.counts[key] = self.counts.get(key, 0) + 1
                return self.counts[key], window

        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(auth.router, prefix="/api/v1")

        class _Container:
            auth_service = self.service
            rate_limiter = RateLimiter(_Repo())  # type: ignore[arg-type]

        app.state.container = _Container()
        self.http = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")

    async def login(self, token: str = "jwt-de-google"):
        return await self.http.post("/api/v1/auth/google", json={"id_token": token})


@pytest.mark.asyncio
async def test_new_user_is_created_active_verified_without_password() -> None:
    e = Env()
    r = await e.login()
    assert r.status_code == 200
    body = r.json()
    user = next(iter(e.repo.users.values()))
    assert user["proveedor_auth"] == "google" and user["google_sub"] == SUB
    assert user["estado_cuenta"] == "activa" and user["email_verificado"] is True
    assert user["password_hash"] is None and user["nombre"] == "Ana Pérez"
    assert decode_access_token(body["access_token"])["sub"] == str(user["_id"])
    assert decode_refresh_token(body["refresh_token"])["type"] == "refresh"


@pytest.mark.asyncio
async def test_new_user_without_name_uses_email_local_part() -> None:
    e = Env(identity=GoogleIdentity(SUB, "sin.nombre@correo.com", True, None))
    assert (await e.login()).status_code == 200
    assert next(iter(e.repo.users.values()))["nombre"] == "sin.nombre"


@pytest.mark.asyncio
async def test_existing_google_user_logs_in_by_sub_even_if_email_changed() -> None:
    u = _local(
        proveedor_auth="google", google_sub=SUB, password_hash=None, email="viejo@correo.com"
    )
    e = Env(u)
    assert (await e.login()).status_code == 200
    assert len(e.repo.users) == 1


@pytest.mark.asyncio
async def test_active_local_account_is_linked_keeping_provider_and_password() -> None:
    u = _local()
    original_hash = u["password_hash"]
    e = Env(u)
    assert (await e.login()).status_code == 200
    assert u["google_sub"] == SUB and u["proveedor_auth"] == "local"
    assert u["password_hash"] == original_hash


@pytest.mark.asyncio
async def test_pending_account_is_activated_discarding_password_and_revoking_tokens() -> None:
    u = _local("pendiente_verificacion")
    e = Env(u)
    assert (await e.login()).status_code == 200
    assert u["estado_cuenta"] == "activa" and u["email_verificado"] is True
    assert u["password_hash"] is None and u["proveedor_auth"] == "google"
    assert u["password_changed_at"] is not None


@pytest.mark.asyncio
async def test_unverified_google_email_is_409_and_creates_nothing() -> None:
    e = Env(identity=GoogleIdentity(SUB, "ana@correo.com", False, "Ana"))
    assert (await e.login()).status_code == 409
    assert not e.repo.users


@pytest.mark.asyncio
async def test_account_linked_to_another_google_identity_is_409() -> None:
    u = _local(google_sub="otra-identidad")
    e = Env(u)
    assert (await e.login()).status_code == 409
    assert u["google_sub"] == "otra-identidad"


@pytest.mark.asyncio
@pytest.mark.parametrize("estado", ["suspendida", "eliminada"])
async def test_suspended_or_deleted_accounts_are_401(estado: str) -> None:
    u = _local(estado)
    e = Env(u)
    r = await e.login()
    assert r.status_code == 401
    assert u["estado_cuenta"] == estado and u["google_sub"] is None


@pytest.mark.asyncio
async def test_invalid_google_token_is_401_without_echoing_it() -> None:
    e = Env(identity=GoogleTokenInvalidError())
    r = await e.login("secreto-token-123")
    assert r.status_code == 401
    assert "secreto-token-123" not in r.text


@pytest.mark.asyncio
async def test_google_unavailable_is_503() -> None:
    e = Env(identity=IdentityProviderUnavailableError())
    assert (await e.login()).status_code == 503


@pytest.mark.asyncio
async def test_concurrent_creation_is_retried_once() -> None:
    e = Env()
    e.repo.duplicate_once = True
    assert (await e.login()).status_code == 200
    assert len(e.repo.users) == 1


@pytest.mark.asyncio
async def test_google_login_is_rate_limited_per_ip() -> None:
    e = Env()
    codes = [(await e.login()).status_code for _ in range(6)]
    assert codes[:5] == [200] * 5 and codes[5] == 429
