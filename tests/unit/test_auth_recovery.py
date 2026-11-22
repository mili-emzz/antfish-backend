"""Pruebas de resend-code, password/forgot, password/reset y refresh (RF-06.3, RF-06.6, D17, D18)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from bson import ObjectId
from fastapi import FastAPI

from app.api.errors import register_exception_handlers
from app.api.v1 import auth
from app.core.exceptions import EmailDeliveryError
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.services.auth_service import AuthService
from app.services.rate_limiter import RateLimiter
from app.services.verification_service import VerificationService

PASSWORD = "PasswordSeguro123!"


class FakeUserRepo:
    def __init__(self, *users: dict[str, Any]) -> None:
        self.users = {u["_id"]: u for u in users}

    async def find_by_email(self, email: str) -> dict[str, Any] | None:
        return next((u for u in self.users.values() if u["email"] == email), None)

    async def find_by_id(self, user_id: Any) -> dict[str, Any] | None:
        return self.users.get(ObjectId(user_id))

    async def update_password(self, user_id: Any, password_hash: str) -> bool:
        user = self.users[ObjectId(user_id)]
        if user["estado_cuenta"] != "activa":
            return False
        user["password_hash"] = password_hash
        user["password_changed_at"] = datetime.now(UTC)
        return True

    async def mark_as_verified(self, user_id: str) -> bool:
        self.users[ObjectId(user_id)]["estado_cuenta"] = "activa"
        return True


class FakeVerificationRepo:
    def __init__(self) -> None:
        self.codes: dict[str, str] = {}
        self.attempts: dict[str, int] = {}

    async def save_code(self, user_id: str, hashed: str, ttl: int = 600) -> None:
        self.codes[user_id] = hashed

    async def get_code(self, user_id: str) -> str | None:
        return self.codes.get(user_id)

    async def delete_code(self, user_id: str) -> None:
        self.codes.pop(user_id, None)

    async def increment_attempts(self, user_id: str) -> int:
        self.attempts[user_id] = self.attempts.get(user_id, 0) + 1
        return self.attempts[user_id]

    async def clear_attempts(self, user_id: str) -> None:
        self.attempts.pop(user_id, None)


class FakeSessionRepo:
    def __init__(self) -> None:
        self.families: dict[str, str] = {}

    async def start(self, family: str, jti: str, ttl_seconds: int) -> None:
        self.families[family] = jti

    async def rotate(self, family: str, old_jti: str, new_jti: str, ttl_seconds: int) -> bool:
        if self.families.get(family) != old_jti:
            return False
        self.families[family] = new_jti
        return True

    async def revoke(self, family: str) -> None:
        self.families.pop(family, None)


class FakeRateRepo:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    async def hit(self, key: str, window: int) -> tuple[int, int]:
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key], window


def _user(estado: str = "activa", **extra: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "_id": ObjectId(),
        "email": "ana@correo.com",
        "nombre": "Ana",
        "password_hash": hash_password(PASSWORD),
        "estado_cuenta": estado,
        "password_changed_at": None,
    }
    doc.update(extra)
    return doc


class Env:
    def __init__(self, user: dict[str, Any] | None) -> None:
        self.user_repo = FakeUserRepo(*([user] if user else []))
        self.verif_repo = FakeVerificationRepo()
        self.email = AsyncMock()
        self.rate_repo = FakeRateRepo()
        self.limiter = RateLimiter(self.rate_repo)  # type: ignore[arg-type]
        self.verification = VerificationService(
            verification_repo=self.verif_repo,  # type: ignore[arg-type]
            email_client=self.email,
            rate_limiter=self.limiter,
        )
        self.sessions = FakeSessionRepo()
        self.service = AuthService(
            self.user_repo,  # type: ignore[arg-type]
            self.verification,
            session_repository=self.sessions,  # type: ignore[arg-type]
        )

        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(auth.router, prefix="/api/v1")

        class _Container:
            auth_service = self.service
            rate_limiter = self.limiter

        app.state.container = _Container()
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        )

    def sent_code(self, kind: str) -> str:
        method = getattr(self.email, kind)
        return method.await_args.args[1]


@pytest.fixture
def env() -> Env:
    return Env(_user())


# ---------------------------------------------------------------- resend-code


@pytest.mark.asyncio
async def test_resend_code_sends_for_pending_and_resets_attempts() -> None:
    e = Env(_user("pendiente_verificacion"))
    uid = str(next(iter(e.user_repo.users)))
    e.verif_repo.attempts[uid] = 4
    r = await e.client.post("/api/v1/auth/resend-code", json={"email": "Ana@Correo.com "})
    assert r.status_code == 200
    e.email.send_verification_code.assert_awaited_once()
    assert uid not in e.verif_repo.attempts  # RF-06.3: restablece intentos


@pytest.mark.asyncio
async def test_resend_code_uniform_for_unknown_and_active(env: Env) -> None:
    unknown = await env.client.post("/api/v1/auth/resend-code", json={"email": "no@x.com"})
    active = await env.client.post("/api/v1/auth/resend-code", json={"email": "ana@correo.com"})
    assert unknown.status_code == active.status_code == 200
    assert unknown.json() == active.json()
    env.email.send_verification_code.assert_not_awaited()


@pytest.mark.asyncio
async def test_resend_code_fourth_request_in_hour_is_429() -> None:
    e = Env(_user("pendiente_verificacion"))
    for _ in range(3):
        assert (
            await e.client.post("/api/v1/auth/resend-code", json={"email": "ana@correo.com"})
        ).status_code == 200
    # 4.º dentro de la hora; el límite por IP (5/min) aún no se agota
    r = await e.client.post("/api/v1/auth/resend-code", json={"email": "ana@correo.com"})
    assert r.status_code == 429
    assert r.headers["Retry-After"] == "3600"


@pytest.mark.asyncio
async def test_resend_code_email_failure_is_503() -> None:
    e = Env(_user("pendiente_verificacion"))
    e.email.send_verification_code.side_effect = EmailDeliveryError("x")
    r = await e.client.post("/api/v1/auth/resend-code", json={"email": "ana@correo.com"})
    assert r.status_code == 503


# ------------------------------------------------------------------- forgot


@pytest.mark.asyncio
async def test_forgot_is_uniform_and_only_sends_for_active_local(env: Env) -> None:
    known = await env.client.post("/api/v1/auth/password/forgot", json={"email": "ana@correo.com"})
    unknown = await env.client.post("/api/v1/auth/password/forgot", json={"email": "no@x.com"})
    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json()
    env.email.send_recovery_code.assert_awaited_once()
    assert env.email.send_recovery_code.await_args.args[0] == "ana@correo.com"


@pytest.mark.parametrize(
    "user",
    [
        _user("pendiente_verificacion"),
        _user("eliminada"),
        _user("suspendida"),
        _user(password_hash=None),
    ],
)
@pytest.mark.asyncio
async def test_forgot_skips_non_eligible_accounts(user: dict[str, Any]) -> None:
    e = Env(user)
    r = await e.client.post("/api/v1/auth/password/forgot", json={"email": "ana@correo.com"})
    assert r.status_code == 200
    e.email.send_recovery_code.assert_not_awaited()


@pytest.mark.asyncio
async def test_forgot_hides_rate_limit_and_email_failures(env: Env) -> None:
    env.email.send_recovery_code.side_effect = EmailDeliveryError("x")
    bodies = set()
    for _ in range(4):  # el 4.º excede reenvio:{user_id}
        r = await env.client.post("/api/v1/auth/password/forgot", json={"email": "ana@correo.com"})
        assert r.status_code == 200
        bodies.add(r.text)
    assert len(bodies) == 1


@pytest.mark.asyncio
async def test_forgot_shares_resend_counter(env: Env) -> None:
    uid = str(next(iter(env.user_repo.users)))
    env.rate_repo.counts[f"reenvio:{uid}"] = 3
    await env.client.post("/api/v1/auth/password/forgot", json={"email": "ana@correo.com"})
    env.email.send_recovery_code.assert_not_awaited()


# -------------------------------------------------------------------- reset


async def _request_code(e: Env) -> str:
    await e.client.post("/api/v1/auth/password/forgot", json={"email": "ana@correo.com"})
    return e.sent_code("send_recovery_code")


@pytest.mark.asyncio
async def test_reset_success_updates_hash_and_revokes_tokens(env: Env) -> None:
    user = next(iter(env.user_repo.users.values()))
    old_refresh = (await env.service._issue_tokens(user))["refresh_token"]
    code = await _request_code(env)

    r = await env.client.post(
        "/api/v1/auth/password/reset",
        json={"email": "ana@correo.com", "codigo": code, "nueva_password": "OtraClave456!"},
    )
    assert r.status_code == 200
    assert verify_password("OtraClave456!", user["password_hash"])
    assert user["password_changed_at"] is not None

    # el código es de un solo uso
    again = await env.client.post(
        "/api/v1/auth/password/reset",
        json={"email": "ana@correo.com", "codigo": code, "nueva_password": "Tercera789!!"},
    )
    assert again.status_code == 400

    # un refresh emitido antes del reset queda revocado (D18)
    user["password_changed_at"] = datetime.now(UTC) + timedelta(seconds=5)
    refreshed = await env.client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert refreshed.status_code == 401


@pytest.mark.asyncio
async def test_reset_failures_are_uniform(env: Env) -> None:
    code = await _request_code(env)
    wrong = "000000" if code != "000000" else "111111"
    body = {"codigo": wrong, "nueva_password": "OtraClave456!"}
    cases = [
        {"email": "ana@correo.com", **body},  # código erróneo
        {"email": "no@x.com", **body},  # correo inexistente
    ]
    results = [await env.client.post("/api/v1/auth/password/reset", json=c) for c in cases]
    assert {r.status_code for r in results} == {400}
    assert results[0].json() == results[1].json()


@pytest.mark.asyncio
async def test_reset_locks_after_5_attempts_even_with_right_code(env: Env) -> None:
    code = await _request_code(env)
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        r = await env.client.post(
            "/api/v1/auth/password/reset",
            json={"email": "ana@correo.com", "codigo": wrong, "nueva_password": "OtraClave456!"},
        )
        assert r.status_code == 400
    env.rate_repo.counts = {
        k: v for k, v in env.rate_repo.counts.items() if not k.startswith("rl:auth:")
    }
    r = await env.client.post(
        "/api/v1/auth/password/reset",
        json={"email": "ana@correo.com", "codigo": code, "nueva_password": "OtraClave456!"},
    )
    assert r.status_code == 400
    user = next(iter(env.user_repo.users.values()))
    assert verify_password(PASSWORD, user["password_hash"])


@pytest.mark.asyncio
async def test_reset_rejects_short_password(env: Env) -> None:
    code = await _request_code(env)
    r = await env.client.post(
        "/api/v1/auth/password/reset",
        json={"email": "ana@correo.com", "codigo": code, "nueva_password": "corta"},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_verify_email_attempts_exhausted_is_400_not_500() -> None:
    e = Env(_user("pendiente_verificacion"))
    await e.client.post("/api/v1/auth/resend-code", json={"email": "ana@correo.com"})
    for _ in range(6):
        r = await e.client.post(
            "/api/v1/auth/verify-email", json={"email": "ana@correo.com", "codigo": "000000"}
        )
        assert r.status_code == 400


# ------------------------------------------------------------------ refresh


@pytest.mark.asyncio
async def test_refresh_issues_access_token(env: Env) -> None:
    user = next(iter(env.user_repo.users.values()))
    refresh = (await env.service._issue_tokens(user))["refresh_token"]
    r = await env.client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 200
    claims = decode_access_token(r.json()["access_token"])
    assert claims["sub"] == str(user["_id"]) and claims["type"] == "access"
    # rotación: se entrega un refresh nuevo, distinto al presentado
    assert r.json()["refresh_token"] != refresh


@pytest.mark.asyncio
async def test_refresh_rejects_access_token_garbage_and_inactive(env: Env) -> None:
    user = next(iter(env.user_repo.users.values()))
    claims = {"sub": str(user["_id"]), "email": user["email"]}
    for bad in (create_access_token(claims), "no.es.jwt"):
        r = await env.client.post("/api/v1/auth/refresh", json={"refresh_token": bad})
        assert r.status_code == 401

    refresh = (await env.service._issue_tokens(user))["refresh_token"]
    for estado in ("pendiente_verificacion", "suspendida", "eliminada"):
        user["estado_cuenta"] = estado
        r = await env.client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert r.status_code == 401

    tracked = {"fam": "f-x", "jti": "j-x"}
    env.sessions.families["f-x"] = "j-x"
    ghost = create_refresh_token({"sub": str(ObjectId()), "email": "x@x.com", **tracked})
    assert (
        await env.client.post("/api/v1/auth/refresh", json={"refresh_token": ghost})
    ).status_code == 401
    bad_id = create_refresh_token({"sub": "no-es-objectid", "email": "x@x.com", **tracked})
    assert (
        await env.client.post("/api/v1/auth/refresh", json={"refresh_token": bad_id})
    ).status_code == 401
