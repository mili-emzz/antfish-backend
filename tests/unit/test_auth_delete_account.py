"""Pruebas de DELETE /auth/me para cuentas locales (RF-06.7, O12, RN-26, D4)."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from bson import ObjectId
from fastapi import FastAPI
from pymongo.errors import PyMongoError

from app.api.errors import register_exception_handlers
from app.api.v1 import auth
from app.core.security import create_access_token, hash_password
from app.services.auth_service import AuthService
from app.services.rate_limiter import RateLimiter

PASSWORD = "PasswordSeguro123!"


class FakeUow:
    """Registra si la transacción se confirmó o se abortó."""

    def __init__(self) -> None:
        self.committed = False
        self.aborted = False

    @asynccontextmanager
    async def transaction(self):
        try:
            yield object()
        except BaseException:
            self.aborted = True
            raise
        self.committed = True


class FakeUserRepo:
    def __init__(self, user: dict[str, Any]) -> None:
        self.user = user
        self.anonymized = False
        self.fail = False

    async def find_by_id(self, user_id: Any) -> dict[str, Any] | None:
        return self.user if ObjectId(user_id) == self.user["_id"] else None

    async def anonymize_user(self, user_id: Any, session: Any = None) -> bool:
        if self.fail:
            raise PyMongoError("boom")
        self.anonymized = True
        self.user["estado_cuenta"] = "eliminada"
        return True


class Env:
    def __init__(self, **user_extra: Any) -> None:
        self.user: dict[str, Any] = {
            "_id": ObjectId(),
            "email": "ana@correo.com",
            "nombre": "Ana",
            "password_hash": hash_password(PASSWORD),
            "estado_cuenta": "activa",
            "password_changed_at": None,
            **user_extra,
        }
        self.users = FakeUserRepo(self.user)
        self.uow = FakeUow()
        self.analysis = AsyncMock()
        self.metrics = AsyncMock()
        service = AuthService(
            self.users,  # type: ignore[arg-type]
            AsyncMock(),
            unit_of_work=self.uow,  # type: ignore[arg-type]
            analysis_repository=self.analysis,
            metrics_repository=self.metrics,
        )

        class _Repo:
            def __init__(self) -> None:
                self.counts: dict[str, int] = {}

            async def hit(self, key: str, window: int) -> tuple[int, int]:
                self.counts[key] = self.counts.get(key, 0) + 1
                return self.counts[key], window

        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(auth.router, prefix="/api/v1")

        class _Container:
            auth_service = service
            user_repository = self.users
            rate_limiter = RateLimiter(_Repo())  # type: ignore[arg-type]

        app.state.container = _Container()
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        )
        self.headers = {
            "Authorization": "Bearer "
            + create_access_token({"sub": str(self.user["_id"]), "email": "ana@correo.com"})
        }

    async def delete(self, password: str = PASSWORD, headers: dict[str, str] | None = None):
        return await self.client.request(
            "DELETE",
            "/api/v1/auth/me",
            json={"password": password},
            headers=self.headers if headers is None else headers,
        )


@pytest.mark.asyncio
async def test_delete_me_purges_and_anonymizes_in_one_transaction() -> None:
    e = Env()
    r = await e.delete()
    assert r.status_code == 204
    assert e.users.anonymized
    e.analysis.delete_all_by_user.assert_awaited_once()
    e.metrics.delete_by_user.assert_awaited_once()
    assert e.uow.committed and not e.uow.aborted
    # las tres operaciones comparten la misma sesión transaccional
    sessions = {
        e.analysis.delete_all_by_user.await_args.args[1],
        e.metrics.delete_by_user.await_args.args[1],
    }
    assert len(sessions) == 1


@pytest.mark.asyncio
async def test_delete_me_wrong_password_is_403_and_touches_nothing() -> None:
    e = Env()
    r = await e.delete("otra-clave")
    assert r.status_code == 403
    assert not e.users.anonymized
    e.analysis.delete_all_by_user.assert_not_awaited()
    e.metrics.delete_by_user.assert_not_awaited()


@pytest.mark.asyncio
async def test_delete_me_requires_valid_session() -> None:
    e = Env()
    assert (await e.delete(headers={})).status_code == 401
    assert (await e.delete(headers={"Authorization": "Bearer basura"})).status_code == 401
    assert not e.users.anonymized


@pytest.mark.asyncio
async def test_delete_me_google_account_is_501_until_google_reauth_exists() -> None:
    e = Env(password_hash=None, proveedor_auth="google")
    r = await e.delete()
    assert r.status_code == 501
    assert not e.users.anonymized


@pytest.mark.asyncio
async def test_delete_me_db_failure_is_503_and_transaction_aborted() -> None:
    e = Env()
    e.users.fail = True
    r = await e.delete()
    assert r.status_code == 503
    assert e.uow.aborted and not e.uow.committed


@pytest.mark.asyncio
async def test_deleted_account_cannot_reuse_tokens() -> None:
    e = Env()
    assert (await e.delete()).status_code == 204
    # el access token previo ya no sirve: cuenta eliminada -> 401
    assert (await e.delete()).status_code == 401


@pytest.mark.asyncio
async def test_delete_me_password_attempts_are_rate_limited_per_ip() -> None:
    e = Env()
    codes = [(await e.delete("mala")).status_code for _ in range(6)]
    assert codes[:5] == [403] * 5
    assert codes[5] == 429
