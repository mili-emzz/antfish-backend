"""Rotación de refresh token con detección de reutilización y retroceso por cuenta en login."""

from __future__ import annotations

import pytest

from app.core.exceptions import RateLimitExceededError, UnauthorizedError
from app.core.security import create_refresh_token, decode_refresh_token
from app.services.auth_service import AuthService
from app.services.rate_limiter import RateLimiter
from tests.unit.test_auth_recovery import PASSWORD, Env, FakeSessionRepo, _user

# --------------------------------------------------------------------- refresh: rotación


async def _login_tokens(env: Env) -> tuple[dict, dict]:
    user = next(iter(env.user_repo.users.values()))
    return user, await env.service._issue_tokens(user)


@pytest.mark.asyncio
async def test_refresh_rotates_and_old_token_is_single_use() -> None:
    env = Env(_user())
    _, tokens = await _login_tokens(env)
    first = tokens["refresh_token"]

    r1 = await env.client.post("/api/v1/auth/refresh", json={"refresh_token": first})
    assert r1.status_code == 200
    second = r1.json()["refresh_token"]
    assert decode_refresh_token(second)["fam"] == decode_refresh_token(first)["fam"]
    assert decode_refresh_token(second)["jti"] != decode_refresh_token(first)["jti"]

    r2 = await env.client.post("/api/v1/auth/refresh", json={"refresh_token": second})
    assert r2.status_code == 200


@pytest.mark.asyncio
async def test_refresh_reuse_revokes_whole_family() -> None:
    env = Env(_user())
    _, tokens = await _login_tokens(env)
    stolen = tokens["refresh_token"]

    legit = await env.client.post("/api/v1/auth/refresh", json={"refresh_token": stolen})
    newest = legit.json()["refresh_token"]

    # el atacante reutiliza el token ya consumido: se rechaza y se revoca la familia
    reuse = await env.client.post("/api/v1/auth/refresh", json={"refresh_token": stolen})
    assert reuse.status_code == 401
    assert env.sessions.families == {}

    # el token vigente de la víctima también deja de servir
    after = await env.client.post("/api/v1/auth/refresh", json={"refresh_token": newest})
    assert after.status_code == 401


@pytest.mark.asyncio
async def test_refresh_without_family_claims_is_rejected() -> None:
    env = Env(_user())
    user, _ = await _login_tokens(env)
    legacy = create_refresh_token({"sub": str(user["_id"]), "email": user["email"]})
    r = await env.client.post("/api/v1/auth/refresh", json={"refresh_token": legacy})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_logout_revokes_session_and_is_idempotent() -> None:
    env = Env(_user())
    _, tokens = await _login_tokens(env)
    refresh = tokens["refresh_token"]

    out = await env.client.post("/api/v1/auth/logout", json={"refresh_token": refresh})
    assert out.status_code == 204
    assert env.sessions.families == {}
    assert (
        await env.client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    ).status_code == 401

    for token in (refresh, "no.es.jwt"):
        again = await env.client.post("/api/v1/auth/logout", json={"refresh_token": token})
        assert again.status_code == 204


# --------------------------------------------------------- login: retroceso por cuenta


class FakeLoginRepo:
    """Réplica en memoria de la lógica del script Lua (el script real va en integración)."""

    def __init__(self) -> None:
        self.failures: dict[str, int] = {}
        self.blocked: dict[str, int] = {}

    async def record_login_failure(
        self, account: str, window: int, free: int, base: int, maximum: int
    ) -> int:
        self.failures[account] = count = self.failures.get(account, 0) + 1
        if count > free:
            delay = int(min(base * 2 ** (count - free - 1), maximum))
            self.blocked[account] = delay
            return delay
        return 0

    async def login_block_ttl(self, account: str) -> int:
        return self.blocked.get(account, 0)

    async def clear_login_failures(self, account: str) -> None:
        self.failures.pop(account, None)
        self.blocked.pop(account, None)


def _service(env: Env, repo: FakeLoginRepo) -> AuthService:
    return AuthService(
        env.user_repo,  # type: ignore[arg-type]
        env.verification,
        session_repository=FakeSessionRepo(),  # type: ignore[arg-type]
        rate_limiter=RateLimiter(repo),  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_login_backoff_blocks_after_free_failures_even_with_right_password() -> None:
    env = Env(_user())
    repo = FakeLoginRepo()
    service = _service(env, repo)

    for _ in range(5):  # fallos "gratis"
        with pytest.raises(UnauthorizedError):
            await service.authenticate_user("ana@correo.com", "incorrecta-123")
    with pytest.raises(UnauthorizedError):  # el 6.º fallo activa la espera
        await service.authenticate_user("ana@correo.com", "incorrecta-123")

    with pytest.raises(RateLimitExceededError) as exc:
        await service.authenticate_user("ana@correo.com", PASSWORD)
    assert exc.value.retry_after == 30


@pytest.mark.asyncio
async def test_login_backoff_doubles_and_is_capped() -> None:
    repo = FakeLoginRepo()
    delays = [await repo.record_login_failure("a", 900, 5, 30, 900) for _ in range(12)]
    assert delays[:5] == [0] * 5
    assert delays[5:9] == [30, 60, 120, 240]
    assert max(delays) == 900


@pytest.mark.asyncio
async def test_login_backoff_counts_unknown_emails_and_success_resets() -> None:
    env = Env(_user())
    repo = FakeLoginRepo()
    service = _service(env, repo)

    with pytest.raises(UnauthorizedError):
        await service.authenticate_user("fantasma@correo.com", "cualquiera-123")
    assert sum(repo.failures.values()) == 1  # no distingue cuentas inexistentes (anti-enumeración)

    with pytest.raises(UnauthorizedError):
        await service.authenticate_user("ana@correo.com", "incorrecta-123")
    await service.authenticate_user("ana@correo.com", PASSWORD)
    assert len(repo.failures) == 1  # solo queda el de la cuenta inexistente; el de ana se limpió
