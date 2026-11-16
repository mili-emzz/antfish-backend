"""Pruebas de endurecimiento de seguridad (RNF-03, RNF-05, RF-06)."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import jwt
import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.exceptions import UnauthorizedError
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.services.auth_service import AuthService

GOOD = secrets.token_urlsafe(48)


def _settings(**overrides: str) -> Settings:
    base = {
        "HMAC_PEPPER": secrets.token_urlsafe(48),
        "JWT_SECRET": secrets.token_urlsafe(48),
        "JWT_REFRESH_SECRET": secrets.token_urlsafe(48),
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


def test_secrets_are_required(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HMAC_PEPPER", "JWT_SECRET", "JWT_REFRESH_SECRET"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "overrides",
    [
        {"JWT_SECRET": "corto"},
        {"HMAC_PEPPER": "default_pepper_" + "x" * 30},
        {"JWT_REFRESH_SECRET": "antfish_jwt_secret_key_change_in_production"},
    ],
)
def test_weak_or_placeholder_secrets_rejected(overrides: dict[str, str]) -> None:
    with pytest.raises(ValidationError) as exc:
        _settings(**overrides)
    assert next(iter(overrides.values())) not in str(exc.value)  # no filtra el valor


def test_jwt_secrets_must_differ() -> None:
    with pytest.raises(ValidationError):
        _settings(JWT_SECRET=GOOD, JWT_REFRESH_SECRET=GOOD)


def test_valid_settings_and_default_environment() -> None:
    assert _settings().ENVIRONMENT == "development"


def test_decode_requires_exp_iat_sub() -> None:
    from app.core.config import settings

    now = datetime.now(UTC)
    no_sub = jwt.encode(
        {"exp": now + timedelta(minutes=5), "iat": now},
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    no_exp = jwt.encode(
        {"sub": "u1", "iat": now}, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM
    )
    for token in (no_sub, no_exp):
        with pytest.raises(jwt.PyJWTError):
            decode_access_token(token)
    assert decode_access_token(create_access_token({"sub": "u1"}))["sub"] == "u1"


def test_verify_password_handles_invalid_hash_without_broad_except() -> None:
    assert verify_password("x", "no-es-un-hash") is False
    assert verify_password("clave-correcta", hash_password("clave-correcta")) is True
    assert verify_password("otra", hash_password("clave-correcta")) is False


@pytest.mark.asyncio
async def test_login_unknown_user_spends_argon2_time(monkeypatch: pytest.MonkeyPatch) -> None:
    called = MagicMock()
    monkeypatch.setattr("app.services.auth_service.verify_password_decoy", called)
    repo = MagicMock()
    repo.find_by_email = AsyncMock(return_value=None)
    service = AuthService(user_repository=repo, verification_service=MagicMock())
    with pytest.raises(UnauthorizedError):
        await service.login("nadie@example.com", "cualquiera")
    called.assert_called_once_with("cualquiera")


def test_verification_code_uses_secrets_module() -> None:
    import inspect

    from app.services import verification_service

    source = inspect.getsource(verification_service)
    assert "random." not in source and "secrets.randbelow" in source
