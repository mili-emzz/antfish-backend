"""Dependencias FastAPI: autenticación JWT con validación activa (RNF-03, D18)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC
from typing import Any

import jwt
from bson.errors import InvalidId
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.api.errors import api_error
from app.core.security import decode_access_token

_bearer = HTTPBearer(auto_error=False)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict[str, Any]:
    """Valida el Access Token y el estado de la cuenta; devuelve el documento de usuario.

    - Token inválido/expirado o de otro tipo -> 401.
    - iat anterior a password_changed_at -> 401 (D18).
    - estado_cuenta pendiente_verificacion -> 403 ACCOUNT_NOT_VERIFIED.
    - Cualquier otro estado distinto de activa -> 401.
    """
    if credentials is None:
        raise _unauthorized()
    try:
        payload = decode_access_token(credentials.credentials)
    except jwt.PyJWTError:
        raise _unauthorized() from None
    if payload.get("type") != "access" or not payload.get("sub"):
        raise _unauthorized()

    container = getattr(request.app.state, "container", None)
    if container is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de autenticación no disponible",
        )
    try:
        user = await container.user_repository.find_by_id(payload["sub"])
    except InvalidId:
        raise _unauthorized() from None
    if user is None:
        raise _unauthorized()

    password_changed_at = user.get("password_changed_at")
    if password_changed_at is not None:
        if password_changed_at.tzinfo is None:
            password_changed_at = password_changed_at.replace(tzinfo=UTC)
        if int(payload.get("iat", 0)) < int(password_changed_at.timestamp()):
            raise _unauthorized()

    estado = user.get("estado_cuenta")
    if estado == "pendiente_verificacion":
        raise api_error(status.HTTP_403_FORBIDDEN, "ACCOUNT_NOT_VERIFIED", "ACCOUNT_NOT_VERIFIED")
    if estado != "activa":
        raise _unauthorized()
    return user


def _get_rate_limiter(request: Request) -> Any:
    container = getattr(request.app.state, "container", None)
    limiter = getattr(container, "rate_limiter", None)
    if limiter is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio temporalmente no disponible",
        )
    return limiter


def rate_limit_auth(
    endpoint: str, limit: int | None = None
) -> Callable[[Request], Awaitable[None]]:
    """Dependencia: límite por minuto por IP en el endpoint de auth (fail-closed; def. 5)."""

    async def _dependency(request: Request) -> None:
        # request.client.host ya refleja X-Forwarded-For solo si uvicorn confía en el proxy
        # (--proxy-headers/--forwarded-allow-ips); no se leen cabeceras manualmente (anti-spoofing).
        ip = request.client.host if request.client else "desconocida"
        await _get_rate_limiter(request).check_auth(endpoint, ip, limit)

    return _dependency


async def rate_limit_analysis(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """Dependencia: máx. 20 análisis por minuto por usuario (fail-open ante fallo de Redis)."""
    await _get_rate_limiter(request).check_analysis(str(user["_id"]))
    return user


async def rate_limit_read(
    request: Request,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """Dependencia: máx. 60 consultas por minuto por usuario (fail-open ante fallo de Redis)."""
    await _get_rate_limiter(request).check_read(str(user["_id"]))
    return user
