"""Manejadores globales de errores HTTP (RNF-06, sin exponer trazas internas)."""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.core.exceptions import (
    PersistenceError,
    RateLimitBackendError,
    RateLimitExceededError,
)


async def _persistence_error_handler(_: Request, exc: PersistenceError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": exc.message},
    )


async def _rate_limit_handler(_: Request, exc: RateLimitExceededError) -> JSONResponse:
    headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": exc.message},
        headers=headers,
    )


async def _backend_unavailable_handler(_: Request, exc: RateLimitBackendError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": exc.message},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Registra los mapeos de excepciones de dominio a respuestas HTTP."""
    app.add_exception_handler(PersistenceError, _persistence_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RateLimitExceededError, _rate_limit_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RateLimitBackendError, _backend_unavailable_handler)  # type: ignore[arg-type]
