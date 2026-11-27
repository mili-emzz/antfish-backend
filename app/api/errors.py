"""Manejadores globales de errores HTTP (RNF-06, sin exponer trazas internas).

Contrato único de error: `{"code": "<CODIGO>", "detail": <texto o lista de validación>}`.
Los códigos específicos se fijan con `api_error`; el resto recibe un código genérico según el
estado HTTP.
"""

from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.exceptions import (
    PersistenceError,
    RateLimitBackendError,
    RateLimitExceededError,
)

# Código genérico por estado HTTP cuando el endpoint no fija uno específico.
_DEFAULT_CODES: dict[int, str] = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    409: "CONFLICT",
    413: "PAYLOAD_TOO_LARGE",
    422: "VALIDATION_ERROR",
    429: "RATE_LIMIT_EXCEEDED",
    500: "INTERNAL_ERROR",
    501: "NOT_IMPLEMENTED",
    503: "SERVICE_UNAVAILABLE",
}


def api_error(
    status_code: int,
    code: str,
    detail: str,
    headers: dict[str, str] | None = None,
) -> HTTPException:
    """HTTPException con código de error específico (se aplana en el manejador global)."""
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "detail": detail},
        headers=headers,
    )


def _body(code: str, detail: Any) -> dict[str, Any]:
    return {"code": code, "detail": detail}


async def _http_exception_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    detail: Any = exc.detail
    if isinstance(detail, dict) and "code" in detail:
        code, detail = str(detail["code"]), detail.get("detail", "")
    else:
        code = _DEFAULT_CODES.get(exc.status_code, f"HTTP_{exc.status_code}")
    return JSONResponse(
        status_code=exc.status_code,
        content=_body(code, detail),
        headers=getattr(exc, "headers", None),
    )


async def _validation_error_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        # Solo tipo, ubicación y mensaje: `input`/`ctx` devolverían contraseñas o el texto del
        # SMS, y un cuerpo binario o con surrogates rompía la serialización (500).
        content=_body(
            "VALIDATION_ERROR",
            jsonable_encoder([{k: e[k] for k in ("type", "loc", "msg")} for e in exc.errors()]),
        ),
    )


async def _persistence_error_handler(_: Request, exc: PersistenceError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content=_body("SERVICE_UNAVAILABLE", exc.message),
    )


async def _rate_limit_handler(_: Request, exc: RateLimitExceededError) -> JSONResponse:
    headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content=_body("RATE_LIMIT_EXCEEDED", exc.message),
        headers=headers,
    )


async def _backend_unavailable_handler(_: Request, exc: RateLimitBackendError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content=_body("SERVICE_UNAVAILABLE", exc.message),
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Registra los mapeos de excepciones de dominio a respuestas HTTP."""
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, _validation_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(PersistenceError, _persistence_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RateLimitExceededError, _rate_limit_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RateLimitBackendError, _backend_unavailable_handler)  # type: ignore[arg-type]
