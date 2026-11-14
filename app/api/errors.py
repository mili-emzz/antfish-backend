"""Manejadores globales de errores HTTP (RNF-06, sin exponer trazas internas)."""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.core.exceptions import PersistenceError


async def _persistence_error_handler(_: Request, exc: PersistenceError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": exc.message},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Registra los mapeos de excepciones de dominio a respuestas HTTP."""
    app.add_exception_handler(PersistenceError, _persistence_error_handler)  # type: ignore[arg-type]
