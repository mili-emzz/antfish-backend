"""DTO de salida del healthcheck."""

from typing import Literal

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Estado global de la instancia, sin detalles internos."""

    status: Literal["ok", "degradado", "no_disponible"]
