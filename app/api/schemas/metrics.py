"""Esquemas del panel de estadísticas del usuario (RF-05.2)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class MetricsResponse(BaseModel):
    """Contadores acumulados del usuario autenticado."""

    total_escaneos: int = Field(..., ge=0, description="Total de escaneos realizados")
    total_url: int = Field(..., ge=0, description="Escaneos de tipo URL")
    total_sms: int = Field(..., ge=0, description="Escaneos de tipo SMS")
    amenazas_bloqueadas: int = Field(
        ..., ge=0, description="Escaneos con riesgo alto o crítico (RN-15)"
    )
    ultima_actualizacion: datetime | None = Field(
        default=None, description="Fecha del último escaneo contabilizado"
    )
