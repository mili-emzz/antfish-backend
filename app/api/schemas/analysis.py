"""Esquemas y DTOs Pydantic para el análisis de URLs y SMS (RF-01.1, RF-01.2)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


class AnalysisRequest(BaseModel):
    """DTO de entrada para solicitud de análisis de SMS o URL (RF-01.1, RF-01.2)."""

    tipo_entrada: Literal["sms", "url"] = Field(
        ...,
        description="Tipo de contenido recibido: 'sms' o 'url'",
        examples=["sms"],
    )
    contenido: str = Field(
        ...,
        min_length=1,
        description="Texto del SMS recibido o URL directa a analizar",
        examples=[
            "BBVA Alerta: Tu cuenta ha sido bloqueada. Verifica en https://bbva-verifica.seguro-acceso.xyz/login urgente"
        ],
    )

    model_config = ConfigDict(str_strip_whitespace=True)

    @model_validator(mode="after")
    def validate_content_length(self) -> AnalysisRequest:
        """Aplica límites de longitud estrictos condicionados por el tipo de entrada."""
        content = self.contenido
        if self.tipo_entrada == "sms":
            if len(content) > 1600:
                raise ValueError("El contenido para tipo_entrada 'sms' no puede exceder los 1,600 caracteres.")
        elif self.tipo_entrada == "url":
            if len(content) > 2048:
                raise ValueError("El contenido para tipo_entrada 'url' no puede exceder los 2,048 caracteres.")
        return self


class FindingSchema(BaseModel):
    """Snapshot de un hallazgo o regla heurística disparada."""

    regla_codigo: str = Field(..., description="Código identificador único de la regla")
    titulo: str = Field(..., description="Título legible del hallazgo")
    descripcion: str = Field(..., description="Descripción detallada del riesgo detectado")
    puntos: int = Field(..., description="Puntos aportados por la regla")


class ExtractedUrlSchema(BaseModel):
    """URL extraída y procesada del mensaje."""

    url: str = Field(..., description="URL normalizada con path y sin query string")
    dominio: str = Field(..., description="Nombre de dominio o dirección IP")
    flags_sintacticos: list[str] = Field(
        default_factory=list,
        description="Banderas sintácticas detectadas en la URL",
    )


class ReputationSchema(BaseModel):
    """Snapshot del estado devuelto por una API externa de reputación."""

    api: str = Field(..., description="Nombre de la API externa (google_web_risk, virustotal, phishtank)")
    estado: str = Field(..., description="Estado de la consulta (ok, timeout, rate_limit, error)")
    positivo: bool = Field(..., description="Indica si la fuente confirmó amenaza maliciosa")
    detecciones: int | None = Field(default=None, description="Número de detecciones reportadas")
    desde_cache: bool = Field(default=False, description="Indica si el resultado provino de caché Redis")


class LayerPointsSchema(BaseModel):
    """Puntos acumulados por cada capa de análisis (recortados a sus topes respectivos)."""

    apis: int = Field(..., ge=0, le=60, description="Puntos de Capa 1: Inteligencia externa (tope 60)")
    url: int = Field(..., ge=0, le=30, description="Puntos de Capa 2: Heurística sintáctica de URL (tope 30)")
    texto: int = Field(..., ge=0, le=20, description="Puntos de Capa 3: Heurística de texto (tope 20)")


class AnalysisResponse(BaseModel):
    """Diagnóstico consolidado retornado al usuario (RF-03)."""

    id: str | None = Field(default=None, description="Identificador único del análisis")
    tipo_entrada: str = Field(..., description="Tipo de entrada procesada ('sms' o 'url')")
    mensaje_hash: str | None = Field(
        default=None,
        description="Digesto HMAC-SHA256 del SMS (null si tipo_entrada = url)",
    )
    urls_extraidas: list[ExtractedUrlSchema] = Field(
        default_factory=list,
        description="Lista de URLs analizadas (hasta 2 de mayor riesgo)",
    )
    dominio_principal: str = Field(
        ...,
        description="Dominio de la URL dominante utilizado para historial y diagnóstico",
    )
    score_total: int = Field(..., ge=0, le=100, description="Puntuación total de riesgo (0 a 100)")
    nivel_riesgo: str = Field(
        ...,
        description="Nivel de riesgo clasificado: bajo, medio, alto o critico",
    )
    puntos_por_capa: LayerPointsSchema = Field(
        ...,
        description="Desglose de puntos por capa para auditoría",
    )
    motivo_cortocircuito: str | None = Field(
        default=None,
        description="Motivo del cortocircuito si aplicó ('lista_negra', 'suplantacion_marca' o null)",
    )
    analisis_parcial: bool = Field(
        default=False,
        description="Indica si ocurrió degradación grácil por fallo de alguna API externa",
    )
    hallazgos: list[FindingSchema] = Field(
        default_factory=list,
        description="Lista desglosada de hallazgos detectados en la URL dominante y texto",
    )
    recomendaciones: list[str] = Field(
        default_factory=list,
        description="Recomendaciones de acción concretas (1 a 3)",
    )
    fuentes_consultadas: list[ReputationSchema] = Field(
        default_factory=list,
        description="Estado y resultado de las consultas a APIs externas de la URL dominante",
    )
    fecha: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Marca temporal en la que se generó el análisis",
    )



class HistoryPageResponse(BaseModel):
    """Página del historial de análisis con cursor opaco (RF-05.1, D8)."""

    items: list[AnalysisResponse] = Field(default_factory=list)
    next_cursor: str | None = Field(
        default=None, description="Cursor opaco para la siguiente página; null si no hay más"
    )
