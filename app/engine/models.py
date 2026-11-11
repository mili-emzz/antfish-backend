"""Modelos de dominio puro del motor heurístico de AntFish.

Contiene las dataclasses y enums fundamentales utilizados para la
extracción, evaluación sintáctica, análisis de texto y puntuación.
Este módulo utiliza exclusivamente la librería estándar de Python
(sin dependencias externas, Pydantic, I/O ni acceso a bases de datos).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    """Nivel de riesgo asignado a un análisis (semáforo)."""

    BAJO = "bajo"
    MEDIO = "medio"
    ALTO = "alto"
    CRITICO = "critico"


class EntryType(str, Enum):
    """Tipo de entrada procesada por el motor."""

    SMS = "sms"
    URL = "url"


class SourceStatus(str, Enum):
    """Estado devuelto por una fuente externa de reputación."""

    OK = "ok"
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    ERROR = "error"


class CircuitBreakerReason(str, Enum):
    """Motivo de activación del cortocircuito de riesgo crítico."""

    LISTA_NEGRA = "lista_negra"
    SUPLANTACION_MARCA = "suplantacion_marca"


@dataclass(frozen=True, slots=True)
class Finding:
    """Snapshot inmutable de un hallazgo o regla disparada durante el análisis."""

    regla_codigo: str
    titulo: str
    descripcion: str
    puntos: int


@dataclass(slots=True)
class ExtractedUrl:
    """Representación de una URL extraída y normalizada para persistencia."""

    url: str
    dominio: str
    flags_sintacticos: list[str] = field(default_factory=list)


@dataclass(slots=True)
class UrlFeatures:
    """Características y banderas sintácticas evaluadas en una URL (Capa 2)."""

    url: str
    dominio: str
    es_ip_directa: bool = False
    subdominio_enganoso: bool = False
    marca_detectada: str | None = None
    tld_alto_riesgo: bool = False
    es_acortador: bool = False
    exceso_guiones: bool = False
    puntos_sintacticos: int = 0
    flags_sintacticos: list[str] = field(default_factory=list)
    hallazgos: list[Finding] = field(default_factory=list)


@dataclass(slots=True)
class Reputation:
    """Resultado de la consulta a una API externa de inteligencia de amenazas."""

    api: str
    estado: SourceStatus
    positivo: bool
    detecciones: int | None = None
    desde_cache: bool = False


@dataclass(slots=True)
class Rule:
    """Definición de una regla heurística configurable del motor."""

    codigo: str
    capa: str
    titulo: str
    descripcion: str
    puntos: int
    tipo_patron: str = ""
    parametros: dict[str, Any] = field(default_factory=dict)
    activa: bool = True
    version: int = 1


@dataclass(slots=True)
class Brand:
    """Definición de una marca comercial protegida contra suplantación."""

    codigo: str
    nombre: str
    categoria: str = ""
    dominios_oficiales: list[str] = field(default_factory=list)
    variantes_ofuscadas: list[str] = field(default_factory=list)
    activa: bool = True


@dataclass(slots=True)
class ScoreResult:
    """Resultado integral consolidado del motor de análisis."""

    score_total: int
    nivel_riesgo: RiskLevel
    puntos_por_capa: dict[str, int]
    motivo_cortocircuito: CircuitBreakerReason | None = None
    analisis_parcial: bool = False
    dominio_principal: str = ""
    url_dominante: str = ""
    hallazgos: list[Finding] = field(default_factory=list)
    recomendaciones: list[str] = field(default_factory=list)
    fuentes_consultadas: list[Reputation] = field(default_factory=list)
    urls_extraidas: list[ExtractedUrl] = field(default_factory=list)

