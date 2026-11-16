"""Proveedor de reglas y marcas con caché en memoria RAM (CU-11, P4, TTL 3600 s).

Política de resiliencia (decisión confirmada): si Mongo no responde o el catálogo es inválido o
está vacío, el análisis continúa con los valores internos del motor (degradación grácil); si ya
había un catálogo válido en memoria se conserva el último. Tras un fallo se reintenta pronto
(RULES_RETRY_SECONDS) en lugar de esperar al TTL completo.

Los puntos NUNCA se toman de Mongo (RN-03 a RN-05 son requisitos): se normalizan al valor
canónico del catálogo del motor y se advierte si difieren.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pymongo.errors import PyMongoError

from app.core.config import settings
from app.core.logging import logger
from app.engine.models import Brand, Rule
from app.engine.public_suffixes import DEFAULT_PROTECTED_BRANDS
from app.engine.rule_catalog import RULE_CATALOG
from app.repositories.mongo.rules_repository import RulesRepository


@dataclass(frozen=True, slots=True)
class RulesSnapshot:
    """Catálogo vigente entregado al motor."""

    brands: tuple[Brand, ...]
    rules: tuple[Rule, ...]
    source: str  # "mongo" | "defaults"


_DEFAULTS = RulesSnapshot(brands=DEFAULT_PROTECTED_BRANDS, rules=(), source="defaults")


def _str_list(value: Any) -> list[str] | None:
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return value
    return None


def parse_brands(docs: list[dict[str, Any]]) -> tuple[list[Brand], int]:
    """Convierte documentos en Brand; devuelve (marcas válidas, cantidad descartada)."""
    brands: list[Brand] = []
    skipped = 0
    for doc in docs:
        codigo, nombre = doc.get("codigo"), doc.get("nombre")
        oficiales = _str_list(doc.get("dominios_oficiales", []))
        variantes = _str_list(doc.get("variantes_ofuscadas", []))
        activa = doc.get("activa", True)
        if (
            not isinstance(codigo, str)
            or not codigo.strip()
            or not isinstance(nombre, str)
            or oficiales is None
            or variantes is None
            or not isinstance(activa, bool)
        ):
            skipped += 1
            continue
        brands.append(
            Brand(
                codigo=codigo.strip().lower(),
                nombre=nombre,
                categoria=str(doc.get("categoria", "")),
                dominios_oficiales=[d.strip().lower() for d in oficiales],
                variantes_ofuscadas=variantes,
                activa=activa,
            )
        )
    return brands, skipped


def parse_rules(docs: list[dict[str, Any]]) -> tuple[list[Rule], int, int]:
    """Convierte documentos en Rule; devuelve (reglas, descartadas, con_puntos_distintos)."""
    rules: list[Rule] = []
    skipped = mismatched = 0
    for doc in docs:
        codigo = doc.get("codigo")
        if not isinstance(codigo, str) or codigo not in RULE_CATALOG:
            skipped += 1
            continue
        capa, puntos_canonicos = RULE_CATALOG[codigo]
        activa = doc.get("activa", True)
        parametros = doc.get("parametros", {})
        if not isinstance(activa, bool) or not isinstance(parametros, dict):
            skipped += 1
            continue
        if doc.get("puntos") != puntos_canonicos:
            mismatched += 1
        version = doc.get("version", 1)
        rules.append(
            Rule(
                codigo=codigo,
                capa=capa,
                titulo=str(doc.get("titulo", "")),
                descripcion=str(doc.get("descripcion", "")),
                puntos=puntos_canonicos,  # nunca el valor de Mongo
                tipo_patron=str(doc.get("tipo_patron", "")),
                parametros=parametros,
                activa=activa,
                version=version if isinstance(version, int) else 1,
            )
        )
    return rules, skipped, mismatched


class RulesProvider:
    """Entrega el catálogo al motor con caché TTL y respaldo a valores internos."""

    def __init__(
        self,
        repository: RulesRepository,
        ttl_seconds: int | None = None,
        retry_seconds: int | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._repo = repository
        self._ttl = ttl_seconds if ttl_seconds is not None else settings.RULES_CACHE_TTL_SECONDS
        self._retry = retry_seconds if retry_seconds is not None else settings.RULES_RETRY_SECONDS
        self._clock = clock
        self._snapshot: RulesSnapshot | None = None
        self._expires_at = 0.0
        self._lock = asyncio.Lock()

    async def get(self) -> RulesSnapshot:
        """Devuelve el catálogo vigente (recarga al expirar el TTL; nunca lanza por Mongo)."""
        if self._snapshot is not None and self._clock() < self._expires_at:
            return self._snapshot
        async with self._lock:
            if self._snapshot is not None and self._clock() < self._expires_at:
                return self._snapshot
            return await self._reload()

    async def _reload(self) -> RulesSnapshot:
        now = self._clock()
        try:
            rule_docs = await self._repo.find_rules()
            brand_docs = await self._repo.find_brands()
        except PyMongoError as exc:
            logger.warning(f"Catálogo de reglas no disponible: {type(exc).__name__}")
            return self._fallback(now)

        brands, skipped_brands = parse_brands(brand_docs)
        rules, skipped_rules, mismatched = parse_rules(rule_docs)
        if skipped_brands or skipped_rules:
            logger.warning(
                f"Catálogo con documentos inválidos descartados: marcas={skipped_brands} "
                f"reglas={skipped_rules}"
            )
        if mismatched:
            logger.warning(
                f"{mismatched} regla(s) con puntos distintos a RN-03/04/05: se ignoran los de Mongo"
            )
        if not brands:
            logger.warning("Catálogo de marcas vacío o inválido: se usan marcas internas")
            return self._fallback(now)

        self._snapshot = RulesSnapshot(brands=tuple(brands), rules=tuple(rules), source="mongo")
        self._expires_at = now + self._ttl
        return self._snapshot

    def _fallback(self, now: float) -> RulesSnapshot:
        """Conserva el último catálogo válido o, si no hay, los valores internos."""
        if self._snapshot is None:
            self._snapshot = _DEFAULTS
        self._expires_at = now + self._retry
        return self._snapshot
