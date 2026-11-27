"""Repositorio MongoDB de reglas_heuristicas y marcas_protegidas (P4, I5, I6, I7).

Solo lectura. Se cargan TODOS los documentos (activos e inactivos): un código de regla ausente
significa "usa el valor por defecto", así que para poder desactivar una regla hay que conocer
también las inactivas. Sin lógica de negocio.
"""

from __future__ import annotations

from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase


class RulesRepository:
    """Lectura del catálogo de reglas y marcas."""

    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self._rules = db["reglas_heuristicas"]
        self._brands = db["marcas_protegidas"]

    async def find_rules(self) -> list[dict[str, Any]]:
        """Devuelve todas las reglas heurísticas."""
        return await self._rules.find({}).to_list(length=None)

    async def find_brands(self) -> list[dict[str, Any]]:
        """Devuelve todas las marcas protegidas."""
        return await self._brands.find({}).to_list(length=None)
