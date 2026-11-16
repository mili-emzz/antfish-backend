"""Repositorio MongoDB de la colección metricas_usuario (RF-05.2, P7, RN-15)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClientSession, AsyncIOMotorDatabase


class MetricsRepository:
    """Contadores acumulados por usuario (_id = user_id, relación 1:1)."""

    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self._collection = db["metricas_usuario"]

    async def increment(
        self,
        user_id: str | ObjectId,
        tipo_entrada: str,
        es_amenaza: bool,
        session: AsyncIOMotorClientSession | None = None,
    ) -> None:
        """$inc atómico con upsert; mantiene total_escaneos == total_url + total_sms."""
        oid = ObjectId(user_id) if isinstance(user_id, str) else user_id
        inc: dict[str, int] = {
            "total_escaneos": 1,
            "total_url": 1 if tipo_entrada == "url" else 0,
            "total_sms": 1 if tipo_entrada == "sms" else 0,
            "amenazas_bloqueadas": 1 if es_amenaza else 0,
        }
        await self._collection.update_one(
            {"_id": oid},
            {
                "$inc": inc,
                "$set": {"ultima_actualizacion": datetime.now(timezone.utc)},
            },
            upsert=True,
            session=session,
        )

    async def delete_by_user(
        self,
        user_id: str | ObjectId,
        session: AsyncIOMotorClientSession | None = None,
    ) -> None:
        """Elimina el documento de métricas del usuario (O12, RN-26)."""
        oid = ObjectId(user_id) if isinstance(user_id, str) else user_id
        await self._collection.delete_one({"_id": oid}, session=session)

    async def find_by_user(self, user_id: str | ObjectId) -> dict[str, Any] | None:
        """Lee el panel de estadísticas del usuario (P7)."""
        oid = ObjectId(user_id) if isinstance(user_id, str) else user_id
        return await self._collection.find_one({"_id": oid})
