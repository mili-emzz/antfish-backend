"""Repositorio MongoDB de analisis y respuestas_apis (RF-05.1, P6, P8, P9, P10, D8)."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
from typing import Any

from bson import ObjectId
from bson.errors import InvalidId
from motor.motor_asyncio import AsyncIOMotorClientSession, AsyncIOMotorDatabase

from app.core.exceptions import InvalidCursorError

HISTORY_PAGE_SIZE = 20


def encode_cursor(fecha: datetime, doc_id: ObjectId) -> str:
    """Codifica el cursor opaco (fecha, _id) en base64url."""
    if fecha.tzinfo is None:
        fecha = fecha.replace(tzinfo=timezone.utc)
    raw = f"{fecha.astimezone(timezone.utc).isoformat()}|{doc_id}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def decode_cursor(cursor: str) -> tuple[datetime, ObjectId]:
    """Decodifica un cursor opaco; lanza InvalidCursorError si está malformado."""
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
        fecha_str, id_str = raw.split("|", 1)
        fecha = datetime.fromisoformat(fecha_str)
        return fecha, ObjectId(id_str)
    except (ValueError, UnicodeError, binascii.Error, InvalidId) as exc:
        raise InvalidCursorError() from exc


class AnalysisRepository:
    """Persistencia de análisis y de las respuestas crudas de APIs."""

    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self._analisis = db["analisis"]
        self._respuestas = db["respuestas_apis"]

    async def insert_analysis(
        self,
        document: dict[str, Any],
        session: AsyncIOMotorClientSession | None = None,
    ) -> ObjectId:
        """Inserta un análisis (P6) y devuelve su _id."""
        result = await self._analisis.insert_one(document, session=session)
        return result.inserted_id  # type: ignore[no-any-return]

    async def insert_api_responses(
        self,
        documents: list[dict[str, Any]],
        session: AsyncIOMotorClientSession | None = None,
    ) -> None:
        """Inserta hasta 6 respuestas crudas de APIs (P6, D1)."""
        if documents:
            await self._respuestas.insert_many(documents, session=session)

    async def list_history(
        self,
        user_id: str | ObjectId,
        cursor: str | None = None,
        limit: int = HISTORY_PAGE_SIZE,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Historial paginado por cursor (fecha, _id) respaldado por I2 (P8, D8).

        Returns:
            (documentos, siguiente_cursor); siguiente_cursor es None en la última página.
        """
        oid = ObjectId(user_id) if isinstance(user_id, str) else user_id
        query: dict[str, Any] = {"user_id": oid}
        if cursor:
            fecha, last_id = decode_cursor(cursor)
            query["$or"] = [
                {"fecha": {"$lt": fecha}},
                {"fecha": fecha, "_id": {"$lt": last_id}},
            ]

        docs = (
            await self._analisis.find(query)
            .sort([("fecha", -1), ("_id", -1)])
            .limit(limit + 1)
            .to_list(length=limit + 1)
        )
        next_cursor: str | None = None
        if len(docs) > limit:
            docs = docs[:limit]
            last = docs[-1]
            next_cursor = encode_cursor(last["fecha"], last["_id"])
        return docs, next_cursor

    async def find_by_id_and_user(
        self, analysis_id: str, user_id: str | ObjectId
    ) -> dict[str, Any] | None:
        """Detalle de un análisis garantizando pertenencia (P9)."""
        try:
            oid = ObjectId(analysis_id)
        except InvalidId:
            return None
        uid = ObjectId(user_id) if isinstance(user_id, str) else user_id
        return await self._analisis.find_one({"_id": oid, "user_id": uid})

    async def delete_all_by_user(
        self,
        user_id: ObjectId,
        session: AsyncIOMotorClientSession | None = None,
    ) -> None:
        """Purga todos los análisis y respuestas crudas del usuario (O12, RN-26)."""
        await self._analisis.delete_many({"user_id": user_id}, session=session)
        await self._respuestas.delete_many({"user_id": user_id}, session=session)

    async def delete_analysis(
        self,
        analysis_id: ObjectId,
        user_id: ObjectId,
        session: AsyncIOMotorClientSession | None = None,
    ) -> bool:
        """Borra el análisis y sus respuestas crudas (P10, O11, índice I9)."""
        result = await self._analisis.delete_one(
            {"_id": analysis_id, "user_id": user_id}, session=session
        )
        if result.deleted_count == 0:
            return False
        await self._respuestas.delete_many(
            {"user_id": user_id, "analisis_id": analysis_id}, session=session
        )
        return True
