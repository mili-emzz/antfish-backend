"""Repositorio MongoDB con Motor para la colección usuarios."""

from datetime import datetime, timezone
from typing import Any
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase


class UserRepository:
    """Repositorio asíncrono para gestionar operaciones de persistencia en la colección usuarios."""

    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self._db = db
        self._collection = db["usuarios"]

    async def find_by_email(self, email: str) -> dict[str, Any] | None:
        """Busca un usuario por su correo electrónico normalizado (P1, I1)."""
        normalized_email = email.strip().lower()
        return await self._collection.find_one({"email": normalized_email})

    async def find_by_id(self, user_id: str | ObjectId) -> dict[str, Any] | None:
        """Busca un usuario por su ObjectId (P2)."""
        oid = ObjectId(user_id) if isinstance(user_id, str) else user_id
        return await self._collection.find_one({"_id": oid})

    async def create_user(self, user_data: dict[str, Any]) -> dict[str, Any]:
        """Inserta un nuevo documento en la colección usuarios (O1)."""
        if "email" in user_data and isinstance(user_data["email"], str):
            user_data["email"] = user_data["email"].strip().lower()

        result = await self._collection.insert_one(user_data)
        user_data["_id"] = result.inserted_id
        return user_data

    async def update_pending_user(
        self,
        user_id: str | ObjectId,
        nombre: str,
        password_hash: str,
    ) -> dict[str, Any] | None:
        """Sobrescribe datos de un usuario en pendiente_verificacion y reinicia fecha_registro (D14, RN-23)."""
        oid = ObjectId(user_id) if isinstance(user_id, str) else user_id
        now = datetime.now(timezone.utc)
        await self._collection.update_one(
            {"_id": oid, "estado_cuenta": "pendiente_verificacion"},
            {
                "$set": {
                    "nombre": nombre.strip(),
                    "password_hash": password_hash,
                    "fecha_registro": now,
                }
            },
        )
        return await self.find_by_id(oid)

