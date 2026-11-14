"""Unidad de trabajo MongoDB para transacciones ACID (RF-05.1, D4, P6, P10, P11)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from motor.motor_asyncio import AsyncIOMotorClientSession, AsyncIOMotorDatabase


class UnitOfWork:
    """Provee sesiones transaccionales; los repositorios reciben la sesión activa."""

    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self._db = db

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[AsyncIOMotorClientSession]:
        """Abre una sesión con transacción ACID: commit al salir, abort si hay excepción."""
        async with await self._db.client.start_session() as session:
            async with session.start_transaction():
                yield session
