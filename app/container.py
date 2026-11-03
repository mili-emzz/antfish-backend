"""Composition Root: instanciación y cableado de dependencias del backend."""

from motor.motor_asyncio import AsyncIOMotorDatabase
from app.repositories.mongo.user_repository import UserRepository
from app.services.auth_service import AuthService


class Container:
    """Contenedor de dependencias de la aplicación."""

    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.user_repository = UserRepository(db)
        self.auth_service = AuthService(self.user_repository)

