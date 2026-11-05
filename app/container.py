from motor.motor_asyncio import AsyncIOMotorDatabase
from redis.asyncio import Redis

from app.clients.resend_email import ResendEmailClient
from app.repositories.mongo.user_repository import UserRepository
from app.repositories.redis.verification_repository import VerificationRepository
from app.services.auth_service import AuthService
from app.services.verification_service import VerificationService


class Container:
    """Contenedor de dependencias de la aplicación (Composition Root)."""

    def __init__(self, db: AsyncIOMotorDatabase, redis_client: Redis) -> None:
        self.user_repository = UserRepository(db)
        self.verification_repo = VerificationRepository(redis_client)
        self.email_client = ResendEmailClient()
        self.verification_service = VerificationService(
            verification_repo=self.verification_repo,
            email_client=self.email_client,
        )
        self.auth_service = AuthService(
            user_repository=self.user_repository,
            verification_service=self.verification_service,
        )
