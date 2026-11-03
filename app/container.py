from motor.motor_asyncio import AsyncIOMotorDatabase
from redis.asyncio import Redis
from app.repositories.mongo.user_repository import UserRepository
from app.repositories.redis.verification_repository import VerificationRepository
from app.services.verification_service import VerificationService
from app.services.auth_service import AuthService

class Container:
    def __init__(self, db: AsyncIOMotorDatabase, redis_client: Redis) -> None:
        self.user_repository = UserRepository(db)
        self.verification_repo = VerificationRepository(redis_client)
        self.verification_service = VerificationService(self.verification_repo)
        
        # Le pasamos ambos servicios al AuthService
        self.auth_service = AuthService(self.user_repository, self.verification_service)