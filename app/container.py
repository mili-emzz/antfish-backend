from motor.motor_asyncio import AsyncIOMotorDatabase
from redis.asyncio import Redis

from app.clients.google_web_risk import GoogleWebRiskClient
from app.clients.phishtank import PhishTankClient
from app.clients.resend_email import ResendEmailClient
from app.clients.virustotal import VirusTotalClient
from app.repositories.mongo.analysis_repository import AnalysisRepository
from app.repositories.mongo.metrics_repository import MetricsRepository
from app.repositories.mongo.unit_of_work import UnitOfWork
from app.repositories.mongo.user_repository import UserRepository
from app.repositories.redis.quota_repository import QuotaRepository
from app.repositories.redis.rate_limit_repository import RateLimitRepository
from app.repositories.redis.verification_repository import VerificationRepository
from app.services.analysis_service import AnalysisService
from app.services.auth_service import AuthService
from app.services.metrics_service import MetricsService
from app.services.rate_limiter import RateLimiter
from app.services.verification_service import VerificationService


class Container:
    """Contenedor de dependencias de la aplicación (Composition Root)."""

    def __init__(self, db: AsyncIOMotorDatabase, redis_client: Redis) -> None:
        # Repositorios
        self.user_repository = UserRepository(db)
        self.analysis_repository = AnalysisRepository(db)
        self.metrics_repository = MetricsRepository(db)
        self.unit_of_work = UnitOfWork(db)
        self.verification_repo = VerificationRepository(redis_client)
        self.quota_repository = QuotaRepository(redis_client)
        self.rate_limiter = RateLimiter(RateLimitRepository(redis_client))

        # Clientes externos de comunicación e inteligencia de amenazas (RF-02.2, RF-06.2)
        self.email_client = ResendEmailClient()
        self.web_risk_client = GoogleWebRiskClient()
        self.virustotal_client = VirusTotalClient()
        self.phishtank_client = PhishTankClient()

        # Servicios
        self.verification_service = VerificationService(
            verification_repo=self.verification_repo,
            email_client=self.email_client,
            rate_limiter=self.rate_limiter,
        )
        self.auth_service = AuthService(
            user_repository=self.user_repository,
            verification_service=self.verification_service,
        )
        self.analysis_service = AnalysisService(
            web_risk_client=self.web_risk_client,
            virustotal_client=self.virustotal_client,
            phishtank_client=self.phishtank_client,
            analysis_repository=self.analysis_repository,
            metrics_repository=self.metrics_repository,
            unit_of_work=self.unit_of_work,
            quota_repository=self.quota_repository,
        )
        self.metrics_service = MetricsService(self.metrics_repository)
