"""Servicio de verificación de códigos de 6 dígitos (RF-06.2, RF-06.3, RNF-06)."""

import hashlib
import hmac
import secrets

from app.clients.resend_email import ResendEmailClient
from app.core.config import settings
from app.core.exceptions import EmailDeliveryError, VerificationAttemptsExceededError
from app.repositories.redis.verification_repository import VerificationRepository
from app.services.rate_limiter import RateLimiter


class VerificationService:
    """Gestiona la generación, hash HMAC-SHA256, persistencia en Redis y despacho vía Resend."""

    def __init__(
        self,
        verification_repo: VerificationRepository,
        email_client: ResendEmailClient | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.repo = verification_repo
        self.rate_limiter = rate_limiter
        self.email_client = email_client or ResendEmailClient()

    def hash_code(self, code: str) -> str:
        """Aplica HMAC-SHA256 al código usando el PEPPER del servidor (RF-06.2)."""
        secret = settings.HMAC_PEPPER.encode("utf-8")
        return hmac.new(secret, code.encode("utf-8"), hashlib.sha256).hexdigest()

    async def generate_and_save_code(
        self,
        user_id: str,
        email: str | None = None,
        purpose: str = "verificacion",
    ) -> str:
        """Genera un código de 6 dígitos, lo guarda hasheado en Redis y lo envía por correo vía Resend.

        `purpose` es `verificacion` o `recuperacion` (RF-06.2 / RF-06.6). Sobrescribe el código
        anterior (lo invalida) y reinicia el contador de intentos (RF-06.3).
        Si ocurre una falla de red o error de entrega en Resend, lanza EmailDeliveryError (RNF-06).
        """
        # Máx. 3 envíos/hora por usuario (D17); fail-closed. Sin código no se envía correo.
        if self.rate_limiter is not None:
            await self.rate_limiter.check_resend(user_id)

        plain_code = f"{secrets.randbelow(1_000_000):06d}"
        hashed_code = self.hash_code(plain_code)
        await self.repo.save_code(user_id, hashed_code)
        await self.repo.clear_attempts(user_id)

        if email:
            if purpose == "recuperacion":
                await self.email_client.send_recovery_code(email, plain_code)
            else:
                await self.email_client.send_verification_code(email, plain_code)

        return plain_code

    async def send_verification_email(self, email: str, code: str) -> None:
        """Envía el código de 6 dígitos al correo especificado mediante Resend."""
        await self.email_client.send_verification_code(email, code)

    async def validate_code(self, user_id: str, plain_code: str) -> bool:
        """Valida el código ingresado contra el hash almacenado en Redis bajo política fail-closed."""
        attempts = await self.repo.increment_attempts(user_id)
        if attempts > 5:
            raise VerificationAttemptsExceededError("Se excedió el límite de intentos permitidos.")

        stored_hash = await self.repo.get_code(user_id)
        if not stored_hash:
            return False

        input_hash = self.hash_code(plain_code)
        if hmac.compare_digest(stored_hash, input_hash):
            await self.repo.delete_code(user_id)
            await self.repo.clear_attempts(user_id)
            return True
        return False
