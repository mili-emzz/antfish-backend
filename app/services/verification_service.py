import hmac
import hashlib
from app.core.config import settings
from app.repositories.redis.verification_repository import VerificationRepository

class VerificationService:
    def __init__(self, verification_repo: VerificationRepository):
        self.repo = verification_repo

    def hash_code(self, code: str) -> str:
        """Aplica HMAC-SHA256 al código usando el PEPPER del servidor (RF-06.2)."""
        secret = settings.HMAC_PEPPER.encode("utf-8")
        return hmac.new(secret, code.encode("utf-8"), hashlib.sha256).hexdigest()

    async def generate_and_save_code(self, user_id: str) -> str:
        """Genera un código, lo hashea y lo guarda (usarías esto al registrar/reenviar)."""
        import random
        plain_code = f"{random.randint(0, 999999):06d}"
        hashed_code = self.hash_code(plain_code)
        await self.repo.save_code(user_id, hashed_code)
        # Aquí llamarías a Resend para enviar 'plain_code' por email
        return plain_code

    async def validate_code(self, user_id: str, plain_code: str) -> bool:
        """Valida el código ingresado contra el hash en Redis."""
        attempts = await self.repo.increment_attempts(user_id)
        if attempts > 5:
            raise ValueError("Se excedió el límite de intentos permitidos.")
        
        stored_hash = await self.repo.get_code(user_id)
        if not stored_hash:
            return False
        
        input_hash = self.hash_code(plain_code)
        if hmac.compare_digest(stored_hash, input_hash):
            await self.repo.delete_code(user_id)
            await self.repo.clear_attempts(user_id)
            return True
        return False