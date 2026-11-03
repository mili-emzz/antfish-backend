from redis.asyncio import Redis

class VerificationRepository:
    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    async def save_code(self, user_id: str, hashed_code: str, ttl: int = 600) -> None:
        """Guarda el código hasheado con un TTL de 10 minutos."""
        await self.redis.set(f"verif:{user_id}", hashed_code, ex=ttl)

    async def get_code(self, user_id: str) -> str | None:
        """Obtiene el código hasheado."""
        code = await self.redis.get(f"verif:{user_id}")
        return code.decode("utf-8") if code else None

    async def delete_code(self, user_id: str) -> None:
        """Elimina el código tras un uso exitoso."""
        await self.redis.delete(f"verif:{user_id}")

    async def increment_attempts(self, user_id: str) -> int:
        """Controla el máximo de intentos (fail-closed)."""
        attempts = await self.redis.incr(f"verif_attempts:{user_id}")
        if attempts == 1:
            await self.redis.expire(f"verif_attempts:{user_id}", 600)
        return attempts
    
    async def clear_attempts(self, user_id: str) -> None:
        await self.redis.delete(f"verif_attempts:{user_id}")