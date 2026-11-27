from redis.asyncio import Redis

_ATTEMPTS_TTL = 600

# INCR + EXPIRE atómicos: si el proceso cae entre ambas órdenes no queda una clave sin TTL
# (bloqueo permanente de la verificación). También repara claves sin TTL ya existentes.
_INCR_ATTEMPTS_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 or redis.call('TTL', KEYS[1]) < 0 then
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
end
return count
"""


class VerificationRepository:
    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    async def save_code(self, user_id: str, hashed_code: str, ttl: int = 600) -> None:
        """Guarda el código hasheado con un TTL de 10 minutos."""
        await self.redis.set(f"verif:{user_id}", hashed_code, ex=ttl)

    async def get_code(self, user_id: str) -> str | None:
        """Obtiene el código hasheado."""
        code = await self.redis.get(f"verif:{user_id}")
        if not code:
            return None
        return code.decode("utf-8") if isinstance(code, bytes) else code

    async def delete_code(self, user_id: str) -> None:
        """Elimina el código tras un uso exitoso."""
        await self.redis.delete(f"verif:{user_id}")

    async def increment_attempts(self, user_id: str) -> int:
        """Controla el máximo de intentos (fail-closed)."""
        attempts = await self.redis.eval(
            _INCR_ATTEMPTS_SCRIPT, 1, f"verif_attempts:{user_id}", _ATTEMPTS_TTL
        )
        return int(attempts)

    async def clear_attempts(self, user_id: str) -> None:
        await self.redis.delete(f"verif_attempts:{user_id}")
