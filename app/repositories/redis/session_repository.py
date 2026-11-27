"""Sesiones de refresh token en Redis: rotación y detección de reutilización (D18)."""

from __future__ import annotations

from redis.asyncio import Redis

# Compara-y-cambia atómico: solo el jti vigente de la familia puede rotarse.
_ROTATE_SCRIPT = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
    redis.call('SET', KEYS[1], ARGV[2], 'EX', tonumber(ARGV[3]))
    return 1
end
return 0
"""


class RefreshSessionRepository:
    """Guarda, por familia de sesión (`fam`), el único `jti` de refresh vigente."""

    def __init__(self, redis_client: Redis) -> None:
        self._redis = redis_client

    @staticmethod
    def _key(family: str) -> str:
        return f"rt:{family}"

    async def start(self, family: str, jti: str, ttl_seconds: int) -> None:
        """Abre una familia con su primer jti."""
        await self._redis.set(self._key(family), jti, ex=ttl_seconds)

    async def rotate(self, family: str, old_jti: str, new_jti: str, ttl_seconds: int) -> bool:
        """Cambia old_jti por new_jti; False si old_jti no es el vigente (reutilización/revocada)."""
        result = await self._redis.eval(
            _ROTATE_SCRIPT, 1, self._key(family), old_jti, new_jti, ttl_seconds
        )
        return int(result) == 1

    async def revoke(self, family: str) -> None:
        """Revoca la familia completa."""
        await self._redis.delete(self._key(family))
