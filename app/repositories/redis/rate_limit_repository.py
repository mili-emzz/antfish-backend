"""Contadores de ventana fija en Redis para rate limiting (DP-04, D17, P13)."""

from __future__ import annotations

from redis.asyncio import Redis

# INCR + EXPIRE atómicos: evita claves inmortales si el proceso cae entre ambas órdenes.
_HIT_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
end
return {count, redis.call('TTL', KEYS[1])}
"""


class RateLimitRepository:
    """Registra solicitudes por clave dentro de una ventana fija."""

    def __init__(self, redis_client: Redis) -> None:
        self._redis = redis_client

    async def hit(self, key: str, window_seconds: int) -> tuple[int, int]:
        """Incrementa la clave y devuelve (contador, segundos_restantes_de_la_ventana)."""
        count, ttl = await self._redis.eval(_HIT_SCRIPT, 1, key, window_seconds)  # type: ignore[misc]
        return int(count), max(int(ttl), 1)
