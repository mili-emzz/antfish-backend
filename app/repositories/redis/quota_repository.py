"""Control atómico de cuota dual por API externa (RF-04, P5).

Claves: cuota:{api}:pm (TTL 60 s) y cuota:{api}:daily (TTL 86400 s).
"""

from __future__ import annotations

from redis.asyncio import Redis

# Verifica ambos límites y consume ambos contadores en una sola operación atómica.
_CONSUME_SCRIPT = """
local pm = tonumber(redis.call('GET', KEYS[1]) or '0')
local daily = tonumber(redis.call('GET', KEYS[2]) or '0')
if pm >= tonumber(ARGV[1]) or daily >= tonumber(ARGV[2]) then
    return 0
end
if redis.call('INCR', KEYS[1]) == 1 then
    redis.call('EXPIRE', KEYS[1], 60)
end
if redis.call('INCR', KEYS[2]) == 1 then
    redis.call('EXPIRE', KEYS[2], 86400)
end
return 1
"""


class QuotaRepository:
    """Consume cuota por API sin condiciones de carrera."""

    def __init__(self, redis_client: Redis) -> None:
        self._redis = redis_client

    async def try_consume(self, api: str, limit_per_minute: int, limit_daily: int) -> bool:
        """True si había cuota y se consumió una unidad; False si algún límite está agotado."""
        allowed = await self._redis.eval(
            _CONSUME_SCRIPT,
            2,
            f"cuota:{api}:pm",
            f"cuota:{api}:daily",
            limit_per_minute,
            limit_daily,
        )
        return bool(int(allowed))
