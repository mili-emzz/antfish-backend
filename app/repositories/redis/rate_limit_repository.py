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


# Registra un fallo de login y, pasados los fallos gratis, activa un bloqueo cuya duración se
# duplica con cada fallo extra (tope ARGV[4]). Devuelve los segundos de bloqueo (0 = ninguno).
_LOGIN_FAILURE_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
local free = tonumber(ARGV[2])
if count > free then
    local delay = math.floor(math.min(tonumber(ARGV[3]) * 2 ^ (count - free - 1), tonumber(ARGV[4])))
    redis.call('SET', KEYS[2], 1, 'EX', delay)
    return delay
end
return 0
"""


class RateLimitRepository:
    """Registra solicitudes por clave dentro de una ventana fija."""

    def __init__(self, redis_client: Redis) -> None:
        self._redis = redis_client

    async def hit(self, key: str, window_seconds: int) -> tuple[int, int]:
        """Incrementa la clave y devuelve (contador, segundos_restantes_de_la_ventana)."""
        count, ttl = await self._redis.eval(_HIT_SCRIPT, 1, key, window_seconds)
        return int(count), max(int(ttl), 1)

    async def record_login_failure(
        self, account: str, window: int, free: int, base: int, maximum: int
    ) -> int:
        """Cuenta un fallo de login de la cuenta; devuelve los segundos de bloqueo aplicados."""
        delay = await self._redis.eval(
            _LOGIN_FAILURE_SCRIPT,
            2,
            f"lf:{account}",
            f"lb:{account}",
            window,
            free,
            base,
            maximum,
        )
        return int(delay)

    async def login_block_ttl(self, account: str) -> int:
        """Segundos restantes de bloqueo de la cuenta (0 si no está bloqueada)."""
        ttl = int(await self._redis.ttl(f"lb:{account}"))
        return max(ttl, 0)

    async def clear_login_failures(self, account: str) -> None:
        await self._redis.delete(f"lf:{account}", f"lb:{account}")
