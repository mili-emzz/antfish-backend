"""Servicio de control de tasa (RF-06.3, RNF-03, DP-04).

Políticas de resiliencia (AGENTS.md):
- Autenticación y envío de códigos: fail-closed (Redis caído -> 503).
- Análisis: fail-open (Redis caído -> se permite y se registra una advertencia).

Claves (ventana fija): rl:auth:{endpoint}:{ip}, rl:analysis:{user_id}, reenvio:{user_id}.
"""

from __future__ import annotations

from redis.exceptions import RedisError

from app.core.config import settings
from app.core.exceptions import RateLimitBackendError, RateLimitExceededError
from app.core.logging import logger
from app.repositories.redis.rate_limit_repository import RateLimitRepository

WINDOW_MINUTE = 60
WINDOW_HOUR = 3600


class RateLimiter:
    """Aplica límites de tasa por IP o por usuario."""

    def __init__(self, repository: RateLimitRepository) -> None:
        self._repo = repository

    async def _enforce(self, key: str, limit: int, window: int) -> None:
        count, ttl = await self._repo.hit(key, window)
        if count > limit:
            raise RateLimitExceededError(retry_after=ttl)

    async def check_auth(self, endpoint: str, ip: str) -> None:
        """Máx. N intentos por minuto por IP en endpoints de autenticación (fail-closed)."""
        try:
            await self._enforce(
                f"rl:auth:{endpoint}:{ip}", settings.RATE_LIMIT_AUTH_PER_MIN, WINDOW_MINUTE
            )
        except RedisError as exc:
            logger.error(f"Rate limit de autenticación no disponible: {type(exc).__name__}")
            raise RateLimitBackendError() from exc

    async def check_resend(self, user_id: str) -> None:
        """Máx. 3 envíos de código por hora por usuario, compartido (D17; fail-closed)."""
        try:
            await self._enforce(
                f"reenvio:{user_id}", settings.RATE_LIMIT_RESEND_PER_HOUR, WINDOW_HOUR
            )
        except RedisError as exc:
            logger.error(f"Control de reenvío no disponible: {type(exc).__name__}")
            raise RateLimitBackendError() from exc

    async def check_analysis(self, user_id: str) -> None:
        """Máx. 20 análisis por minuto por usuario (fail-open ante fallo de Redis)."""
        try:
            await self._enforce(
                f"rl:analysis:{user_id}", settings.RATE_LIMIT_ANALYSIS_PER_MIN, WINDOW_MINUTE
            )
        except RedisError as exc:
            logger.warning(
                f"Rate limit de análisis no disponible (fail-open): {type(exc).__name__}"
            )
