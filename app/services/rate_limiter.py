"""Servicio de control de tasa (RF-06.3, RNF-03, DP-04).

Políticas de resiliencia (AGENTS.md):
- Autenticación y envío de códigos: fail-closed (Redis caído -> 503).
- Análisis y consultas (historial, detalle, borrado, métricas): fail-open (Redis caído -> se permite y se registra una advertencia).

Claves (ventana fija): rl:auth:{endpoint}:{ip}, rl:analysis:{user_id}, rl:read:{user_id}, reenvio:{user_id}.
"""

from __future__ import annotations

from redis.exceptions import RedisError

from app.core.config import settings
from app.core.exceptions import RateLimitBackendError, RateLimitExceededError
from app.core.logging import logger
from app.core.security import generate_message_hmac
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

    async def check_auth(self, endpoint: str, ip: str, limit: int | None = None) -> None:
        """Máx. N intentos por minuto por IP en endpoints de autenticación (fail-closed)."""
        try:
            await self._enforce(
                f"rl:auth:{endpoint}:{ip}",
                limit if limit is not None else settings.RATE_LIMIT_AUTH_PER_MIN,
                WINDOW_MINUTE,
            )
        except RedisError as exc:
            logger.error(f"Rate limit de autenticación no disponible: {type(exc).__name__}")
            raise RateLimitBackendError() from exc

    @staticmethod
    def _account_key(email: str) -> str:
        """Clave opaca por cuenta (HMAC): no deja el correo en claro en Redis."""
        return generate_message_hmac(email.strip().lower())[:32]

    async def check_login_account(self, email: str) -> None:
        """Rechaza (429) el login si la cuenta está en espera por fallos previos (fail-closed)."""
        try:
            ttl = await self._repo.login_block_ttl(self._account_key(email))
        except RedisError as exc:
            logger.error(f"Control de login por cuenta no disponible: {type(exc).__name__}")
            raise RateLimitBackendError() from exc
        if ttl > 0:
            raise RateLimitExceededError(retry_after=ttl)

    async def record_login_failure(self, email: str) -> None:
        """Registra un fallo de login; tras N fallos la espera crece de forma exponencial."""
        try:
            await self._repo.record_login_failure(
                self._account_key(email),
                settings.LOGIN_FAILURE_WINDOW_SECONDS,
                settings.LOGIN_FREE_FAILURES,
                settings.LOGIN_BACKOFF_BASE_SECONDS,
                settings.LOGIN_BACKOFF_MAX_SECONDS,
            )
        except RedisError as exc:
            logger.error(f"No se pudo registrar el fallo de login: {type(exc).__name__}")
            raise RateLimitBackendError() from exc

    async def clear_login_failures(self, email: str) -> None:
        """Olvida los fallos tras un login correcto (mejor esfuerzo)."""
        try:
            await self._repo.clear_login_failures(self._account_key(email))
        except RedisError as exc:
            logger.warning(f"No se pudieron limpiar los fallos de login: {type(exc).__name__}")

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

    async def check_read(self, user_id: str) -> None:
        """Máx. N consultas por minuto por usuario, contador compartido (fail-open)."""
        try:
            await self._enforce(
                f"rl:read:{user_id}", settings.RATE_LIMIT_READ_PER_MIN, WINDOW_MINUTE
            )
        except RedisError as exc:
            logger.warning(
                f"Rate limit de consultas no disponible (fail-open): {type(exc).__name__}"
            )
