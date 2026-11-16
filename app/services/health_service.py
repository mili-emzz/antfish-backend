"""Comprobación de salud de dependencias (GET /health, §9.6).

Política:
- MongoDB es imprescindible (persistencia, auth): sin él la instancia no atiende -> no_disponible (503).
- Redis caído deja sin servicio a los flujos fail-closed (login, registro, verificación) pero el
  análisis sigue operando en fail-open (RF-04, RNF-02) -> degradado (200).
Los detalles del fallo solo van al log; la respuesta no expone errores internos.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from pymongo.errors import PyMongoError
from redis.exceptions import RedisError

from app.core.logging import logger

Probe = Callable[[], Awaitable[object]]

_PROBE_ERRORS = (PyMongoError, RedisError, asyncio.TimeoutError, OSError)


@dataclass(frozen=True)
class HealthReport:
    status: str  # "ok" | "degradado" | "no_disponible"

    @property
    def http_status(self) -> int:
        return 503 if self.status == "no_disponible" else 200


class HealthService:
    """Sondea Mongo y Redis en paralelo con un timeout corto por sonda."""

    def __init__(
        self,
        mongo_probe: Probe,
        redis_probe: Probe,
        timeout_seconds: float = 2.0,
    ) -> None:
        self._mongo_probe = mongo_probe
        self._redis_probe = redis_probe
        self._timeout = timeout_seconds

    async def _check(self, name: str, probe: Probe) -> bool:
        try:
            await asyncio.wait_for(probe(), timeout=self._timeout)
        except _PROBE_ERRORS as exc:
            logger.error(f"Health: {name} no disponible ({type(exc).__name__})")
            return False
        return True

    async def check(self) -> HealthReport:
        mongo_ok, redis_ok = await asyncio.gather(
            self._check("mongodb", self._mongo_probe),
            self._check("redis", self._redis_probe),
        )
        if not mongo_ok:
            return HealthReport("no_disponible")
        if not redis_ok:
            return HealthReport("degradado")
        return HealthReport("ok")
