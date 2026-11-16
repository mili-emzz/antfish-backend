"""Caché de reputación en Redis (RF-04, P3).

Clave: rep:{url_normalizada} (URL con path, sin query string, fragmento ni userinfo; D10).
Solo get/set con TTL: la decisión de cuándo cachear vive en AnalysisService.
No se guarda el texto del SMS ni las respuestas crudas de las APIs.
"""

from __future__ import annotations

import json
from typing import Any

from redis.asyncio import Redis

from app.core.config import settings


class ReputationCacheRepository:
    """Lectura y escritura de reputaciones por URL normalizada."""

    def __init__(self, redis_client: Redis, ttl_seconds: int | None = None) -> None:
        self._redis = redis_client
        self._ttl = ttl_seconds if ttl_seconds is not None else settings.REPUTATION_CACHE_TTL_SECONDS

    @staticmethod
    def _key(normalized_url: str) -> str:
        return f"rep:{normalized_url}"

    async def get(self, normalized_url: str) -> dict[str, Any] | None:
        """Devuelve la entrada cacheada o None si no existe o está corrupta."""
        raw = await self._redis.get(self._key(normalized_url))
        if raw is None:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    async def set(self, normalized_url: str, payload: dict[str, Any]) -> None:
        """Guarda la entrada con TTL (3600 s por defecto)."""
        await self._redis.set(
            self._key(normalized_url), json.dumps(payload, separators=(",", ":")), ex=self._ttl
        )
