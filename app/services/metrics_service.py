"""Servicio de lectura de métricas del panel de usuario (RF-05.2, O8)."""

from __future__ import annotations

from typing import Any

from app.repositories.mongo.metrics_repository import MetricsRepository


class MetricsService:
    """Expone las estadísticas acumuladas del usuario autenticado."""

    def __init__(self, metrics_repository: MetricsRepository) -> None:
        self._repo = metrics_repository

    async def get_user_metrics(self, user_id: str) -> dict[str, Any]:
        """Devuelve los contadores del usuario; ceros si aún no tiene escaneos."""
        doc = await self._repo.find_by_user(user_id)
        if doc is None:
            return {
                "total_escaneos": 0,
                "total_url": 0,
                "total_sms": 0,
                "amenazas_bloqueadas": 0,
                "ultima_actualizacion": None,
            }
        return {
            "total_escaneos": doc["total_escaneos"],
            "total_url": doc["total_url"],
            "total_sms": doc["total_sms"],
            "amenazas_bloqueadas": doc["amenazas_bloqueadas"],
            "ultima_actualizacion": doc.get("ultima_actualizacion"),
        }
