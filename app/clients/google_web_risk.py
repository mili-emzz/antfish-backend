"""Cliente asíncrono para Google Web Risk Lookup API (RF-02.2).

Consulta la API uris:search con cabecera X-Goog-Api-Key y timeout de 1.5 s.
Evalúa amenazas de tipo MALWARE, SOCIAL_ENGINEERING y UNWANTED_SOFTWARE.
"""

from __future__ import annotations

from typing import Any
import httpx

from app.clients.base import BaseReputationClient, ReputationResult
from app.core.config import settings
from app.core.logging import logger
from app.engine.models import Reputation, SourceStatus


class GoogleWebRiskClient(BaseReputationClient):
    """Cliente para la API Google Web Risk."""

    ENDPOINT: str = "https://webrisk.googleapis.com/v1/uris:search"
    THREAT_TYPES: tuple[str, ...] = (
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
    )

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 1.5,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        key = api_key if api_key is not None else getattr(settings, "GOOGLE_WEB_RISK_API_KEY", "")
        super().__init__(
            api_name="google_web_risk",
            api_key=key,
            timeout=timeout,
            client=client,
        )

    async def check_url(self, url: str) -> ReputationResult:
        """RF-02.2: Consulta la reputación de la URL en Google Web Risk.

        Args:
            url: URL normalizada a evaluar.

        Returns:
            ReputationResult con el modelo Reputation y respuesta cruda.
        """
        if not self.api_key:
            logger.warning("GOOGLE_WEB_RISK_API_KEY no configurada; degradando consulta")
            return ReputationResult(
                reputation=self._build_fallback_reputation(SourceStatus.ERROR)
            )

        headers = {
            "X-Goog-Api-Key": self.api_key,
            "Accept": "application/json",
        }
        # Web Risk acepta múltiples parámetros repetidos para threatTypes
        params: list[tuple[str, str]] = [("uri", url)]
        for threat_type in self.THREAT_TYPES:
            params.append(("threatTypes", threat_type))

        response, estado = await self._execute_request(
            method="GET",
            url=self.ENDPOINT,
            headers=headers,
            params=params,  # type: ignore[arg-type]
        )

        if estado != SourceStatus.OK or response is None:
            return ReputationResult(
                reputation=self._build_fallback_reputation(estado)
            )

        try:
            data: dict[str, Any] = response.json()
            threat = data.get("threat")
            if threat and isinstance(threat, dict):
                threat_types = threat.get("threatTypes", [])
                positivo = bool(threat_types)
                detecciones = len(threat_types) if threat_types else 1
            else:
                positivo = False
                detecciones = None

            return ReputationResult(
                reputation=Reputation(
                    api=self.api_name,
                    estado=SourceStatus.OK,
                    positivo=positivo,
                    detecciones=detecciones,
                    desde_cache=False,
                ),
                raw_response=data,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                f"Error al deserializar respuesta de Web Risk: {type(exc).__name__}"
            )
            return ReputationResult(
                reputation=self._build_fallback_reputation(SourceStatus.ERROR)
            )

