"""Cliente asíncrono para VirusTotal API v3 (RF-02.2).

Consulta el análisis previo de la URL mediante su identificador base64url
enviando cabecera x-apikey y respetando un timeout estricto de 1.5 s.
El código HTTP 404 se procesa como ok sin detecciones (sin enviar a escanear).
"""

from __future__ import annotations

import base64
from typing import Any

import httpx

from app.clients.base import BaseReputationClient, ReputationResult
from app.core.config import settings
from app.core.logging import logger
from app.engine.models import Reputation, SourceStatus


class VirusTotalClient(BaseReputationClient):
    """Cliente para la API v3 de VirusTotal."""

    BASE_URL: str = "https://www.virustotal.com/api/v3/urls"

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 1.5,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        key = api_key if api_key is not None else getattr(settings, "VIRUSTOTAL_API_KEY", "")
        super().__init__(
            api_name="virustotal",
            api_key=key,
            timeout=timeout,
            client=client,
        )

    @staticmethod
    def calculate_url_id(url: str) -> str:
        """Calcula el identificador base64url sin padding para la API v3 de VirusTotal."""
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")

    async def check_url(self, url: str) -> ReputationResult:
        """RF-02.2: Consulta el reporte previo de la URL en VirusTotal.

        Tratamiento específico:
        - HTTP 404: Se considera 'ok' sin detecciones (positivo: False, detecciones: 0).
          Bajo la directriz de privacidad, jamás se envía la URL a escanear.
        - HTTP 200: Suma detecciones de 'malicious' y 'suspicious' de last_analysis_stats.

        Args:
            url: URL normalizada a evaluar.

        Returns:
            ReputationResult con el modelo Reputation y respuesta cruda.
        """
        if not self.api_key:
            logger.warning("VIRUSTOTAL_API_KEY no configurada; degradando consulta")
            return ReputationResult(reputation=self._build_fallback_reputation(SourceStatus.ERROR))

        url_id = self.calculate_url_id(url)
        endpoint = f"{self.BASE_URL}/{url_id}"

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

        response, estado = await self._execute_request(
            method="GET",
            url=endpoint,
            headers=headers,
        )

        # Manejo especial de 404: URL no analizada previamente
        if response is not None and response.status_code == 404:
            return ReputationResult(
                reputation=Reputation(
                    api=self.api_name,
                    estado=SourceStatus.OK,
                    positivo=False,
                    detecciones=0,
                    desde_cache=False,
                ),
                raw_response={
                    "message": "URL not found in VirusTotal database",
                    "status_code": 404,
                },
            )

        if estado != SourceStatus.OK or response is None:
            return ReputationResult(reputation=self._build_fallback_reputation(estado))

        if response.status_code != 200:
            logger.warning(f"VirusTotal retornó código inesperado {response.status_code}")
            return ReputationResult(reputation=self._build_fallback_reputation(SourceStatus.ERROR))

        try:
            data: dict[str, Any] = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            detecciones = malicious + suspicious
            positivo = detecciones >= 1

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
        except Exception as exc:
            logger.error(f"Error al deserializar respuesta de VirusTotal: {type(exc).__name__}")
            return ReputationResult(reputation=self._build_fallback_reputation(SourceStatus.ERROR))
