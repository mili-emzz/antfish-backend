"""Cliente asíncrono para PhishTank checkurl API (RF-02.2).

Consulta puntual mediante petición POST al endpoint de verificación de PhishTank
con cabecera obligatoria User-Agent AntFish/1.0 y timeout estricto de 1.5 s.
"""

from __future__ import annotations

from typing import Any
import httpx

from app.clients.base import BaseReputationClient, ReputationResult
from app.core.config import settings
from app.core.logging import logger
from app.engine.models import Reputation, SourceStatus


class PhishTankClient(BaseReputationClient):
    """Cliente para la API de verificación checkurl de PhishTank."""

    ENDPOINT: str = "https://checkurl.phishtank.com/checkurl/"
    USER_AGENT: str = "AntFish/1.0 (antfish-app)"

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 1.5,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        key = api_key if api_key is not None else getattr(settings, "PHISHTANK_API_KEY", "")
        super().__init__(
            api_name="phishtank",
            api_key=key,
            timeout=timeout,
            client=client,
        )

    async def check_url(self, url: str) -> ReputationResult:
        """RF-02.2: Consulta si la URL se encuentra listada como phishing en PhishTank.

        Args:
            url: URL normalizada a evaluar.

        Returns:
            ReputationResult con el modelo Reputation y respuesta cruda.
        """
        headers = {
            "User-Agent": self.USER_AGENT,
            "Accept": "application/json",
        }

        payload: dict[str, str] = {
            "url": url,
            "format": "json",
        }
        if self.api_key:
            payload["app_key"] = self.api_key

        response, estado = await self._execute_request(
            method="POST",
            url=self.ENDPOINT,
            headers=headers,
            data=payload,
        )

        if estado != SourceStatus.OK or response is None:
            return ReputationResult(
                reputation=self._build_fallback_reputation(estado)
            )

        try:
            data: dict[str, Any] = response.json()
            results = data.get("results", {})

            if isinstance(results, dict):
                in_database = bool(results.get("in_database", False))
                valid = bool(results.get("valid", False))
                positivo = in_database and valid
                detecciones = 1 if positivo else None
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
                f"Error al deserializar respuesta de PhishTank: {type(exc).__name__}"
            )
            return ReputationResult(
                reputation=self._build_fallback_reputation(SourceStatus.ERROR)
            )

