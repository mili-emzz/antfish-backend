"""Cliente HTTP asíncrono base para fuentes de inteligencia de amenazas (RF-02.2).

Estandariza la ejecución de peticiones externas, el timeout estricto de 1.5 s
y la traducción uniforme de respuestas y excepciones a los estados:
ok, timeout, rate_limit y error.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from app.core.logging import logger
from app.engine.models import Reputation, SourceStatus


@dataclass(slots=True)
class ReputationResult:
    """Contenedor de resultado que incluye el modelo de reputación y la respuesta cruda."""

    reputation: Reputation
    raw_response: dict[str, Any] | list[Any] | None = None


class BaseReputationClient:
    """Cliente base para proveedores de reputación de URLs y dominios."""

    def __init__(
        self,
        api_name: str,
        api_key: str = "",
        timeout: float = 1.5,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_name = api_name
        self.api_key = api_key
        self.timeout = timeout
        self._client = client

    def _build_fallback_reputation(
        self,
        estado: SourceStatus,
        positivo: bool = False,
        detecciones: int | None = None,
        desde_cache: bool = False,
    ) -> Reputation:
        """Construye un objeto Reputation estandarizado."""
        return Reputation(
            api=self.api_name,
            estado=estado,
            positivo=positivo,
            detecciones=detecciones,
            desde_cache=desde_cache,
        )

    async def _execute_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> tuple[httpx.Response | None, SourceStatus]:
        """Ejecuta la petición HTTP traduciendo fallos a estados estandarizados.

        Returns:
            Tupla (response, estado): si la llamada tuvo éxito o fue 404/429 se retorna
            el response y el estado correspondiente; si ocurrió timeout, rate_limit o error
            de red, response puede ser None con el estado adecuado.
        """
        try:
            if self._client is not None:
                response = await self._client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json_body,
                    timeout=self.timeout,
                )
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.request(
                        method=method,
                        url=url,
                        headers=headers,
                        params=params,
                        data=data,
                        json=json_body,
                    )

            if response.status_code == 429:
                logger.warning(
                    "API de reputación excedió límite de peticiones (429)",
                    extra={"api": self.api_name},
                )
                return response, SourceStatus.RATE_LIMIT

            if response.status_code >= 500:
                logger.warning(
                    f"API de reputación retornó error de servidor ({response.status_code})",
                    extra={"api": self.api_name},
                )
                return response, SourceStatus.ERROR

            return response, SourceStatus.OK

        except httpx.TimeoutException:
            logger.warning(
                f"Timeout de {self.timeout}s alcanzado en API de reputación",
                extra={"api": self.api_name},
            )
            return None, SourceStatus.TIMEOUT

        except httpx.RequestError as exc:
            logger.warning(
                f"Error de red al consultar API de reputación: {type(exc).__name__}",
                extra={"api": self.api_name},
            )
            return None, SourceStatus.ERROR

        except Exception as exc:
            logger.error(
                f"Error inesperado en cliente de reputación: {type(exc).__name__}",
                extra={"api": self.api_name},
            )
            return None, SourceStatus.ERROR

    async def check_url(self, url: str) -> ReputationResult:
        """Método abstracto que debe implementar cada cliente específico.

        Args:
            url: URL normalizada a evaluar.

        Returns:
            ReputationResult con el modelo Reputation y la respuesta JSON cruda.
        """
        raise NotImplementedError("check_url debe ser implementado por la subclase.")
