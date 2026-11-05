"""Cliente HTTP asíncrono para el servicio transaccional de correos Resend (RF-06.2, RNF-06)."""

from typing import Any
import httpx

from app.core.config import settings
from app.core.exceptions import EmailDeliveryError
from app.core.logging import logger


class ResendEmailClient:
    """Cliente para envío transaccional de correos electrónicos mediante la API REST de Resend."""

    BASE_URL: str = "https://api.resend.com/emails"

    def __init__(
        self,
        api_key: str | None = None,
        email_from: str | None = None,
        timeout: float = 10.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_key = api_key or getattr(settings, "RESEND_API_KEY", "")
        self.email_from = email_from or getattr(
            settings, "EMAIL_FROM", "AntFish <onboarding@resend.dev>"
        )
        self.timeout = timeout
        self._client = client

    async def send_email(
        self,
        to_email: str,
        subject: str,
        html: str,
        text: str | None = None,
    ) -> dict[str, Any]:
        """Envía un correo transaccional vía Resend API.

        Maneja fallos de red y respuestas de error traduciéndolos a EmailDeliveryError (RNF-06).
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "from": self.email_from,
            "to": [to_email],
            "subject": subject,
            "html": html,
        }
        if text:
            payload["text"] = text

        try:
            if self._client is not None:
                response = await self._client.post(
                    self.BASE_URL,
                    json=payload,
                    headers=headers,
                )
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(
                        self.BASE_URL,
                        json=payload,
                        headers=headers,
                    )

            if response.status_code >= 400:
                logger.error(
                    f"Resend API retornó error HTTP {response.status_code} al enviar correo"
                )
                raise EmailDeliveryError(
                    f"Fallo en la entrega de correo por Resend (HTTP {response.status_code}): {response.text}"
                )

            data: dict[str, Any] = response.json()
            return data

        except (httpx.RequestError, httpx.TimeoutException) as exc:
            logger.error(f"Fallo de red al conectar con Resend: {type(exc).__name__}")
            raise EmailDeliveryError(f"Fallo de red al enviar el correo: {exc}") from exc
        except EmailDeliveryError:
            raise
        except Exception as exc:
            logger.error(f"Error inesperado en servicio de correo: {type(exc).__name__}")
            raise EmailDeliveryError(f"Error inesperado al enviar correo: {exc}") from exc

    async def send_verification_code(
        self,
        to_email: str,
        code: str,
    ) -> dict[str, Any]:
        """Envía el código de verificación de 6 dígitos al correo del usuario (RF-06.2)."""
        subject = "Código de verificación - AntFish"
        html = (
            "<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; "
            "padding: 24px; border: 1px solid #e5e7eb; border-radius: 8px; background-color: #ffffff;'>"
            "<h2 style='color: #1e3a8a; margin-top: 0;'>AntFish Security</h2>"
            "<p style='color: #374151; font-size: 16px;'>Tu código de verificación de 6 dígitos es:</p>"
            "<div style='text-align: center; margin: 28px 0;'>"
            f"<span style='font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #1e3a8a; "
            f"background-color: #eff6ff; padding: 12px 24px; border-radius: 6px; border: 1px solid #bfdbfe; "
            f"display: inline-block;'>{code}</span>"
            "</div>"
            "<p style='color: #6b7280; font-size: 14px; margin-bottom: 0;'>"
            "Este código tiene una vigencia estricta de 10 minutos y un límite de 5 intentos. "
            "Si no solicitaste este código, puedes ignorar este mensaje de forma segura."
            "</p>"
            "</div>"
        )
        text = f"Tu código de verificación de AntFish es: {code}. Vigencia: 10 minutos."
        return await self.send_email(
            to_email=to_email,
            subject=subject,
            html=html,
            text=text,
        )

