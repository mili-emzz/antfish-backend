"""Pruebas unitarias para ResendEmailClient y VerificationService (RF-06.2, RNF-06)."""

from unittest.mock import AsyncMock, patch
import httpx
import pytest

from app.clients.resend_email import ResendEmailClient
from app.core.exceptions import EmailDeliveryError
from app.services.verification_service import VerificationService


@pytest.mark.asyncio
async def test_resend_email_client_success():
    """Verifica que el cliente envíe el correo correctamente ante una respuesta 200 de Resend."""
    mock_response = httpx.Response(
        status_code=200,
        json={"id": "email_12345"},
        request=httpx.Request("POST", "https://api.resend.com/emails"),
    )

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.post.return_value = mock_response

    client = ResendEmailClient(
        api_key="re_test_key",
        email_from="AntFish <test@antfish.dev>",
        client=mock_client,
    )

    result = await client.send_verification_code("user@example.com", "123456")

    assert result == {"id": "email_12345"}
    mock_client.post.assert_awaited_once()
    call_kwargs = mock_client.post.call_args.kwargs
    assert call_kwargs["json"]["to"] == ["user@example.com"]
    assert "123456" in call_kwargs["json"]["html"]
    assert "123456" in call_kwargs["json"]["text"]


@pytest.mark.asyncio
async def test_resend_email_client_network_error():
    """Verifica que un fallo de red (httpx.RequestError) se traduzca a EmailDeliveryError."""
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.post.side_effect = httpx.ConnectError("Connection refused")

    client = ResendEmailClient(
        api_key="re_test_key",
        email_from="AntFish <test@antfish.dev>",
        client=mock_client,
    )

    with pytest.raises(EmailDeliveryError) as exc_info:
        await client.send_verification_code("user@example.com", "123456")

    assert "Fallo de red" in str(exc_info.value)


@pytest.mark.asyncio
async def test_resend_email_client_timeout_error():
    """Verifica que un timeout se traduzca a EmailDeliveryError."""
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.post.side_effect = httpx.ReadTimeout("Read timed out")

    client = ResendEmailClient(
        api_key="re_test_key",
        email_from="AntFish <test@antfish.dev>",
        client=mock_client,
    )

    with pytest.raises(EmailDeliveryError) as exc_info:
        await client.send_verification_code("user@example.com", "123456")

    assert "Fallo de red" in str(exc_info.value)


@pytest.mark.asyncio
async def test_resend_email_client_http_error_status():
    """Verifica que respuestas 4xx o 5xx de la API de Resend lancen EmailDeliveryError."""
    mock_response = httpx.Response(
        status_code=429,
        text="Rate limit exceeded",
        request=httpx.Request("POST", "https://api.resend.com/emails"),
    )

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.post.return_value = mock_response

    client = ResendEmailClient(
        api_key="re_test_key",
        email_from="AntFish <test@antfish.dev>",
        client=mock_client,
    )

    with pytest.raises(EmailDeliveryError) as exc_info:
        await client.send_verification_code("user@example.com", "123456")

    assert "Fallo en la entrega de correo por Resend (HTTP 429)" in str(exc_info.value)


@pytest.mark.asyncio
async def test_verification_service_injects_and_calls_email_client():
    """Verifica que VerificationService use el email_client inyectado al generar y guardar código."""
    mock_repo = AsyncMock()
    mock_email_client = AsyncMock(spec=ResendEmailClient)

    service = VerificationService(
        verification_repo=mock_repo,
        email_client=mock_email_client,
    )

    code = await service.generate_and_save_code(
        user_id="user_abc123",
        email="test@correo.com",
    )

    assert len(code) == 6
    assert code.isdigit()
    mock_repo.save_code.assert_awaited_once()
    mock_email_client.send_verification_code.assert_awaited_once_with(
        "test@correo.com",
        code,
    )


@pytest.mark.asyncio
async def test_verification_service_propagates_email_delivery_error():
    """Verifica que fallos de red en el cliente se propaguen como EmailDeliveryError en el servicio."""
    mock_repo = AsyncMock()
    mock_email_client = AsyncMock(spec=ResendEmailClient)
    mock_email_client.send_verification_code.side_effect = EmailDeliveryError(
        "Fallo de red al enviar el correo"
    )

    service = VerificationService(
        verification_repo=mock_repo,
        email_client=mock_email_client,
    )

    with pytest.raises(EmailDeliveryError):
        await service.generate_and_save_code(
            user_id="user_abc123",
            email="test@correo.com",
        )

