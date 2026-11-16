"""Pruebas unitarias para clientes de inteligencia de amenazas (RF-02.2)."""

import httpx
import pytest

from app.clients.base import BaseReputationClient
from app.clients.google_web_risk import GoogleWebRiskClient
from app.clients.phishtank import PhishTankClient
from app.clients.virustotal import VirusTotalClient
from app.engine.models import SourceStatus


@pytest.mark.asyncio
async def test_base_client_timeout_handling() -> None:
    """Verifica que los timeouts se traduzcan al estado SourceStatus.TIMEOUT."""

    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Timeout simulado", request=request)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as mock_client:
        client = BaseReputationClient(
            api_name="test_api",
            timeout=1.5,
            client=mock_client,
        )
        _, estado = await client._execute_request(
            method="GET",
            url="https://test.local/check",
        )
        assert estado == SourceStatus.TIMEOUT


@pytest.mark.asyncio
async def test_base_client_rate_limit_handling() -> None:
    """Verifica que el error HTTP 429 se traduzca al estado SourceStatus.RATE_LIMIT."""

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": "Rate limit exceeded"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as mock_client:
        client = BaseReputationClient(
            api_name="test_api",
            timeout=1.5,
            client=mock_client,
        )
        _, estado = await client._execute_request(
            method="GET",
            url="https://test.local/check",
        )
        assert estado == SourceStatus.RATE_LIMIT


@pytest.mark.asyncio
async def test_google_web_risk_threat_detected() -> None:
    """Verifica la detección positiva de amenazas en Google Web Risk."""
    mock_payload = {
        "threat": {
            "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE"],
            "expireTime": "2026-11-11T12:00:00Z",
        }
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("X-Goog-Api-Key") == "fake_key"
        assert "uri=https%3A%2F%2Fmalicioso.xyz" in str(request.url)
        return httpx.Response(200, json=mock_payload)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as mock_client:
        client = GoogleWebRiskClient(
            api_key="fake_key",
            timeout=1.5,
            client=mock_client,
        )
        result = await client.check_url("https://malicioso.xyz")
        assert result.reputation.estado == SourceStatus.OK
        assert result.reputation.positivo is True
        assert result.reputation.detecciones == 2
        assert result.reputation.api == "google_web_risk"


@pytest.mark.asyncio
async def test_google_web_risk_clean_url() -> None:
    """Verifica el procesamiento de URL limpia (sin amenazas) en Google Web Risk."""

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as mock_client:
        client = GoogleWebRiskClient(
            api_key="fake_key",
            timeout=1.5,
            client=mock_client,
        )
        result = await client.check_url("https://limpio.com")
        assert result.reputation.estado == SourceStatus.OK
        assert result.reputation.positivo is False
        assert result.reputation.detecciones is None


@pytest.mark.asyncio
async def test_virustotal_404_handled_as_clean() -> None:
    """Verifica que el status 404 en VirusTotal se procese como ok sin detecciones."""

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("x-apikey") == "fake_vt_key"
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as mock_client:
        client = VirusTotalClient(
            api_key="fake_vt_key",
            timeout=1.5,
            client=mock_client,
        )
        result = await client.check_url("https://nueva-url-nunca-escaneada.xyz")
        assert result.reputation.estado == SourceStatus.OK
        assert result.reputation.positivo is False
        assert result.reputation.detecciones == 0
        assert result.reputation.api == "virustotal"


@pytest.mark.asyncio
async def test_virustotal_positive_detections() -> None:
    """Verifica la extracción de detecciones maliciosas en VirusTotal."""
    mock_payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 4,
                    "suspicious": 1,
                    "undetected": 50,
                    "harmless": 20,
                }
            }
        }
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=mock_payload)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as mock_client:
        client = VirusTotalClient(
            api_key="fake_vt_key",
            timeout=1.5,
            client=mock_client,
        )
        result = await client.check_url("https://malicioso-reportado.com")
        assert result.reputation.estado == SourceStatus.OK
        assert result.reputation.positivo is True
        assert result.reputation.detecciones == 5


@pytest.mark.asyncio
async def test_phishtank_user_agent_and_detection() -> None:
    """Verifica el User-Agent obligatorio y la detección positiva en PhishTank."""
    mock_payload = {
        "results": {
            "url": "https://fake-phish.xyz",
            "in_database": True,
            "phish_id": 9999,
            "valid": True,
            "verified": True,
        }
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        user_agent = request.headers.get("User-Agent", "")
        assert "AntFish/1.0" in user_agent
        return httpx.Response(200, json=mock_payload)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as mock_client:
        client = PhishTankClient(
            api_key="fake_pt_key",
            timeout=1.5,
            client=mock_client,
        )
        result = await client.check_url("https://fake-phish.xyz")
        assert result.reputation.estado == SourceStatus.OK
        assert result.reputation.positivo is True
        assert result.reputation.detecciones == 1
        assert result.reputation.api == "phishtank"


@pytest.mark.asyncio
async def test_phishtank_non_json_degrades_to_error_and_logs_only_metadata(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Diagnóstico: respuesta no JSON -> estado error; el log no incluye cuerpo ni URL."""
    import logging

    from app.core.logging import logger as app_logger

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, text="<html>SECRETO-DEL-CUERPO</html>", headers={"content-type": "text/html"}
        )

    app_logger.propagate = True
    try:
        with caplog.at_level(logging.WARNING, logger="antfish"):
            client = PhishTankClient(
                client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
            )
            result = await client.check_url("https://evil.example/login")
    finally:
        app_logger.propagate = False

    assert result.reputation.estado == SourceStatus.ERROR
    assert "content_type=text/html" in caplog.text
    assert "SECRETO-DEL-CUERPO" not in caplog.text
    assert "evil.example" not in caplog.text
