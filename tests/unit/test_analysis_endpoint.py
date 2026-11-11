"""Pruebas unitarias para el endpoint y servicio de análisis (RF-01, RF-02, RF-03)."""

import pytest
from unittest.mock import AsyncMock
from pydantic import ValidationError

from app.api.schemas.analysis import AnalysisRequest
from app.clients.base import ReputationResult
from app.engine.models import Reputation, SourceStatus
from app.services.analysis_service import AnalysisService


def test_analysis_request_length_validation() -> None:
    """RF-01.1 & RF-01.2: Verifica los límites de longitud estrictos para SMS y URL."""
    # SMS válido dentro del límite de 1,600
    valid_sms = AnalysisRequest(tipo_entrada="sms", contenido="Mensaje de prueba seguro")
    assert valid_sms.contenido == "Mensaje de prueba seguro"

    # SMS que excede 1,600 caracteres debe fallar
    with pytest.raises(ValidationError):
        AnalysisRequest(tipo_entrada="sms", contenido="a" * 1601)

    # URL válida dentro del límite de 2,048
    valid_url = AnalysisRequest(tipo_entrada="url", contenido="https://seguro.com/login")
    assert valid_url.contenido == "https://seguro.com/login"

    # URL que excede 2,048 caracteres debe fallar
    with pytest.raises(ValidationError):
        AnalysisRequest(tipo_entrada="url", contenido="https://seguro.com/" + "a" * 2035)


@pytest.mark.asyncio
async def test_analysis_service_orchestration() -> None:
    """RF-02 & RF-03: Verifica la orquestación del análisis combinando heurísticas y APIs."""
    # Mock de los clientes de reputación
    mock_gwr = AsyncMock()
    mock_gwr.check_url.return_value = ReputationResult(
        reputation=Reputation(
            api="google_web_risk",
            estado=SourceStatus.OK,
            positivo=True,
            detecciones=1,
        )
    )

    mock_vt = AsyncMock()
    mock_vt.check_url.return_value = ReputationResult(
        reputation=Reputation(
            api="virustotal",
            estado=SourceStatus.OK,
            positivo=True,
            detecciones=4,
        )
    )

    mock_pt = AsyncMock()
    mock_pt.check_url.return_value = ReputationResult(
        reputation=Reputation(
            api="phishtank",
            estado=SourceStatus.OK,
            positivo=False,
            detecciones=None,
        )
    )

    service = AnalysisService(
        web_risk_client=mock_gwr,
        virustotal_client=mock_vt,
        phishtank_client=mock_pt,
    )

    sms_text = "URGENTE: BBVA cuenta suspendida. Ingresa tu NIP en https://bbva-alerta.seguro.xyz/login"
    result = await service.analyze(tipo_entrada="sms", contenido=sms_text)

    # Verificaciones del flujo
    assert result["tipo_entrada"] == "sms"
    assert result["mensaje_hash"] is not None
    assert len(result["urls_extraidas"]) >= 1
    # Lista negra activada por Google Web Risk -> Cortocircuito piso 95-100 (Crítico)
    assert result["score_total"] >= 95
    assert result["nivel_riesgo"] == "critico"
    assert result["motivo_cortocircuito"] == "lista_negra"
    assert len(result["hallazgos"]) > 0
    assert len(result["recomendaciones"]) > 0

    # Verificar que se consultaron las 3 APIs
    mock_gwr.check_url.assert_awaited_once()
    mock_vt.check_url.assert_awaited_once()
    mock_pt.check_url.assert_awaited_once()

