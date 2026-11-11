"""Controlador de rutas para el análisis de URLs y SMS (v1)."""

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api.schemas.analysis import AnalysisRequest, AnalysisResponse
from app.services.analysis_service import AnalysisService

router = APIRouter(prefix="/analysis", tags=["analysis"])


def get_analysis_service(request: Request) -> AnalysisService:
    """Resuelve la instancia de AnalysisService desde el Composition Root en app.state."""
    container = getattr(request.app.state, "container", None)
    if container is not None and hasattr(container, "analysis_service"):
        return container.analysis_service

    analysis_service = getattr(request.app.state, "analysis_service", None)
    if analysis_service is not None:
        return analysis_service

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Servicio de análisis no disponible en la aplicación",
    )


@router.post(
    "",
    response_model=AnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Análisis de SMS o URL sospechosa",
    description=(
        "Analiza el contenido de un SMS o enlace URL evaluando heurísticas locales (sintácticas y de texto) "
        "y consultando en paralelo las fuentes externas de inteligencia (Google Web Risk, VirusTotal, PhishTank). "
        "Devuelve la puntuación consolidada de riesgo (0-100), el semáforo y recomendaciones (RF-01, RF-02, RF-03)."
    ),
)
async def analyze_content(
    payload: AnalysisRequest,
    analysis_service: AnalysisService = Depends(get_analysis_service),
) -> AnalysisResponse:
    """Ejecuta el análisis combinado de amenazas y devuelve el diagnóstico."""
    result = await analysis_service.analyze(
        tipo_entrada=payload.tipo_entrada,
        contenido=payload.contenido,
    )
    return AnalysisResponse(**result)

