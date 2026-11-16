"""Controlador de rutas para el análisis de URLs y SMS (v1)."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.api.deps import get_current_user, rate_limit_analysis
from app.api.schemas.analysis import (
    AnalysisRequest,
    AnalysisResponse,
    HistoryPageResponse,
)
from app.core.exceptions import AnalysisNotFoundError, InvalidCursorError
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
        "y consultando en paralelo las fuentes externas de inteligencia (Google Web Risk, VirusTotal). "
        "Devuelve la puntuación consolidada de riesgo (0-100), el semáforo y recomendaciones (RF-01, RF-02, RF-03)."
    ),
)
async def analyze_content(
    payload: AnalysisRequest,
    user: dict[str, Any] = Depends(rate_limit_analysis),
    analysis_service: AnalysisService = Depends(get_analysis_service),
) -> AnalysisResponse:
    """Ejecuta el análisis combinado de amenazas y devuelve el diagnóstico."""
    result = await analysis_service.analyze(
        tipo_entrada=payload.tipo_entrada,
        contenido=payload.contenido,
        user_id=str(user["_id"]),
    )
    return AnalysisResponse(**result)


@router.get(
    "",
    response_model=HistoryPageResponse,
    summary="Historial de análisis del usuario",
    description="Historial paginado por cursor opaco (fecha, _id), 20 por página (RF-05.1, D8).",
)
async def list_history(
    cursor: str | None = None,
    user: dict[str, Any] = Depends(get_current_user),
    analysis_service: AnalysisService = Depends(get_analysis_service),
) -> HistoryPageResponse:
    """Devuelve una página del historial del usuario autenticado."""
    try:
        items, next_cursor = await analysis_service.list_history(str(user["_id"]), cursor)
    except InvalidCursorError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.message) from exc
    return HistoryPageResponse(
        items=[AnalysisResponse(**i) for i in items], next_cursor=next_cursor
    )


@router.get(
    "/{analysis_id}",
    response_model=AnalysisResponse,
    summary="Detalle de un análisis",
)
async def get_analysis(
    analysis_id: str,
    user: dict[str, Any] = Depends(get_current_user),
    analysis_service: AnalysisService = Depends(get_analysis_service),
) -> AnalysisResponse:
    """Detalle de un análisis propio; 404 si no existe o es de otro usuario."""
    try:
        result = await analysis_service.get_detail(str(user["_id"]), analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return AnalysisResponse(**result)


@router.delete(
    "/{analysis_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminar un análisis",
    description="Elimina el análisis y sus respuestas crudas sin alterar las métricas (O11).",
)
async def delete_analysis(
    analysis_id: str,
    user: dict[str, Any] = Depends(get_current_user),
    analysis_service: AnalysisService = Depends(get_analysis_service),
) -> Response:
    """Borra un análisis propio en transacción ACID."""
    try:
        await analysis_service.delete_analysis(str(user["_id"]), analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
