"""Endpoint del panel de estadísticas del usuario (RF-05.2, O8)."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api.deps import get_current_user
from app.api.schemas.metrics import MetricsResponse
from app.services.metrics_service import MetricsService

router = APIRouter(prefix="/metrics", tags=["metrics"])


def get_metrics_service(request: Request) -> MetricsService:
    """Resuelve MetricsService desde el Composition Root."""
    container = getattr(request.app.state, "container", None)
    if container is not None and hasattr(container, "metrics_service"):
        return container.metrics_service  # type: ignore[no-any-return]
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Servicio de métricas no disponible en la aplicación",
    )


@router.get(
    "/me",
    response_model=MetricsResponse,
    summary="Estadísticas del usuario autenticado",
)
async def get_my_metrics(
    user: dict[str, Any] = Depends(get_current_user),
    metrics_service: MetricsService = Depends(get_metrics_service),
) -> MetricsResponse:
    """Total de escaneos, desglose SMS/URL y amenazas bloqueadas (RF-05.2)."""
    data = await metrics_service.get_user_metrics(str(user["_id"]))
    return MetricsResponse(**data)
