"""Healthcheck global (§9.6): verifica la conectividad activa de MongoDB y Redis."""

from fastapi import APIRouter, Request, Response

from app.api.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Estado de la instancia",
    description=(
        "200 `ok`: Mongo y Redis responden. 200 `degradado`: Redis caído (el análisis sigue "
        "funcionando en fail-open; login y registro no). 503 `no_disponible`: Mongo caído. "
        "No expone detalles de errores internos."
    ),
    responses={503: {"model": HealthResponse}},
)
async def health(request: Request, response: Response) -> HealthResponse:
    container = getattr(request.app.state, "container", None)
    service = getattr(container, "health_service", None)
    response.headers["Cache-Control"] = "no-store"
    if service is None:
        response.status_code = 503
        return HealthResponse(status="no_disponible")
    report = await service.check()
    response.status_code = report.http_status
    return HealthResponse(status=report.status)
