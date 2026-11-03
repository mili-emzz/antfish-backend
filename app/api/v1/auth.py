"""Controlador de rutas de autenticación y gestión de cuentas (v1)."""

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api.schemas.auth import UserRegisterRequest, UserRegisterResponse
from app.core.exceptions import DuplicateEmailError
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


def get_auth_service(request: Request) -> AuthService:
    """Resuelve la instancia de AuthService desde el Composition Root en app.state."""
    container = getattr(request.app.state, "container", None)
    if container is not None and hasattr(container, "auth_service"):
        return container.auth_service

    auth_service = getattr(request.app.state, "auth_service", None)
    if auth_service is not None:
        return auth_service

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Servicio de autenticación no disponible en la aplicación",
    )


@router.post(
    "/register",
    response_model=UserRegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registro local de usuarios",
    description=(
        "Registra un nuevo usuario con proveedor local ('local'), hashea la contraseña con Argon2id "
        "y establece el estado inicial en 'pendiente_verificacion' (RF-06.1, D14)."
    ),
)
async def register(
    payload: UserRegisterRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> UserRegisterResponse:
    """Endpoint POST /api/v1/auth/register para registrar usuarios locales."""
    try:
        user = await auth_service.register_user(
            email=payload.email,
            password=payload.password,
            nombre=payload.nombre,
        )
        return UserRegisterResponse(
            id=str(user["_id"]),
            email=user["email"],
            nombre=user["nombre"],
            estado_cuenta=user["estado_cuenta"],
            email_verificado=user["email_verificado"],
            mensaje="Usuario registrado exitosamente. Se ha generado la cuenta en estado pendiente de verificación.",
        )
    except DuplicateEmailError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=exc.message if hasattr(exc, "message") else str(exc),
        ) from exc

