"""Controlador de rutas de autenticación y gestión de cuentas (v1)."""

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api.schemas.auth import (
    LoginRequest,
    LoginResponse,
    UserRegisterRequest,
    UserRegisterResponse,
    VerifyEmailRequest,
)
from app.core.exceptions import (
    AccountNotVerifiedError,
    DuplicateEmailError,
    EmailDeliveryError,
    UnauthorizedError,
)
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
    except EmailDeliveryError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Error al enviar el correo de verificación. Intenta nuevamente mediante el reenvío de código.",
        ) from exc


@router.post(
    "/verify-email",
    status_code=status.HTTP_200_OK,
    summary="Verifica el correo del usuario (RF-06.2)",
)
async def verify_email(
    payload: VerifyEmailRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    """Endpoint POST /api/v1/auth/verify-email para verificar el código de 6 dígitos."""
    try:
        result = await auth_service.verify_email(
            email=payload.email, codigo=payload.codigo
        )
        return result
    except ValueError as exc:
        # Devuelve 400 uniformemente si algo falla, previniendo enumeración
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        )


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Inicio de sesión local de usuario (RF-06.8)",
    description=(
        "Valida credenciales con Argon2id antes de verificar el estado. "
        "Devuelve Access Token (30 min) y Refresh Token (30 días). "
        "Si la cuenta sigue en 'pendiente_verificacion', devuelve HTTP 403 Forbidden."
    ),
)
async def login(
    payload: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> LoginResponse:
    """Endpoint POST /api/v1/auth/login para inicio de sesión."""
    try:
        tokens = await auth_service.authenticate_user(
            email=payload.email,
            password=payload.password,
        )
        return LoginResponse(**tokens)
    except UnauthorizedError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=exc.message if hasattr(exc, "message") else "Credenciales inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except AccountNotVerifiedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=exc.message if hasattr(exc, "message") else "ACCOUNT_NOT_VERIFIED",
        ) from exc
