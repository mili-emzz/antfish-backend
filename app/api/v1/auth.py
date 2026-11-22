"""Controlador de rutas de autenticación y gestión de cuentas (v1)."""

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status

from app.api.deps import get_current_user, rate_limit_auth
from app.api.errors import api_error
from app.api.schemas.auth import (
    DeleteAccountRequest,
    ForgotPasswordRequest,
    GoogleLoginRequest,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    MessageResponse,
    RefreshRequest,
    RefreshResponse,
    ResendCodeRequest,
    ResetPasswordRequest,
    UserRegisterRequest,
    UserRegisterResponse,
    VerifyEmailRequest,
)
from app.core.exceptions import (
    AccountConflictError,
    AccountNotVerifiedError,
    DuplicateEmailError,
    EmailDeliveryError,
    GoogleEmailNotVerifiedError,
    GoogleTokenInvalidError,
    IdentityProviderUnavailableError,
    ReauthMethodUnavailableError,
    UnauthorizedError,
)
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])

_RESEND_MESSAGE = "Si la cuenta está pendiente de verificación, se envió un nuevo código."
_FORGOT_MESSAGE = (
    "Si el correo corresponde a una cuenta activa, recibirás un código de recuperación."
)


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
    dependencies=[Depends(rate_limit_auth("register"))],
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
        result = await auth_service.verify_email(email=payload.email, codigo=payload.codigo)
        return result
    except ValueError as exc:
        # Devuelve 400 uniformemente si algo falla, previniendo enumeración
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/resend-code",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_auth("resend-code"))],
    summary="Reenvía el código de verificación (RF-06.3)",
    description=(
        "Máx. 3 envíos/hora por usuario (compartido, D17; 429 al excederse). "
        "Responde igual exista o no una cuenta pendiente."
    ),
)
async def resend_code(
    payload: ResendCodeRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> MessageResponse:
    try:
        await auth_service.resend_code(payload.email)
    except EmailDeliveryError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Error al enviar el correo de verificación. Intenta nuevamente más tarde.",
        ) from exc
    return MessageResponse(mensaje=_RESEND_MESSAGE)


@router.post(
    "/password/forgot",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_auth("forgot"))],
    summary="Solicita código de recuperación de contraseña (RF-06.6)",
    description=(
        "Responde siempre 200 con mensaje uniforme (D16, RN-25). El código se genera y envía "
        "en segundo plano solo si la cuenta existe, está activa y tiene contraseña."
    ),
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    background_tasks: BackgroundTasks,
    auth_service: AuthService = Depends(get_auth_service),
) -> MessageResponse:
    background_tasks.add_task(auth_service.request_password_reset, payload.email)
    return MessageResponse(mensaje=_FORGOT_MESSAGE)


@router.post(
    "/password/reset",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_auth("reset"))],
    summary="Restablece la contraseña con código (RF-06.6, D17, D18)",
)
async def reset_password(
    payload: ResetPasswordRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> MessageResponse:
    try:
        result = await auth_service.reset_password(
            email=payload.email,
            codigo=payload.codigo,
            nueva_password=payload.nueva_password,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from None
    return MessageResponse(**result)


@router.post(
    "/refresh",
    response_model=RefreshResponse,
    status_code=status.HTTP_200_OK,
    summary="Renueva la sesión con rotación del refresh token (D18)",
    description=(
        "Emite un nuevo Access Token y un nuevo Refresh Token si el refresh es válido, vigente "
        "y no usado, la cuenta está activa e iat >= password_changed_at. El refresh anterior "
        "queda invalidado; reutilizarlo revoca la sesión completa (401)."
    ),
)
async def refresh(
    payload: RefreshRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> RefreshResponse:
    try:
        tokens = await auth_service.refresh_access_token(payload.refresh_token)
    except UnauthorizedError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    return RefreshResponse(**tokens)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(rate_limit_auth("logout"))],
    summary="Cierra la sesión revocando el refresh token",
    description=(
        "Revoca toda la familia de la sesión. Idempotente: responde 204 aunque el token sea "
        "inválido o ya esté revocado."
    ),
)
async def logout(
    payload: LogoutRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> Response:
    await auth_service.logout(payload.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/google",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_auth("google"))],
    summary="Login, alta o vinculación con Google (RF-06.4, RF-06.5)",
    description=(
        "Valida el ID token (firma, expiración, aud, emisor, email_verified) y devuelve "
        "Access y Refresh Tokens. Token inválido: 401; correo de Google no verificado o cuenta "
        "ya vinculada a otra identidad: 409; Google sin configurar o inalcanzable: 503."
    ),
)
async def login_google(
    payload: GoogleLoginRequest,
    auth_service: AuthService = Depends(get_auth_service),
) -> LoginResponse:
    try:
        tokens = await auth_service.login_with_google(payload.id_token)
    except GoogleTokenInvalidError as exc:
        raise api_error(
            status.HTTP_401_UNAUTHORIZED,
            "INVALID_TOKEN",
            "El token de Google no es válido o ha expirado",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except UnauthorizedError as exc:
        raise api_error(
            status.HTTP_401_UNAUTHORIZED,
            "ACCOUNT_NOT_AUTHORIZED",
            exc.message,
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except GoogleEmailNotVerifiedError as exc:
        raise api_error(status.HTTP_409_CONFLICT, "EMAIL_NOT_VERIFIED", exc.message) from exc
    except AccountConflictError as exc:
        raise api_error(status.HTTP_409_CONFLICT, "ACCOUNT_CONFLICT", exc.message) from exc
    except IdentityProviderUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=exc.message
        ) from exc
    return LoginResponse(**tokens)


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_auth("login"))],
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
        raise api_error(
            status.HTTP_401_UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            exc.message,
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except AccountNotVerifiedError as exc:
        raise api_error(status.HTTP_403_FORBIDDEN, "ACCOUNT_NOT_VERIFIED", exc.message) from exc


@router.delete(
    "/me",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(rate_limit_auth("delete-account"))],
    summary="Baja de cuenta con reautenticación (RF-06.7, O12)",
    description=(
        "Cuentas con contraseña: exige `password` en el body; cuentas solo Google: `id_token` "
        "del mismo google_sub. Anonimiza el usuario y purga "
        "análisis, respuestas de APIs y métricas en una transacción ACID. "
        "Credencial incorrecta: 403."
    ),
)
async def delete_me(
    payload: DeleteAccountRequest,
    user: dict[str, Any] = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> None:
    try:
        await auth_service.delete_account(user, payload.password, payload.id_token)
    except GoogleTokenInvalidError as exc:
        raise api_error(
            status.HTTP_403_FORBIDDEN,
            "INVALID_TOKEN",
            "El token de Google no es válido o ha expirado",
        ) from exc
    except UnauthorizedError as exc:
        # 403 y no 401: un 401 haría que la app intente renovar la sesión en vez de pedir la contraseña.
        raise api_error(status.HTTP_403_FORBIDDEN, "INVALID_CREDENTIALS", exc.message) from exc
    except IdentityProviderUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=exc.message
        ) from exc
    except ReauthMethodUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=exc.message
        ) from exc
