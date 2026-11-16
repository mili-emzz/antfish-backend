"""DTOs y esquemas Pydantic para los flujos de autenticación y cuenta."""

from typing import Any, Self

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator


class UserRegisterRequest(BaseModel):
    """DTO de entrada para el registro local de usuarios (RF-06.1, D5)."""

    email: EmailStr = Field(
        ...,
        description="Correo electrónico del usuario, normalizado a minúsculas y sin espacios",
        examples=["usuario@correo.com"],
    )
    password: str = Field(
        ...,
        min_length=8,
        description="Contraseña en texto plano para el usuario (mínimo 8 caracteres)",
        examples=["PasswordSeguro123!"],
    )
    nombre: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Nombre completo del usuario",
        examples=["Carlos Ramírez"],
    )

    model_config = ConfigDict(str_strip_whitespace=True)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: Any) -> Any:
        """Normaliza el correo electrónico a minúsculas y sin espacios (D5, ADR #55)."""
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @field_validator("nombre", mode="before")
    @classmethod
    def strip_nombre(cls, value: Any) -> Any:
        """Elimina espacios en blanco sobrantes del nombre."""
        if isinstance(value, str):
            return value.strip()
        return value


class UserRegisterResponse(BaseModel):
    """DTO de salida tras el registro exitoso o sobrescritura de cuenta pendiente."""

    id: str = Field(..., description="Identificador único del usuario registrado en MongoDB")
    email: str = Field(..., description="Correo electrónico registrado")
    nombre: str = Field(..., description="Nombre del usuario registrado")
    estado_cuenta: str = Field(
        default="pendiente_verificacion",
        description="Estado de la cuenta ('pendiente_verificacion')",
    )
    email_verificado: bool = Field(
        default=False,
        description="Indicador de verificación del correo (falso al registrar)",
    )
    mensaje: str = Field(
        default="Usuario registrado exitosamente. Se ha generado la cuenta en estado pendiente de verificación.",
        description="Mensaje descriptivo del resultado del registro",
    )

    model_config = ConfigDict(from_attributes=True)


class VerifyEmailRequest(BaseModel):
    """DTO de entrada para verificación de código de correo (RF-06.2)."""

    email: EmailStr = Field(..., description="Correo electrónico del usuario")
    codigo: str = Field(..., min_length=6, max_length=6, description="Código numérico de 6 dígitos")

    model_config = ConfigDict(str_strip_whitespace=True)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip().lower()
        return value


class LoginRequest(BaseModel):
    """DTO de entrada para inicio de sesión local (RF-06.8)."""

    email: EmailStr = Field(
        ...,
        description="Correo electrónico del usuario",
        examples=["usuario@correo.com"],
    )
    password: str = Field(
        ...,
        description="Contraseña en texto plano del usuario",
        examples=["PasswordSeguro123!"],
    )

    model_config = ConfigDict(str_strip_whitespace=True)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: Any) -> Any:
        """Normaliza el correo electrónico a minúsculas y sin espacios (D5)."""
        if isinstance(value, str):
            return value.strip().lower()
        return value


class UserInfo(BaseModel):
    """Datos básicos de sesión; `proveedor_auth` indica con qué reautenticar (local/google)."""

    email: str
    nombre: str | None = None
    proveedor_auth: str


class LoginResponse(BaseModel):
    """DTO de salida con tokens JWT tras login exitoso (RF-06.8)."""

    access_token: str = Field(
        ...,
        description="JWT Access Token para llamadas autenticadas (vigencia 30 min)",
    )
    refresh_token: str = Field(
        ...,
        description="JWT Refresh Token para renovación de sesión (vigencia 30 días)",
    )
    token_type: str = Field(
        default="bearer",
        description="Tipo de token para el encabezado Authorization",
    )
    user: UserInfo = Field(..., description="Datos básicos del usuario autenticado")

    model_config = ConfigDict(from_attributes=True)


class _EmailOnlyRequest(BaseModel):
    email: EmailStr = Field(..., description="Correo electrónico del usuario")

    model_config = ConfigDict(str_strip_whitespace=True)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip().lower()
        return value


class ResendCodeRequest(_EmailOnlyRequest):
    """DTO de entrada para reenvío de código de verificación (RF-06.3)."""


class ForgotPasswordRequest(_EmailOnlyRequest):
    """DTO de entrada para solicitar recuperación de contraseña (RF-06.6)."""


class ResetPasswordRequest(_EmailOnlyRequest):
    """DTO de entrada para restablecer la contraseña con código (RF-06.6, D17)."""

    codigo: str = Field(..., min_length=6, max_length=6, description="Código numérico de 6 dígitos")
    nueva_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Nueva contraseña en texto plano (8 a 128 caracteres)",
    )


class GoogleLoginRequest(BaseModel):
    """DTO de entrada para login con Google (RF-06.4): el ID token del SDK de Google Sign-In."""

    id_token: str = Field(..., min_length=1, max_length=4096, description="Google ID Token (JWT)")


class DeleteAccountRequest(BaseModel):
    """DTO de reautenticación para la baja de cuenta (RF-06.7, RN-21).

    Cuentas con contraseña: `password`. Cuentas solo Google: `id_token` del mismo `google_sub`.
    """

    password: str | None = Field(
        default=None, min_length=1, max_length=128, description="Contraseña actual"
    )
    id_token: str | None = Field(
        default=None, min_length=1, max_length=4096, description="Google ID Token (cuentas Google)"
    )

    @model_validator(mode="after")
    def require_a_credential(self) -> Self:
        if self.password is None and self.id_token is None:
            raise ValueError("Se requiere password o id_token")
        return self


class RefreshRequest(BaseModel):
    """DTO de entrada para renovar el Access Token (RF-06)."""

    refresh_token: str = Field(..., min_length=1, description="JWT Refresh Token vigente")


class RefreshResponse(BaseModel):
    """DTO de salida con el nuevo Access Token."""

    access_token: str
    token_type: str = "bearer"


class MessageResponse(BaseModel):
    """Respuesta uniforme con un mensaje."""

    mensaje: str


# Alias de compatibilidad
RegisterRequest = UserRegisterRequest
RegisterResponse = UserRegisterResponse
UserLoginRequest = LoginRequest
UserLoginResponse = LoginResponse
TokenResponse = LoginResponse
