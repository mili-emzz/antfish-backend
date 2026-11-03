"""DTOs y esquemas Pydantic para los flujos de autenticación y cuenta."""

from typing import Any
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


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


# Alias de compatibilidad
RegisterRequest = UserRegisterRequest
RegisterResponse = UserRegisterResponse

