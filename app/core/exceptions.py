"""Jerarquía unificada de excepciones de dominio de AntFish."""


class AntFishError(Exception):
    """Excepción base para todos los errores de dominio de AntFish."""

    def __init__(self, message: str = "Error en el sistema AntFish") -> None:
        super().__init__(message)
        self.message = message


class DuplicateEmailError(AntFishError):
    """Lanzada cuando un correo ya está registrado con cuenta activa o suspendida (HTTP 409)."""

    def __init__(self, message: str = "El correo electrónico ya se encuentra registrado") -> None:
        super().__init__(message)


class UnauthorizedError(AntFishError):
    """Credenciales inválidas o no autorizadas (HTTP 401)."""

    def __init__(self, message: str = "Credenciales inválidas") -> None:
        super().__init__(message)


class AccountNotVerifiedError(AntFishError):
    """Cuenta en estado pendiente de verificación (HTTP 403)."""

    def __init__(self, message: str = "Cuenta pendiente de verificación") -> None:
        super().__init__(message)


class DomainNotFoundError(AntFishError):
    """Dominio o URL no encontrado."""

    def __init__(self, message: str = "Dominio no encontrado") -> None:
        super().__init__(message)


class QuotaExceededError(AntFishError):
    """Límite de cuota de APIs de reputación excedido."""

    def __init__(self, message: str = "Cuota externa excedida") -> None:
        super().__init__(message)


class RateLimitExceededError(AntFishError):
    """Límite de tasa de peticiones excedido (HTTP 429)."""

    def __init__(self, message: str = "Límite de peticiones excedido") -> None:
        super().__init__(message)


class InvalidVerificationCodeError(AntFishError):
    """Código de verificación de 6 dígitos inválido o expirado."""

    def __init__(self, message: str = "Código de verificación inválido") -> None:
        super().__init__(message)


class VerificationAttemptsExceededError(AntFishError):
    """Intentos de verificación excedidos (máximo 5)."""

    def __init__(self, message: str = "Máximo de intentos excedido") -> None:
        super().__init__(message)


class EmailDeliveryError(AntFishError):
    """Fallo en el servicio de despacho de correos vía Resend."""

    def __init__(self, message: str = "Error al enviar el correo") -> None:
        super().__init__(message)


class GoogleTokenInvalidError(AntFishError):
    """Token de identidad de Google inválido o no certificado."""

    def __init__(self, message: str = "Token de Google inválido") -> None:
        super().__init__(message)

