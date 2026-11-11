"""Servicio de autenticación y gestión de usuarios (RF-06)."""

from datetime import datetime, timezone
from typing import Any
from argon2 import PasswordHasher

from app.core.exceptions import (
    AccountNotVerifiedError,
    DuplicateEmailError,
    UnauthorizedError,
)
from app.core.security import (
    create_access_token,
    create_refresh_token,
    verify_password,
)
from app.repositories.mongo.user_repository import UserRepository
from app.services.verification_service import VerificationService

# Configuración estándar para Argon2id según RFC 9106
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
)


class AuthService:
    """Lógica de negocio para registro, autenticación y ciclo de vida de usuarios."""

    def __init__(
        self,
        user_repository: UserRepository,
        verification_service: VerificationService,
    ) -> None:
        self._user_repo = user_repository
        self.verification_service = verification_service

    def hash_password(self, password: str) -> str:
        """Genera un hash seguro Argon2id para la contraseña."""
        return _hasher.hash(password)

    async def register_user(
        self,
        email: str,
        password: str,
        nombre: str,
    ) -> dict[str, Any]:
        """Registra un nuevo usuario local o actualiza cuenta en pendiente_verificacion (RF-06.1, D14).

        - Normaliza correo a minúsculas y sin espacios (D5).
        - Hashea la contraseña con Argon2id.
        - Asigna estado inicial 'pendiente_verificacion' con email_verificado=False.
        - Si existe cuenta en 'pendiente_verificacion', sobrescribe datos y reinicia fecha_registro (D14).
        - Si existe cuenta activa o suspendida, responde con DuplicateEmailError (HTTP 409).
        - Genera código numérico de 6 dígitos y lo envía vía Resend (RF-06.2).
        """
        normalized_email = email.strip().lower()
        existing_user = await self._user_repo.find_by_email(normalized_email)

        password_hash = self.hash_password(password)

        if existing_user:
            estado = existing_user.get("estado_cuenta")
            if estado == "pendiente_verificacion":
                # Sobrescribe nombre y contraseña, reinicia fecha_registro (D14, RN-23)
                updated_user = await self._user_repo.update_pending_user(
                    user_id=existing_user["_id"],
                    nombre=nombre.strip(),
                    password_hash=password_hash,
                )
                if updated_user is None:
                    existing_user["nombre"] = nombre.strip()
                    existing_user["password_hash"] = password_hash
                    existing_user["fecha_registro"] = datetime.now(timezone.utc)

                    # Generar código en Redis y despachar por correo vía Resend
                    await self.verification_service.generate_and_save_code(
                        str(existing_user["_id"]),
                        email=normalized_email,
                    )
                    return existing_user

                # Generar código en Redis y despachar por correo vía Resend
                await self.verification_service.generate_and_save_code(
                    str(existing_user["_id"]),
                    email=normalized_email,
                )
                return updated_user

            # Si la cuenta ya está activa, suspendida o eliminada, genera conflicto (409)
            raise DuplicateEmailError("El correo electrónico ya se encuentra registrado")

        now = datetime.now(timezone.utc)
        user_doc: dict[str, Any] = {
            "email": normalized_email,
            "proveedor_auth": "local",
            "google_sub": None,
            "password_hash": password_hash,
            "nombre": nombre.strip(),
            "estado_cuenta": "pendiente_verificacion",
            "email_verificado": False,
            "fecha_verificacion": None,
            "fecha_registro": now,
            "password_changed_at": None,
            "fecha_eliminacion": None,
        }

        created_user = await self._user_repo.create_user(user_doc)

        # Generar código en Redis y despachar por correo vía Resend
        await self.verification_service.generate_and_save_code(
            str(created_user["_id"]),
            email=normalized_email,
        )

        return created_user

    async def verify_email(self, email: str, codigo: str) -> dict[str, Any]:
        """Verifica el código efímero y activa la cuenta del usuario (RF-06.2)."""
        normalized_email = email.strip().lower()
        user = await self._user_repo.find_by_email(normalized_email)

        # Respuestas uniformes: si no existe o ya está activa, damos error genérico
        if not user or user.get("estado_cuenta") != "pendiente_verificacion":
            raise ValueError("Código inválido o expirado.")

        user_id = str(user["_id"])
        is_valid = await self.verification_service.validate_code(user_id, codigo)

        if not is_valid:
            raise ValueError("Código inválido o expirado.")

        await self._user_repo.mark_as_verified(user_id)
        return {"mensaje": "Cuenta verificada exitosamente. Ya puedes iniciar sesión."}

    async def authenticate_user(
        self,
        email: str,
        password: str,
    ) -> dict[str, str]:
        """Autentica un usuario local y genera tokens Access y Refresh (RF-06.8, D12).

        1. Busca el usuario en MongoDB por email normalizado.
        2. Valida credenciales con Argon2id ANTES de evaluar el estado de la cuenta.
        3. Si credenciales inválidas (usuario no existe, sin hash o contraseña errónea): UnauthorizedError (401).
        4. Si contraseña válida pero estado_cuenta == 'pendiente_verificacion': AccountNotVerifiedError (403).
        5. Si estado_cuenta != 'activa': UnauthorizedError (401).
        6. Genera access_token (30 min) y refresh_token (30 días).
        """
        normalized_email = email.strip().lower()
        user = await self._user_repo.find_by_email(normalized_email)

        # Validación uniforme de existencia y presencia de hash local
        if not user or not user.get("password_hash"):
            raise UnauthorizedError("Credenciales inválidas")

        # Validación de contraseña con Argon2id ANTES de evaluar el estado (D12, ADR #62)
        if not verify_password(password, user["password_hash"]):
            raise UnauthorizedError("Credenciales inválidas")

        # Si las credenciales son válidas, verificar estado_cuenta
        estado = user.get("estado_cuenta")
        if estado == "pendiente_verificacion":
            raise AccountNotVerifiedError("ACCOUNT_NOT_VERIFIED")

        if estado != "activa":
            raise UnauthorizedError("Cuenta no autorizada")

        # Generación de tokens JWT
        user_id = str(user["_id"])
        token_payload = {
            "sub": user_id,
            "email": user["email"],
        }

        access_token = create_access_token(token_payload)
        refresh_token = create_refresh_token(token_payload)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    # Alias de conveniencia
    login_user = authenticate_user
    login = authenticate_user
