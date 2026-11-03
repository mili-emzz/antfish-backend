"""Servicio de autenticación y gestión de usuarios (RF-06)."""

from datetime import datetime, timezone
from typing import Any
from argon2 import PasswordHasher
from app.core.exceptions import DuplicateEmailError
from app.repositories.mongo.user_repository import UserRepository

# Configuración estándar para Argon2id según RFC 9106
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
)


class AuthService:
    """Lógica de negocio para registro, autenticación y ciclo de vida de usuarios."""

    def __init__(self, user_repository: UserRepository) -> None:
        self._user_repo = user_repository

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
                    # En caso improbable de no encontrarlo tras update
                    existing_user["nombre"] = nombre.strip()
                    existing_user["password_hash"] = password_hash
                    existing_user["fecha_registro"] = datetime.now(timezone.utc)
                    return existing_user
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
        return created_user

