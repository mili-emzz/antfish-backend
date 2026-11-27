"""Servicio de autenticación y gestión de usuarios (RF-06)."""

import secrets
from datetime import UTC, datetime
from typing import Any

import jwt
from bson import ObjectId
from bson.errors import InvalidId
from pymongo.errors import DuplicateKeyError, PyMongoError
from redis.exceptions import RedisError

from app.clients.google_identity import GoogleIdentityClient
from app.core.config import settings
from app.core.exceptions import (
    AccountConflictError,
    AccountNotVerifiedError,
    DuplicateEmailError,
    EmailDeliveryError,
    GoogleEmailNotVerifiedError,
    PersistenceError,
    RateLimitBackendError,
    RateLimitExceededError,
    ReauthMethodUnavailableError,
    UnauthorizedError,
    VerificationAttemptsExceededError,
)
from app.core.logging import logger
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    hash_password_async,
    verify_password_async,
    verify_password_decoy_async,
)
from app.repositories.mongo.analysis_repository import AnalysisRepository
from app.repositories.mongo.metrics_repository import MetricsRepository
from app.repositories.mongo.unit_of_work import UnitOfWork
from app.repositories.mongo.user_repository import UserRepository
from app.repositories.redis.session_repository import RefreshSessionRepository
from app.services.rate_limiter import RateLimiter
from app.services.verification_service import VerificationService


class AuthService:
    """Lógica de negocio para registro, autenticación y ciclo de vida de usuarios."""

    def __init__(
        self,
        user_repository: UserRepository,
        verification_service: VerificationService,
        unit_of_work: UnitOfWork | None = None,
        analysis_repository: AnalysisRepository | None = None,
        metrics_repository: MetricsRepository | None = None,
        google_client: GoogleIdentityClient | None = None,
        session_repository: RefreshSessionRepository | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        # Sin session_repository no hay rotación: /auth/refresh rechaza todo (solo para pruebas).
        self._sessions = session_repository
        self._rate_limiter = rate_limiter
        self._user_repo = user_repository
        self._uow = unit_of_work
        self._analysis_repo = analysis_repository
        self._metrics_repo = metrics_repository
        self._google = google_client
        self.verification_service = verification_service

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
        - Si existe cuenta en 'pendiente_verificacion', NO modifica sus datos (evita el
          pre-hijacking de la cuenta) y solo reenvía el código (desvía de D14/RN-23).
        - Si existe cuenta activa o suspendida, responde con DuplicateEmailError (HTTP 409).
        - Genera código numérico de 6 dígitos y lo envía vía Resend (RF-06.2).
        """
        normalized_email = email.strip().lower()
        existing_user = await self._user_repo.find_by_email(normalized_email)

        if existing_user:
            estado = existing_user.get("estado_cuenta")
            if estado == "pendiente_verificacion":
                # No se sobrescribe contraseña ni nombre: quien registra no ha probado controlar
                # el correo (pre-hijacking). Solo se reenvía el código al titular del correo.
                await self.verification_service.generate_and_save_code(
                    str(existing_user["_id"]),
                    email=normalized_email,
                )
                return existing_user

            # Si la cuenta ya está activa, suspendida o eliminada, genera conflicto (409)
            raise DuplicateEmailError("El correo electrónico ya se encuentra registrado")

        password_hash = await hash_password_async(password)
        now = datetime.now(UTC)
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
        try:
            is_valid = await self.verification_service.validate_code(user_id, codigo)
        except VerificationAttemptsExceededError:
            # Uniforme: no distingue intentos agotados de código erróneo (RN-25).
            raise ValueError("Código inválido o expirado.") from None

        if not is_valid:
            raise ValueError("Código inválido o expirado.")

        await self._user_repo.mark_as_verified(user_id)
        return {"mensaje": "Cuenta verificada exitosamente. Ya puedes iniciar sesión."}

    async def resend_code(self, email: str) -> None:
        """Reenvía el código de verificación a una cuenta pendiente (RF-06.3, D17).

        Cuentas inexistentes o no pendientes no hacen nada (la respuesta HTTP es uniforme).
        El límite de 3/hora por usuario lanza RateLimitExceededError (429).
        """
        user = await self._user_repo.find_by_email(email.strip().lower())
        if not user or user.get("estado_cuenta") != "pendiente_verificacion":
            return
        await self.verification_service.generate_and_save_code(
            str(user["_id"]), email=user["email"]
        )

    async def request_password_reset(self, email: str) -> None:
        """Emite código de recuperación si la cuenta existe, está activa y tiene contraseña (RF-06.6).

        Pensado para ejecutarse en segundo plano: la respuesta HTTP es uniforme y de tiempo
        constante (D16, RN-25). Límite compartido `reenvio:{user_id}`; los fallos se registran
        sin revelar si el correo existe.
        """
        user = await self._user_repo.find_by_email(email.strip().lower())
        if not user or user.get("estado_cuenta") != "activa" or not user.get("password_hash"):
            return
        try:
            await self.verification_service.generate_and_save_code(
                str(user["_id"]), email=user["email"], purpose="recuperacion"
            )
        except RateLimitExceededError:
            logger.warning("Recuperación de contraseña omitida: límite de reenvíos alcanzado")
        except RateLimitBackendError:
            logger.error("Recuperación de contraseña omitida: control de tasa no disponible")
        except EmailDeliveryError:
            logger.error("Recuperación de contraseña: fallo al entregar el correo")

    async def reset_password(self, email: str, codigo: str, nueva_password: str) -> dict[str, str]:
        """Restablece la contraseña con el código de recuperación (RF-06.6, D17, D18).

        Cualquier fallo (correo inexistente, cuenta no activa, código erróneo o intentos
        agotados) produce el mismo ValueError (RN-25). Al éxito fija password_changed_at,
        lo que revoca todos los tokens previos.
        """
        generic = ValueError("Código inválido o expirado.")
        user = await self._user_repo.find_by_email(email.strip().lower())
        if not user or user.get("estado_cuenta") != "activa" or not user.get("password_hash"):
            raise generic

        try:
            is_valid = await self.verification_service.validate_code(str(user["_id"]), codigo)
        except VerificationAttemptsExceededError:
            raise generic from None
        if not is_valid:
            raise generic

        updated = await self._user_repo.update_password(
            user["_id"], await hash_password_async(nueva_password)
        )
        if not updated:
            raise generic
        return {"mensaje": "Contraseña actualizada. Inicia sesión con tu nueva contraseña."}

    async def refresh_access_token(self, refresh_token: str) -> dict[str, str]:
        """Renueva la sesión con rotación del Refresh Token (RF-06, D18).

        Exige firma/expiración válidas, tipo `refresh`, `fam`/`jti`, cuenta `activa` e
        `iat >= password_changed_at`. Cada refresh es de un solo uso: se emite uno nuevo y el
        anterior deja de valer. Si se presenta un refresh ya usado (posible robo) se revoca
        toda la familia de la sesión. Redis caído -> 503 (fail-closed).
        """
        if self._sessions is None:
            raise UnauthorizedError("Credenciales inválidas")
        try:
            claims = decode_refresh_token(refresh_token)
        except jwt.PyJWTError:
            raise UnauthorizedError("Credenciales inválidas") from None
        if (
            claims.get("type") != "refresh"
            or not claims.get("sub")
            or not claims.get("fam")
            or not claims.get("jti")
        ):
            raise UnauthorizedError("Credenciales inválidas")

        try:
            user = await self._user_repo.find_by_id(claims["sub"])
        except InvalidId:
            raise UnauthorizedError("Credenciales inválidas") from None
        if not user or user.get("estado_cuenta") != "activa":
            raise UnauthorizedError("Credenciales inválidas")

        changed_at = user.get("password_changed_at")
        if changed_at is not None:
            if changed_at.tzinfo is None:
                changed_at = changed_at.replace(tzinfo=UTC)
            if int(claims.get("iat", 0)) < int(changed_at.timestamp()):
                raise UnauthorizedError("Credenciales inválidas")

        payload = {"sub": str(user["_id"]), "email": user["email"]}
        new_jti = secrets.token_urlsafe(16)
        try:
            rotated = await self._sessions.rotate(
                claims["fam"], claims["jti"], new_jti, self._refresh_ttl_seconds()
            )
            if not rotated:
                # jti ya usado o familia revocada: se corta la sesión completa.
                await self._sessions.revoke(claims["fam"])
        except RedisError as exc:
            logger.error(f"Almacén de sesiones no disponible: {type(exc).__name__}")
            raise RateLimitBackendError() from exc
        if not rotated:
            logger.warning("Refresh token reutilizado o revocado: familia de sesión revocada")
            raise UnauthorizedError("Credenciales inválidas")

        return {
            "access_token": create_access_token(payload),
            "refresh_token": create_refresh_token(
                {**payload, "fam": claims["fam"], "jti": new_jti}
            ),
            "token_type": "bearer",
        }

    async def logout(self, refresh_token: str) -> None:
        """Revoca la familia de sesión del refresh token (cierre de sesión).

        Idempotente y uniforme: un token inválido, expirado o ya revocado no produce error.
        """
        if self._sessions is None:
            return
        try:
            claims = decode_refresh_token(refresh_token)
        except jwt.PyJWTError:
            return
        family = claims.get("fam")
        if claims.get("type") != "refresh" or not family:
            return
        try:
            await self._sessions.revoke(family)
        except RedisError as exc:
            logger.error(f"Almacén de sesiones no disponible: {type(exc).__name__}")
            raise RateLimitBackendError() from exc

    @staticmethod
    def _refresh_ttl_seconds() -> int:
        return settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400

    async def authenticate_user(
        self,
        email: str,
        password: str,
    ) -> dict[str, Any]:
        """Autentica un usuario local y genera tokens Access y Refresh (RF-06.8, D12).

        1. Busca el usuario en MongoDB por email normalizado.
        2. Valida credenciales con Argon2id ANTES de evaluar el estado de la cuenta.
        3. Si credenciales inválidas (usuario no existe, sin hash o contraseña errónea): UnauthorizedError (401).
        4. Si contraseña válida pero estado_cuenta == 'pendiente_verificacion': AccountNotVerifiedError (403).
        5. Si estado_cuenta != 'activa': UnauthorizedError (401).
        6. Genera access_token (30 min) y refresh_token (30 días).
        """
        normalized_email = email.strip().lower()
        # Retroceso progresivo por cuenta (además del límite por IP): 429 mientras dure la espera.
        if self._rate_limiter is not None:
            await self._rate_limiter.check_login_account(normalized_email)
        user = await self._user_repo.find_by_email(normalized_email)

        # Validación uniforme de existencia y presencia de hash local
        if not user or not user.get("password_hash"):
            # Mismo costo de Argon2id que un login real: evita enumerar correos por tiempo.
            await verify_password_decoy_async(password)
            await self._record_login_failure(normalized_email)
            raise UnauthorizedError("Credenciales inválidas")

        # Validación de contraseña con Argon2id ANTES de evaluar el estado (D12, ADR #62)
        if not await verify_password_async(password, user["password_hash"]):
            await self._record_login_failure(normalized_email)
            raise UnauthorizedError("Credenciales inválidas")
        if self._rate_limiter is not None:
            await self._rate_limiter.clear_login_failures(normalized_email)

        # Si las credenciales son válidas, verificar estado_cuenta
        estado = user.get("estado_cuenta")
        if estado == "pendiente_verificacion":
            raise AccountNotVerifiedError("ACCOUNT_NOT_VERIFIED")

        if estado != "activa":
            raise UnauthorizedError("Cuenta no autorizada")

        return await self._issue_tokens(user)

    async def _record_login_failure(self, email: str) -> None:
        if self._rate_limiter is not None:
            await self._rate_limiter.record_login_failure(email)

    async def _issue_tokens(self, user: dict[str, Any]) -> dict[str, Any]:
        """Emite Access (30 min) y Refresh (30 días, nueva familia de sesión) y datos de sesión."""
        token_payload = {"sub": str(user["_id"]), "email": user["email"]}
        family = secrets.token_urlsafe(16)
        jti = secrets.token_urlsafe(16)
        if self._sessions is not None:
            try:
                await self._sessions.start(family, jti, self._refresh_ttl_seconds())
            except RedisError as exc:
                logger.error(f"Almacén de sesiones no disponible: {type(exc).__name__}")
                raise RateLimitBackendError() from exc
        return {
            "access_token": create_access_token(token_payload),
            "refresh_token": create_refresh_token({**token_payload, "fam": family, "jti": jti}),
            "token_type": "bearer",
            "user": {
                "email": user["email"],
                "nombre": user.get("nombre"),
                "proveedor_auth": user.get("proveedor_auth", "local"),
            },
        }

    async def login_with_google(self, id_token: str) -> dict[str, Any]:
        """Login/alta/vinculación con Google ID Token (RF-06.4, RF-06.5, RN-18, RN-19, RN-24, D13).

        - Token inválido -> GoogleTokenInvalidError (401); Google/config no disponible -> 503.
        - email_verified = false -> AccountConflictError (409).
        - Sin cuenta: alta `google`, `activa`, verificada, sin password.
        - Cuenta `pendiente_verificacion`: se activa, se descarta password_hash y se fija
          password_changed_at (RN-24).
        - Cuenta local `activa`: se vincula google_sub conservando proveedor y password (RN-18);
          si ya tenía otro google_sub -> 409.
        - Cuenta suspendida o eliminada: UnauthorizedError (401).
        El ID token nunca se guarda ni se registra.
        """
        assert self._google is not None
        identity = await self._google.verify_id_token(id_token)
        if not identity.email_verified:
            raise GoogleEmailNotVerifiedError()

        for _ in range(2):  # un reintento si otra petición creó la cuenta en paralelo
            user = await self._user_repo.find_by_google_sub(identity.sub)
            if user is None:
                user = await self._user_repo.find_by_email(identity.email)

            if user is None:
                try:
                    user = await self._create_google_user(
                        identity.sub, identity.email, identity.nombre
                    )
                except DuplicateKeyError:
                    continue
                return await self._issue_tokens(user)

            estado = user.get("estado_cuenta")
            if estado == "pendiente_verificacion":
                if not await self._user_repo.activate_pending_with_google(
                    user["_id"], identity.sub
                ):
                    continue
                user = {**user, "proveedor_auth": "google"}
            elif estado == "activa":
                current_sub = user.get("google_sub")
                if current_sub is None:
                    if not await self._user_repo.link_google_sub(user["_id"], identity.sub):
                        continue
                elif current_sub != identity.sub:
                    raise AccountConflictError(
                        "La cuenta ya está vinculada a otra identidad de Google"
                    )
            else:
                raise UnauthorizedError("Cuenta no autorizada")
            return await self._issue_tokens(user)

        raise UnauthorizedError("Cuenta no autorizada")

    async def _create_google_user(
        self, google_sub: str, email: str, nombre: str | None
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        display = (nombre or email.split("@", 1)[0])[:100]
        return await self._user_repo.create_user(
            {
                "email": email,
                "proveedor_auth": "google",
                "google_sub": google_sub,
                "password_hash": None,
                "nombre": display,
                "estado_cuenta": "activa",
                "email_verificado": True,
                "fecha_verificacion": now,
                "fecha_registro": now,
                "password_changed_at": None,
                "fecha_eliminacion": None,
            }
        )

    async def delete_account(
        self,
        user: dict[str, Any],
        password: str | None = None,
        id_token: str | None = None,
    ) -> None:
        """Baja de cuenta local con reautenticación, anonimización y purga ACID (RF-06.7, O12, D4).

        - Cuentas con password_hash (incluidas locales con Google vinculado) se reautentican con
          contraseña. Cuentas solo Google (sin password_hash) con id_token del mismo google_sub
          (RN-21); token inválido -> GoogleTokenInvalidError, Google caído -> 503.
        - Contraseña incorrecta: UnauthorizedError.
        - Purga analisis, respuestas_apis y metricas_usuario y anonimiza el usuario en una
          sola transacción; si algo falla se revierte todo (PersistenceError, 503).
        """
        assert self._uow is not None
        assert self._analysis_repo is not None
        assert self._metrics_repo is not None

        password_hash = user.get("password_hash")
        if password_hash:
            if password is None:
                raise UnauthorizedError("Se requiere la contraseña")
            if not await verify_password_async(password, password_hash):
                raise UnauthorizedError("Contraseña incorrecta")
        else:
            # Cuenta solo Google: reautenticación con id_token del mismo google_sub (RN-21).
            google_sub = user.get("google_sub")
            if self._google is None or not google_sub:
                raise ReauthMethodUnavailableError(
                    "No hay un método de reautenticación disponible para esta cuenta."
                )
            if id_token is None:
                raise UnauthorizedError("Se requiere el id_token de Google")
            identity = await self._google.verify_id_token(id_token)
            if identity.sub != google_sub:
                raise UnauthorizedError("El token de Google no corresponde a esta cuenta")

        oid = user["_id"] if isinstance(user["_id"], ObjectId) else ObjectId(user["_id"])
        try:
            async with self._uow.transaction() as session:
                await self._analysis_repo.delete_all_by_user(oid, session)
                await self._metrics_repo.delete_by_user(oid, session)
                if not await self._user_repo.anonymize_user(oid, session):
                    # La cuenta cambió de estado tras autenticar: se aborta toda la transacción.
                    raise UnauthorizedError("Cuenta no autorizada")
        except PyMongoError as exc:
            logger.error(f"Fallo al eliminar la cuenta: {type(exc).__name__}")
            raise PersistenceError() from exc

    # Alias de conveniencia
    login_user = authenticate_user
    login = authenticate_user
