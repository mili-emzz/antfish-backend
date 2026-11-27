"""Módulo de seguridad criptográfica: Argon2id, JWT y HMAC (RF-06.8, RNF-03)."""

import asyncio
import functools
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.core.config import settings

# Parámetros recomendados para Argon2id (RFC 9106)
_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
)


def hash_password(password: str) -> str:
    """Hashea una contraseña en texto plano utilizando Argon2id."""
    return _password_hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica si una contraseña plana coincide con el hash Argon2id."""
    try:
        return _password_hasher.verify(hashed_password, plain_password)
    except VerificationError, InvalidHashError:
        return False


@functools.cache
def _decoy_hash() -> str:
    """Hash Argon2id aleatorio de un solo uso para igualar tiempos cuando el usuario no existe."""
    return _password_hasher.hash(secrets.token_urlsafe(24))


def verify_password_decoy(plain_password: str) -> None:
    """Consume el mismo costo de Argon2id que una verificación real (anti-enumeración por tiempo)."""
    verify_password(plain_password, _decoy_hash())


# Argon2id (64 MiB, ~100-300 ms de CPU) no debe correr en el event loop. Se ejecuta en hilos y
# con concurrencia acotada: memoria máxima ≈ _MAX_CONCURRENT_HASHES × 64 MiB.
_MAX_CONCURRENT_HASHES = 4
_hash_slots = asyncio.Semaphore(_MAX_CONCURRENT_HASHES)


async def hash_password_async(password: str) -> str:
    """Versión no bloqueante de `hash_password`."""
    async with _hash_slots:
        return await asyncio.to_thread(hash_password, password)


async def verify_password_async(plain_password: str, hashed_password: str) -> bool:
    """Versión no bloqueante de `verify_password`."""
    async with _hash_slots:
        return await asyncio.to_thread(verify_password, plain_password, hashed_password)


async def verify_password_decoy_async(plain_password: str) -> None:
    """Versión no bloqueante de `verify_password_decoy`."""
    async with _hash_slots:
        await asyncio.to_thread(verify_password_decoy, plain_password)


def create_access_token(
    data: dict[str, Any],
    expires_delta: timedelta | None = None,
) -> str:
    """Genera un Access Token JWT con vigencia de 30 minutos por defecto."""
    to_encode = data.copy()
    now = datetime.now(UTC)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update(
        {
            "exp": expire,
            "iat": now,
            "type": "access",
        }
    )
    return jwt.encode(
        to_encode,
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )


def create_refresh_token(
    data: dict[str, Any],
    expires_delta: timedelta | None = None,
) -> str:
    """Genera un Refresh Token JWT con vigencia de 30 días firmado con JWT_REFRESH_SECRET."""
    to_encode = data.copy()
    now = datetime.now(UTC)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode.update(
        {
            "exp": expire,
            "iat": now,
            "type": "refresh",
        }
    )
    return jwt.encode(
        to_encode,
        settings.JWT_REFRESH_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_access_token(token: str) -> dict[str, Any]:
    """Decodifica y valida un Access Token JWT contra JWT_SECRET."""
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["exp", "iat", "sub"]},
    )


def decode_refresh_token(token: str) -> dict[str, Any]:
    """Decodifica y valida un Refresh Token JWT contra JWT_REFRESH_SECRET."""
    return jwt.decode(
        token,
        settings.JWT_REFRESH_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["exp", "iat", "sub"]},
    )


def generate_message_hmac(message: str) -> str:
    """Genera un digesto HMAC-SHA256 con HMAC_PEPPER para el texto analizado (RN-14, RNF-03)."""
    return hmac.new(
        settings.HMAC_PEPPER.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
