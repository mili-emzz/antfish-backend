"""Módulo de seguridad criptográfica: Argon2id, JWT y HMAC."""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

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
    except (VerifyMismatchError, Exception):
        return False

