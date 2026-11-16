"""Validación de Google ID Tokens (RF-06.4, RN-19).

Verifica firma (certificados públicos de Google), expiración, `aud = GOOGLE_CLIENT_ID`,
emisor y `email_verified`. Nunca guarda ni registra el ID token (AGENTS.md).

Los certificados se descargan con httpx (asíncrono, TLS verificado) y se cachean según
`Cache-Control: max-age`; la librería `google-auth` solo valida el JWT (CPU, sin I/O), por lo
que no se bloquea el event loop. `google-auth` se importa de forma diferida.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from app.core.config import settings
from app.core.exceptions import GoogleTokenInvalidError, IdentityProviderUnavailableError
from app.core.logging import logger

CERTS_URL = "https://www.googleapis.com/oauth2/v1/certs"
VALID_ISSUERS = frozenset({"accounts.google.com", "https://accounts.google.com"})
_DEFAULT_CERTS_TTL = 3600
_MAX_AGE = re.compile(r"max-age=(\d+)")

Decoder = Callable[[str, Mapping[str, str], str], Mapping[str, Any]]


@dataclass(frozen=True)
class GoogleIdentity:
    """Identidad certificada por Google."""

    sub: str
    email: str
    email_verified: bool
    nombre: str | None


def _decode_with_google_auth(
    token: str, certs: Mapping[str, str], audience: str
) -> Mapping[str, Any]:
    """Valida firma, expiración y audiencia con google-auth (importación diferida)."""
    try:
        from google.auth import jwt as google_jwt
        from google.auth.exceptions import GoogleAuthError
    except ImportError as exc:
        logger.error("La dependencia google-auth no está instalada")
        raise IdentityProviderUnavailableError() from exc
    try:
        claims: Mapping[str, Any] = google_jwt.decode(
            token, certs=dict(certs), audience=audience, clock_skew_in_seconds=10
        )
    except (ValueError, GoogleAuthError) as exc:
        # No se incluye el mensaje original: podría contener fragmentos del token.
        raise GoogleTokenInvalidError() from exc
    return claims


class GoogleIdentityClient:
    """Cliente de validación de ID tokens de Google Sign-In."""

    def __init__(
        self,
        client_id: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        timeout: float = 5.0,
        decoder: Decoder | None = None,
    ) -> None:
        self._client_id = client_id if client_id is not None else settings.GOOGLE_CLIENT_ID
        self._http = http_client
        self._timeout = timeout
        self._decode = decoder or _decode_with_google_auth
        self._certs: dict[str, str] = {}
        self._certs_expiry = 0.0

    async def _get_certs(self) -> dict[str, str]:
        if self._certs and time.monotonic() < self._certs_expiry:
            return self._certs
        try:
            if self._http is not None:
                response = await self._http.get(CERTS_URL, timeout=self._timeout)
            else:
                async with httpx.AsyncClient(timeout=self._timeout) as http:
                    response = await http.get(CERTS_URL)
            response.raise_for_status()
            certs = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.error(f"No se pudieron obtener los certificados de Google: {type(exc).__name__}")
            raise IdentityProviderUnavailableError() from exc
        if not isinstance(certs, dict) or not certs:
            logger.error("Respuesta de certificados de Google inválida")
            raise IdentityProviderUnavailableError()
        match = _MAX_AGE.search(response.headers.get("cache-control", ""))
        ttl = int(match.group(1)) if match else _DEFAULT_CERTS_TTL
        self._certs = {str(k): str(v) for k, v in certs.items()}
        self._certs_expiry = time.monotonic() + max(60, min(ttl, 24 * 3600))
        return self._certs

    async def verify_id_token(self, id_token: str) -> GoogleIdentity:
        """Devuelve la identidad certificada o lanza GoogleTokenInvalidError (401)."""
        if not self._client_id:
            logger.error("GOOGLE_CLIENT_ID no está configurado")
            raise IdentityProviderUnavailableError()

        certs = await self._get_certs()
        claims = self._decode(id_token, certs, self._client_id)

        if claims.get("iss") not in VALID_ISSUERS:
            raise GoogleTokenInvalidError()
        sub, email = claims.get("sub"), claims.get("email")
        if not isinstance(sub, str) or not sub or not isinstance(email, str) or not email:
            raise GoogleTokenInvalidError()
        verified = claims.get("email_verified")
        name = claims.get("name")
        return GoogleIdentity(
            sub=sub,
            email=email.strip().lower(),
            email_verified=verified is True or verified == "true",
            nombre=name.strip() if isinstance(name, str) and name.strip() else None,
        )
