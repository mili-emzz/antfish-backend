"""Middleware ASGI: límite de tamaño del cuerpo de la petición."""

from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException, status

# Los mayores cuerpos legítimos son un SMS (1600 caracteres) o un id_token (4096): 64 KiB sobran.
MAX_BODY_BYTES = 64 * 1024


class BodySizeLimitMiddleware:
    """Rechaza con 413 cuerpos mayores al límite, antes o durante su lectura."""

    def __init__(self, app: Any, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            await self._reject(send)
            return

        received = 0

        async def limited_receive() -> Any:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    # Cuerpo sin Content-Length (chunked) o mentido: lo traduce el manejador global.
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        detail="El cuerpo de la petición excede el tamaño permitido",
                    )
            return message

        await self.app(scope, limited_receive, send)

    @staticmethod
    async def _reject(send: Any) -> None:
        body = json.dumps(
            {
                "code": "PAYLOAD_TOO_LARGE",
                "detail": "El cuerpo de la petición excede el tamaño permitido",
            }
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status.HTTP_413_CONTENT_TOO_LARGE,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
