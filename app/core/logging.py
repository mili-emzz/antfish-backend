import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("antfish")

# Atributos estándar de LogRecord: lo que no esté aquí vino de `extra=` y se serializa también.
_STANDARD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {
    "message",
    "asctime",
    "taskName",
}


class JsonFormatter(logging.Formatter):
    """Una línea JSON por registro, con escape correcto (evita inyección de líneas/campos)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS:
                payload[key] = value
        if record.exc_info:
            payload["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
        # default=str: un valor no serializable nunca rompe el log.
        return json.dumps(payload, ensure_ascii=False, default=str)


if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    """Configura el logger estructurado único de la aplicación."""
    logger.setLevel(level)
    return logger
