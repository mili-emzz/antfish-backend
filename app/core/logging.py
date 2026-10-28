import logging
import sys

logger = logging.getLogger("antfish")

if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "name": "%(name)s", "message": "%(message)s"}'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    """Configura el logger estructurado único de la aplicación."""
    logger.setLevel(level)
    return logger
