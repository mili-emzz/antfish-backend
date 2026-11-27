# Imagen de producción de la API de AntFish (FastAPI + uvicorn).
# Solo incluye dependencias de ejecución (requirements.txt) y el paquete `app`.
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Capa de dependencias aparte: se reutiliza mientras requirements.txt no cambie.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app

# Sin privilegios de root dentro del contenedor.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin antfish
USER antfish

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"]

# Detrás de un proxy (Caddy): uvicorn confía en X-Forwarded-For solo desde las IPs de
# FORWARDED_ALLOW_IPS (variable de entorno; la fija docker-compose.prod.yml).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-server-header"]
