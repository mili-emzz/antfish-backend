from contextlib import asynccontextmanager
from typing import Any

import redis.asyncio as redis
from fastapi import FastAPI
from motor.motor_asyncio import AsyncIOMotorClient

from app.api.errors import register_exception_handlers
from app.api.v1 import analysis, auth, health, metrics
from app.container import Container
from app.core.config import settings

# 1. Crear el cliente de conexión a MongoDB
db_client: AsyncIOMotorClient[Any] = AsyncIOMotorClient(settings.MONGODB_URL)

# 2. Seleccionar la base de datos (antfish_db)
db = db_client[settings.DATABASE_NAME]

# 3. Crear el cliente asíncrono de conexión a Redis
redis_client = redis.from_url(settings.REDIS_URL)

# 4. Inicializar el contenedor entregándole ambas bases de datos
container = Container(db=db, redis_client=redis_client)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail-fast: las transacciones ACID (UnitOfWork) exigen un replica set.
    hello = await db_client.admin.command("hello")
    if not hello.get("setName"):
        raise RuntimeError(
            "MongoDB no es un replica set: las transacciones ACID no están disponibles. "
            "Use docker compose up -d mongo y MONGODB_URL con ?replicaSet=rs0."
        )
    yield
    # Cerrar las conexiones limpiamente cuando se apague el servidor
    db_client.close()
    await redis_client.close()


_is_prod = settings.ENVIRONMENT == "production"
app = FastAPI(
    title=settings.PROJECT_NAME,
    lifespan=lifespan,
    docs_url=None if _is_prod else "/docs",
    redoc_url=None if _is_prod else "/redoc",
    openapi_url=None if _is_prod else "/openapi.json",
)
register_exception_handlers(app)

# Vincular el contenedor al "state" de la aplicación
app.state.container = container

# Registrar las rutas
app.include_router(health.router)  # GET /health en la raíz (§9.6)
app.include_router(auth.router, prefix="/api/v1")
app.include_router(analysis.router, prefix="/api/v1")
app.include_router(metrics.router, prefix="/api/v1")
