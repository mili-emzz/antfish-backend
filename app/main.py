from fastapi import FastAPI
from contextlib import asynccontextmanager
from motor.motor_asyncio import AsyncIOMotorClient
import redis.asyncio as redis
from app.core.config import settings
from app.api.v1 import auth
from app.container import Container

# 1. Crear el cliente de conexión a MongoDB
db_client = AsyncIOMotorClient(settings.MONGODB_URL)

# 2. Seleccionar la base de datos (antfish_db)
db = db_client[settings.DATABASE_NAME]

# 3. Crear el cliente asíncrono de conexión a Redis
redis_client = redis.from_url(settings.REDIS_URL)

# 4. Inicializar el contenedor entregándole ambas bases de datos
container = Container(db=db, redis_client=redis_client)

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    # Cerrar las conexiones limpiamente cuando se apague el servidor
    db_client.close()
    await redis_client.close()

app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

# Vincular el contenedor al "state" de la aplicación
app.state.container = container 

# Registrar las rutas (el agente ya le puso prefijo /auth por dentro)
app.include_router(auth.router, prefix="/api/v1")

@app.get("/health")
async def health_check():
    return {"status": "ok"}