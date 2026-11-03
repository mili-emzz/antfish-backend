from fastapi import FastAPI
from contextlib import asynccontextmanager
from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings
from app.api.v1 import auth
from app.container import Container

# 1. Crear el cliente de conexión a MongoDB
db_client = AsyncIOMotorClient(settings.MONGODB_URL)

# 2. Seleccionar la base de datos (antfish_db)
db = db_client[settings.DATABASE_NAME]

# 3. Inicializar el contenedor entregándole la base de datos
container = Container(db=db)

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    # Cerrar la conexión limpiamente cuando se apague el servidor
    db_client.close()

app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

# EL CAMBIO CLAVE: Vincular el contenedor al "state" de la aplicación
app.state.container = container 

# Registrar las rutas (el agente ya le puso prefijo /auth por dentro)
app.include_router(auth.router, prefix="/api/v1")

@app.get("/health")
async def health_check():
    return {"status": "ok"}