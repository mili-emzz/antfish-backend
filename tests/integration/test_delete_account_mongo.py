"""Integración con MongoDB real: DELETE /auth/me (RF-06.7, O12, RN-26, D4).

Verifica con el $jsonSchema real que el documento anonimizado es válido, que la purga es
atómica y que solo se afectan los datos del usuario que se da de baja.
Usa MONGO_URI y una base temporal que se elimina al final.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import AsyncMongoClient

from app.core.exceptions import PersistenceError, UnauthorizedError
from app.core.security import hash_password
from app.repositories.mongo.analysis_repository import AnalysisRepository
from app.repositories.mongo.init_db import init_db
from app.repositories.mongo.metrics_repository import MetricsRepository
from app.repositories.mongo.unit_of_work import UnitOfWork
from app.repositories.mongo.user_repository import UserRepository
from app.services.auth_service import AuthService

MONGO_URI = os.getenv(
    "MONGO_URI", "mongodb://localhost:27017/?replicaSet=rs0&directConnection=true"
)
PASSWORD = "PasswordSeguro123!"


@pytest_asyncio.fixture
async def dbs():
    name = f"antfish_del_{uuid.uuid4().hex[:8]}"
    pym = AsyncMongoClient(MONGO_URI, serverSelectionTimeoutMS=4000)
    try:
        await pym.admin.command("ping")
    except Exception as exc:  # noqa: BLE001 - se omite si no hay Mongo
        await pym.close()
        pytest.skip(f"MongoDB no disponible: {type(exc).__name__}")
    motor = AsyncIOMotorClient(MONGO_URI)
    await init_db(pym[name])
    yield motor[name]
    await pym.drop_database(name)
    await pym.close()
    motor.close()


def _service(db) -> AuthService:
    return AuthService(
        UserRepository(db),
        AsyncMock(),
        unit_of_work=UnitOfWork(db),
        analysis_repository=AnalysisRepository(db),
        metrics_repository=MetricsRepository(db),
    )


async def _seed_user(db, email: str) -> dict:
    now = datetime.now(timezone.utc)
    doc = {
        "email": email,
        "proveedor_auth": "local",
        "google_sub": None,
        "password_hash": hash_password(PASSWORD),
        "nombre": "Ana",
        "estado_cuenta": "activa",
        "email_verificado": True,
        "fecha_verificacion": now,
        "fecha_registro": now,
        "password_changed_at": None,
        "fecha_eliminacion": None,
    }
    doc["_id"] = (await db["usuarios"].insert_one(doc)).inserted_id
    return doc


async def _seed_data(db, user_id: ObjectId) -> None:
    now = datetime.now(timezone.utc)
    analysis_id = (
        await db["analisis"].insert_one(
            {
                "user_id": user_id,
                "tipo_entrada": "url",
                "mensaje_hash": None,
                "dominio_principal": "ejemplo.com",
                "score_total": 10,
                "nivel_riesgo": "bajo",
                "puntos_por_capa": {"apis": 0, "url": 10, "texto": 0},
                "analisis_parcial": False,
                "hallazgos": [],
                "recomendaciones": [],
                "fuentes_consultadas": [],
                "fecha": now,
            }
        )
    ).inserted_id
    await db["respuestas_apis"].insert_one(
        {
            "analisis_id": analysis_id,
            "user_id": user_id,
            "url_normalizada": "https://ejemplo.com/",
            "dominio": "ejemplo.com",
            "api": "virustotal",
            "respuesta_cruda": {},
            "fecha": now,
            "expira_en": now + timedelta(days=30),
        }
    )
    await db["metricas_usuario"].insert_one(
        {
            "_id": user_id,
            "total_escaneos": 1,
            "total_url": 1,
            "total_sms": 0,
            "amenazas_bloqueadas": 0,
            "ultima_actualizacion": now,
        }
    )


async def _counts(db, user_id: ObjectId) -> tuple[int, int, int]:
    return (
        await db["analisis"].count_documents({"user_id": user_id}),
        await db["respuestas_apis"].count_documents({"user_id": user_id}),
        await db["metricas_usuario"].count_documents({"_id": user_id}),
    )


@pytest.mark.asyncio
async def test_delete_account_purges_and_anonymizes_only_that_user(dbs) -> None:
    ana = await _seed_user(dbs, "ana@correo.com")
    otro = await _seed_user(dbs, "otro@correo.com")
    await _seed_data(dbs, ana["_id"])
    await _seed_data(dbs, otro["_id"])
    assert await _counts(dbs, ana["_id"]) == (1, 1, 1)

    await _service(dbs).delete_account(ana, PASSWORD)

    assert await _counts(dbs, ana["_id"]) == (0, 0, 0)
    assert await _counts(dbs, otro["_id"]) == (1, 1, 1)  # el otro usuario no se toca

    doc = await dbs["usuarios"].find_one({"_id": ana["_id"]})
    assert doc["email"] == f"deleted_{ana['_id']}@deleted.local"
    assert doc["estado_cuenta"] == "eliminada"
    assert doc["email_verificado"] is False
    assert doc["nombre"] is None and doc["password_hash"] is None and doc["google_sub"] is None
    assert isinstance(doc["fecha_eliminacion"], datetime)
    assert doc["proveedor_auth"] == "local"

    # el correo original queda libre para un registro nuevo (I1 único)
    await _seed_user(dbs, "ana@correo.com")


@pytest.mark.asyncio
async def test_wrong_password_changes_nothing(dbs) -> None:
    ana = await _seed_user(dbs, "ana@correo.com")
    await _seed_data(dbs, ana["_id"])
    with pytest.raises(UnauthorizedError):
        await _service(dbs).delete_account(ana, "incorrecta")
    assert await _counts(dbs, ana["_id"]) == (1, 1, 1)
    assert (await dbs["usuarios"].find_one({"_id": ana["_id"]}))["estado_cuenta"] == "activa"


@pytest.mark.asyncio
async def test_transaction_rolls_back_purge_if_user_not_active(dbs) -> None:
    """Si la cuenta dejó de estar activa, la purga ya hecha dentro de la transacción se revierte."""
    ana = await _seed_user(dbs, "ana@correo.com")
    await _seed_data(dbs, ana["_id"])
    await dbs["usuarios"].update_one({"_id": ana["_id"]}, {"$set": {"estado_cuenta": "suspendida"}})

    with pytest.raises(UnauthorizedError):
        await _service(dbs).delete_account(ana, PASSWORD)

    assert await _counts(dbs, ana["_id"]) == (1, 1, 1)  # rollback: nada se perdió


@pytest.mark.asyncio
async def test_mongo_error_becomes_persistence_error(dbs) -> None:
    ana = await _seed_user(dbs, "ana@correo.com")
    await _seed_data(dbs, ana["_id"])
    service = _service(dbs)
    ana_bad = {**ana, "_id": ana["_id"]}
    # fuerza un fallo real de Mongo: transacción sobre un cliente cerrado
    dbs.client.close()
    with pytest.raises(PersistenceError):
        await service.delete_account(ana_bad, PASSWORD)
