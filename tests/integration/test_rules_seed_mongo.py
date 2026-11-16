"""Integración con MongoDB real: siembra de initial_data.json y carga por RulesProvider (CU-11).

Usa MONGO_URI (igual que test_init_db) y una base temporal que se elimina al final.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import AsyncMongoClient

from app.clients.base import ReputationResult
from app.engine.models import Reputation, SourceStatus
from app.repositories.mongo.init_db import init_db
from app.repositories.mongo.rules_repository import RulesRepository
from app.services.analysis_service import AnalysisService
from app.services.rules_provider import RulesProvider

MONGO_URI = os.getenv(
    "MONGO_URI", "mongodb://localhost:27017/?replicaSet=rs0&directConnection=true"
)


@pytest_asyncio.fixture
async def dbs():
    name = f"antfish_rules_{uuid.uuid4().hex[:8]}"
    pym = AsyncMongoClient(MONGO_URI, serverSelectionTimeoutMS=4000)
    try:
        await pym.admin.command("ping")
    except Exception as exc:  # noqa: BLE001 - se omite si no hay Mongo
        await pym.close()
        pytest.skip(f"MongoDB no disponible: {type(exc).__name__}")
    motor = AsyncIOMotorClient(MONGO_URI)
    yield pym[name], motor[name]
    await pym.drop_database(name)
    await pym.close()
    motor.close()


@pytest.mark.asyncio
async def test_seed_then_provider_loads_catalog_from_mongo(dbs) -> None:
    pym_db, motor_db = dbs
    await init_db(pym_db)
    await init_db(pym_db)  # idempotente: no duplica la siembra

    assert await motor_db["reglas_heuristicas"].count_documents({}) == 12
    assert await motor_db["marcas_protegidas"].count_documents({}) == 21
    regla = await motor_db["reglas_heuristicas"].find_one({"codigo": "URL_TLD_ALTO_RIESGO"})
    assert isinstance(regla["fecha_actualizacion"], datetime) and regla["puntos"] == 15

    snap = await RulesProvider(RulesRepository(motor_db)).get()
    assert snap.source == "mongo"
    assert len(snap.brands) == 21 and sum(b.activa for b in snap.brands) == 11
    assert len(snap.rules) == 12


def _api(name: str) -> AsyncMock:
    m = AsyncMock()
    m.check_url.return_value = ReputationResult(
        reputation=Reputation(api=name, estado=SourceStatus.OK, positivo=False, detecciones=0)
    )
    return m


@pytest.mark.asyncio
async def test_catalog_changes_in_mongo_change_the_analysis(dbs) -> None:
    pym_db, motor_db = dbs
    await init_db(pym_db)
    url = "https://telcel-recarga.verifica-ya.net/"

    def service() -> AnalysisService:
        return AnalysisService(
            web_risk_client=_api("google_web_risk"), virustotal_client=_api("virustotal"),
            phishtank_client=None, rules_provider=RulesProvider(RulesRepository(motor_db)),
        )

    # Marca nueva sembrada INACTIVA: no se detecta hasta que se revise y active
    antes = await service().analyze("url", url)
    assert "URL_SUBDOMINIO_ENGANOSO" not in {h["regla_codigo"] for h in antes["hallazgos"]}

    await motor_db["marcas_protegidas"].update_one({"codigo": "telcel"}, {"$set": {"activa": True}})
    despues = await service().analyze("url", url)
    assert "URL_SUBDOMINIO_ENGANOSO" in {h["regla_codigo"] for h in despues["hallazgos"]}
    assert despues["motivo_cortocircuito"] == "suplantacion_marca"

    # Puntos adulterados en Mongo no afectan el puntaje (requisito inmutable)
    await motor_db["reglas_heuristicas"].update_one(
        {"codigo": "URL_SUBDOMINIO_ENGANOSO"}, {"$set": {"puntos": 1}}
    )
    adulterado = await service().analyze("url", url)
    assert adulterado["puntos_por_capa"] == despues["puntos_por_capa"]
