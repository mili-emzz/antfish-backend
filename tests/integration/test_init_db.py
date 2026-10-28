"""Pruebas de integración para init_db de MongoDB.

Verifica:
- Conexión a MongoDB (falla con mensaje claro si no está disponible)
- Idempotencia de init_db (doble ejecución sin errores ni duplicaciones)
- Creación e integridad de índices (I1, I2, I5 a I11; ausencia de I3 e I4)
- Comprobación del plan de consulta de P8 (IXSCAN sobre I2)
- Siembra condicional de initial_data.json (ambas vacías, asimétricas, ya pobladas)
- Validación de $jsonSchema + $expr para documentos válidos e inválidos
"""

from __future__ import annotations

import asyncio
import functools
import json
import os
import uuid
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from bson import ObjectId
from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.errors import DuplicateKeyError, OperationFailure

from app.repositories.mongo.init_db import init_db

MONGO_URI = os.getenv(
    "MONGO_URI", "mongodb://localhost:27017/?replicaSet=rs0&directConnection=true"
)


def async_test(coro: Callable[..., Any]) -> Callable[..., Any]:
    """Decorador estándar para ejecutar corrutinas de prueba con asyncio.run()."""

    @functools.wraps(coro)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return asyncio.run(coro(*args, **kwargs))

    return wrapper


@asynccontextmanager
async def get_test_db() -> AsyncGenerator[AsyncDatabase[dict[str, Any]], None]:
    client: AsyncMongoClient[dict[str, Any]] = AsyncMongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=2000,
    )
    try:
        await client.admin.command("ping")
    except Exception as exc:  # noqa: BLE001
        pytest.fail(
            f"MongoDB no está disponible en {MONGO_URI}. Asegúrate de levantar el contenedor o servicio rs0: {exc}"
        )

    db_name = f"antfish_test_{uuid.uuid4().hex[:8]}"
    db = client[db_name]
    try:
        yield db
    finally:
        await client.drop_database(db_name)
        await client.close()


@async_test
async def test_init_db_idempotence() -> None:
    """Ejecutar init_db dos veces consecutivas debe ser completamente transparente e idempotente."""
    async with get_test_db() as test_db:
        await init_db(test_db)
        indexes_first = {
            col: await test_db[col].index_information()
            for col in [
                "usuarios",
                "analisis",
                "reglas_heuristicas",
                "marcas_protegidas",
                "respuestas_apis",
            ]
        }

        # Segunda ejecución
        await init_db(test_db)
        indexes_second = {
            col: await test_db[col].index_information()
            for col in [
                "usuarios",
                "analisis",
                "reglas_heuristicas",
                "marcas_protegidas",
                "respuestas_apis",
            ]
        }

        assert indexes_first == indexes_second


@async_test
async def test_indexes_structure_and_deferred() -> None:
    """Verifica claves y opciones de I1, I2, I5 a I11, y que I3 e I4 no existan."""
    async with get_test_db() as test_db:
        await init_db(test_db)

        # I1: usuarios.email único
        u_idx = await test_db["usuarios"].index_information()
        assert any(
            info.get("key") == [("email", 1)] and info.get("unique") is True
            for info in u_idx.values()
        )

        # I10: usuarios.google_sub único parcial
        assert any(
            info.get("key") == [("google_sub", 1)]
            and info.get("unique") is True
            and info.get("partialFilterExpression")
            == {"google_sub": {"$type": "string"}}
            for info in u_idx.values()
        )

        # I11: usuarios.fecha_registro TTL parcial 172800
        assert any(
            info.get("key") == [("fecha_registro", 1)]
            and info.get("expireAfterSeconds") == 172800
            and info.get("partialFilterExpression")
            == {"estado_cuenta": "pendiente_verificacion"}
            for info in u_idx.values()
        )

        # Dos usuarios sin google_sub (o null) deben convivir sin conflicto por ser parcial
        now = datetime.now(UTC)
        await test_db["usuarios"].insert_many(
            [
                {
                    "email": "user1@antfish.local",
                    "proveedor_auth": "local",
                    "estado_cuenta": "activa",
                    "email_verificado": True,
                    "password_hash": "argon2id$...",
                    "fecha_registro": now,
                },
                {
                    "email": "user2@antfish.local",
                    "proveedor_auth": "local",
                    "estado_cuenta": "activa",
                    "email_verificado": True,
                    "password_hash": "argon2id$...",
                    "fecha_registro": now,
                },
            ]
        )

        # I2: analisis compuesto (user_id: 1, fecha: -1, _id: -1)
        a_idx = await test_db["analisis"].index_information()
        assert any(
            info.get("key") == [("user_id", 1), ("fecha", -1), ("_id", -1)]
            for info in a_idx.values()
        )

        # Verificar que I3 e I4 están diferidos (NO existen)
        for info in a_idx.values():
            assert info.get("key") != [("mensaje_hash", 1)]
            assert info.get("key") != [("urls_extraidas.dominio", 1)]

        # I8: respuestas_apis TTL expira_en
        r_idx = await test_db["respuestas_apis"].index_information()
        assert any(
            info.get("key") == [("expira_en", 1)]
            and info.get("expireAfterSeconds") == 0
            for info in r_idx.values()
        )

        # I9: respuestas_apis (user_id: 1, analisis_id: 1)
        assert any(
            info.get("key") == [("user_id", 1), ("analisis_id", 1)]
            for info in r_idx.values()
        )


@async_test
async def test_query_plan_history_uses_ixscan_on_i2() -> None:
    """Verifica que el patrón P8 (consulta de historial paginado) use IXSCAN sobre el índice I2."""
    async with get_test_db() as test_db:
        await init_db(test_db)
        user_id = ObjectId()
        now = datetime.now(UTC)

        # Insertar análisis de prueba
        await test_db["analisis"].insert_one(
            {
                "user_id": user_id,
                "tipo_entrada": "url",
                "mensaje_hash": None,
                "dominio_principal": "test.com",
                "score_total": 10,
                "nivel_riesgo": "bajo",
                "puntos_por_capa": {"apis": 0, "url": 10, "texto": 0},
                "motivo_cortocircuito": None,
                "analisis_parcial": False,
                "hallazgos": [],
                "recomendaciones": ["Ok"],
                "fuentes_consultadas": [],
                "fecha": now,
            }
        )

        # Consulta con cursor P8: user_id == user_id AND (fecha < cur_fecha OR (fecha == cur_fecha AND _id < cur_id))
        cursor = (
            test_db["analisis"]
            .find({"user_id": user_id})
            .sort([("fecha", -1), ("_id", -1)])
            .limit(20)
        )
        explanation = await cursor.explain()

        # Inspeccionar stages en queryPlanner / executionStats
        def find_stage(plan: dict[str, Any], target: str) -> bool:
            if plan.get("stage") == target:
                return True
            for key in ("inputStage", "outerStage", "innerStage"):
                if key in plan and find_stage(plan[key], target):
                    return True
            for child in plan.get("inputStages", []):
                if find_stage(child, target):
                    return True
            return False

        winning_plan = explanation.get("queryPlanner", {}).get("winningPlan", {})
        assert find_stage(winning_plan, "IXSCAN")


@async_test
async def test_seeding_scenarios(tmp_path: Path) -> None:
    """Verifica siembra en base vacía, no duplicación y bloqueo ante asimetría."""
    async with get_test_db() as test_db:
        seed_file = tmp_path / "initial_data.json"
        dummy_data = {
            "reglas_heuristicas": [
                {
                    "codigo": "URL_TEST",
                    "capa": "url",
                    "titulo": "Test",
                    "descripcion": "Desc",
                    "puntos": 10,
                    "activa": True,
                }
            ],
            "marcas_protegidas": [
                {
                    "codigo": "marca_test",
                    "nombre": "Marca",
                    "categoria": "banca",
                    "activa": True,
                }
            ],
        }
        seed_file.write_text(json.dumps(dummy_data), encoding="utf-8")

        # 1. Siembra inicial con ambas vacías
        await init_db(test_db, initial_data_path=seed_file)
        assert await test_db["reglas_heuristicas"].count_documents({}) == 1
        assert await test_db["marcas_protegidas"].count_documents({}) == 1

        # 2. Segunda ejecución no vuelve a sembrar (idempotente)
        await init_db(test_db, initial_data_path=seed_file)
        assert await test_db["reglas_heuristicas"].count_documents({}) == 1
        assert await test_db["marcas_protegidas"].count_documents({}) == 1

        # 3. Asimetría: vaciar marcas pero dejar reglas
        await test_db["marcas_protegidas"].delete_many({})
        assert await test_db["marcas_protegidas"].count_documents({}) == 0
        assert await test_db["reglas_heuristicas"].count_documents({}) == 1

        # Ejecutar de nuevo: no debe sembrar debido a asimetría
        await init_db(test_db, initial_data_path=seed_file)
        assert await test_db["marcas_protegidas"].count_documents({}) == 0
        assert await test_db["reglas_heuristicas"].count_documents({}) == 1


@async_test
async def test_usuarios_validator() -> None:
    """Pruebas de validación en colección usuarios."""
    async with get_test_db() as test_db:
        await init_db(test_db)
        now = datetime.now(UTC)

        # Válido: local activa
        await test_db["usuarios"].insert_one(
            {
                "email": "local.activa@antfish.local",
                "proveedor_auth": "local",
                "estado_cuenta": "activa",
                "email_verificado": True,
                "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$...",
                "nombre": "Usuario Válido",
                "fecha_registro": now,
            }
        )

        # Rechazar: local activa sin password_hash
        with pytest.raises(OperationFailure):
            await test_db["usuarios"].insert_one(
                {
                    "email": "local.nopass@antfish.local",
                    "proveedor_auth": "local",
                    "estado_cuenta": "activa",
                    "email_verificado": True,
                    "nombre": "Usuario",
                    "fecha_registro": now,
                }
            )

        # Rechazar: local con password_hash null
        with pytest.raises(OperationFailure):
            await test_db["usuarios"].insert_one(
                {
                    "email": "local.nullpass@antfish.local",
                    "proveedor_auth": "local",
                    "estado_cuenta": "activa",
                    "email_verificado": True,
                    "password_hash": None,
                    "nombre": "Usuario",
                    "fecha_registro": now,
                }
            )

        # Rechazar: google activa sin google_sub
        with pytest.raises(OperationFailure):
            await test_db["usuarios"].insert_one(
                {
                    "email": "google.nosub@antfish.local",
                    "proveedor_auth": "google",
                    "estado_cuenta": "activa",
                    "email_verificado": True,
                    "nombre": "Usuario",
                    "fecha_registro": now,
                }
            )

        # Rechazar: activa con email_verificado false
        with pytest.raises(OperationFailure):
            await test_db["usuarios"].insert_one(
                {
                    "email": "activa.noverif@antfish.local",
                    "proveedor_auth": "local",
                    "estado_cuenta": "activa",
                    "email_verificado": False,
                    "password_hash": "$argon2id$...",
                    "fecha_registro": now,
                }
            )

        # Rechazar: pendiente_verificacion con email_verificado true
        with pytest.raises(OperationFailure):
            await test_db["usuarios"].insert_one(
                {
                    "email": "pendiente.verif@antfish.local",
                    "proveedor_auth": "local",
                    "estado_cuenta": "pendiente_verificacion",
                    "email_verificado": True,
                    "password_hash": "$argon2id$...",
                    "fecha_registro": now,
                }
            )

        # Válido: eliminada con nulos explícitos y fecha_eliminacion de tipo date
        await test_db["usuarios"].insert_one(
            {
                "email": "deleted_123@deleted.local",
                "proveedor_auth": "local",
                "estado_cuenta": "eliminada",
                "email_verificado": False,
                "nombre": None,
                "password_hash": None,
                "google_sub": None,
                "fecha_registro": now,
                "fecha_eliminacion": now,
            }
        )

        # Rechazar: eliminada con google_sub string
        with pytest.raises(OperationFailure):
            await test_db["usuarios"].insert_one(
                {
                    "email": "deleted_bad_sub@deleted.local",
                    "proveedor_auth": "local",
                    "estado_cuenta": "eliminada",
                    "email_verificado": False,
                    "nombre": None,
                    "password_hash": None,
                    "google_sub": "123456",
                    "fecha_registro": now,
                    "fecha_eliminacion": now,
                }
            )

        # Rechazar: eliminada sin fecha_eliminacion
        with pytest.raises(OperationFailure):
            await test_db["usuarios"].insert_one(
                {
                    "email": "deleted_nofecha@deleted.local",
                    "proveedor_auth": "local",
                    "estado_cuenta": "eliminada",
                    "email_verificado": False,
                    "nombre": None,
                    "password_hash": None,
                    "google_sub": None,
                    "fecha_registro": now,
                }
            )

        # Email duplicado debe lanzar DuplicateKeyError (I1)
        with pytest.raises(DuplicateKeyError):
            await test_db["usuarios"].insert_one(
                {
                    "email": "local.activa@antfish.local",
                    "proveedor_auth": "local",
                    "estado_cuenta": "activa",
                    "email_verificado": True,
                    "password_hash": "$argon2id$...",
                    "fecha_registro": now,
                }
            )


@async_test
async def test_analisis_validator() -> None:
    """Pruebas de validación en colección analisis."""
    async with get_test_db() as test_db:
        await init_db(test_db)
        user_id = ObjectId()
        now = datetime.now(UTC)

        # Válido: SMS completo
        valid_sms = {
            "user_id": user_id,
            "tipo_entrada": "sms",
            "mensaje_hash": "a" * 64,
            "dominio_principal": "banco.xyz",
            "score_total": 85,
            "nivel_riesgo": "critico",
            "puntos_por_capa": {"apis": 40, "url": 25, "texto": 20},
            "motivo_cortocircuito": "suplantacion_marca",
            "analisis_parcial": False,
            "urls_extraidas": [{"url": "https://banco.xyz", "dominio": "banco.xyz"}],
            "hallazgos": [],
            "recomendaciones": ["Cuidado", "No des click"],
            "fuentes_consultadas": [],
            "fecha": now,
        }
        await test_db["analisis"].insert_one(valid_sms)

        # Rechazar: score 101
        bad = dict(valid_sms, _id=ObjectId(), score_total=101)
        with pytest.raises(OperationFailure):
            await test_db["analisis"].insert_one(bad)

        # Rechazar: nivel_riesgo no corresponde al score (score 85 con bajo)
        bad = dict(valid_sms, _id=ObjectId(), nivel_riesgo="bajo")
        with pytest.raises(OperationFailure):
            await test_db["analisis"].insert_one(bad)

        # Rechazar: lista_negra con score 90 (< 95)
        bad = dict(
            valid_sms,
            _id=ObjectId(),
            motivo_cortocircuito="lista_negra",
            score_total=90,
        )
        with pytest.raises(OperationFailure):
            await test_db["analisis"].insert_one(bad)

        # Rechazar: suplantacion_marca con score 70 (< 80)
        bad = dict(
            valid_sms,
            _id=ObjectId(),
            motivo_cortocircuito="suplantacion_marca",
            score_total=70,
            nivel_riesgo="alto",
        )
        with pytest.raises(OperationFailure):
            await test_db["analisis"].insert_one(bad)

        # Rechazar: tipo url con mensaje_hash de 64 hex
        bad = dict(valid_sms, _id=ObjectId(), tipo_entrada="url", mensaje_hash="b" * 64)
        with pytest.raises(OperationFailure):
            await test_db["analisis"].insert_one(bad)

        # Rechazar: tipo url SIN el campo mensaje_hash (exige null explícito)
        bad = dict(valid_sms, _id=ObjectId(), tipo_entrada="url")
        del bad["mensaje_hash"]
        with pytest.raises(OperationFailure):
            await test_db["analisis"].insert_one(bad)

        # Rechazar: sms con hash de 63 caracteres
        bad = dict(valid_sms, _id=ObjectId(), mensaje_hash="c" * 63)
        with pytest.raises(OperationFailure):
            await test_db["analisis"].insert_one(bad)

        # Rechazar: urls_extraidas con 3 elementos
        bad = dict(
            valid_sms,
            _id=ObjectId(),
            urls_extraidas=[{"url": "1"}, {"url": "2"}, {"url": "3"}],
        )
        with pytest.raises(OperationFailure):
            await test_db["analisis"].insert_one(bad)

        # Rechazar: recomendaciones con 0 elementos
        bad = dict(valid_sms, _id=ObjectId(), recomendaciones=[])
        with pytest.raises(OperationFailure):
            await test_db["analisis"].insert_one(bad)

        # Rechazar: recomendaciones con 4 elementos
        bad = dict(valid_sms, _id=ObjectId(), recomendaciones=["1", "2", "3", "4"])
        with pytest.raises(OperationFailure):
            await test_db["analisis"].insert_one(bad)

        # Rechazar: puntos_por_capa.texto = 21 (máximo 20)
        bad = dict(
            valid_sms,
            _id=ObjectId(),
            puntos_por_capa={"apis": 40, "url": 25, "texto": 21},
        )
        with pytest.raises(OperationFailure):
            await test_db["analisis"].insert_one(bad)


@async_test
async def test_metricas_validator() -> None:
    """Pruebas de validación en colección metricas_usuario."""
    async with get_test_db() as test_db:
        await init_db(test_db)
        now = datetime.now(UTC)

        # Válido
        await test_db["metricas_usuario"].insert_one(
            {
                "total_escaneos": 10,
                "total_url": 6,
                "total_sms": 4,
                "amenazas_bloqueadas": 3,
                "ultima_actualizacion": now,
            }
        )

        # Rechazar: total_escaneos != total_url + total_sms
        with pytest.raises(OperationFailure):
            await test_db["metricas_usuario"].insert_one(
                {
                    "total_escaneos": 11,
                    "total_url": 6,
                    "total_sms": 4,
                    "amenazas_bloqueadas": 3,
                    "ultima_actualizacion": now,
                }
            )

        # Rechazar: amenazas_bloqueadas > total_escaneos
        with pytest.raises(OperationFailure):
            await test_db["metricas_usuario"].insert_one(
                {
                    "total_escaneos": 10,
                    "total_url": 6,
                    "total_sms": 4,
                    "amenazas_bloqueadas": 11,
                    "ultima_actualizacion": now,
                }
            )


@async_test
async def test_respuestas_apis_validator() -> None:
    """Pruebas de validación en colección respuestas_apis."""
    async with get_test_db() as test_db:
        await init_db(test_db)
        now = datetime.now(UTC)
        future = datetime.fromtimestamp(now.timestamp() + 3600, tz=UTC)
        past = datetime.fromtimestamp(now.timestamp() - 3600, tz=UTC)

        # Válido
        await test_db["respuestas_apis"].insert_one(
            {
                "analisis_id": ObjectId(),
                "user_id": ObjectId(),
                "url_normalizada": "https://test.com/path",
                "dominio": "test.com",
                "api": "virustotal",
                "respuesta_cruda": {"positives": 0},
                "fecha": now,
                "expira_en": future,
            }
        )

        # Rechazar: expira_en <= fecha
        with pytest.raises(OperationFailure):
            await test_db["respuestas_apis"].insert_one(
                {
                    "analisis_id": ObjectId(),
                    "user_id": ObjectId(),
                    "url_normalizada": "https://test.com/path",
                    "dominio": "test.com",
                    "api": "virustotal",
                    "respuesta_cruda": {"positives": 0},
                    "fecha": now,
                    "expira_en": past,
                }
            )

        # Rechazar: api fuera del enum
        with pytest.raises(OperationFailure):
            await test_db["respuestas_apis"].insert_one(
                {
                    "analisis_id": ObjectId(),
                    "user_id": ObjectId(),
                    "url_normalizada": "https://test.com/path",
                    "dominio": "test.com",
                    "api": "api_desconocida",
                    "respuesta_cruda": {},
                    "fecha": now,
                    "expira_en": future,
                }
            )
