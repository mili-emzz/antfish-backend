"""Inicialización idempotente de MongoDB para AntFish.

Implementa la creación de colecciones con $jsonSchema + $expr, sincronización
de validadores (collMod), creación de índices (I1, I2, I5 a I11) y siembra
condicional de initial_data.json según ADR #51, #52, #54, #55, #57, #58, #59, #61, #65, #69.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pymongo.asynchronous.database import AsyncDatabase
from pymongo.operations import IndexModel

from app.core.logging import logger

VALIDATORS: dict[str, dict[str, Any]] = {
    "usuarios": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": [
                "email",
                "proveedor_auth",
                "estado_cuenta",
                "email_verificado",
                "fecha_registro",
            ],
            "properties": {
                "email": {"bsonType": "string"},
                "proveedor_auth": {"enum": ["local", "google"]},
                "estado_cuenta": {
                    "enum": [
                        "pendiente_verificacion",
                        "activa",
                        "suspendida",
                        "eliminada",
                    ]
                },
                "email_verificado": {"bsonType": "bool"},
                "fecha_registro": {"bsonType": "date"},
                "fecha_verificacion": {"bsonType": ["date", "null"]},
                "password_changed_at": {"bsonType": ["date", "null"]},
                "fecha_eliminacion": {"bsonType": ["date", "null"]},
            },
        },
        "$expr": {
            "$and": [
                {
                    "$cond": [
                        {
                            "$and": [
                                {"$eq": ["$proveedor_auth", "local"]},
                                {"$ne": ["$estado_cuenta", "eliminada"]},
                            ]
                        },
                        {"$eq": [{"$type": "$password_hash"}, "string"]},
                        True,
                    ]
                },
                {
                    "$cond": [
                        {
                            "$and": [
                                {"$eq": ["$proveedor_auth", "google"]},
                                {"$ne": ["$estado_cuenta", "eliminada"]},
                            ]
                        },
                        {"$eq": [{"$type": "$google_sub"}, "string"]},
                        True,
                    ]
                },
                {
                    "$cond": [
                        {"$eq": ["$estado_cuenta", "activa"]},
                        {"$eq": ["$email_verificado", True]},
                        True,
                    ]
                },
                {
                    "$cond": [
                        {"$eq": ["$estado_cuenta", "pendiente_verificacion"]},
                        {"$eq": ["$email_verificado", False]},
                        True,
                    ]
                },
                {
                    "$cond": [
                        {"$eq": ["$estado_cuenta", "eliminada"]},
                        {
                            "$and": [
                                {"$eq": [{"$type": "$nombre"}, "null"]},
                                {"$eq": [{"$type": "$password_hash"}, "null"]},
                                {"$eq": [{"$type": "$google_sub"}, "null"]},
                                {"$eq": ["$email_verificado", False]},
                                {
                                    "$eq": [
                                        {"$type": "$fecha_eliminacion"},
                                        "date",
                                    ]
                                },
                            ]
                        },
                        True,
                    ]
                },
            ]
        },
    },
    "analisis": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": [
                "user_id",
                "tipo_entrada",
                "dominio_principal",
                "score_total",
                "nivel_riesgo",
                "puntos_por_capa",
                "analisis_parcial",
                "hallazgos",
                "recomendaciones",
                "fuentes_consultadas",
                "fecha",
            ],
            "properties": {
                "score_total": {
                    "bsonType": ["int", "long"],
                    "minimum": 0,
                    "maximum": 100,
                },
                "nivel_riesgo": {"enum": ["bajo", "medio", "alto", "critico"]},
                "tipo_entrada": {"enum": ["sms", "url"]},
                "motivo_cortocircuito": {
                    "enum": ["lista_negra", "suplantacion_marca", None]
                },
                "analisis_parcial": {"bsonType": "bool"},
                "urls_extraidas": {"bsonType": "array", "maxItems": 2},
                "recomendaciones": {
                    "bsonType": "array",
                    "minItems": 1,
                    "maxItems": 3,
                },
                "puntos_por_capa": {
                    "bsonType": "object",
                    "required": ["apis", "url", "texto"],
                    "properties": {
                        "apis": {
                            "bsonType": ["int", "long"],
                            "minimum": 0,
                            "maximum": 60,
                        },
                        "url": {
                            "bsonType": ["int", "long"],
                            "minimum": 0,
                            "maximum": 30,
                        },
                        "texto": {
                            "bsonType": ["int", "long"],
                            "minimum": 0,
                            "maximum": 20,
                        },
                    },
                },
            },
        },
        "$expr": {
            "$and": [
                {
                    "$cond": [
                        {"$eq": ["$tipo_entrada", "sms"]},
                        {
                            "$regexMatch": {
                                "input": "$mensaje_hash",
                                "regex": "^[a-f0-9]{64}$",
                            }
                        },
                        {"$eq": [{"$type": "$mensaje_hash"}, "null"]},
                    ]
                },
                {
                    "$cond": [
                        {"$lt": ["$score_total", 20]},
                        {"$eq": ["$nivel_riesgo", "bajo"]},
                        {
                            "$cond": [
                                {"$lt": ["$score_total", 50]},
                                {"$eq": ["$nivel_riesgo", "medio"]},
                                {
                                    "$cond": [
                                        {"$lt": ["$score_total", 80]},
                                        {"$eq": ["$nivel_riesgo", "alto"]},
                                        {"$eq": ["$nivel_riesgo", "critico"]},
                                    ]
                                },
                            ]
                        },
                    ]
                },
                {
                    "$cond": [
                        {"$eq": ["$motivo_cortocircuito", "lista_negra"]},
                        {"$gte": ["$score_total", 95]},
                        True,
                    ]
                },
                {
                    "$cond": [
                        {
                            "$eq": [
                                "$motivo_cortocircuito",
                                "suplantacion_marca",
                            ]
                        },
                        {"$gte": ["$score_total", 80]},
                        True,
                    ]
                },
            ]
        },
    },
    "metricas_usuario": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": [
                "total_escaneos",
                "total_url",
                "total_sms",
                "amenazas_bloqueadas",
                "ultima_actualizacion",
            ],
            "properties": {
                "total_escaneos": {
                    "bsonType": ["int", "long"],
                    "minimum": 0,
                },
                "total_url": {
                    "bsonType": ["int", "long"],
                    "minimum": 0,
                },
                "total_sms": {
                    "bsonType": ["int", "long"],
                    "minimum": 0,
                },
                "amenazas_bloqueadas": {
                    "bsonType": ["int", "long"],
                    "minimum": 0,
                },
                "ultima_actualizacion": {"bsonType": "date"},
            },
        },
        "$expr": {
            "$and": [
                {
                    "$eq": [
                        "$total_escaneos",
                        {"$add": ["$total_url", "$total_sms"]},
                    ]
                },
                {"$lte": ["$amenazas_bloqueadas", "$total_escaneos"]},
            ]
        },
    },
    "respuestas_apis": {
        "$jsonSchema": {
            "bsonType": "object",
            "required": [
                "analisis_id",
                "user_id",
                "url_normalizada",
                "dominio",
                "api",
                "respuesta_cruda",
                "fecha",
                "expira_en",
            ],
            "properties": {
                "api": {"enum": ["google_web_risk", "virustotal", "phishtank"]},
                "url_normalizada": {"bsonType": "string"},
                "dominio": {"bsonType": "string"},
                "fecha": {"bsonType": "date"},
                "expira_en": {"bsonType": "date"},
            },
        },
        "$expr": {"$gt": ["$expira_en", "$fecha"]},
    },
}

INDEX_MODELS: dict[str, list[IndexModel]] = {
    "usuarios": [
        IndexModel([("email", 1)], name="idx_usuarios_email_unique", unique=True),
        IndexModel(
            [("google_sub", 1)],
            name="idx_usuarios_google_sub_partial",
            unique=True,
            partialFilterExpression={"google_sub": {"$type": "string"}},
        ),
        IndexModel(
            [("fecha_registro", 1)],
            name="idx_usuarios_pendientes_ttl",
            expireAfterSeconds=172800,
            partialFilterExpression={"estado_cuenta": "pendiente_verificacion"},
        ),
    ],
    "analisis": [
        IndexModel(
            [("user_id", 1), ("fecha", -1), ("_id", -1)],
            name="idx_analisis_user_fecha_id",
        )
    ],
    "reglas_heuristicas": [
        IndexModel([("codigo", 1)], name="idx_reglas_codigo_unique", unique=True),
        IndexModel([("activa", 1), ("capa", 1)], name="idx_reglas_activa_capa"),
    ],
    "marcas_protegidas": [
        IndexModel([("codigo", 1)], name="idx_marcas_codigo_unique", unique=True)
    ],
    "respuestas_apis": [
        IndexModel(
            [("expira_en", 1)],
            name="idx_respuestas_apis_expira_ttl",
            expireAfterSeconds=0,
        ),
        IndexModel(
            [("user_id", 1), ("analisis_id", 1)],
            name="idx_respuestas_apis_user_analisis",
        ),
    ],
}


async def _sync_collection_validator(
    db: AsyncDatabase[Mapping[str, Any]],
    col_name: str,
    validator: dict[str, Any] | None,
    existing_collections: set[str],
) -> None:
    """Crea la colección con su validador o la actualiza vía collMod de forma idempotente."""
    if col_name not in existing_collections:
        create_kwargs: dict[str, Any] = {}
        if validator is not None:
            create_kwargs = {
                "validator": validator,
                "validationLevel": "strict",
                "validationAction": "error",
            }
        await db.create_collection(col_name, **create_kwargs)
        logger.info("Colección creada", extra={"collection": col_name})
    else:
        if validator is not None:
            await db.command(
                {
                    "collMod": col_name,
                    "validator": validator,
                    "validationLevel": "strict",
                    "validationAction": "error",
                }
            )
            logger.info(
                "Validador sincronizado con collMod", extra={"collection": col_name}
            )


def _keys_match(
    model_keys: list[tuple[str, Any]],
    existing_key_doc: Mapping[str, Any],
) -> bool:
    """Compara si la secuencia de campos y ordenes coincide exactamente."""
    existing_items = list(existing_key_doc.items())
    if len(model_keys) != len(existing_items):
        return False
    for (k1, v1), (k2, v2) in zip(model_keys, existing_items, strict=False):
        if k1 != k2 or v1 != v2:
            return False
    return True


async def _sync_collection_indexes(
    db: AsyncDatabase[Mapping[str, Any]],
    col_name: str,
    models: list[IndexModel],
) -> None:
    """Sincroniza índices: crea nuevos, actualiza TTL con collMod o falla si hay conflicto de opciones."""
    col = db[col_name]
    existing_indexes: dict[str, Any] = await col.index_information()

    for model in models:
        model_name = model.name
        model_document = model.document
        model_keys = model_document["key"]
        model_options = {
            k: v for k, v in model_document.items() if k not in ("key", "name", "v")
        }

        # Buscar si ya existe un índice con las mismas claves
        matching_existing_name: str | None = None
        for ex_name, ex_info in existing_indexes.items():
            if _keys_match(model_keys, ex_info["key"]):
                matching_existing_name = ex_name
                break

        if matching_existing_name is None:
            await col.create_indexes([model])
            logger.info(
                "Índice creado",
                extra={"collection": col_name, "index": model_name},
            )
            continue

        ex_info = existing_indexes[matching_existing_name]
        is_ttl_model = "expireAfterSeconds" in model_options

        if is_ttl_model:
            ex_ttl = ex_info.get("expireAfterSeconds")
            req_ttl = model_options["expireAfterSeconds"]
            ex_partial = ex_info.get("partialFilterExpression")
            req_partial = model_options.get("partialFilterExpression")

            if ex_partial != req_partial:
                raise ValueError(
                    f"Conflicto de índice en {col_name}.{matching_existing_name}: "
                    f"partialFilterExpression existente {ex_partial} no coincide con {req_partial}"
                )

            if ex_ttl != req_ttl:
                await db.command(
                    {
                        "collMod": col_name,
                        "index": {
                            "name": matching_existing_name,
                            "expireAfterSeconds": req_ttl,
                        },
                    }
                )
                logger.info(
                    "TTL actualizado mediante collMod",
                    extra={
                        "collection": col_name,
                        "index": matching_existing_name,
                        "expireAfterSeconds": req_ttl,
                    },
                )
        else:
            ex_unique = ex_info.get("unique", False)
            req_unique = model_options.get("unique", False)
            ex_partial = ex_info.get("partialFilterExpression")
            req_partial = model_options.get("partialFilterExpression")

            if ex_unique != req_unique or ex_partial != req_partial:
                raise ValueError(
                    f"Conflicto de opciones en índice {col_name}.{matching_existing_name}: "
                    f"existente {ex_info} vs requerido {model_options}"
                )


async def _seed_data_if_needed(
    db: AsyncDatabase[Mapping[str, Any]],
    initial_data_path: Path,
) -> None:
    """Siembra reglas_heuristicas y marcas_protegidas si y solo si ambas están vacías."""
    count_reglas = await db["reglas_heuristicas"].count_documents({})
    count_marcas = await db["marcas_protegidas"].count_documents({})

    if count_reglas > 0 and count_marcas > 0:
        logger.info("Siembra omitida: ambas colecciones ya contienen datos")
        return

    if (count_reglas == 0 and count_marcas > 0) or (
        count_reglas > 0 and count_marcas == 0
    ):
        logger.warning(
            "Siembra no ejecutada: asimetría en colecciones de reglas y marcas (una vacía y otra no)",
            extra={"count_reglas": count_reglas, "count_marcas": count_marcas},
        )
        return

    # Ambas están en 0
    if not initial_data_path.exists():
        logger.warning(
            "Archivo de siembra no encontrado, siembra omitida",
            extra={"path": str(initial_data_path)},
        )
        return

    try:
        raw_data = initial_data_path.read_text(encoding="utf-8")
        data = json.loads(raw_data)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Error al leer initial_data.json, siembra omitida",
            extra={"error": str(exc)},
        )
        return

    reglas = data.get("reglas_heuristicas", [])
    marcas = data.get("marcas_protegidas", [])

    if not reglas and not marcas:
        logger.warning("initial_data.json no contiene reglas ni marcas para sembrar")
        return

    if reglas:
        await db["reglas_heuristicas"].insert_many(reglas)
    if marcas:
        await db["marcas_protegidas"].insert_many(marcas)

    logger.info(
        "Siembra inicial completada exitosamente",
        extra={"reglas_insertadas": len(reglas), "marcas_insertadas": len(marcas)},
    )


async def init_db(
    db: AsyncDatabase[Mapping[str, Any]],
    initial_data_path: Path | None = None,
) -> None:
    """Inicializa de forma idempotente las colecciones, validadores, índices y siembra de MongoDB."""
    all_collections = [
        "usuarios",
        "analisis",
        "metricas_usuario",
        "reglas_heuristicas",
        "marcas_protegidas",
        "respuestas_apis",
    ]

    existing = set(await db.list_collection_names())

    # 1. Colecciones y validadores
    for col_name in all_collections:
        validator = VALIDATORS.get(col_name)
        await _sync_collection_validator(db, col_name, validator, existing)

    # 2. Índices
    for col_name, models in INDEX_MODELS.items():
        await _sync_collection_indexes(db, col_name, models)

    # 3. Siembra condicional
    seed_path = initial_data_path or Path(__file__).parent / "initial_data.json"
    await _seed_data_if_needed(db, seed_path)
