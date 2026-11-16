"""Servicio de orquestación para el análisis de URLs y SMS (RF-02, RF-03).

Coordina:
1. Extracción de URLs en RAM (url_extractor).
2. Evaluación de heurísticas de texto para SMS (text_heuristics).
3. Evaluación de heurísticas sintácticas y selección de hasta 2 URLs (url_heuristics).
4. Consultas paralelas concurrentes a Google Web Risk, VirusTotal y PhishTank (asyncio.gather).
5. Consolidación de puntuación, cortocircuitos y recomendaciones (scoring, risk_levels, recommendations).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

from bson import ObjectId
from pymongo.errors import PyMongoError
from redis.exceptions import RedisError

from app.clients.base import ReputationResult
from app.clients.google_web_risk import GoogleWebRiskClient
from app.clients.phishtank import PhishTankClient
from app.clients.virustotal import VirusTotalClient
from app.core.config import settings
from app.core.exceptions import AnalysisNotFoundError, PersistenceError
from app.core.logging import logger
from app.core.security import generate_message_hmac
from app.engine.models import (
    CircuitBreakerReason,
    Finding,
    Reputation,
    RiskLevel,
    SourceStatus,
    UrlFeatures,
)
from app.engine.recommendations import generate_recommendations
from app.engine.risk_levels import get_risk_level
from app.engine.scoring import consolidate_score, evaluate_api_reputations
from app.engine.url_extractor import extract_urls_from_text, normalize_url
from app.engine.url_heuristics import select_top_urls
from app.repositories.mongo.analysis_repository import AnalysisRepository
from app.repositories.mongo.metrics_repository import MetricsRepository
from app.repositories.mongo.unit_of_work import UnitOfWork
from app.repositories.redis.quota_repository import QuotaRepository

API_RESPONSE_TTL_DAYS = 30


class AnalysisService:
    """Servicio de aplicación para análisis de amenazas en SMS y URLs."""

    def __init__(
        self,
        web_risk_client: GoogleWebRiskClient,
        virustotal_client: VirusTotalClient,
        phishtank_client: PhishTankClient,
        analysis_repository: AnalysisRepository | None = None,
        metrics_repository: MetricsRepository | None = None,
        unit_of_work: UnitOfWork | None = None,
        quota_repository: QuotaRepository | None = None,
    ) -> None:
        self.web_risk_client = web_risk_client
        self.virustotal_client = virustotal_client
        self.phishtank_client = phishtank_client
        self._analysis_repo = analysis_repository
        self._metrics_repo = metrics_repository
        self._uow = unit_of_work
        self._quota_repo = quota_repository

    async def _consume_quota(self, api: str) -> bool:
        """Consume cuota local de la API; fail-open si Redis no responde (RNF-02)."""
        if self._quota_repo is None:
            return True
        per_minute, daily = settings.quota_limits()[api]
        try:
            return await self._quota_repo.try_consume(api, per_minute, daily)
        except RedisError as exc:
            logger.warning(f"Control de cuota no disponible (fail-open): {type(exc).__name__}")
            return True

    @staticmethod
    async def _quota_exhausted(api: str) -> ReputationResult:
        """Resultado degradado cuando la cuota local de la API está agotada (RN-13)."""
        return ReputationResult(
            reputation=Reputation(
                api=api,
                estado=SourceStatus.RATE_LIMIT,
                positivo=False,
                detecciones=None,
                desde_cache=False,
            )
        )

    async def _query_external_apis_for_url(
        self,
        url: str,
    ) -> tuple[list[Reputation], bool, dict[str, Any]]:
        """Ejecuta consultas concurrentes a las 3 APIs de reputación para una URL dada.

        Returns:
            Tupla (reputaciones, tiene_fallos, respuestas_crudas): modelos Reputation, un
            booleano que indica si alguna API degradó a timeout/rate_limit/error y las
            respuestas crudas por API (solo las no nulas) para auditoría (D1).
        """
        api_names = ["google_web_risk", "virustotal", "phishtank"]
        check_fns = [
            self.web_risk_client.check_url,
            self.virustotal_client.check_url,
            self.phishtank_client.check_url,
        ]

        # Cuota dual atómica por API (P5): sin cuota -> estado rate_limit sin llamar a la API.
        permits = await asyncio.gather(*(self._consume_quota(n) for n in api_names))
        tasks = [
            fn(url) if allowed else self._quota_exhausted(name)
            for fn, name, allowed in zip(check_fns, api_names, permits)
        ]

        # Consultas paralelas concurrentes mediante asyncio.gather (RF-02.2)
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        reputations: list[Reputation] = []
        raw_by_api: dict[str, Any] = {}
        tiene_fallos = False

        for idx, item in enumerate(raw_results):
            api_name = api_names[idx]
            if isinstance(item, Exception):
                logger.warning(
                    f"Excepción al consultar API {api_name}: {type(item).__name__}"
                )
                reputations.append(
                    Reputation(
                        api=api_name,
                        estado=SourceStatus.ERROR,
                        positivo=False,
                        detecciones=None,
                        desde_cache=False,
                    )
                )
                tiene_fallos = True
            elif isinstance(item, ReputationResult):
                reputations.append(item.reputation)
                if item.raw_response is not None:
                    raw_by_api[api_name] = item.raw_response
                if item.reputation.estado != SourceStatus.OK:
                    tiene_fallos = True
            else:
                reputations.append(
                    Reputation(
                        api=api_name,
                        estado=SourceStatus.ERROR,
                        positivo=False,
                        detecciones=None,
                        desde_cache=False,
                    )
                )
                tiene_fallos = True

        return reputations, tiene_fallos, raw_by_api

    async def analyze(
        self,
        tipo_entrada: str,
        contenido: str,
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """RF-02, RF-03 y RF-05.1: analiza y, si hay usuario autenticado, persiste el resultado."""
        result, api_responses = await self._analyze_core(tipo_entrada, contenido)
        if user_id is not None and self._uow is not None:
            result["id"] = await self._persist(user_id, result, api_responses)
        return result

    async def _analyze_core(
        self,
        tipo_entrada: str,
        contenido: str,
    ) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
        """RF-02 & RF-03: Orquesta el flujo completo de análisis de SMS o URL.

        Args:
            tipo_entrada: 'sms' o 'url'.
            contenido: Texto del mensaje SMS o URL a evaluar.

        Returns:
            (resultado conforme a AnalysisResponse, respuestas crudas {url: {api: raw}}).
        """
        now = datetime.now(timezone.utc)
        analisis_parcial = False
        api_responses: dict[str, dict[str, Any]] = {}

        # 1. Tratamiento del texto y Capa 3 (Heurísticas de Texto)
        if tipo_entrada == "sms":
            mensaje_hash: str | None = generate_message_hmac(contenido)
            from app.engine.text_heuristics import analyze_text

            text_findings: list[Finding] = analyze_text(contenido)
            puntos_texto = min(20, sum(f.puntos for f in text_findings))
            raw_urls = extract_urls_from_text(contenido)
        else:  # tipo_entrada == "url"
            mensaje_hash = None
            text_findings = []
            puntos_texto = 0
            normalized_direct = normalize_url(contenido)
            raw_urls = [normalized_direct] if normalized_direct else []

        # 2. Selección de URLs y Capa 2 (Heurísticas Sintácticas)
        selected_url_features: list[UrlFeatures] = (
            select_top_urls(raw_urls) if raw_urls else []
        )

        # Caso especial: SMS sin URLs detectadas
        if not selected_url_features:
            score_total = puntos_texto
            nivel_riesgo = get_risk_level(score_total)
            recommendations = generate_recommendations(nivel_riesgo, text_findings)

            return {
                "id": None,
                "tipo_entrada": tipo_entrada,
                "mensaje_hash": mensaje_hash,
                "urls_extraidas": [],
                "dominio_principal": "sin-url",
                "score_total": score_total,
                "nivel_riesgo": nivel_riesgo.value,
                "puntos_por_capa": {
                    "apis": 0,
                    "url": 0,
                    "texto": puntos_texto,
                },
                "motivo_cortocircuito": None,
                "analisis_parcial": False,
                "hallazgos": [
                    {
                        "regla_codigo": f.regla_codigo,
                        "titulo": f.titulo,
                        "descripcion": f.descripcion,
                        "puntos": f.puntos,
                    }
                    for f in text_findings
                ],
                "recomendaciones": recommendations,
                "fuentes_consultadas": [],
                "fecha": now,
            }, api_responses

        # 3. Consultas paralelas a las APIs externas para cada una de las hasta 2 URLs
        urls_reputations: list[list[Reputation]] = []
        for feat in selected_url_features:
            reps, api_fallo, raw_by_api = await self._query_external_apis_for_url(
                feat.url
            )
            urls_reputations.append(reps)
            api_responses[feat.url] = raw_by_api
            if api_fallo:
                analisis_parcial = True

        # 4. Evaluación de Capa 1 y selección de la URL dominante
        # Cada URL se evalúa combinando puntos de APIs + puntos sintácticos
        url_evaluations: list[
            tuple[
                UrlFeatures,
                int,  # puntos_apis
                list[Finding],  # hallazgos_api
                bool,  # es_lista_negra
                list[Reputation],  # fuentes_consultadas
                int,  # riesgo_combinado para definir dominante
            ]
        ] = []

        for idx, feat in enumerate(selected_url_features):
            reps = urls_reputations[idx]
            puntos_apis, api_findings, es_ln = evaluate_api_reputations(reps)
            riesgo_combinado = puntos_apis + feat.puntos_sintacticos
            url_evaluations.append(
                (feat, puntos_apis, api_findings, es_ln, reps, riesgo_combinado)
            )

        # La URL dominante es la de mayor riesgo combinado (APIs + sintaxis)
        url_evaluations.sort(key=lambda item: item[5], reverse=True)
        dominant_eval = url_evaluations[0]

        dominant_feat = dominant_eval[0]
        puntos_apis = dominant_eval[1]
        api_findings = dominant_eval[2]
        es_lista_negra = dominant_eval[3]
        dominant_reputations = dominant_eval[4]

        # Verificar si alguna de las URLs analizadas disparó cortocircuito por lista negra
        any_lista_negra = any(ev[3] for ev in url_evaluations)
        tiene_suplantacion_marca = dominant_feat.marca_detectada is not None

        # 5. Consolidación de Puntuación (ScoreResult)
        score_total, motivo_cortocircuito = consolidate_score(
            puntos_apis=puntos_apis,
            puntos_url=dominant_feat.puntos_sintacticos,
            puntos_texto=puntos_texto,
            es_lista_negra=any_lista_negra,
            tiene_suplantacion_marca=tiene_suplantacion_marca,
        )

        nivel_riesgo = get_risk_level(score_total)

        # Consolidar todos los hallazgos de la URL dominante + texto
        all_findings: list[Finding] = (
            api_findings + dominant_feat.hallazgos + text_findings
        )
        recommendations = generate_recommendations(nivel_riesgo, all_findings)

        # Estructurar urls_extraidas
        urls_extraidas_data = [
            {
                "url": feat.url,
                "dominio": feat.dominio,
                "flags_sintacticos": feat.flags_sintacticos,
            }
            for feat in selected_url_features
        ]

        result: dict[str, Any] = {
            "id": None,
            "tipo_entrada": tipo_entrada,
            "mensaje_hash": mensaje_hash,
            "urls_extraidas": urls_extraidas_data,
            "dominio_principal": dominant_feat.dominio,
            "score_total": score_total,
            "nivel_riesgo": nivel_riesgo.value,
            "puntos_por_capa": {
                "apis": puntos_apis,
                "url": dominant_feat.puntos_sintacticos,
                "texto": puntos_texto,
            },
            "motivo_cortocircuito": (
                motivo_cortocircuito.value if motivo_cortocircuito else None
            ),
            "analisis_parcial": analisis_parcial,
            "hallazgos": [
                {
                    "regla_codigo": f.regla_codigo,
                    "titulo": f.titulo,
                    "descripcion": f.descripcion,
                    "puntos": f.puntos,
                }
                for f in all_findings
            ],
            "recomendaciones": recommendations,
            "fuentes_consultadas": [
                {
                    "api": r.api,
                    "estado": r.estado.value,
                    "positivo": r.positivo,
                    "detecciones": r.detecciones,
                    "desde_cache": r.desde_cache,
                }
                for r in dominant_reputations
            ],
            "fecha": now,
        }

        return result, api_responses

    async def _persist(
        self,
        user_id: str,
        result: dict[str, Any],
        api_responses: dict[str, dict[str, Any]],
    ) -> str:
        """RF-05.1: analisis + respuestas_apis + $inc de métricas en una transacción ACID (P6, P7)."""
        assert self._uow is not None
        assert self._analysis_repo is not None
        assert self._metrics_repo is not None

        uid = ObjectId(user_id)
        document = {
            "user_id": uid,
            "tipo_entrada": result["tipo_entrada"],
            "mensaje_hash": result["mensaje_hash"],
            "urls_extraidas": result["urls_extraidas"],
            "dominio_principal": result["dominio_principal"],
            "score_total": result["score_total"],
            "nivel_riesgo": result["nivel_riesgo"],
            "puntos_por_capa": result["puntos_por_capa"],
            "motivo_cortocircuito": result["motivo_cortocircuito"],
            "analisis_parcial": result["analisis_parcial"],
            "hallazgos": result["hallazgos"],
            "recomendaciones": result["recomendaciones"],
            "fuentes_consultadas": result["fuentes_consultadas"],
            "fecha": result["fecha"],
        }
        es_amenaza = result["nivel_riesgo"] in ("alto", "critico")
        domain_by_url = {u["url"]: u["dominio"] for u in result["urls_extraidas"]}

        try:
            async with self._uow.transaction() as session:
                analysis_id = await self._analysis_repo.insert_analysis(document, session)
                raw_docs = [
                    {
                        "analisis_id": analysis_id,
                        "user_id": uid,
                        "url_normalizada": url,
                        "dominio": domain_by_url.get(url, ""),
                        "api": api,
                        "respuesta_cruda": raw if isinstance(raw, dict) else {"data": raw},
                        "fecha": result["fecha"],
                        "expira_en": result["fecha"] + timedelta(days=API_RESPONSE_TTL_DAYS),
                    }
                    for url, by_api in api_responses.items()
                    for api, raw in by_api.items()
                ]
                await self._analysis_repo.insert_api_responses(raw_docs, session)
                await self._metrics_repo.increment(
                    uid, result["tipo_entrada"], es_amenaza, session
                )
        except PyMongoError as exc:
            logger.error(f"Fallo de persistencia del análisis: {type(exc).__name__}")
            raise PersistenceError() from exc
        return str(analysis_id)

    @staticmethod
    def _to_response(doc: dict[str, Any]) -> dict[str, Any]:
        """Convierte un documento de analisis al formato de AnalysisResponse."""
        fecha = doc["fecha"]
        if fecha.tzinfo is None:
            fecha = fecha.replace(tzinfo=timezone.utc)
        return {
            "id": str(doc["_id"]),
            "tipo_entrada": doc["tipo_entrada"],
            "mensaje_hash": doc.get("mensaje_hash"),
            "urls_extraidas": doc.get("urls_extraidas", []),
            "dominio_principal": doc["dominio_principal"],
            "score_total": doc["score_total"],
            "nivel_riesgo": doc["nivel_riesgo"],
            "puntos_por_capa": doc["puntos_por_capa"],
            "motivo_cortocircuito": doc.get("motivo_cortocircuito"),
            "analisis_parcial": doc["analisis_parcial"],
            "hallazgos": doc.get("hallazgos", []),
            "recomendaciones": doc.get("recomendaciones", []),
            "fuentes_consultadas": doc.get("fuentes_consultadas", []),
            "fecha": fecha,
        }

    async def list_history(
        self, user_id: str, cursor: str | None = None
    ) -> tuple[list[dict[str, Any]], str | None]:
        """RF-05.1 / O9: historial paginado (20 por página) con cursor opaco."""
        assert self._analysis_repo is not None
        docs, next_cursor = await self._analysis_repo.list_history(user_id, cursor)
        return [self._to_response(d) for d in docs], next_cursor

    async def get_detail(self, user_id: str, analysis_id: str) -> dict[str, Any]:
        """O10: detalle de un análisis propio; 404 si no existe o no pertenece al usuario."""
        assert self._analysis_repo is not None
        doc = await self._analysis_repo.find_by_id_and_user(analysis_id, user_id)
        if doc is None:
            raise AnalysisNotFoundError()
        return self._to_response(doc)

    async def delete_analysis(self, user_id: str, analysis_id: str) -> None:
        """O11: borra análisis y respuestas crudas en transacción ACID, sin alterar métricas."""
        assert self._analysis_repo is not None
        assert self._uow is not None
        doc = await self._analysis_repo.find_by_id_and_user(analysis_id, user_id)
        if doc is None:
            raise AnalysisNotFoundError()
        try:
            async with self._uow.transaction() as session:
                await self._analysis_repo.delete_analysis(
                    doc["_id"], ObjectId(user_id), session
                )
        except PyMongoError as exc:
            logger.error(f"Fallo al borrar el análisis: {type(exc).__name__}")
            raise PersistenceError() from exc
