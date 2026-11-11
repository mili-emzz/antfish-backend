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
from datetime import datetime, timezone
from typing import Any

from app.clients.base import ReputationResult
from app.clients.google_web_risk import GoogleWebRiskClient
from app.clients.phishtank import PhishTankClient
from app.clients.virustotal import VirusTotalClient
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


class AnalysisService:
    """Servicio de aplicación para análisis de amenazas en SMS y URLs."""

    def __init__(
        self,
        web_risk_client: GoogleWebRiskClient,
        virustotal_client: VirusTotalClient,
        phishtank_client: PhishTankClient,
    ) -> None:
        self.web_risk_client = web_risk_client
        self.virustotal_client = virustotal_client
        self.phishtank_client = phishtank_client

    async def _query_external_apis_for_url(
        self,
        url: str,
    ) -> tuple[list[Reputation], bool]:
        """Ejecuta consultas concurrentes a las 3 APIs de reputación para una URL dada.

        Returns:
            Tupla (reputaciones, tiene_fallos): lista de modelos Reputation y un booleano
            que indica si alguna API falló o degradó a timeout/rate_limit/error.
        """
        tasks = [
            self.web_risk_client.check_url(url),
            self.virustotal_client.check_url(url),
            self.phishtank_client.check_url(url),
        ]

        # Consultas paralelas concurrentes mediante asyncio.gather (RF-02.2)
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        reputations: list[Reputation] = []
        tiene_fallos = False
        api_names = ["google_web_risk", "virustotal", "phishtank"]

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

        return reputations, tiene_fallos

    async def analyze(
        self,
        tipo_entrada: str,
        contenido: str,
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """RF-02 & RF-03: Orquesta el flujo completo de análisis de SMS o URL.

        Args:
            tipo_entrada: 'sms' o 'url'.
            contenido: Texto del mensaje SMS o URL a evaluar.
            user_id: Identificador opcional del usuario autenticado.

        Returns:
            Diccionario estructurado conforme al esquema de AnalysisResponse.
        """
        now = datetime.now(timezone.utc)
        analisis_parcial = False

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
            }

        # 3. Consultas paralelas a las APIs externas para cada una de las hasta 2 URLs
        urls_reputations: list[list[Reputation]] = []
        for feat in selected_url_features:
            reps, api_fallo = await self._query_external_apis_for_url(feat.url)
            urls_reputations.append(reps)
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

        return {
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

