"""Consolidación de puntaje, topes de capa y cortocircuitos (Capa 1 + 2 + 3).

RN-01 a RN-05:
- Topes por capa:
  - APIs <= 60
  - URL <= 30
  - Texto <= 20
- Cortocircuito por lista negra (Google Web Risk o PhishTank positivo):
  score = min(100, 95 + min(5, (puntos_url + puntos_texto) // 10))
  motivo_cortocircuito = "lista_negra"
- Cortocircuito por suplantación de marca:
  score = max(score, 80)
  motivo_cortocircuito = "suplantacion_marca"
- Si coinciden ambos cortocircuitos:
  prevalece estrictamente "lista_negra"
- Elección de URL dominante por riesgo total acumulado.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.engine.models import (
    CircuitBreakerReason,
    Finding,
    Reputation,
    RiskLevel,
    ScoreResult,
    SourceStatus,
    UrlFeatures,
)
from app.engine.recommendations import generate_recommendations
from app.engine.risk_levels import get_risk_level


def evaluate_api_reputations(reputations: Sequence[Reputation]) -> tuple[int, list[Finding], bool]:
    """Evalúa las respuestas de las APIs externas (Capa 1).

    Returns:
        Tupla (puntos_apis, hallazgos_api, es_lista_negra).
    """
    raw_api_points = 0
    api_findings: list[Finding] = []
    es_lista_negra = False

    for rep in reputations:
        if rep.estado != SourceStatus.OK:
            continue

        if rep.api == "google_web_risk" and rep.positivo:
            raw_api_points += 50
            es_lista_negra = True
            api_findings.append(
                Finding(
                    regla_codigo="API_GOOGLE_WEB_RISK",
                    titulo="Lista negra Google Web Risk",
                    descripcion="Google Web Risk confirma que el dominio es malicioso o de ingeniería social.",
                    puntos=50,
                )
            )

        elif rep.api == "phishtank" and rep.positivo:
            raw_api_points += 50
            es_lista_negra = True
            api_findings.append(
                Finding(
                    regla_codigo="API_PHISHTANK",
                    titulo="Lista negra PhishTank",
                    descripcion="PhishTank confirma que la URL es un sitio verificado de phishing.",
                    puntos=50,
                )
            )

        elif rep.api == "virustotal":
            detecciones = rep.detecciones or 0
            if detecciones >= 3:
                raw_api_points += 40
                api_findings.append(
                    Finding(
                        regla_codigo="API_VIRUSTOTAL_3_MAS",
                        titulo="Reputación negativa VirusTotal",
                        descripcion=f"Múltiples motores de seguridad ({detecciones}) reportan la URL como maliciosa.",
                        puntos=40,
                    )
                )
            elif detecciones in (1, 2):
                raw_api_points += 20
                api_findings.append(
                    Finding(
                        regla_codigo="API_VIRUSTOTAL_1_2",
                        titulo="Alerta sospechosa VirusTotal",
                        descripcion=f"Uno o dos motores de seguridad ({detecciones}) reportan la URL como sospechosa.",
                        puntos=20,
                    )
                )

    puntos_apis = min(60, raw_api_points)
    return puntos_apis, api_findings, es_lista_negra


def consolidate_score(
    puntos_apis: int,
    puntos_url: int,
    puntos_texto: int,
    es_lista_negra: bool,
    tiene_suplantacion_marca: bool,
) -> tuple[int, CircuitBreakerReason | None]:
    """Calcula el score total y determina el motivo del cortocircuito si aplica."""
    # Score base sumando capas con sus topes
    base_score = min(100, puntos_apis + puntos_url + puntos_texto)

    score = base_score
    motivo: CircuitBreakerReason | None = None

    # Cortocircuito por suplantación de marca (piso 80)
    if tiene_suplantacion_marca:
        score = max(score, 80)
        motivo = CircuitBreakerReason.SUPLANTACION_MARCA

    # Cortocircuito por lista negra (piso 95-100; prevalece si ambos coinciden)
    if es_lista_negra:
        score = min(100, 95 + min(5, (puntos_url + puntos_texto) // 10))
        motivo = CircuitBreakerReason.LISTA_NEGRA

    final_score = max(0, min(100, score))
    return final_score, motivo

