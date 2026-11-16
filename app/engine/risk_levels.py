"""Mapeo de puntuación (0 a 100) a niveles de riesgo del semáforo.

RN-06 a RN-09:
- 0 a 19 pts   -> bajo (verde)
- 20 a 49 pts  -> medio (amarillo)
- 50 a 79 pts  -> alto (naranja)
- 80 a 100 pts -> critico (rojo)
"""

from __future__ import annotations

from app.engine.models import RiskLevel


def get_risk_level(score: int) -> RiskLevel:
    """Calcula el nivel de riesgo en función del puntaje de 0 a 100."""
    clamped_score = max(0, min(100, score))
    if clamped_score < 20:
        return RiskLevel.BAJO
    if clamped_score < 50:
        return RiskLevel.MEDIO
    if clamped_score < 80:
        return RiskLevel.ALTO
    return RiskLevel.CRITICO
