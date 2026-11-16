"""Catálogo canónico de reglas heurísticas y utilidades de configuración (RN-03, RN-04, RN-05).

Los puntos por regla son requisitos (AGENTS.md): viven aquí y en el motor, nunca se leen de
la base de datos. Mongo solo aporta el flag ``activa`` y las listas de valores (TLDs,
acortadores, filtro de marcas); cualquier puntaje distinto en Mongo se ignora.
Módulo puro: solo librería estándar.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.engine.models import Rule

# código de regla -> (capa, puntos). Fuente: RN-03 (api), RN-04 (url), RN-05 (texto).
RULE_CATALOG: dict[str, tuple[str, int]] = {
    "API_GOOGLE_WEB_RISK": ("api", 50),
    "API_PHISHTANK": ("api", 50),
    "API_VIRUSTOTAL_3_MAS": ("api", 40),
    "API_VIRUSTOTAL_1_2": ("api", 20),
    "URL_IP_DIRECTA": ("url", 20),
    "URL_SUBDOMINIO_ENGANOSO": ("url", 20),
    "URL_TLD_ALTO_RIESGO": ("url", 15),
    "URL_ACORTADOR": ("url", 10),
    "URL_EXCESO_GUIONES": ("url", 10),
    "TXT_LENGUAJE_URGENCIA": ("texto", 10),
    "TXT_SOLICITUD_DATOS": ("texto", 10),
    "TXT_LEETSPEAK": ("texto", 5),
}


def disabled_rule_codes(rules: Sequence[Rule] | None) -> frozenset[str]:
    """Códigos de reglas conocidas que el catálogo marca como inactivas."""
    if not rules:
        return frozenset()
    return frozenset(r.codigo for r in rules if not r.activa and r.codigo in RULE_CATALOG)


def rule_values(rules: Sequence[Rule] | None, codigo: str) -> frozenset[str]:
    """Valores configurados (parametros.valores) de una regla activa, normalizados.

    Devuelve un conjunto vacío si la regla no existe, está inactiva o no trae valores
    válidos; el llamador debe usar entonces sus valores por defecto.
    """
    for rule in rules or ():
        if rule.codigo != codigo or not rule.activa:
            continue
        raw = rule.parametros.get("valores") if isinstance(rule.parametros, dict) else None
        if not isinstance(raw, list):
            return frozenset()
        return frozenset(
            v.strip().lower().lstrip(".")
            for v in raw
            if isinstance(v, str) and v.strip().lstrip(".")
        )
    return frozenset()


def rule_brand_filter(rules: Sequence[Rule] | None, codigo: str) -> frozenset[str]:
    """Códigos de marca a los que se limita una regla; vacío significa todas las marcas."""
    for rule in rules or ():
        if rule.codigo != codigo or not rule.activa:
            continue
        raw = rule.parametros.get("marcas_codigos") if isinstance(rule.parametros, dict) else None
        if not isinstance(raw, list):
            return frozenset()
        return frozenset(v.strip().lower() for v in raw if isinstance(v, str) and v.strip())
    return frozenset()
