"""Análisis heurístico de texto para mensajes SMS (Capa 3).

RF-02.4: El backend debe analizar el texto del mensaje buscando lenguaje
de urgencia, patrones de suplantación de identidad (leetspeak) y solicitudes
de información sensible.

Reglas evaluadas:
- TXT_LENGUAJE_URGENCIA (+10 pts): lenguaje de urgencia o amenaza de bloqueo/suspensión.
- TXT_SOLICITUD_DATOS (+10 pts): solicitud de credenciales, datos bancarios o cancelación de cargos.
- TXT_LEETSPEAK (+5 pts): ofuscación con reemplazo de letras por números o caracteres leet.

Retorna una lista inmutable de objetos Finding.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence

from app.engine.models import Brand, Finding, Rule
from app.engine.public_suffixes import DEFAULT_PROTECTED_BRANDS
from app.engine.rule_catalog import disabled_rule_codes

# Patrones para TXT_LENGUAJE_URGENCIA (+10 pts)
_URGENCY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:urgente|urgencia|inmediato|inmediata|de inmediato)\b", re.IGNORECASE),
    re.compile(r"\b(?:bloquead[oas]|bloqueo|bloqueara|bloquearan)\b", re.IGNORECASE),
    re.compile(r"\b(?:suspensi[oó]n|suspendid[oas]|suspender[aá]|evita la suspensi[oó]n)\b", re.IGNORECASE),
    re.compile(r"\b(?:cancelaci[oó]n|cancelad[oas]|desactivaci[oó]n|desactivad[oas])\b", re.IGNORECASE),
    re.compile(r"\b(?:vence hoy|plazo vencido|tiempo l[ií]mite|expirad[oas]|expira)\b", re.IGNORECASE),
    re.compile(r"\b(?:alerta de seguridad|aviso importante|aviso urgente|accion requerida|act[uú]a ya)\b", re.IGNORECASE),
    re.compile(r"\b(?:ultim[oa] aviso|en menos de \d+\s*(?:horas?|hrs?|minutos?))\b", re.IGNORECASE),
)

# Patrones para TXT_SOLICITUD_DATOS (+10 pts)
_DATA_REQUEST_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:verific[aá]|confirm[aá]|valid[aá]|actualiz[aá]|ingres[aá])\s+(?:tu|tus|su|sus)\b", re.IGNORECASE),
    re.compile(r"\b(?:inici[aá]\s+sesi[oó]n|acced[eé]\s+a\s+tu\s+cuenta)\b", re.IGNORECASE),
    re.compile(r"\b(?:cancel[aá]\s+(?:el\s+)?cargo|cargo\s+no\s+reconocido|cargo\s+de\s+\$?\d+)\b", re.IGNORECASE),
    re.compile(r"\b(?:transferencia\s+retenida|dep[oó]sito\s+retenido|pago\s+rechazado)\b", re.IGNORECASE),
    re.compile(r"\b(?:c[oó]digo\s+de\s+seguridad|c[oó]digo\s+de\s+verificaci[oó]n|token|nip|pin|cvv)\b", re.IGNORECASE),
    re.compile(r"\b(?:banca\s+m[oó]vil|banca\s+por\s+internet|datos\s+bancarios|tarjeta\s+de\s+(?:cr[eé]dito|d[eé]bito))\b", re.IGNORECASE),
    re.compile(r"\b(?:contrase[nñ]a|clave\s+de\s+acceso|credenciales?)\b", re.IGNORECASE),
)

# Patrones genéricos de leetspeak / ofuscación dentro de palabras sospechosas
_GENERIC_LEET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bb[4a]nc[0o]\b", re.IGNORECASE),
    re.compile(r"\bcu[3e]nt[4a]\b", re.IGNORECASE),
    re.compile(r"\bbl[0o]qu[3e][4a]d[4a0o]\b", re.IGNORECASE),
    re.compile(r"\bp[4a]ssw[0o]rd\b", re.IGNORECASE),
    re.compile(r"\bt[4a]rj[3e]t[4a]\b", re.IGNORECASE),
    re.compile(r"\bv[3e]r[1i]f[1i]c[4a]\b", re.IGNORECASE),
    re.compile(r"\b[a-záéíóúñ]+[0-9]+[a-záéíóúñ]+[0-9a-záéíóúñ]*\b", re.IGNORECASE),
)


def _strip_accents(text: str) -> str:
    """Remueve tildes y diacríticos preservando caracteres base."""
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def analyze_text(
    text: str,
    brands: Sequence[Brand] | None = None,
    rules: Sequence[Rule] | None = None,
) -> list[Finding]:
    """RF-02.4: Analiza el texto completo de un SMS buscando heurísticas de la Capa 3.

    Evalúa:
    1. Lenguaje de urgencia o amenaza (TXT_LENGUAJE_URGENCIA, +10 pts).
    2. Solicitud de datos personales, bancarios o cancelación (TXT_SOLICITUD_DATOS, +10 pts).
    3. Ofuscación de caracteres o leetspeak (TXT_LEETSPEAK, +5 pts).

    Args:
        text: Contenido completo del mensaje SMS en memoria RAM.
        brands: Marcas protegidas a cotejar (si es None, usa DEFAULT_PROTECTED_BRANDS).
        rules: Reglas activas configurables del motor (opcional).

    Returns:
        Lista de objetos Finding correspondientes a las reglas disparadas.
    """
    if not text or not text.strip():
        return []

    clean_text = text.strip()
    normalized_text = _strip_accents(clean_text)
    active_brands = brands if brands is not None else DEFAULT_PROTECTED_BRANDS

    findings: list[Finding] = []
    disabled = disabled_rule_codes(rules)

    # 1. Detección de Lenguaje de Urgencia (+10 pts)
    urgency_detected = any(pattern.search(clean_text) for pattern in _URGENCY_PATTERNS) or any(
        pattern.search(normalized_text) for pattern in _URGENCY_PATTERNS
    )
    if urgency_detected and "TXT_LENGUAJE_URGENCIA" not in disabled:
        findings.append(
            Finding(
                regla_codigo="TXT_LENGUAJE_URGENCIA",
                titulo="Lenguaje de urgencia",
                descripcion="El mensaje intenta provocar una acción inmediata o amenaza con suspender la cuenta.",
                puntos=10,
            )
        )

    # 2. Detección de Solicitud de Datos Personales / Financieros (+10 pts)
    data_detected = any(pattern.search(clean_text) for pattern in _DATA_REQUEST_PATTERNS) or any(
        pattern.search(normalized_text) for pattern in _DATA_REQUEST_PATTERNS
    )
    if data_detected and "TXT_SOLICITUD_DATOS" not in disabled:
        findings.append(
            Finding(
                regla_codigo="TXT_SOLICITUD_DATOS",
                titulo="Solicitud de credenciales",
                descripcion="El mensaje solicita ingresar contraseñas, PIN, NIP, datos bancarios o validar cargos.",
                puntos=10,
            )
        )

    # 3. Detección de Leetspeak y Ofuscación (+5 pts)
    leet_detected = False

    # 3.1 Búsqueda de variantes ofuscadas específicas de marcas registradas
    lower_text = clean_text.lower()
    lower_normalized = normalized_text.lower()
    for brand in active_brands:
        if not brand.activa:
            continue
        for variant in brand.variantes_ofuscadas:
            var_lower = variant.lower()
            if var_lower in lower_text or var_lower in lower_normalized:
                leet_detected = True
                break
        if leet_detected:
            break

    # 3.2 Búsqueda de patrones leetspeak generales
    if not leet_detected:
        leet_detected = any(pattern.search(clean_text) for pattern in _GENERIC_LEET_PATTERNS)

    if leet_detected and "TXT_LEETSPEAK" not in disabled:
        findings.append(
            Finding(
                regla_codigo="TXT_LEETSPEAK",
                titulo="Ofuscación de caracteres",
                descripcion="El mensaje utiliza números o caracteres especiales para ocultar palabras clave o marcas.",
                puntos=5,
            )
        )

    return findings

