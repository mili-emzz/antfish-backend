"""Extracción y normalización sintáctica de URLs en memoria RAM.

RF-02.1: El backend debe extraer sintácticamente todas las URLs contenidas
dentro de un mensaje de texto en memoria RAM.

Normaliza las URLs forzando esquema https:// y descartando query strings,
fragmentos y credenciales de usuario (userinfo) conforme a las políticas
de Privacy by Design (ADR #51, ADR #60).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

# Expresión regular para URLs con esquema explícito (http:// o https://)
_EXPLICIT_URL_REGEX = re.compile(
    r"\bhttps?://[^\s<>\"'{}|\\^`]+",
    re.IGNORECASE,
)

# Expresión regular para dominios sin esquema (ej. bbva-alerta.com/login, bit.ly/3xyz, 192.168.1.1/update)
_DOMAIN_URL_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s<>\"'{}|\\^`]*)?"
    r"|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>\"'{}|\\^`]*)?",
    re.IGNORECASE,
)

# Caracteres de puntuación final común en oraciones de lenguaje natural
_TRAILING_PUNCTUATION = ".,;:!?)>]}\"'“’"


def normalize_url(raw_url: str) -> str:
    """RF-02.1: Normaliza una URL forzando https:// y descartando query y fragmentos.

    Reglas de normalización aplicadas:
    - Elimina espacios en blanco iniciales y finales.
    - Forzar esquema https:// independientemente de si venía con http:// o sin esquema.
    - Convierte el nombre de host (dominio) a minúsculas.
    - Elimina credenciales incrustadas (user:password@).
    - Elimina puertos por defecto (80 para http y 443 para https).
    - Elimina la query string (?param=valor) para protección de datos personales.
    - Elimina los fragmentos (#seccion).
    - Normaliza barras diagonales duplicadas en la ruta.

    Args:
        raw_url: Cadena con la URL original o dominio extraído.

    Returns:
        URL canónica normalizada lista para evaluación sintáctica y caché.
    """
    clean_url = raw_url.strip()
    if not clean_url:
        return ""

    # Asegurar esquema previo al análisis para que urlsplit analice netloc correctamente
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_url):
        clean_url = f"https://{clean_url}"

    try:
        parsed = urlsplit(clean_url)
    except ValueError:
        # Entrada malformada (p. ej. IPv6 sin cerrar): no es una URL analizable.
        return ""

    # Separar host y puerto para normalizar minúsculas y omitir puertos estándar
    hostname = (parsed.hostname or "").lower()

    try:
        port = parsed.port
    except ValueError:
        # Puerto fuera de rango o no numérico: se descarta y se analiza el host.
        port = None
    normalized_netloc = f"{hostname}:{port}" if port and port not in (80, 443) else hostname

    # Normalizar ruta (conserva el path pero elimina slashes redundantes)
    path = parsed.path or ""
    if path:
        # Colapsar barras redundantes
        path = re.sub(r"/{2,}", "/", path)
        if path == "/":
            path = ""
    else:
        path = ""

    # Forzar esquema https:// y descartar query y fragment
    return urlunsplit(("https", normalized_netloc, path, "", ""))


def extract_domain(url: str) -> str:
    """RF-02.1: Extrae únicamente el nombre de host/dominio en minúsculas de una URL.

    Args:
        url: URL completa o parcial.

    Returns:
        Nombre de dominio o dirección IP en minúsculas.
    """
    normalized = normalize_url(url)
    if not normalized:
        return ""
    parsed = urlsplit(normalized)
    return (parsed.hostname or "").lower()


def extract_urls_from_text(text: str) -> list[str]:
    """RF-02.1: Extrae en memoria RAM todas las URLs y dominios detectados en un texto.

    Procesa el texto completo buscando tanto URLs con esquema explícito
    (http://, https://) como nombres de dominio sin esquema o direcciones IP
    acompañadas de ruta. Todas las URLs devueltas se encuentran normalizadas
    y deduplicadas respetando el orden estricto de aparición.

    Args:
        text: Mensaje de texto (SMS) o contenido a analizar.

    Returns:
        Lista ordenada de URLs normalizadas únicas encontradas en el texto.
    """
    if not text:
        return []

    candidates: list[tuple[int, str]] = []

    # 1. Búsqueda de URLs con esquema explícito
    for match in _EXPLICIT_URL_REGEX.finditer(text):
        url_cand = match.group(0).rstrip(_TRAILING_PUNCTUATION)
        candidates.append((match.start(), url_cand))

    # 2. Búsqueda de dominios o IPs sin esquema explícito
    for match in _DOMAIN_URL_REGEX.finditer(text):
        url_cand = match.group(0).rstrip(_TRAILING_PUNCTUATION)
        start_idx = match.start()

        # Evitar capturar subcadenas ya cubiertas por un esquema http/https previo
        prefix = text[max(0, start_idx - 8) : start_idx].lower()
        if "http://" in prefix or "https://" in prefix:
            continue

        candidates.append((start_idx, url_cand))

    # Ordenar por posición de aparición en el texto original
    candidates.sort(key=lambda item: item[0])

    # Normalizar y deduplicar preservando el orden de aparición
    seen: set[str] = set()
    result: list[str] = []

    for _, raw_candidate in candidates:
        normalized = normalize_url(raw_candidate)
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)

    return result
