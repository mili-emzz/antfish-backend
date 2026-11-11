"""Análisis heurístico sintáctico de URLs (Capa 2).

RF-02.3: El backend debe evaluar las reglas heurísticas sintácticas de la URL
(IP directa, TLDs de alto riesgo, subdominios engañosos, acortadores y exceso de guiones).
Incluye el algoritmo para seleccionar las 2 URLs de mayor riesgo sintáctico
(empate: por orden estricto de aparición en el texto, RN-10).

Reglas evaluadas:
- URL_IP_DIRECTA (+20 pts): uso de dirección IP en lugar de nombre de dominio.
- URL_SUBDOMINIO_ENGANOSO (+20 pts): imitación de marca protegida en subdominio o path.
- URL_TLD_ALTO_RIESGO (+15 pts): terminación de dominio de alto riesgo (.xyz, .top, etc.).
- URL_ACORTADOR (+10 pts): servicios de acortamiento de URLs (bit.ly, tinyurl.com, etc.).
- URL_EXCESO_GUIONES (+10 pts): múltiples guiones o palabras clave encadenadas en el host.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import urlsplit

from app.engine.models import Brand, Finding, Rule, UrlFeatures
from app.engine.public_suffixes import (
    DEFAULT_PROTECTED_BRANDS,
    HIGH_RISK_TLDS,
    KNOWN_SHORTENERS,
    extract_subdomain,
    get_registered_domain,
    is_direct_ip,
)
from app.engine.url_extractor import normalize_url


def _detect_brand_impersonation(
    hostname: str,
    path: str,
    registered_domain: str,
    brands: Sequence[Brand],
) -> tuple[bool, str | None]:
    """Detecta si la URL imita una marca protegida sin pertenecer a sus dominios oficiales.

    Comprueba si el subdominio, el hostname o el inicio de la ruta contienen
    el nombre o variantes ofuscadas de una marca, y valida que el dominio
    registrable no figure entre los dominios legítimos oficiales.

    Args:
        hostname: Hostname completo en minúsculas.
        path: Ruta normalizada de la URL.
        registered_domain: Dominio registrable de la URL.
        brands: Lista de marcas protegidas a contrastar.

    Returns:
        Tupla (es_enganoso, marca_codigo_detectado).
    """
    subdomain = extract_subdomain(hostname).lower()
    clean_path = path.lower()
    full_host = hostname.lower()

    for brand in brands:
        if not brand.activa:
            continue

        # Si el dominio registrable es oficial de la marca, no es engañoso
        is_official = any(
            registered_domain == official.lower()
            or registered_domain.endswith(f".{official.lower()}")
            for official in brand.dominios_oficiales
        )
        if is_official:
            continue

        brand_identifiers = [brand.codigo.lower(), brand.nombre.lower()] + [
            v.lower() for v in brand.variantes_ofuscadas
        ]

        # Verificar presencia en subdominio, estructura del host o ruta
        for identifier in brand_identifiers:
            if not identifier:
                continue

            # Patrón de palabra delimitada o precedida/sucedida por guión/punto
            id_escaped = re.escape(identifier)
            pattern = re.compile(rf"(?:^|[-._/]){id_escaped}(?:[-._/]|$)", re.IGNORECASE)

            if (
                pattern.search(subdomain)
                or pattern.search(full_host)
                or pattern.search(clean_path)
                or identifier in subdomain
            ):
                return True, brand.codigo

    return False, None


def analyze_url(
    url: str,
    brands: Sequence[Brand] | None = None,
    rules: Sequence[Rule] | None = None,
) -> UrlFeatures:
    """RF-02.3: Realiza la evaluación sintáctica completa de una URL individual (Capa 2).

    Calcula banderas, hallazgos y puntos sintácticos según RN-04:
    - IP directa (+20 pts)
    - Subdominio engañoso (+20 pts)
    - TLD de alto riesgo (+15 pts)
    - Acortador (+10 pts)
    - Exceso de guiones (+10 pts)

    Args:
        url: URL candidata a evaluar.
        brands: Colección de marcas protegidas (opcional, usa defaults).
        rules: Reglas activas configurables del motor (opcional).

    Returns:
        Instancia de UrlFeatures con las banderas y hallazgos determinados.
    """
    canonical_url = normalize_url(url)
    parsed = urlsplit(canonical_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""

    active_brands = brands if brands is not None else DEFAULT_PROTECTED_BRANDS
    registered_domain = get_registered_domain(hostname)

    findings: list[Finding] = []
    flags: list[str] = []
    raw_points = 0

    # 1. Regla: IP directa (+20 pts)
    es_ip = is_direct_ip(hostname)
    if es_ip:
        flags.append("ip_directa")
        raw_points += 20
        findings.append(
            Finding(
                regla_codigo="URL_IP_DIRECTA",
                titulo="Uso de IP directa",
                descripcion="La URL utiliza una dirección IP directa en lugar de un nombre de dominio.",
                puntos=20,
            )
        )

    # 2. Regla: Subdominio engañoso o impersonación (+20 pts)
    es_enganoso, marca_codigo = _detect_brand_impersonation(
        hostname=hostname,
        path=path,
        registered_domain=registered_domain,
        brands=active_brands,
    )
    if es_enganoso:
        flags.append("subdominio_enganoso")
        raw_points += 20
        findings.append(
            Finding(
                regla_codigo="URL_SUBDOMINIO_ENGANOSO",
                titulo="Subdominio engañoso",
                descripcion="La URL imita el nombre de una marca legítima en el subdominio o estructura.",
                puntos=20,
            )
        )

    # 3. Regla: TLD de alto riesgo (+15 pts)
    tld = hostname.rsplit(".", 1)[-1] if "." in hostname and not es_ip else ""
    es_tld_riesgo = tld in HIGH_RISK_TLDS
    if es_tld_riesgo:
        flags.append("tld_alto_riesgo")
        raw_points += 15
        findings.append(
            Finding(
                regla_codigo="URL_TLD_ALTO_RIESGO",
                titulo="Dominio de alto riesgo",
                descripcion=f"El dominio usa una terminación frecuente en fraudes (.{tld}).",
                puntos=15,
            )
        )

    # 4. Regla: Acortador de enlaces (+10 pts)
    es_acortador = (registered_domain in KNOWN_SHORTENERS) or (hostname in KNOWN_SHORTENERS)
    if es_acortador:
        flags.append("acortador")
        raw_points += 10
        findings.append(
            Finding(
                regla_codigo="URL_ACORTADOR",
                titulo="Uso de acortador de enlaces",
                descripcion="La URL utiliza un servicio acortador que oculta el destino real.",
                puntos=10,
            )
        )

    # 5. Regla: Exceso de guiones en el dominio (+10 pts)
    # Se considera exceso cuando el nombre de host contiene 2 o más guiones
    hyphen_count = hostname.count("-")
    es_exceso_guiones = hyphen_count >= 2
    if es_exceso_guiones:
        flags.append("exceso_guiones")
        raw_points += 10
        findings.append(
            Finding(
                regla_codigo="URL_EXCESO_GUIONES",
                titulo="Exceso de guiones en el dominio",
                descripcion="El dominio contiene múltiples guiones encadenados de forma sospechosa.",
                puntos=10,
            )
        )

    # El tope de la Capa 2 es de 30 puntos conforme a RN-04
    puntos_sintacticos = min(30, raw_points)

    return UrlFeatures(
        url=canonical_url,
        dominio=registered_domain or hostname,
        es_ip_directa=es_ip,
        subdominio_enganoso=es_enganoso,
        marca_detectada=marca_codigo,
        tld_alto_riesgo=es_tld_riesgo,
        es_acortador=es_acortador,
        exceso_guiones=es_exceso_guiones,
        puntos_sintacticos=puntos_sintacticos,
        flags_sintacticos=flags,
        hallazgos=findings,
    )


def select_top_urls(
    urls: Sequence[str],
    brands: Sequence[Brand] | None = None,
    rules: Sequence[Rule] | None = None,
) -> list[UrlFeatures]:
    """RF-02.3 & RN-10: Selecciona las 2 URLs de mayor riesgo sintáctico de un mensaje.

    Evalúa la heurística sintáctica (Capa 2) a cada una de las URLs extraídas
    y las clasifica de forma determinista:
    1. Mayor puntaje sintáctico acumulado (riesgo sintáctico descendente).
    2. En caso de empate, prevalece el orden estricto de aparición en el texto.

    Args:
        urls: Secuencia de URLs normalizadas extraídas del texto.
        brands: Marcas protegidas a evaluar.
        rules: Reglas configurables del motor.

    Returns:
        Lista con un máximo de 2 objetos UrlFeatures seleccionados.
    """
    if not urls:
        return []

    evaluated: list[tuple[UrlFeatures, int, int]] = []
    for index, url in enumerate(urls):
        features = analyze_url(url, brands=brands, rules=rules)
        # Calculamos la suma bruta para desempatar adecuadamente antes del tope
        raw_sum = sum(h.puntos for h in features.hallazgos)
        evaluated.append((features, raw_sum, index))

    # Ordenar por raw_sum descendente, y luego por index ascendente (orden de aparición)
    evaluated.sort(key=lambda item: (-item[1], item[2]))

    # Devolver las 2 primeras URLs analizadas
    return [item[0] for item in evaluated[:2]]

