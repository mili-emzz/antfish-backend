"""Sufijos públicos estáticos, TLDs de alto riesgo y acortadores.

RF-02.3: Evaluación de reglas heurísticas sintácticas de la URL
(IP directa, TLDs de alto riesgo, subdominios engañosos, acortadores).

Este módulo proporciona constantes estáticas embebidas en memoria RAM
para evitar I/O de red o disco en tiempo de importación, garantizando
la pureza del motor de dominio.
"""

from __future__ import annotations

import re

from app.engine.models import Brand

# TLDs de alto riesgo frecuentemente abusados en campañas de phishing/smishing
# Citados explícitamente en la especificación (.xyz, .top, .tk) más extensiones comunes
HIGH_RISK_TLDS: frozenset[str] = frozenset(
    {
        "xyz",
        "top",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "buzz",
        "fit",
        "rest",
        "icu",
        "monster",
        "club",
        "work",
        "click",
        "link",
        "live",
        "loan",
        "cam",
        "vip",
        "space",
        "site",
        "online",
        "racing",
        "surf",
        "country",
        "kim",
        "science",
        "party",
        "stream",
    }
)

# Servicios de acortamiento de enlaces reconocidos que enmascaran el destino real
KNOWN_SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "bit.do",
        "mcaf.ee",
        "rebrand.ly",
        "cutt.ly",
        "tiny.cc",
        "shorturl.at",
        "rb.gy",
        "qr.ae",
        "lnkd.in",
        "snip.ly",
        "clck.ru",
        "v.gd",
        "s.id",
        "rotf.lol",
        "bc.vc",
    }
)

# Sufijos públicos compuestos frecuentes (para determinación exacta del dominio registrable)
MULTI_PART_TLDS: frozenset[str] = frozenset(
    {
        "com.mx",
        "gob.mx",
        "org.mx",
        "edu.mx",
        "net.mx",
        "co.uk",
        "org.uk",
        "me.uk",
        "ltd.uk",
        "plc.uk",
        "net.uk",
        "ac.uk",
        "gov.uk",
        "com.ar",
        "gob.ar",
        "edu.ar",
        "org.ar",
        "com.co",
        "gov.co",
        "edu.co",
        "org.co",
        "com.br",
        "gov.br",
        "edu.br",
        "org.br",
        "com.es",
        "nom.es",
        "org.es",
        "gob.es",
        "edu.es",
        "com.pe",
        "gob.pe",
        "edu.pe",
        "org.pe",
        "com.cl",
        "gob.cl",
        "com.uy",
        "gub.uy",
        "com.ve",
        "com.gt",
        "com.sv",
        "com.pa",
        "co.cr",
        "co.jp",
        "ne.jp",
        "or.jp",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "co.nz",
        "net.nz",
        "org.nz",
        "co.za",
        "org.za",
    }
)

# Marcas protegidas integradas por defecto para evaluación sintáctica y leetspeak
DEFAULT_PROTECTED_BRANDS: tuple[Brand, ...] = (
    Brand(
        codigo="bbva",
        nombre="BBVA México",
        categoria="banca",
        dominios_oficiales=["bbva.mx", "bbva.com.mx", "bbva.com"],
        variantes_ofuscadas=["bbv4", "b6va", "bb va", "bbva-seguridad"],
        activa=True,
    ),
    Brand(
        codigo="banorte",
        nombre="Banorte",
        categoria="banca",
        dominios_oficiales=["banorte.com", "banorte.com.mx"],
        variantes_ofuscadas=["b4norte", "ban0rte", "banort3", "banorte-linea"],
        activa=True,
    ),
    Brand(
        codigo="santander",
        nombre="Santander",
        categoria="banca",
        dominios_oficiales=["santander.com.mx", "santander.com"],
        variantes_ofuscadas=["s4nt4nd3r", "santand3r", "santan-der"],
        activa=True,
    ),
    Brand(
        codigo="citibanamex",
        nombre="Citibanamex",
        categoria="banca",
        dominios_oficiales=["banamex.com", "citibanamex.com"],
        variantes_ofuscadas=["c1t1", "b4n4mex", "citiban4mex", "citi-banamex"],
        activa=True,
    ),
    Brand(
        codigo="hsbc",
        nombre="HSBC",
        categoria="banca",
        dominios_oficiales=["hsbc.com.mx", "hsbc.com"],
        variantes_ofuscadas=["h5bc", "hs-bc", "hsbc-mexico"],
        activa=True,
    ),
    Brand(
        codigo="paypal",
        nombre="PayPal",
        categoria="pagos",
        dominios_oficiales=["paypal.com", "paypal.me"],
        variantes_ofuscadas=["p4yp4l", "pay-pal", "paypa1", "p4ypal"],
        activa=True,
    ),
    Brand(
        codigo="mercadolibre",
        nombre="Mercado Libre / Mercado Pago",
        categoria="comercio",
        dominios_oficiales=["mercadolibre.com.mx", "mercadopago.com.mx", "mercadolibre.com"],
        variantes_ofuscadas=["merc4dolibre", "m3rc4do", "mercad0pago", "mercado-pago"],
        activa=True,
    ),
    Brand(
        codigo="netflix",
        nombre="Netflix",
        categoria="streaming",
        dominios_oficiales=["netflix.com"],
        variantes_ofuscadas=["n3tfl1x", "net-flix", "netfl1x"],
        activa=True,
    ),
    Brand(
        codigo="amazon",
        nombre="Amazon",
        categoria="comercio",
        dominios_oficiales=["amazon.com.mx", "amazon.com"],
        variantes_ofuscadas=["4m4z0n", "amaz0n", "amz-on"],
        activa=True,
    ),
    Brand(
        codigo="coppel",
        nombre="Coppel",
        categoria="retail",
        dominios_oficiales=["coppel.com"],
        variantes_ofuscadas=["c0ppel", "copp3l", "coppel-credito"],
        activa=True,
    ),
    Brand(
        codigo="sat",
        nombre="SAT México",
        categoria="gobierno",
        dominios_oficiales=["sat.gob.mx"],
        variantes_ofuscadas=["s4t", "sat-gob", "sat-devolucion"],
        activa=True,
    ),
)

_IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def is_direct_ip(hostname: str) -> bool:
    """RF-02.3: Determina si el host es una dirección IPv4 o IPv6 directa.

    Args:
        hostname: Nombre de host o dirección de red.

    Returns:
        True si el host corresponde a una dirección IP directa.
    """
    clean_host = hostname.strip().lower()
    if clean_host.startswith("[") and clean_host.endswith("]"):
        clean_host = clean_host[1:-1]
    if _IPV4_PATTERN.match(clean_host):
        parts = clean_host.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    # Detección básica de IPv6 con al menos dos caracteres ':'
    return ":" in clean_host and clean_host.count(":") >= 2


def get_registered_domain(hostname: str) -> str:
    """RF-02.3: Extrae el dominio raíz o registrable de un hostname.

    Ejemplos:
        'bbva-verifica.seguro-acceso.xyz' -> 'seguro-acceso.xyz'
        'login.banco.com.mx'              -> 'banco.com.mx'
        '192.168.1.1'                     -> '192.168.1.1'
        'bit.ly'                          -> 'bit.ly'

    Args:
        hostname: Hostname extraído de la URL.

    Returns:
        Cadena con el dominio registrable en minúsculas.
    """
    clean_host = hostname.strip().lower()
    if not clean_host:
        return ""
    if is_direct_ip(clean_host):
        return clean_host

    parts = clean_host.split(".")
    if len(parts) <= 2:
        return clean_host

    # Revisar si los últimos dos segmentos coinciden con un TLD multi-parte
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in MULTI_PART_TLDS:
        if len(parts) >= 3:
            return f"{parts[-3]}.{last_two}"
        return clean_host

    # TLD estándar de una sola palabra (.com, .xyz, etc.)
    return f"{parts[-2]}.{parts[-1]}"


def extract_subdomain(hostname: str) -> str:
    """RF-02.3: Extrae la porción de subdominio previa al dominio registrable.

    Ejemplo:
        'bbva-verifica.seguro-acceso.xyz' -> 'bbva-verifica'
        'seguro-acceso.xyz'               -> ''

    Args:
        hostname: Hostname completo.

    Returns:
        Cadena con el subdominio o cadena vacía si no existe.
    """
    clean_host = hostname.strip().lower()
    if is_direct_ip(clean_host):
        return ""

    registered = get_registered_domain(clean_host)
    if clean_host == registered:
        return ""

    if clean_host.endswith(f".{registered}"):
        return clean_host[: -(len(registered) + 1)]
    return ""
