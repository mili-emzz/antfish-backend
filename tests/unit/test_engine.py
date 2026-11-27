"""Pruebas unitarias para el motor heurístico puro (Capa local/offline).

Prueba models, url_extractor (RF-02.1), url_heuristics (RF-02.3),
public_suffixes (RF-02.3) y text_heuristics (RF-02.4).
"""

from app.engine.models import (
    CircuitBreakerReason,
    Finding,
    RiskLevel,
)
from app.engine.public_suffixes import (
    extract_subdomain,
    get_registered_domain,
    is_direct_ip,
)
from app.engine.text_heuristics import analyze_text
from app.engine.url_extractor import (
    extract_domain,
    extract_urls_from_text,
    normalize_url,
)
from app.engine.url_heuristics import analyze_url, select_top_urls


def test_models_instantiation() -> None:
    """Verifica que los modelos base y enums se instancien correctamente."""
    finding = Finding(
        regla_codigo="TXT_LENGUAJE_URGENCIA",
        titulo="Lenguaje de urgencia",
        descripcion="Prueba",
        puntos=10,
    )
    assert finding.regla_codigo == "TXT_LENGUAJE_URGENCIA"
    assert finding.puntos == 10
    assert RiskLevel.CRITICO.value == "critico"
    assert CircuitBreakerReason.SUPLANTACION_MARCA.value == "suplantacion_marca"


def test_public_suffixes_and_domains() -> None:
    """RF-02.3: Verifica el análisis de dominios registrables y subdominios."""
    assert is_direct_ip("192.168.1.1") is True
    assert is_direct_ip("google.com") is False
    assert is_direct_ip("[2001:db8::1]") is True

    assert get_registered_domain("bbva-verifica.seguro-acceso.xyz") == "seguro-acceso.xyz"
    assert get_registered_domain("login.banco.com.mx") == "banco.com.mx"
    assert get_registered_domain("192.168.1.1") == "192.168.1.1"

    assert extract_subdomain("bbva-verifica.seguro-acceso.xyz") == "bbva-verifica"
    assert extract_subdomain("seguro-acceso.xyz") == ""
    assert extract_subdomain("login.banco.com.mx") == "login"


def test_url_normalization() -> None:
    """RF-02.1: Verifica la normalización estricta (https://, sin query ni fragmentos)."""
    raw = "http://Usuario:Pass@bbva-alerta.com:80/login?token=123#seccion"
    normalized = normalize_url(raw)
    assert normalized == "https://bbva-alerta.com/login"

    domain_only = normalize_url("seguro-acceso.xyz")
    assert domain_only == "https://seguro-acceso.xyz"

    extract_dom = extract_domain("http://sub.dominio.com/ruta")
    assert extract_dom == "sub.dominio.com"


def test_extract_urls_from_text() -> None:
    """RF-02.1: Verifica la extracción en RAM de todas las URLs explícitas y dominios."""
    sms = (
        "BBVA Alerta: Tu cuenta ha sido bloqueada. "
        "Verifica en http://bbva-seguro.xyz/login, o en bit.ly/3xpto. "
        "Tambien consulta 192.168.1.1/update de inmediato!"
    )
    urls = extract_urls_from_text(sms)
    assert len(urls) == 3
    assert urls[0] == "https://bbva-seguro.xyz/login"
    assert urls[1] == "https://bit.ly/3xpto"
    assert urls[2] == "https://192.168.1.1/update"


def test_text_heuristics_urgency_data_leetspeak() -> None:
    """RF-02.4: Verifica la detección de urgencia, datos sensibles y leetspeak."""
    sms = "URGENTE: Tu cuenta ha sido bloqueada. Verifica tu NIP en el enlace antes de que expire en 24 horas."
    findings = analyze_text(sms)
    codigos = [f.regla_codigo for f in findings]

    assert "TXT_LENGUAJE_URGENCIA" in codigos
    assert "TXT_SOLICITUD_DATOS" in codigos

    # Prueba de leetspeak
    sms_leet = "Aviso de b4nco: confirma tu cu3nt4 de b4norte inmediatamente."
    findings_leet = analyze_text(sms_leet)
    codigos_leet = [f.regla_codigo for f in findings_leet]
    assert "TXT_LEETSPEAK" in codigos_leet


def test_url_heuristics_analysis() -> None:
    """RF-02.3: Verifica el análisis sintáctico de URL_IP_DIRECTA, URL_SUBDOMINIO_ENGANOSO, etc."""
    url_phish = "https://bbva-seguro.acceso-inmediato.xyz/login"
    features = analyze_url(url_phish)

    assert features.subdominio_enganoso is True
    assert features.marca_detectada == "bbva"
    assert features.tld_alto_riesgo is True
    assert features.exceso_guiones is True
    assert features.puntos_sintacticos == 30  # tope 30 por capa 2

    codigos = [h.regla_codigo for h in features.hallazgos]
    assert "URL_SUBDOMINIO_ENGANOSO" in codigos
    assert "URL_TLD_ALTO_RIESGO" in codigos
    assert "URL_EXCESO_GUIONES" in codigos


def test_select_top_urls_ranking_and_tie_break() -> None:
    """RF-02.3 & RN-10: Verifica la selección de las 2 URLs de mayor riesgo sintáctico con desempate."""
    urls = [
        "https://google.com/search",  # Riesgo 0
        "https://bit.ly/seguro",  # Acortador (+10)
        "https://bbva-alerta.acceso.xyz/login",  # Subdominio engañoso (+20) + TLD (+15) + guion
        "https://192.168.1.1/admin",  # IP (+20)
    ]

    top_2 = select_top_urls(urls)
    assert len(top_2) == 2
    # La más riesgosa es bbva-alerta.acceso.xyz
    assert top_2[0].url == "https://bbva-alerta.acceso.xyz/login"
    # La segunda es la IP directa
    assert top_2[1].url == "https://192.168.1.1/admin"
