"""Pruebas del motor con catálogo configurable (RF-02.3, RF-02.4, RN-03 a RN-05).

Los puntos son fijos: el catálogo solo aporta activa, listas de valores y filtro de marcas.
"""

from __future__ import annotations

import pytest

from app.engine.models import Brand, Rule
from app.engine.rule_catalog import RULE_CATALOG
from app.engine.text_heuristics import analyze_text
from app.engine.url_heuristics import analyze_url, select_top_urls


def rule(
    codigo: str,
    activa: bool = True,
    valores: list[str] | None = None,
    marcas: list[str] | None = None,
    puntos: int | None = None,
) -> Rule:
    capa, pts = RULE_CATALOG[codigo]
    return Rule(
        codigo=codigo,
        capa=capa,
        titulo=codigo,
        descripcion="",
        puntos=puntos or pts,
        parametros={"marcas_codigos": marcas or [], "valores": valores or []},
        activa=activa,
    )


ACME = Brand(
    codigo="acme",
    nombre="Acme Bank",
    categoria="banca",
    dominios_oficiales=["acme.com"],
    variantes_ofuscadas=["4cme"],
    activa=True,
)


def codes(features) -> set[str]:
    return {h.regla_codigo for h in features.hallazgos}


def test_default_behaviour_without_rules_is_unchanged() -> None:
    f = analyze_url("https://promo-gratis-ya.xyz/login")
    assert {"URL_TLD_ALTO_RIESGO", "URL_EXCESO_GUIONES"} <= codes(f)
    assert f.puntos_sintacticos == 25


@pytest.mark.parametrize(
    ("codigo", "url"),
    [
        ("URL_IP_DIRECTA", "https://192.168.10.5/login"),
        ("URL_TLD_ALTO_RIESGO", "https://tienda.xyz/"),
        ("URL_ACORTADOR", "https://bit.ly/abc"),
        ("URL_EXCESO_GUIONES", "https://a-b-c.com/"),
    ],
)
def test_inactive_rule_stops_contributing(codigo: str, url: str) -> None:
    assert codigo in codes(analyze_url(url))
    f = analyze_url(url, rules=[rule(codigo, activa=False)])
    assert codigo not in codes(f)


def test_inactive_rules_remove_their_points() -> None:
    url = "https://promo-gratis-ya.xyz/"
    base = analyze_url(url).puntos_sintacticos
    f = analyze_url(url, rules=[rule("URL_TLD_ALTO_RIESGO", activa=False)])
    assert f.puntos_sintacticos == base - 15


def test_points_always_come_from_the_engine_not_from_the_catalog() -> None:
    f = analyze_url("https://tienda.xyz/", rules=[rule("URL_TLD_ALTO_RIESGO", puntos=1)])
    assert [h.puntos for h in f.hallazgos if h.regla_codigo == "URL_TLD_ALTO_RIESGO"] == [15]
    rogue = rule("URL_TLD_ALTO_RIESGO", puntos=999)
    assert analyze_url("https://tienda.xyz/", rules=[rogue]).puntos_sintacticos == 15


def test_tld_list_is_taken_from_the_catalog() -> None:
    # '.mx' no es TLD de alto riesgo por defecto; con la lista del catálogo sí.
    assert "URL_TLD_ALTO_RIESGO" not in codes(analyze_url("https://tienda.mx/"))
    custom = [rule("URL_TLD_ALTO_RIESGO", valores=[".MX", " ru "])]
    assert "URL_TLD_ALTO_RIESGO" in codes(analyze_url("https://tienda.mx/", rules=custom))
    # y la lista del catálogo reemplaza a la interna
    assert "URL_TLD_ALTO_RIESGO" not in codes(analyze_url("https://tienda.xyz/", rules=custom))


def test_empty_or_invalid_values_fall_back_to_internal_lists() -> None:
    for valores in ([], [""], ["   "]):
        f = analyze_url("https://tienda.xyz/", rules=[rule("URL_TLD_ALTO_RIESGO", valores=valores)])
        assert "URL_TLD_ALTO_RIESGO" in codes(f)


def test_shortener_list_is_taken_from_the_catalog() -> None:
    assert "URL_ACORTADOR" not in codes(analyze_url("https://corto.example/x"))
    custom = [rule("URL_ACORTADOR", valores=["corto.example"])]
    assert "URL_ACORTADOR" in codes(analyze_url("https://corto.example/x", rules=custom))


def test_brand_from_catalog_triggers_impersonation_and_override_marker() -> None:
    url = "https://acme-seguro.login-verifica.net/"
    assert analyze_url(url).marca_detectada is None  # marca desconocida para el motor
    f = analyze_url(url, brands=[ACME])
    assert f.marca_detectada == "acme" and "URL_SUBDOMINIO_ENGANOSO" in codes(f)


def test_inactive_impersonation_rule_keeps_brand_override_but_drops_points() -> None:
    url = "https://acme-seguro.login-verifica.net/"
    f = analyze_url(url, brands=[ACME], rules=[rule("URL_SUBDOMINIO_ENGANOSO", activa=False)])
    assert "URL_SUBDOMINIO_ENGANOSO" not in codes(f)
    assert f.marca_detectada == "acme"  # el cortocircuito por marca es un override fuera de reglas


def test_brand_filter_of_the_rule_limits_detection() -> None:
    url = "https://acme-seguro.login-verifica.net/"
    other = Brand(
        codigo="otra",
        nombre="Otra",
        categoria="x",
        dominios_oficiales=["otra.com"],
        variantes_ofuscadas=[],
        activa=True,
    )
    only_other = [rule("URL_SUBDOMINIO_ENGANOSO", marcas=["otra"])]
    assert analyze_url(url, brands=[ACME, other], rules=only_other).marca_detectada is None
    only_acme = [rule("URL_SUBDOMINIO_ENGANOSO", marcas=["ACME"])]
    assert analyze_url(url, brands=[ACME, other], rules=only_acme).marca_detectada == "acme"


def test_inactive_brand_is_ignored() -> None:
    off = Brand(
        codigo="acme",
        nombre="Acme Bank",
        categoria="banca",
        dominios_oficiales=["acme.com"],
        variantes_ofuscadas=["4cme"],
        activa=False,
    )
    assert (
        analyze_url("https://acme-seguro.login-verifica.net/", brands=[off]).marca_detectada is None
    )


@pytest.mark.parametrize(
    ("codigo", "texto"),
    [
        ("TXT_LENGUAJE_URGENCIA", "URGENTE: tu cuenta será suspendida"),
        ("TXT_SOLICITUD_DATOS", "Confirma tu contraseña y NIP"),
        ("TXT_LEETSPEAK", "Tu cu3nta fue revisada"),
    ],
)
def test_text_rules_can_be_disabled(codigo: str, texto: str) -> None:
    assert codigo in {f.regla_codigo for f in analyze_text(texto)}
    off = analyze_text(texto, rules=[rule(codigo, activa=False)])
    assert codigo not in {f.regla_codigo for f in off}


def test_text_points_ignore_catalog_points() -> None:
    f = analyze_text(
        "URGENTE: tu cuenta será suspendida", rules=[rule("TXT_LENGUAJE_URGENCIA", puntos=99)]
    )
    assert [x.puntos for x in f if x.regla_codigo == "TXT_LENGUAJE_URGENCIA"] == [10]


def test_catalog_brand_variants_feed_text_leetspeak() -> None:
    texto = "Hola, tu 4cme requiere atención"
    assert "TXT_LEETSPEAK" in {f.regla_codigo for f in analyze_text(texto, brands=[ACME])}


def test_select_top_urls_forwards_catalog_to_each_url() -> None:
    urls = ["https://acme-seguro.login-verifica.net/", "https://example.org/"]
    top = select_top_urls(urls, brands=[ACME])
    assert top[0].marca_detectada == "acme"
