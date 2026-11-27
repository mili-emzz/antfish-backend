"""Pruebas del proveedor de reglas y marcas (CU-11, P4) y su integración con el análisis."""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pymongo.errors import ServerSelectionTimeoutError

from app.clients.base import ReputationResult
from app.engine.models import Reputation, SourceStatus
from app.engine.public_suffixes import DEFAULT_PROTECTED_BRANDS
from app.engine.rule_catalog import RULE_CATALOG
from app.services.analysis_service import AnalysisService
from app.services.rules_provider import RulesProvider, parse_brands, parse_rules


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def brand_doc(codigo: str = "acme", **kw: Any) -> dict[str, Any]:
    doc = {
        "_id": 1,
        "codigo": codigo,
        "nombre": "Acme",
        "categoria": "banca",
        "dominios_oficiales": ["ACME.com "],
        "variantes_ofuscadas": ["4cme"],
        "activa": True,
    }
    doc.update(kw)
    return doc


def rule_doc(codigo: str = "URL_TLD_ALTO_RIESGO", **kw: Any) -> dict[str, Any]:
    doc = {
        "_id": 2,
        "codigo": codigo,
        "capa": RULE_CATALOG[codigo][0],
        "titulo": "t",
        "descripcion": "d",
        "puntos": RULE_CATALOG[codigo][1],
        "tipo_patron": "p",
        "parametros": {"marcas_codigos": [], "valores": ["xyz"]},
        "activa": True,
        "version": 1,
    }
    doc.update(kw)
    return doc


def repo(rules: list[dict[str, Any]], brands: list[dict[str, Any]]) -> MagicMock:
    r = MagicMock()
    r.find_rules = AsyncMock(return_value=rules)
    r.find_brands = AsyncMock(return_value=brands)
    return r


@pytest.mark.asyncio
async def test_loads_from_mongo_normalizes_and_caches_until_ttl() -> None:
    clock = Clock()
    r = repo([rule_doc()], [brand_doc()])
    provider = RulesProvider(r, ttl_seconds=3600, retry_seconds=30, clock=clock)

    snap = await provider.get()
    assert snap.source == "mongo"
    assert snap.brands[0].codigo == "acme" and snap.brands[0].dominios_oficiales == ["acme.com"]
    await provider.get()
    clock.now += 3599
    await provider.get()
    assert r.find_rules.await_count == 1  # dentro del TTL no vuelve a consultar Mongo

    clock.now += 2  # TTL vencido
    await provider.get()
    assert r.find_rules.await_count == 2


@pytest.mark.asyncio
async def test_concurrent_requests_trigger_a_single_load() -> None:
    r = repo([rule_doc()], [brand_doc()])
    provider = RulesProvider(r, clock=Clock())
    await asyncio.gather(*(provider.get() for _ in range(25)))
    assert r.find_rules.await_count == 1


@pytest.mark.asyncio
async def test_mongo_failure_without_previous_catalog_uses_internal_defaults_and_retries_soon() -> (
    None
):
    clock = Clock()
    r = MagicMock()
    r.find_rules = AsyncMock(side_effect=ServerSelectionTimeoutError("caído"))
    r.find_brands = AsyncMock(return_value=[])
    provider = RulesProvider(r, ttl_seconds=3600, retry_seconds=30, clock=clock)

    snap = await provider.get()
    assert (
        snap.source == "defaults" and snap.brands == DEFAULT_PROTECTED_BRANDS and snap.rules == ()
    )
    await provider.get()
    assert r.find_rules.await_count == 1  # no martilla a Mongo en cada análisis

    clock.now += 31  # reintento corto, no el TTL completo
    r.find_rules = AsyncMock(return_value=[rule_doc()])
    r.find_brands = AsyncMock(return_value=[brand_doc()])
    assert (await provider.get()).source == "mongo"


@pytest.mark.asyncio
async def test_mongo_failure_keeps_last_valid_catalog() -> None:
    clock = Clock()
    r = repo([rule_doc()], [brand_doc()])
    provider = RulesProvider(r, ttl_seconds=100, retry_seconds=10, clock=clock)
    good = await provider.get()
    clock.now += 101
    r.find_rules = AsyncMock(side_effect=ServerSelectionTimeoutError("caído"))
    assert await provider.get() is good  # conserva el último catálogo válido


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "brands", [[], [{"codigo": 7}], [brand_doc(dominios_oficiales="no-lista")]]
)
async def test_empty_or_invalid_brand_catalog_falls_back_to_defaults(
    brands: list[dict[str, Any]],
) -> None:
    provider = RulesProvider(repo([rule_doc()], brands), clock=Clock())
    snap = await provider.get()
    assert snap.source == "defaults" and snap.brands == DEFAULT_PROTECTED_BRANDS


def test_invalid_documents_are_discarded_individually() -> None:
    brands, skipped = parse_brands(
        [brand_doc("a"), brand_doc("b", activa="si"), {"codigo": ""}, brand_doc("c")]
    )
    assert [b.codigo for b in brands] == ["a", "c"] and skipped == 2

    inventada = {**rule_doc(), "codigo": "REGLA_INVENTADA"}
    rules, skipped_r, _ = parse_rules(
        [rule_doc(), inventada, rule_doc("URL_ACORTADOR", parametros="x")]
    )
    assert [r.codigo for r in rules] == ["URL_TLD_ALTO_RIESGO"] and skipped_r == 2


def test_points_from_mongo_are_replaced_by_canonical_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from app.core.logging import logger as app_logger

    app_logger.propagate = True
    try:
        with caplog.at_level(logging.WARNING, logger="antfish"):
            rules, _, mismatched = parse_rules(
                [rule_doc(puntos=1), rule_doc("URL_ACORTADOR", puntos=500)]
            )
    finally:
        app_logger.propagate = False
    assert [r.puntos for r in rules] == [15, 10] and mismatched == 2


@pytest.mark.asyncio
async def test_analysis_uses_catalog_brands_and_disabled_rules() -> None:
    def api(name: str) -> AsyncMock:
        m = AsyncMock()
        m.check_url.return_value = ReputationResult(
            reputation=Reputation(api=name, estado=SourceStatus.OK, positivo=False, detecciones=0)
        )
        return m

    provider = RulesProvider(
        repo([rule_doc("URL_EXCESO_GUIONES", activa=False, parametros={})], [brand_doc("acme")]),
        clock=Clock(),
    )
    service = AnalysisService(
        web_risk_client=api("google_web_risk"),
        virustotal_client=api("virustotal"),
        phishtank_client=None,
        rules_provider=provider,
    )
    out = await service.analyze("url", "https://acme-seguro-login.verifica-ya.net/")

    codigos = {h["regla_codigo"] for h in out["hallazgos"]}
    assert "URL_SUBDOMINIO_ENGANOSO" in codigos  # marca 'acme' viene del catálogo, no del código
    assert "URL_EXCESO_GUIONES" not in codigos  # regla desactivada en el catálogo
    assert out["motivo_cortocircuito"] == "suplantacion_marca" and out["score_total"] >= 80
