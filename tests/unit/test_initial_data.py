"""Coherencia de initial_data.json con el motor y con el modelo (CU-11, RN-03 a RN-05, D11)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.engine.public_suffixes import DEFAULT_PROTECTED_BRANDS, HIGH_RISK_TLDS, KNOWN_SHORTENERS
from app.engine.rule_catalog import RULE_CATALOG
from app.services.rules_provider import parse_brands, parse_rules

PATH = Path(__file__).resolve().parents[2] / "app" / "repositories" / "mongo" / "initial_data.json"


@pytest.fixture(scope="module")
def data() -> dict:
    return json.loads(PATH.read_text(encoding="utf-8"))


def test_has_exactly_the_twelve_catalog_rules_with_canonical_points(data: dict) -> None:
    reglas = {r["codigo"]: r for r in data["reglas_heuristicas"]}
    assert set(reglas) == set(RULE_CATALOG)
    for codigo, (capa, puntos) in RULE_CATALOG.items():
        assert reglas[codigo]["capa"] == capa and reglas[codigo]["puntos"] == puntos
        assert reglas[codigo]["activa"] is True and reglas[codigo]["version"] == 1


def test_value_lists_match_the_engine_constants(data: dict) -> None:
    reglas = {r["codigo"]: r for r in data["reglas_heuristicas"]}
    assert set(reglas["URL_TLD_ALTO_RIESGO"]["parametros"]["valores"]) == set(HIGH_RISK_TLDS)
    assert set(reglas["URL_ACORTADOR"]["parametros"]["valores"]) == set(KNOWN_SHORTENERS)


def test_existing_brands_are_identical_to_engine_defaults_and_active(data: dict) -> None:
    by_code = {m["codigo"]: m for m in data["marcas_protegidas"]}
    for b in DEFAULT_PROTECTED_BRANDS:
        m = by_code[b.codigo]
        assert m["activa"] is True and m["nombre"] == b.nombre
        assert m["dominios_oficiales"] == b.dominios_oficiales
        assert m["variantes_ofuscadas"] == b.variantes_ofuscadas


def test_new_brands_are_inactive_and_listed_for_review(data: dict) -> None:
    default_codes = {b.codigo for b in DEFAULT_PROTECTED_BRANDS}
    new = [m for m in data["marcas_protegidas"] if m["codigo"] not in default_codes]
    assert len(new) == 10
    assert all(m["activa"] is False for m in new)
    assert set(data["_revision_pendiente"]["marcas"]) == {m["codigo"] for m in new}


def test_brand_catalog_is_well_formed(data: dict) -> None:
    marcas = data["marcas_protegidas"]
    codes = [m["codigo"] for m in marcas]
    assert len(codes) == len(set(codes))  # índice único I7
    domain = re.compile(r"^(?=.{4,253}$)([a-z0-9-]+\.)+[a-z]{2,}$")
    seen: dict[str, str] = {}
    for m in marcas:
        assert m["dominios_oficiales"], m["codigo"]
        for d in m["dominios_oficiales"]:
            assert domain.match(d), (m["codigo"], d)
            assert seen.setdefault(d, m["codigo"]) == m["codigo"], f"{d} duplicado entre marcas"


def test_provider_parsers_accept_the_whole_file_without_discards(data: dict) -> None:
    brands, skipped_b = parse_brands(data["marcas_protegidas"])
    rules, skipped_r, mismatched = parse_rules(data["reglas_heuristicas"])
    assert (len(brands), skipped_b) == (21, 0)
    assert (len(rules), skipped_r, mismatched) == (12, 0, 0)


def test_underscore_keys_are_not_seed_collections(data: dict) -> None:
    assert {"reglas_heuristicas", "marcas_protegidas"} <= set(data)
    assert all(k.startswith("_") or k in {"reglas_heuristicas", "marcas_protegidas"} for k in data)
