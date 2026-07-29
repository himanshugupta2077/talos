"""
Package: talos.intruder.generators

Purpose:
    Payload generators for Intruder (Phase 1 wordlist/numbers/static;
    Phase 3 uuid/csv/json/example_values/pool).
"""

from __future__ import annotations

from typing import Any

from talos.intruder.generators.base import PayloadGenerator
from talos.intruder.generators.csv_gen import CsvGenerator
from talos.intruder.generators.example_values import ExampleValuesGenerator
from talos.intruder.generators.json_gen import JsonGenerator
from talos.intruder.generators.numbers import NumbersGenerator
from talos.intruder.generators.pool import PoolGenerator
from talos.intruder.generators.static import StaticGenerator
from talos.intruder.generators.uuid_gen import UuidGenerator
from talos.intruder.generators.wordlist import WordlistGenerator
from talos.intruder.models import (
    ERR_UNKNOWN_PLUGIN,
    GEN_CSV,
    GEN_EXAMPLE_VALUES,
    GEN_JSON,
    GEN_NUMBERS,
    GEN_POOL,
    GEN_STATIC,
    GEN_UUID,
    GEN_WORDLIST,
)


def build_generator(name: str, options: dict[str, Any] | None = None) -> PayloadGenerator:
    """
    Factory for Intruder generators.
    Raises ValueError with stable code prefix for unknown plugins.
    """
    opts = dict(options or {})
    key = (name or "").strip().lower()
    if key == GEN_WORDLIST:
        gen: PayloadGenerator = WordlistGenerator()
    elif key == GEN_NUMBERS:
        gen = NumbersGenerator()
    elif key == GEN_STATIC:
        gen = StaticGenerator()
    elif key == GEN_UUID:
        gen = UuidGenerator()
    elif key == GEN_CSV:
        gen = CsvGenerator()
    elif key == GEN_JSON:
        gen = JsonGenerator()
    elif key == GEN_EXAMPLE_VALUES:
        gen = ExampleValuesGenerator()
    elif key == GEN_POOL:
        gen = PoolGenerator()
    else:
        raise ValueError(f"{ERR_UNKNOWN_PLUGIN}:generator:{name}")
    gen.open(opts)
    return gen


__all__ = [
    "PayloadGenerator",
    "WordlistGenerator",
    "NumbersGenerator",
    "StaticGenerator",
    "UuidGenerator",
    "CsvGenerator",
    "JsonGenerator",
    "ExampleValuesGenerator",
    "PoolGenerator",
    "build_generator",
]
