"""
Package: talos.intruder.generators

Purpose:
    Payload generators for Intruder (wordlist, numbers, static in Phase 1).
"""

from __future__ import annotations

from typing import Any

from talos.intruder.generators.base import PayloadGenerator
from talos.intruder.generators.numbers import NumbersGenerator
from talos.intruder.generators.static import StaticGenerator
from talos.intruder.generators.wordlist import WordlistGenerator
from talos.intruder.models import (
    ERR_UNKNOWN_PLUGIN,
    GEN_NUMBERS,
    GEN_STATIC,
    GEN_WORDLIST,
)


def build_generator(name: str, options: dict[str, Any] | None = None) -> PayloadGenerator:
    """
    Factory for Phase 1 generators.
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
    else:
        raise ValueError(f"{ERR_UNKNOWN_PLUGIN}:generator:{name}")
    gen.open(opts)
    return gen


__all__ = [
    "PayloadGenerator",
    "WordlistGenerator",
    "NumbersGenerator",
    "StaticGenerator",
    "build_generator",
]
