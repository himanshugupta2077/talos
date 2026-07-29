"""
Package: talos.intruder.strategies

Purpose:
    Attack strategies: single + sniper (Phase 1).
"""

from __future__ import annotations

from typing import Any

from talos.intruder.generators.base import PayloadGenerator
from talos.intruder.models import (
    ERR_UNKNOWN_PLUGIN,
    STRATEGY_SINGLE,
    STRATEGY_SNIPER,
)
from talos.intruder.strategies.single import SingleStrategy
from talos.intruder.strategies.sniper import SniperStrategy


def build_strategy(
    strategy_type: str,
    variables: list[str],
    payload_sets: dict[str, PayloadGenerator],
    *,
    options: dict[str, Any] | None = None,
) -> Any:
    """
    Build and prepare a strategy.
    payload_sets maps payload-set name → generator (usually keyed by var name).
    """
    key = (strategy_type or "").strip().lower()
    if key == STRATEGY_SINGLE:
        strat = SingleStrategy()
    elif key == STRATEGY_SNIPER:
        strat = SniperStrategy()
    else:
        raise ValueError(f"{ERR_UNKNOWN_PLUGIN}:strategy:{strategy_type}")
    strat.prepare(variables, payload_sets, options or {})
    return strat


__all__ = [
    "SingleStrategy",
    "SniperStrategy",
    "build_strategy",
]
