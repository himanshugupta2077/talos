"""
Package: talos.intruder.strategies

Purpose:
    Attack strategies: single, sniper (Phase 1); pitchfork, zip, cluster_bomb
    (Phase 2 multi-set).
"""

from __future__ import annotations

from typing import Any

from talos.intruder.generators.base import PayloadGenerator
from talos.intruder.models import (
    ERR_UNKNOWN_PLUGIN,
    STRATEGY_CARTESIAN,
    STRATEGY_CLUSTER_BOMB,
    STRATEGY_PITCHFORK,
    STRATEGY_SINGLE,
    STRATEGY_SNIPER,
    STRATEGY_ZIP,
)
from talos.intruder.strategies.cluster_bomb import ClusterBombStrategy
from talos.intruder.strategies.pitchfork import PitchforkStrategy
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
    elif key in (STRATEGY_PITCHFORK, STRATEGY_ZIP):
        # zip is pitchfork with length = min (same implementation).
        strat = PitchforkStrategy(strategy_type=key)
    elif key in (STRATEGY_CLUSTER_BOMB, STRATEGY_CARTESIAN):
        strat = ClusterBombStrategy(strategy_type=key)
    else:
        raise ValueError(f"{ERR_UNKNOWN_PLUGIN}:strategy:{strategy_type}")
    strat.prepare(variables, payload_sets, options or {})
    return strat


__all__ = [
    "SingleStrategy",
    "SniperStrategy",
    "PitchforkStrategy",
    "ClusterBombStrategy",
    "build_strategy",
]
