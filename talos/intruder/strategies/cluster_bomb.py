"""
Module: talos.intruder.strategies.cluster_bomb

Purpose:
    ClusterBomb / cartesian multi-set strategy: full cartesian product of
    N payload sets bound to N variables. Checkpoint restores odometer indices.
"""

from __future__ import annotations

from typing import Any, Optional

from talos.intruder.generators.base import PayloadGenerator
from talos.intruder.processors import apply_processors


class ClusterBombStrategy:
    """
    Cartesian product over ordered payload sets.

    Options:
        sets: ordered payload-set / variable names
        processors: map set_name → processor name list
    """

    def __init__(self, *, strategy_type: str = "cluster_bomb") -> None:
        self._strategy_type = strategy_type
        self._vars: list[str] = []
        self._set_names: list[str] = []
        self._payloads: list[list[str]] = []
        self._processors: list[list[str]] = []
        self._indices: list[int] = []
        self._sent = 0
        self._total: Optional[int] = None
        self._exhausted = False

    def prepare(
        self,
        variables: list[str],
        payload_sets: dict[str, PayloadGenerator],
        options: dict[str, Any] | None = None,
    ) -> None:
        opts = options or {}
        processors_map: dict[str, list[str]] = opts.get("processors") or {}
        ordered = opts.get("sets") or opts.get("variables")
        if ordered:
            set_names = [str(s) for s in ordered]
        else:
            matched = [v for v in variables if v in payload_sets]
            set_names = matched if matched else list(payload_sets.keys())
        if not set_names:
            raise ValueError("multiset_unbound:no_sets")
        for name in set_names:
            if name not in payload_sets:
                raise ValueError(f"unbound_variable:{name}")

        self._set_names = set_names
        self._vars = list(set_names)
        self._processors = [
            list(processors_map.get(n) or []) for n in set_names
        ]
        # Materialize each set so cartesian product can restart inner loops.
        self._payloads = []
        for name in set_names:
            gen = payload_sets[name]
            values = list(gen)
            if not values:
                raise ValueError(f"empty_generator:{name}")
            self._payloads.append(values)

        self._indices = [0] * len(self._payloads)
        self._sent = 0
        self._exhausted = False
        total = 1
        for pl in self._payloads:
            total *= len(pl)
        self._total = total

    def next(self) -> dict[str, str] | None:
        if self._exhausted or not self._payloads:
            return None
        # Bound current odometer position
        bindings: dict[str, str] = {}
        for i, var in enumerate(self._vars):
            raw = self._payloads[i][self._indices[i]]
            value = apply_processors(raw, self._processors[i], {"var": var})
            bindings[var] = value
        self._sent += 1
        # Advance odometer (rightmost fastest)
        for i in range(len(self._indices) - 1, -1, -1):
            self._indices[i] += 1
            if self._indices[i] < len(self._payloads[i]):
                break
            self._indices[i] = 0
            if i == 0:
                self._exhausted = True
        return bindings

    def progress(self) -> dict[str, Any]:
        total = self._total
        pct = None
        if total and total > 0:
            pct = min(100.0, round(100.0 * self._sent / total, 2))
        return {
            "sent": self._sent,
            "total_estimate": total,
            "percent": pct,
            "sets": list(self._set_names),
            "indices": list(self._indices),
            "strategy": self._strategy_type,
        }

    def checkpoint(self) -> dict[str, Any]:
        return {
            "type": self._strategy_type,
            "sent": self._sent,
            "set_names": list(self._set_names),
            "vars": list(self._vars),
            "indices": list(self._indices),
            "exhausted": self._exhausted,
            # Persist materialized payloads so restore does not re-open generators
            "payloads": [list(p) for p in self._payloads],
        }

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._sent = int(checkpoint.get("sent", 0))
        self._exhausted = bool(checkpoint.get("exhausted", False))
        if checkpoint.get("set_names"):
            self._set_names = list(checkpoint["set_names"])
        if checkpoint.get("vars"):
            self._vars = list(checkpoint["vars"])
        if checkpoint.get("indices"):
            self._indices = [int(i) for i in checkpoint["indices"]]
        if checkpoint.get("payloads"):
            self._payloads = [list(p) for p in checkpoint["payloads"]]
            total = 1
            for pl in self._payloads:
                total *= max(1, len(pl))
            self._total = total if self._payloads else 0

