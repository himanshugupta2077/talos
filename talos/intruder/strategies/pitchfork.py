"""
Module: talos.intruder.strategies.pitchfork

Purpose:
    Pitchfork / zip multi-set strategy: advance N payload sets in lockstep,
    one binding per variable per attempt. Stops when the shortest set is
    exhausted (Burp-compatible pitchfork).

    zip is an alias of this behaviour (length = min of set lengths).
"""

from __future__ import annotations

from typing import Any, Iterator, Optional

from talos.intruder.generators.base import PayloadGenerator
from talos.intruder.processors import apply_processors


class PitchforkStrategy:
    """
    Parallel advance of N payload sets for N variables.

    Options:
        sets: ordered list of payload-set / variable names (default: keys of
              payload_sets that match injectable variables, else all set keys)
        processors: map set_name → processor name list (injected by engine)
    """

    def __init__(self, *, strategy_type: str = "pitchfork") -> None:
        self._strategy_type = strategy_type
        self._vars: list[str] = []
        self._set_names: list[str] = []
        self._gens: list[PayloadGenerator] = []
        self._iters: list[Optional[Iterator[str]]] = []
        self._processors: list[list[str]] = []
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
            # Prefer payload sets that match variable names, in variable order.
            matched = [v for v in variables if v in payload_sets]
            set_names = matched if matched else list(payload_sets.keys())
        if not set_names:
            raise ValueError("multiset_unbound:no_sets")
        for name in set_names:
            if name not in payload_sets:
                raise ValueError(f"unbound_variable:{name}")

        self._set_names = set_names
        # Each set binds to a variable of the same name (payload set key == var).
        self._vars = list(set_names)
        self._gens = [payload_sets[n] for n in set_names]
        self._processors = [
            list(processors_map.get(n) or []) for n in set_names
        ]
        self._iters = [iter(g) for g in self._gens]
        self._sent = 0
        self._exhausted = False
        # Estimate = min of known set lengths (zip / pitchfork stop at shortest).
        counts: list[int] = []
        for g in self._gens:
            c = g.estimate_count()
            if c is None:
                self._total = None
                break
            counts.append(c)
        else:
            self._total = min(counts) if counts else 0

    def next(self) -> dict[str, str] | None:
        if self._exhausted or not self._iters:
            return None
        bindings: dict[str, str] = {}
        for i, it in enumerate(self._iters):
            if it is None:
                self._exhausted = True
                return None
            try:
                raw = next(it)
            except StopIteration:
                self._exhausted = True
                return None
            value = apply_processors(
                raw, self._processors[i], {"var": self._vars[i]}
            )
            bindings[self._vars[i]] = value
        self._sent += 1
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
            "strategy": self._strategy_type,
        }

    def checkpoint(self) -> dict[str, Any]:
        return {
            "type": self._strategy_type,
            "sent": self._sent,
            "set_names": list(self._set_names),
            "vars": list(self._vars),
            "exhausted": self._exhausted,
            "generators": [g.checkpoint() for g in self._gens],
        }

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._sent = int(checkpoint.get("sent", 0))
        self._exhausted = bool(checkpoint.get("exhausted", False))
        if checkpoint.get("set_names"):
            self._set_names = list(checkpoint["set_names"])
        if checkpoint.get("vars"):
            self._vars = list(checkpoint["vars"])
        gens_cp = checkpoint.get("generators") or []
        self._iters = []
        for i, gen in enumerate(self._gens):
            if i < len(gens_cp) and gens_cp[i]:
                gen.restore(gens_cp[i])
            self._iters.append(iter(gen))

