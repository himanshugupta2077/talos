"""
Module: talos.intruder.strategies.single

Purpose:
    One payload set drives one primary variable for a single pass.
"""

from __future__ import annotations

from typing import Any, Iterator, Optional

from talos.intruder.generators.base import PayloadGenerator
from talos.intruder.processors import apply_processors


class SingleStrategy:
    """
    Maps one generator onto one target variable.
    Options: primary (var name); default = first non-empty payload set key
    that matches a variable, else first variable.
    """

    def __init__(self) -> None:
        self._var: str = ""
        self._gen: Optional[PayloadGenerator] = None
        self._processors: list[str] = []
        self._iter: Optional[Iterator[str]] = None
        self._sent = 0
        self._total: Optional[int] = None
        self._set_name: str = ""

    def prepare(
        self,
        variables: list[str],
        payload_sets: dict[str, PayloadGenerator],
        options: dict[str, Any] | None = None,
    ) -> None:
        opts = options or {}
        processors_map: dict[str, list[str]] = opts.get("processors") or {}
        primary = opts.get("primary") or opts.get("var")
        if not primary:
            # Prefer a payload set whose name matches a variable.
            for v in variables:
                if v in payload_sets:
                    primary = v
                    break
            if not primary:
                # First payload set key if variables empty use that as var name.
                if payload_sets:
                    primary = next(iter(payload_sets.keys()))
                elif variables:
                    primary = variables[0]
                else:
                    raise ValueError("unbound_variable:no_primary")
        self._var = str(primary)
        # Resolve generator: by var name or explicit set name.
        set_name = opts.get("payload_set") or self._var
        if set_name not in payload_sets:
            if len(payload_sets) == 1:
                set_name = next(iter(payload_sets.keys()))
            else:
                raise ValueError(f"unbound_variable:{self._var}")
        self._set_name = set_name
        self._gen = payload_sets[set_name]
        self._processors = list(
            processors_map.get(set_name)
            or processors_map.get(self._var)
            or opts.get("processors_list")
            or []
        )
        self._total = self._gen.estimate_count()
        self._iter = iter(self._gen)
        self._sent = 0

    def next(self) -> dict[str, str] | None:
        if self._iter is None:
            return None
        try:
            raw = next(self._iter)
        except StopIteration:
            return None
        value = apply_processors(raw, self._processors, {"var": self._var})
        self._sent += 1
        return {self._var: value}

    def progress(self) -> dict[str, Any]:
        total = self._total
        pct = None
        if total and total > 0:
            pct = min(100.0, round(100.0 * self._sent / total, 2))
        return {
            "sent": self._sent,
            "total_estimate": total,
            "percent": pct,
            "primary": self._var,
        }

    def checkpoint(self) -> dict[str, Any]:
        gen_cp = self._gen.checkpoint() if self._gen else {}
        return {
            "type": "single",
            "var": self._var,
            "set_name": self._set_name,
            "sent": self._sent,
            "generator": gen_cp,
        }

    def restore(self, checkpoint: dict[str, Any]) -> None:
        if self._gen and checkpoint.get("generator"):
            self._gen.restore(checkpoint["generator"])
            self._iter = iter(self._gen)
        self._sent = int(checkpoint.get("sent", 0))
