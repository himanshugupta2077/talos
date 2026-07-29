"""
Module: talos.intruder.strategies.sniper

Purpose:
    One payload set applied to each target variable in turn; others stay at
    baseline/fixed (not included in strategy_vars).
"""

from __future__ import annotations

from typing import Any, Iterator, Optional

from talos.intruder.generators.base import PayloadGenerator
from talos.intruder.processors import apply_processors


class SniperStrategy:
    """
    For each target variable in order, re-play the full payload set against
    that variable alone.
    """

    def __init__(self) -> None:
        self._targets: list[str] = []
        self._target_idx = 0
        self._gen: Optional[PayloadGenerator] = None
        self._gen_config: dict[str, Any] = {}
        self._payloads: list[str] = []
        self._payload_idx = 0
        self._processors: list[str] = []
        self._sent = 0
        self._set_name: str = ""
        self._base_checkpoint: dict[str, Any] = {}

    def prepare(
        self,
        variables: list[str],
        payload_sets: dict[str, PayloadGenerator],
        options: dict[str, Any] | None = None,
    ) -> None:
        opts = options or {}
        targets = opts.get("targets") or variables
        self._targets = [str(t) for t in targets]
        if not self._targets:
            raise ValueError("sniper_no_targets")
        processors_map: dict[str, list[str]] = opts.get("processors") or {}
        # Shared payload set: explicit, or first set, or set matching first target.
        set_name = opts.get("payload_set")
        if not set_name:
            for t in self._targets:
                if t in payload_sets:
                    set_name = t
                    break
        if not set_name:
            if payload_sets:
                set_name = next(iter(payload_sets.keys()))
            else:
                raise ValueError("unbound_variable:sniper_no_set")
        self._set_name = str(set_name)
        if self._set_name not in payload_sets:
            raise ValueError(f"unbound_variable:{self._set_name}")
        self._gen = payload_sets[self._set_name]
        self._processors = list(
            processors_map.get(self._set_name)
            or opts.get("processors_list")
            or []
        )
        # Materialize payloads once so each target gets a full pass.
        # Generators are iterators; sniper re-uses the list.
        self._payloads = list(self._gen)
        if not self._payloads:
            raise ValueError("empty_generator:sniper")
        self._target_idx = 0
        self._payload_idx = 0
        self._sent = 0
        self._base_checkpoint = self._gen.checkpoint()

    def next(self) -> dict[str, str] | None:
        while self._target_idx < len(self._targets):
            if self._payload_idx >= len(self._payloads):
                self._target_idx += 1
                self._payload_idx = 0
                continue
            var = self._targets[self._target_idx]
            raw = self._payloads[self._payload_idx]
            self._payload_idx += 1
            value = apply_processors(raw, self._processors, {"var": var})
            self._sent += 1
            return {var: value}
        return None

    def progress(self) -> dict[str, Any]:
        total = len(self._targets) * len(self._payloads) if self._payloads else None
        pct = None
        if total and total > 0:
            pct = min(100.0, round(100.0 * self._sent / total, 2))
        return {
            "sent": self._sent,
            "total_estimate": total,
            "percent": pct,
            "target_index": self._target_idx,
            "targets": list(self._targets),
        }

    def checkpoint(self) -> dict[str, Any]:
        return {
            "type": "sniper",
            "target_idx": self._target_idx,
            "payload_idx": self._payload_idx,
            "sent": self._sent,
            "set_name": self._set_name,
            "targets": list(self._targets),
            # Store payloads length only — values reloaded from generator config
            # on restore via full re-materialize from generator restore+iter.
            "payload_count": len(self._payloads),
            "payloads": list(self._payloads),
        }

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._target_idx = int(checkpoint.get("target_idx", 0))
        self._payload_idx = int(checkpoint.get("payload_idx", 0))
        self._sent = int(checkpoint.get("sent", 0))
        if checkpoint.get("targets"):
            self._targets = list(checkpoint["targets"])
        if checkpoint.get("payloads"):
            self._payloads = list(checkpoint["payloads"])
