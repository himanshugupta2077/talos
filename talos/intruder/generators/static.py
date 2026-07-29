"""
Module: talos.intruder.generators.static

Purpose:
    Finite list of static string payloads.
"""

from __future__ import annotations

from typing import Any, Iterator


class StaticGenerator:
    """Yields values from options.values (list of strings)."""

    def __init__(self) -> None:
        self._values: list[str] = []
        self._index = 0

    def open(self, config: dict[str, Any]) -> None:
        raw = config.get("values")
        if raw is None and "value" in config:
            raw = [config["value"]]
        if not isinstance(raw, list):
            raw = []
        self._values = [str(v) for v in raw]
        self._index = 0

    def __iter__(self) -> Iterator[str]:
        while self._index < len(self._values):
            v = self._values[self._index]
            self._index += 1
            yield v

    def estimate_count(self) -> int | None:
        return len(self._values)

    def checkpoint(self) -> dict[str, Any]:
        return {"type": "static", "index": self._index}

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._index = int(checkpoint.get("index", 0))
