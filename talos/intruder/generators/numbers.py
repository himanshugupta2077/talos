"""
Module: talos.intruder.generators.numbers

Purpose:
    Inclusive integer range generator: start, end, step.
"""

from __future__ import annotations

from typing import Any, Iterator


class NumbersGenerator:
    """Yields str(n) for n in range(start, end+sign, step)."""

    def __init__(self) -> None:
        self.start = 0
        self.end = 0
        self.step = 1
        self._index = 0  # how many values already yielded
        self._values: list[str] = []

    def open(self, config: dict[str, Any]) -> None:
        self.start = int(config.get("start", 0))
        self.end = int(config.get("end", 0))
        self.step = int(config.get("step", 1))
        if self.step == 0:
            raise ValueError("invalid_numbers:step_zero")
        if self.step > 0 and self.start > self.end:
            raise ValueError("invalid_numbers:start_gt_end")
        if self.step < 0 and self.start < self.end:
            raise ValueError("invalid_numbers:start_lt_end")
        self._values = []
        n = self.start
        if self.step > 0:
            while n <= self.end:
                self._values.append(str(n))
                n += self.step
        else:
            while n >= self.end:
                self._values.append(str(n))
                n += self.step
        self._index = 0

    def __iter__(self) -> Iterator[str]:
        while self._index < len(self._values):
            v = self._values[self._index]
            self._index += 1
            yield v

    def estimate_count(self) -> int | None:
        return len(self._values)

    def checkpoint(self) -> dict[str, Any]:
        return {
            "type": "numbers",
            "index": self._index,
            "start": self.start,
            "end": self.end,
            "step": self.step,
        }

    def restore(self, checkpoint: dict[str, Any]) -> None:
        if not self._values:
            self.open({
                "start": checkpoint.get("start", self.start),
                "end": checkpoint.get("end", self.end),
                "step": checkpoint.get("step", self.step),
            })
        self._index = int(checkpoint.get("index", 0))
