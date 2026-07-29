"""
Module: talos.intruder.generators.pattern

Purpose:
    Pattern payload generator (Phase 4). Expands a template string with
    placeholders:

      {n} / {i}     — integer counter from start..end step
      {n:04d}       — zero-padded counter (printf-style after colon)
      {hex} / {h}   — hex counter (lowercase)
      {HEX}         — hex counter (uppercase)
      {a} / {alpha} — letter sequence a,b,...,z,aa,... (base-26)
      {rand:N}      — N random alnum chars (seeded for resume)

    Without placeholders, yields the pattern once (static).
"""

from __future__ import annotations

import re
import string
from typing import Any, Iterator

from talos.intruder.models import (
    DEFAULT_PATTERN_END,
    DEFAULT_PATTERN_START,
    ERR_INVALID_PATTERN,
)

_PLACEHOLDER_RE = re.compile(
    r"\{("
    r"n(?::[^}]+)?"
    r"|i(?::[^}]+)?"
    r"|hex|h|HEX"
    r"|a|alpha"
    r"|rand:\d+"
    r")\}"
)


def _alpha_label(n: int) -> str:
    """0 -> a, 25 -> z, 26 -> aa (1-based Excel-style base-26)."""
    if n < 0:
        n = 0
    # Convert to 1-based for Excel-style
    n += 1
    chars: list[str] = []
    while n > 0:
        n, rem = divmod(n - 1, 26)
        chars.append(string.ascii_lowercase[rem])
    return "".join(reversed(chars)) or "a"


class PatternGenerator:
    """
    Options:
        pattern (str, required) — template with optional placeholders
        start (int, default 0)
        end (int, default 99)
        step (int, default 1)
        seed (int, optional) — for {rand:N} placeholders
        force (bool) — allow large ranges
    """

    def __init__(self) -> None:
        self._values: list[str] = []
        self._index = 0
        self.pattern = ""
        self.start = DEFAULT_PATTERN_START
        self.end = DEFAULT_PATTERN_END
        self.step = 1
        self.seed: Any = None

    def open(self, config: dict[str, Any]) -> None:
        pattern = config.get("pattern")
        if pattern is None or str(pattern) == "":
            raise ValueError(f"{ERR_INVALID_PATTERN}:pattern_required")
        self.pattern = str(pattern)
        self.start = int(config.get("start", DEFAULT_PATTERN_START))
        self.end = int(config.get("end", DEFAULT_PATTERN_END))
        self.step = int(config.get("step", 1))
        if self.step == 0:
            raise ValueError(f"{ERR_INVALID_PATTERN}:step_zero")
        if self.step > 0 and self.start > self.end:
            raise ValueError(f"{ERR_INVALID_PATTERN}:start_gt_end")
        if self.step < 0 and self.start < self.end:
            raise ValueError(f"{ERR_INVALID_PATTERN}:start_lt_end")

        self.seed = config.get("seed", 0)
        placeholders = list(_PLACEHOLDER_RE.finditer(self.pattern))
        force = bool(config.get("force"))

        if not placeholders:
            # Static single value
            self._values = [self.pattern]
            self._index = 0
            return

        # Count iterations
        if self.step > 0:
            count = ((self.end - self.start) // self.step) + 1
        else:
            count = ((self.start - self.end) // abs(self.step)) + 1
        if count < 1:
            raise ValueError(f"{ERR_INVALID_PATTERN}:empty")
        if count > 100_000 and not force:
            raise ValueError(f"{ERR_INVALID_PATTERN}:too_many:{count}")
        if count > 1_000_000:
            raise ValueError(f"{ERR_INVALID_PATTERN}:hard_cap:{count}")

        self._values = []
        n = self.start
        # Local RNG for {rand:N} — reseeded per index for determinism
        import random as _random

        while True:
            if self.step > 0 and n > self.end:
                break
            if self.step < 0 and n < self.end:
                break

            def repl(m: re.Match[str], _n: int = n) -> str:
                token = m.group(1)
                if token.startswith("n") or token.startswith("i"):
                    if ":" in token:
                        _, fmt = token.split(":", 1)
                        try:
                            return format(_n, fmt)
                        except (ValueError, TypeError):
                            return str(_n)
                    return str(_n)
                if token in ("hex", "h"):
                    return format(_n, "x")
                if token == "HEX":
                    return format(_n, "X")
                if token in ("a", "alpha"):
                    return _alpha_label(_n)
                if token.startswith("rand:"):
                    length = int(token.split(":", 1)[1])
                    rng = _random.Random(hash((self.seed, _n, length)) & 0xFFFFFFFF)
                    alphabet = string.ascii_letters + string.digits
                    return "".join(rng.choice(alphabet) for _ in range(length))
                return m.group(0)

            self._values.append(_PLACEHOLDER_RE.sub(repl, self.pattern))
            n += self.step

        self._index = 0
        if not self._values:
            raise ValueError(f"{ERR_INVALID_PATTERN}:empty")

    def __iter__(self) -> Iterator[str]:
        while self._index < len(self._values):
            v = self._values[self._index]
            self._index += 1
            yield v

    def estimate_count(self) -> int | None:
        return len(self._values)

    def checkpoint(self) -> dict[str, Any]:
        return {
            "type": "pattern",
            "index": self._index,
            "pattern": self.pattern,
            "start": self.start,
            "end": self.end,
            "step": self.step,
            "seed": self.seed,
        }

    def restore(self, checkpoint: dict[str, Any]) -> None:
        if not self._values:
            self.open({
                "pattern": checkpoint.get("pattern", self.pattern),
                "start": checkpoint.get("start", DEFAULT_PATTERN_START),
                "end": checkpoint.get("end", DEFAULT_PATTERN_END),
                "step": checkpoint.get("step", 1),
                "seed": checkpoint.get("seed", 0),
                "force": True,
            })
        self._index = int(checkpoint.get("index", 0))
