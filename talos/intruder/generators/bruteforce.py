"""
Module: talos.intruder.generators.bruteforce

Purpose:
    Character-set product generator (Phase 4). Yields all strings of length
    min_len..max_len over a charset (Burp-style brute forcer).

    Large products require ``force`` or stay under DEFAULT_BRUTEFORCE_MAX_COMBOS.
"""

from __future__ import annotations

import itertools
from typing import Any, Iterator

from talos.intruder.models import (
    DEFAULT_BRUTEFORCE_CHARSET,
    DEFAULT_BRUTEFORCE_MAX_COMBOS,
    DEFAULT_BRUTEFORCE_MAX_LEN,
    DEFAULT_BRUTEFORCE_MIN_LEN,
    ERR_BRUTEFORCE_TOO_LARGE,
    ERR_EMPTY_GENERATOR,
)


def _estimate_combos(charset_len: int, min_len: int, max_len: int) -> int:
    if charset_len <= 0 or min_len < 0 or max_len < min_len:
        return 0
    total = 0
    for length in range(min_len, max_len + 1):
        total += charset_len ** length
    return total


class BruteforceGenerator:
    """
    Yields every combination of charset for lengths [min_len, max_len].

    Options:
        charset (str, default alnum lower+digits)
        min_len / min (int, default 1)
        max_len / max (int, default 3)
        force (bool) — allow products above hard cap
        max_combos (int) — override hard cap
    """

    def __init__(self) -> None:
        self._values: list[str] = []
        self._index = 0
        self.charset = DEFAULT_BRUTEFORCE_CHARSET
        self.min_len = DEFAULT_BRUTEFORCE_MIN_LEN
        self.max_len = DEFAULT_BRUTEFORCE_MAX_LEN

    def open(self, config: dict[str, Any]) -> None:
        charset = str(config.get("charset") or DEFAULT_BRUTEFORCE_CHARSET)
        # Deduplicate while preserving order
        seen: set[str] = set()
        chars: list[str] = []
        for ch in charset:
            if ch not in seen:
                seen.add(ch)
                chars.append(ch)
        if not chars:
            raise ValueError(f"{ERR_EMPTY_GENERATOR}:bruteforce_empty_charset")
        self.charset = "".join(chars)

        self.min_len = int(
            config.get("min_len", config.get("min", DEFAULT_BRUTEFORCE_MIN_LEN))
        )
        self.max_len = int(
            config.get("max_len", config.get("max", DEFAULT_BRUTEFORCE_MAX_LEN))
        )
        if self.min_len < 0 or self.max_len < self.min_len:
            raise ValueError(
                f"{ERR_EMPTY_GENERATOR}:bruteforce_bad_lengths:{self.min_len}-{self.max_len}"
            )
        if self.max_len > 12:
            # Absolute guard against combinatorial explosion even with force
            raise ValueError(f"{ERR_BRUTEFORCE_TOO_LARGE}:max_len_gt_12")

        total = _estimate_combos(len(chars), self.min_len, self.max_len)
        cap = int(config.get("max_combos") or DEFAULT_BRUTEFORCE_MAX_COMBOS)
        force = bool(config.get("force"))
        if total > cap and not force:
            raise ValueError(
                f"{ERR_BRUTEFORCE_TOO_LARGE}:{total}:cap={cap}:use_force"
            )
        # Even with force, refuse absurd materializations (> 1e6) to protect memory
        hard = 1_000_000 if force else cap
        if total > hard:
            raise ValueError(f"{ERR_BRUTEFORCE_TOO_LARGE}:{total}:hard_cap={hard}")

        self._values = []
        for length in range(self.min_len, self.max_len + 1):
            if length == 0:
                self._values.append("")
                continue
            for prod in itertools.product(chars, repeat=length):
                self._values.append("".join(prod))
        self._index = 0
        if not self._values:
            raise ValueError(f"{ERR_EMPTY_GENERATOR}:bruteforce_empty")

    def __iter__(self) -> Iterator[str]:
        while self._index < len(self._values):
            v = self._values[self._index]
            self._index += 1
            yield v

    def estimate_count(self) -> int | None:
        return len(self._values)

    def checkpoint(self) -> dict[str, Any]:
        return {
            "type": "bruteforce",
            "index": self._index,
            "charset": self.charset,
            "min_len": self.min_len,
            "max_len": self.max_len,
        }

    def restore(self, checkpoint: dict[str, Any]) -> None:
        if not self._values:
            self.open({
                "charset": checkpoint.get("charset", DEFAULT_BRUTEFORCE_CHARSET),
                "min_len": checkpoint.get("min_len", DEFAULT_BRUTEFORCE_MIN_LEN),
                "max_len": checkpoint.get("max_len", DEFAULT_BRUTEFORCE_MAX_LEN),
                "force": True,  # restore must not re-fail cap
            })
        self._index = int(checkpoint.get("index", 0))
