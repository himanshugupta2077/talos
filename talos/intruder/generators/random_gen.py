"""
Module: talos.intruder.generators.random_gen

Purpose:
    Finite random-string generator (Phase 4). Produces ``count`` random
    payloads of fixed or ranged length from a charset. Values are generated
    once at open() so checkpoint/restore is deterministic for a session.
"""

from __future__ import annotations

import random
from typing import Any, Iterator

from talos.intruder.models import (
    DEFAULT_RANDOM_CHARSET,
    DEFAULT_RANDOM_COUNT,
    DEFAULT_RANDOM_LENGTH,
    ERR_INVALID_RANDOM,
)


class RandomGenerator:
    """
    Options:
        count (int, default 100)
        length (int, default 8) — fixed length when min_len/max_len absent
        min_len / max_len (int, optional) — random length per value
        charset (str)
        seed (int|str, optional) — deterministic sequence for resume/tests
        force (bool) — allow count > 100_000
    """

    def __init__(self) -> None:
        self._values: list[str] = []
        self._index = 0
        self.count = DEFAULT_RANDOM_COUNT
        self.length = DEFAULT_RANDOM_LENGTH
        self.min_len: int | None = None
        self.max_len: int | None = None
        self.charset = DEFAULT_RANDOM_CHARSET
        self.seed: Any = None

    def open(self, config: dict[str, Any]) -> None:
        self.count = int(config.get("count", DEFAULT_RANDOM_COUNT))
        if self.count < 1:
            raise ValueError(f"{ERR_INVALID_RANDOM}:count_lt_1")
        if self.count > 100_000 and not config.get("force"):
            raise ValueError(f"{ERR_INVALID_RANDOM}:count_too_large:{self.count}")
        if self.count > 1_000_000:
            raise ValueError(f"{ERR_INVALID_RANDOM}:count_hard_cap:{self.count}")

        self.charset = str(config.get("charset") or DEFAULT_RANDOM_CHARSET)
        if not self.charset:
            raise ValueError(f"{ERR_INVALID_RANDOM}:empty_charset")

        if "min_len" in config or "max_len" in config:
            self.min_len = int(config.get("min_len", config.get("length", DEFAULT_RANDOM_LENGTH)))
            self.max_len = int(config.get("max_len", self.min_len))
            if self.min_len < 0 or self.max_len < self.min_len:
                raise ValueError(f"{ERR_INVALID_RANDOM}:bad_lengths")
            self.length = self.min_len
        else:
            self.length = int(config.get("length", DEFAULT_RANDOM_LENGTH))
            if self.length < 0:
                raise ValueError(f"{ERR_INVALID_RANDOM}:bad_length")
            self.min_len = None
            self.max_len = None

        # Always pin a seed so checkpoint/restore regenerates the same sequence.
        raw_seed = config.get("seed")
        if raw_seed is None:
            self.seed = random.randrange(0, 2**31 - 1)
        else:
            self.seed = raw_seed
        rng = random.Random(self.seed)

        self._values = []
        for _ in range(self.count):
            if self.min_len is not None and self.max_len is not None:
                n = rng.randint(self.min_len, self.max_len)
            else:
                n = self.length
            if n == 0:
                self._values.append("")
            else:
                self._values.append("".join(rng.choice(self.charset) for _ in range(n)))
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
            "type": "random",
            "index": self._index,
            "count": self.count,
            "length": self.length,
            "min_len": self.min_len,
            "max_len": self.max_len,
            "charset": self.charset,
            "seed": self.seed,
        }

    def restore(self, checkpoint: dict[str, Any]) -> None:
        # Always re-materialize from checkpoint seed so resume matches prior run
        # even when config had no seed (auto-pinned at first open).
        opts: dict[str, Any] = {
            "count": checkpoint.get("count", DEFAULT_RANDOM_COUNT),
            "length": checkpoint.get("length", DEFAULT_RANDOM_LENGTH),
            "charset": checkpoint.get("charset", DEFAULT_RANDOM_CHARSET),
            "seed": checkpoint.get("seed"),
            "force": True,
        }
        if checkpoint.get("min_len") is not None:
            opts["min_len"] = checkpoint["min_len"]
        if checkpoint.get("max_len") is not None:
            opts["max_len"] = checkpoint["max_len"]
        self.open(opts)
        self._index = int(checkpoint.get("index", 0))
