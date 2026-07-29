"""
Module: talos.intruder.generators.uuid_gen

Purpose:
    Finite UUID payload generator (Phase 3). Default UUID v4.
"""

from __future__ import annotations

import uuid
from typing import Any, Iterator

from talos.intruder.models import DEFAULT_UUID_COUNT, ERR_INVALID_FILE_GENERATOR


class UuidGenerator:
    """
    Yields ``count`` UUID strings.

    Options:
        count (int, default 10) — how many UUIDs to produce.
        version (int, default 4) — only 4 supported.
        namespace (str, optional) — for deterministic v5 when name list provided.
        names (list[str], optional) — when set with version=5, map names → v5.
    """

    def __init__(self) -> None:
        self._values: list[str] = []
        self._index = 0
        self.count = DEFAULT_UUID_COUNT
        self.version = 4

    def open(self, config: dict[str, Any]) -> None:
        self.count = int(config.get("count", DEFAULT_UUID_COUNT))
        if self.count < 1:
            raise ValueError(f"{ERR_INVALID_FILE_GENERATOR}:uuid_count_lt_1")
        if self.count > 1_000_000 and not config.get("force"):
            raise ValueError(f"{ERR_INVALID_FILE_GENERATOR}:uuid_count_too_large:{self.count}")
        self.version = int(config.get("version", 4))
        self._values = []
        self._index = 0

        if self.version == 5:
            names = config.get("names") or []
            if not isinstance(names, list) or not names:
                raise ValueError(f"{ERR_INVALID_FILE_GENERATOR}:uuid_v5_needs_names")
            ns_raw = config.get("namespace") or str(uuid.NAMESPACE_DNS)
            try:
                ns = uuid.UUID(str(ns_raw))
            except ValueError as exc:
                raise ValueError(f"{ERR_INVALID_FILE_GENERATOR}:uuid_bad_namespace") from exc
            for n in names:
                self._values.append(str(uuid.uuid5(ns, str(n))))
            # Cap to count if names longer
            if len(self._values) > self.count:
                self._values = self._values[: self.count]
        elif self.version == 4:
            for _ in range(self.count):
                self._values.append(str(uuid.uuid4()))
        else:
            raise ValueError(f"{ERR_INVALID_FILE_GENERATOR}:uuid_version_unsupported:{self.version}")

    def __iter__(self) -> Iterator[str]:
        while self._index < len(self._values):
            v = self._values[self._index]
            self._index += 1
            yield v

    def estimate_count(self) -> int | None:
        return len(self._values)

    def checkpoint(self) -> dict[str, Any]:
        return {"type": "uuid", "index": self._index, "count": self.count, "version": self.version}

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._index = int(checkpoint.get("index", 0))
