"""
Module: talos.intruder.generators.pool

Purpose:
    Payload generator that reads from an Intruder extracted pool (Phase 3).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator

from talos.intruder.models import ERR_EMPTY_GENERATOR, ERR_POOL_NOT_FOUND


class PoolGenerator:
    """
    Yields unique values from ``intruder_pools``.

    Options:
        name / pool / pool_name (required)
        project_id (required when resolving by name)
        db_path (required — injected)
        skip_empty (default True)
    """

    def __init__(self) -> None:
        self._values: list[str] = []
        self._index = 0
        self.pool_name: str = ""

    def open(self, config: dict[str, Any]) -> None:
        # Lazy import to avoid circular import with intruder.db
        from talos.intruder import db as intruder_db

        db_path = config.get("db_path")
        if not db_path:
            raise ValueError(f"{ERR_POOL_NOT_FOUND}:pool_needs_db_path")
        db_path = Path(db_path)
        project_id = config.get("project_id")
        name = (
            config.get("name")
            or config.get("pool")
            or config.get("pool_name")
            or ""
        )
        name = str(name).strip()
        if not name:
            raise ValueError(f"{ERR_POOL_NOT_FOUND}:missing_pool_name")
        if not project_id:
            raise ValueError(f"{ERR_POOL_NOT_FOUND}:missing_project_id")

        self.pool_name = name
        pool = intruder_db.get_pool(db_path, str(project_id), name)
        if pool is None:
            raise ValueError(f"{ERR_POOL_NOT_FOUND}:{name}")

        skip_empty = bool(config.get("skip_empty", True))
        out: list[str] = []
        for v in pool.get("values") or []:
            s = "" if v is None else str(v)
            if skip_empty and not s.strip():
                continue
            out.append(s)
        if not out:
            raise ValueError(f"{ERR_EMPTY_GENERATOR}:pool_empty:{name}")
        self._values = out
        self._index = 0

    def __iter__(self) -> Iterator[str]:
        while self._index < len(self._values):
            v = self._values[self._index]
            self._index += 1
            yield v

    def estimate_count(self) -> int | None:
        return len(self._values)

    def checkpoint(self) -> dict[str, Any]:
        return {"type": "pool", "index": self._index, "name": self.pool_name}

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._index = int(checkpoint.get("index", 0))
