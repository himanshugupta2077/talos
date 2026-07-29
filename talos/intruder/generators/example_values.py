"""
Module: talos.intruder.generators.example_values

Purpose:
    Payload generator backed by Parameter Intelligence example_values
    (Phase 3 param-intel).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterator

from talos.intruder.models import ERR_EMPTY_GENERATOR, ERR_PARAM_NOT_FOUND


class ExampleValuesGenerator:
    """
    Yields strings from ``parameters.example_values``.

    Options (one of):
        param_id — parameters.id UUID
        endpoint_id + name + location — lookup triple
    Plus:
        db_path — Path/str to project DB (injected by engine/CLI)
        skip_empty (default True)
    """

    def __init__(self) -> None:
        self._values: list[str] = []
        self._index = 0
        self.param_id: str | None = None

    def open(self, config: dict[str, Any]) -> None:
        db_path = config.get("db_path")
        if not db_path:
            raise ValueError(f"{ERR_PARAM_NOT_FOUND}:example_values_needs_db_path")
        db_path = Path(db_path)
        param_id = config.get("param_id")
        endpoint_id = config.get("endpoint_id")
        name = config.get("name")
        location = config.get("location")
        skip_empty = bool(config.get("skip_empty", True))

        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            row = None
            if param_id:
                row = conn.execute(
                    "SELECT id, example_values FROM parameters WHERE id = ?",
                    (str(param_id),),
                ).fetchone()
            elif endpoint_id and name and location:
                row = conn.execute(
                    """
                    SELECT id, example_values FROM parameters
                    WHERE endpoint_id = ? AND name = ? AND location = ?
                    """,
                    (str(endpoint_id), str(name), str(location)),
                ).fetchone()
            else:
                raise ValueError(
                    f"{ERR_PARAM_NOT_FOUND}:need_param_id_or_endpoint_name_location"
                )

        if row is None:
            raise ValueError(f"{ERR_PARAM_NOT_FOUND}:no_row")

        self.param_id = str(row["id"])
        try:
            examples = json.loads(row["example_values"] or "[]")
        except (TypeError, json.JSONDecodeError):
            examples = []
        if not isinstance(examples, list):
            examples = []

        out: list[str] = []
        for v in examples:
            s = "" if v is None else str(v)
            if skip_empty and not s.strip():
                continue
            out.append(s)

        if not out:
            raise ValueError(f"{ERR_EMPTY_GENERATOR}:example_values_empty")
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
        return {"type": "example_values", "index": self._index, "param_id": self.param_id}

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._index = int(checkpoint.get("index", 0))
