"""
Module: talos.intruder.generators.json_gen

Purpose:
    Read payloads from a JSON file array / path (Phase 3 file generator).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from talos.intruder.models import (
    DEFAULT_WORDLIST_MAX_BYTES,
    ERR_EMPTY_GENERATOR,
    ERR_INVALID_FILE_GENERATOR,
    ERR_WORDLIST_TOO_LARGE,
)


class JsonGenerator:
    """
    Yields string payloads from a JSON file.

    Options:
        path / file (required)
        json_path — dotted path to an array or scalar, e.g.:
            "" (root array of scalars)
            "ids"
            "users[].id"  (collect id from each object in users)
            "data.items[].value"
        skip_empty (default True)
        force — bypass size guards
        max_items — optional cap
    """

    def __init__(self) -> None:
        self.path: str = ""
        self._values: list[str] = []
        self._index = 0

    def open(self, config: dict[str, Any]) -> None:
        path = config.get("path") or config.get("file") or ""
        if not path:
            raise ValueError(f"{ERR_INVALID_FILE_GENERATOR}:json_missing_path")
        self.path = str(path)
        p = Path(self.path)
        if not p.is_file():
            raise ValueError(f"{ERR_EMPTY_GENERATOR}:json_not_found:{self.path}")

        force = bool(config.get("force", False))
        max_bytes = int(config.get("max_bytes", DEFAULT_WORDLIST_MAX_BYTES))
        st = p.stat()
        if not force and st.st_size > max_bytes:
            raise ValueError(
                f"{ERR_WORDLIST_TOO_LARGE}:bytes:{st.st_size}>{max_bytes}"
            )

        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{ERR_INVALID_FILE_GENERATOR}:json_parse:{exc}") from exc

        json_path = str(config.get("json_path") or config.get("path_expr") or "")
        skip_empty = bool(config.get("skip_empty", True))
        max_items = config.get("max_items")

        try:
            raw_values = _extract_path(data, json_path)
        except ValueError as exc:
            raise ValueError(f"{ERR_INVALID_FILE_GENERATOR}:{exc}") from exc

        out: list[str] = []
        for v in raw_values:
            s = _to_payload(v)
            if skip_empty and not s.strip():
                continue
            out.append(s)
            if max_items is not None and len(out) >= int(max_items):
                break

        if not out:
            raise ValueError(f"{ERR_EMPTY_GENERATOR}:json_empty")
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
        return {"type": "json", "index": self._index, "path": self.path}

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._index = int(checkpoint.get("index", 0))


def _to_payload(v: Any) -> str:
    if isinstance(v, (dict, list)):
        return json.dumps(v, separators=(",", ":"), default=str)
    if v is None:
        return ""
    return str(v)


def _extract_path(data: Any, path: str) -> list[Any]:
    """
    Resolve a simple dotted path with optional [] array walkers.

    Examples:
        "" → data if list else [data]
        "ids" → data["ids"] (must be list or scalar)
        "users[].id" → [u["id"] for u in data["users"]]
    """
    path = (path or "").strip()
    if not path:
        if isinstance(data, list):
            return list(data)
        return [data]

    tokens = path.split(".")
    current: Any = data
    for i, tok in enumerate(tokens):
        if tok.endswith("[]"):
            key = tok[:-2]
            if key:
                if not isinstance(current, dict) or key not in current:
                    raise ValueError(f"json_path_missing:{tok}")
                current = current[key]
            if not isinstance(current, list):
                raise ValueError(f"json_path_not_array:{tok}")
            # Remaining path applied per element
            rest = ".".join(tokens[i + 1 :])
            out: list[Any] = []
            for item in current:
                if rest:
                    out.extend(_extract_path(item, rest))
                else:
                    out.append(item)
            return out
        if not isinstance(current, dict) or tok not in current:
            raise ValueError(f"json_path_missing:{tok}")
        current = current[tok]

    if isinstance(current, list):
        return list(current)
    return [current]
