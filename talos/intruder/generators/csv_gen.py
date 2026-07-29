"""
Module: talos.intruder.generators.csv_gen

Purpose:
    Read payloads from a CSV column (Phase 3 file generator).
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Iterator

from talos.intruder.models import (
    DEFAULT_WORDLIST_MAX_BYTES,
    DEFAULT_WORDLIST_MAX_LINES,
    ERR_EMPTY_GENERATOR,
    ERR_INVALID_FILE_GENERATOR,
    ERR_WORDLIST_TOO_LARGE,
)


class CsvGenerator:
    """
    Yields string values from one CSV column.

    Options:
        path / file (required)
        column — header name (when has_header) or 0-based index (default 0)
        delimiter (default ',')
        has_header / skip_header (default True)
        skip_empty (default True)
        force — bypass size guards
        max_rows — optional hard cap
    """

    def __init__(self) -> None:
        self.path: str = ""
        self._values: list[str] = []
        self._index = 0

    def open(self, config: dict[str, Any]) -> None:
        path = config.get("path") or config.get("file") or ""
        if not path:
            raise ValueError(f"{ERR_INVALID_FILE_GENERATOR}:csv_missing_path")
        self.path = str(path)
        p = Path(self.path)
        if not p.is_file():
            raise ValueError(f"{ERR_EMPTY_GENERATOR}:csv_not_found:{self.path}")

        force = bool(config.get("force", False))
        max_bytes = int(config.get("max_bytes", DEFAULT_WORDLIST_MAX_BYTES))
        max_lines = int(config.get("max_lines", DEFAULT_WORDLIST_MAX_LINES))
        st = p.stat()
        if not force and st.st_size > max_bytes:
            raise ValueError(
                f"{ERR_WORDLIST_TOO_LARGE}:bytes:{st.st_size}>{max_bytes}"
            )

        delimiter = str(config.get("delimiter") or ",")
        has_header = config.get("has_header")
        if has_header is None:
            has_header = config.get("skip_header", True)
        has_header = bool(has_header)
        skip_empty = bool(config.get("skip_empty", True))
        column = config.get("column", 0)
        max_rows = config.get("max_rows")

        text = p.read_text(encoding="utf-8", errors="replace")
        reader = csv.reader(text.splitlines(), delimiter=delimiter)
        rows = list(reader)
        if not force and len(rows) > max_lines:
            raise ValueError(
                f"{ERR_WORDLIST_TOO_LARGE}:lines:{len(rows)}>{max_lines}"
            )

        col_idx: int
        start = 0
        if has_header and rows:
            header = rows[0]
            start = 1
            if isinstance(column, str) and not column.isdigit():
                try:
                    col_idx = header.index(column)
                except ValueError as exc:
                    raise ValueError(
                        f"{ERR_INVALID_FILE_GENERATOR}:csv_column_not_found:{column}"
                    ) from exc
            else:
                col_idx = int(column)
        else:
            col_idx = int(column) if not isinstance(column, str) or column.isdigit() else 0
            if isinstance(column, str) and not column.isdigit():
                # no header but named column → treat as index 0 with warning via empty
                col_idx = 0

        out: list[str] = []
        for row in rows[start:]:
            if col_idx < 0 or col_idx >= len(row):
                continue
            val = row[col_idx]
            if skip_empty and not str(val).strip():
                continue
            out.append(str(val))
            if max_rows is not None and len(out) >= int(max_rows):
                break

        if not out:
            raise ValueError(f"{ERR_EMPTY_GENERATOR}:csv_empty")
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
        return {"type": "csv", "index": self._index, "path": self.path}

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._index = int(checkpoint.get("index", 0))
