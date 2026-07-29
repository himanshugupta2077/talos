"""
Module: talos.intruder.generators.wordlist

Purpose:
    Line-oriented file payload generator with size guards and checkpoint.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator

from talos.intruder.models import (
    DEFAULT_WORDLIST_MAX_BYTES,
    DEFAULT_WORDLIST_MAX_LINES,
    ERR_EMPTY_GENERATOR,
    ERR_WORDLIST_TOO_LARGE,
)


class WordlistGenerator:
    """
    Yields non-empty stripped lines from a file.
    Options: path (required), skip_empty (default True), force (bypass size).
    """

    def __init__(self) -> None:
        self.path: str = ""
        self.skip_empty = True
        self.force = False
        self._lines: list[str] = []
        self._index = 0
        self._file_size = 0
        self._mtime_ns = 0

    def open(self, config: dict[str, Any]) -> None:
        path = config.get("path") or config.get("file") or ""
        if not path:
            raise ValueError(f"{ERR_EMPTY_GENERATOR}:wordlist_missing_path")
        self.path = str(path)
        self.skip_empty = bool(config.get("skip_empty", True))
        self.force = bool(config.get("force", False))
        p = Path(self.path)
        if not p.is_file():
            raise ValueError(f"{ERR_EMPTY_GENERATOR}:wordlist_not_found:{self.path}")
        st = p.stat()
        self._file_size = st.st_size
        self._mtime_ns = getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))
        max_bytes = int(config.get("max_bytes", DEFAULT_WORDLIST_MAX_BYTES))
        max_lines = int(config.get("max_lines", DEFAULT_WORDLIST_MAX_LINES))
        if not self.force:
            if self._file_size > max_bytes:
                raise ValueError(
                    f"{ERR_WORDLIST_TOO_LARGE}:bytes:{self._file_size}>{max_bytes}"
                )
        text = p.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        if not self.force and len(lines) > max_lines:
            raise ValueError(
                f"{ERR_WORDLIST_TOO_LARGE}:lines:{len(lines)}>{max_lines}"
            )
        out: list[str] = []
        for line in lines:
            # strip trailing CR
            if line.endswith("\r"):
                line = line[:-1]
            if self.skip_empty and not line.strip():
                continue
            out.append(line)
        if not out:
            raise ValueError(f"{ERR_EMPTY_GENERATOR}:wordlist_empty")
        self._lines = out
        self._index = 0

    def __iter__(self) -> Iterator[str]:
        while self._index < len(self._lines):
            v = self._lines[self._index]
            self._index += 1
            yield v

    def estimate_count(self) -> int | None:
        return len(self._lines)

    def checkpoint(self) -> dict[str, Any]:
        return {
            "type": "wordlist",
            "index": self._index,
            "path": self.path,
            "size": self._file_size,
            "mtime_ns": self._mtime_ns,
        }

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._index = int(checkpoint.get("index", 0))
