"""
Module: talos.projects.scope_io

Purpose:
    Shared file import and bulk-text parsing for Basic Scope prefixes.
    Used by both in-scope (registry) and out-of-scope (SQLite) managers so
    CLI and Control Panel share one validation path.

File format (UTF-8):
    - one scope prefix per line
    - trim leading/trailing whitespace
    - blank lines ignored
    - lines beginning with # are comments
    - commas are NOT separators — each line is one complete prefix

Atomic import:
    Parse and validate the entire file first. If any entry is invalid,
    reject the whole import with line number and value; do not mutate state.

Dependencies: pathlib, talos.proxy.scope
Data flow:
    CLI import / CP backend temp file → parse_scope_file_text → list[str]
Side effects: None (pure parse/validate).
"""

from __future__ import annotations

from pathlib import Path

from talos.proxy.scope import ScopeParseError, validate_scope_prefix


class ScopeImportError(ValueError):
    """Raised when a scope import file fails validation (atomic reject)."""

    def __init__(self, message: str, *, line_number: int | None = None, value: str | None = None):
        super().__init__(message)
        self.line_number = line_number
        self.value = value


def parse_scope_file_text(text: str) -> list[str]:
    """
    Purpose:
        Parse multiline text into a list of validated scope prefixes.
    Input:
        text — full file or bulk-paste body (UTF-8 string).
    Output:
        Ordered list of unique prefixes (first occurrence wins; later
        duplicates are dropped silently so import is idempotent).
    Raises:
        ScopeImportError with line_number when any non-comment line is invalid.
    Side effects: None.
    """
    prefixes: list[str] = []
    seen: set[str] = set()

    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        try:
            prefix = validate_scope_prefix(stripped)
        except ScopeParseError as exc:
            raise ScopeImportError(
                f"Invalid scope prefix on line {line_no}: {stripped!r} — {exc}",
                line_number=line_no,
                value=stripped,
            ) from exc
        # Deduplicate while preserving order; case-sensitive on raw form after strip.
        key = prefix
        if key in seen:
            continue
        seen.add(key)
        prefixes.append(prefix)

    return prefixes


def parse_scope_file(path: Path) -> list[str]:
    """
    Purpose:
        Read a UTF-8 text file and parse it via parse_scope_file_text.
    Input:
        path — filesystem path to a .txt (or any text) scope list.
    Output:
        Validated prefix list.
    Raises:
        ScopeImportError — validation failure.
        OSError / UnicodeError — I/O failures (caller maps to CLI errors).
    Side effects:
        Reads the file from disk.
    """
    raw = path.read_text(encoding="utf-8")
    return parse_scope_file_text(raw)
