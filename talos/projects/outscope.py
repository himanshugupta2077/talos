"""
Module: talos.projects.outscope

Purpose:
    CRUD for the per-project out-of-scope URL-prefix list.
    Out-of-scope entries use the same Basic Scope prefix model as in-scope
    rules (host, protocol+host, host+port, protocol+host+port, path prefix).

    Matching is enforced by talos.proxy.scope (shared evaluator). This module
    only persists prefixes — it does not implement separate hostname-only logic.

    Storage note:
        The SQLite table remains `out_of_scope_domains` with column `domain`
        for beta stability (no migration). Values stored are full Basic Scope
        prefixes, not hostname-only strings.

Dependencies: sqlite3, pathlib, uuid, datetime, talos.proxy.scope
Data flow:
    outscope_cli / proxy addon / worker → functions here → out_of_scope_domains
Side effects:
    - Write operations mutate out_of_scope_domains rows.
    - Read operations are connection-scoped with no persistent state.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from talos.proxy.scope import ScopeParseError, validate_scope_prefix


# ------------------------------------------------------------------ #
# Read operations                                                      #
# ------------------------------------------------------------------ #


def list_prefixes(db_path: Path) -> list[dict]:
    """
    Purpose:
        Return all out-of-scope prefix entries, oldest first.
    Input:
        db_path — absolute Path to the project's talos.db.
    Output:
        List of dicts: id, prefix, created_at.
        Empty list when DB is absent or table is empty.
    Side effects: None (read-only).
    """
    if not db_path.exists():
        return []

    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT id, domain, created_at FROM out_of_scope_domains"
            " ORDER BY created_at ASC"
        ).fetchall()

    return [
        {"id": row[0], "prefix": row[1], "domain": row[1], "created_at": row[2]}
        for row in rows
    ]


# Backward-compatible alias used by older call sites / Control Panel readers.
def list_domains(db_path: Path) -> list[dict]:
    """Alias for list_prefixes (legacy name)."""
    return list_prefixes(db_path)


def load_prefix_set(db_path: Path) -> frozenset[str]:
    """
    Purpose:
        Load all out-of-scope prefixes for fast capture-time matching.
        Called once at proxy/worker startup.
    Input:
        db_path — absolute Path to the project's talos.db.
    Output:
        Frozenset of prefix strings as stored.
    Side effects: None (read-only).
    """
    if not db_path.exists():
        return frozenset()

    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT domain FROM out_of_scope_domains"
        ).fetchall()

    return frozenset(row[0] for row in rows)


def load_domain_set(db_path: Path) -> frozenset[str]:
    """Alias for load_prefix_set (legacy name used by addon/worker)."""
    return load_prefix_set(db_path)


# ------------------------------------------------------------------ #
# Write operations                                                     #
# ------------------------------------------------------------------ #


def add_prefix(db_path: Path, project_id: str, prefix: str) -> bool:
    """
    Purpose:
        Add one Basic Scope prefix to the out-of-scope list.
    Input:
        db_path    — project talos.db.
        project_id — project slug.
        prefix     — one complete URL/host prefix.
    Output:
        True if inserted; False if already present.
    Raises:
        ScopeParseError — invalid Basic Scope prefix.
    Side effects:
        INSERT OR IGNORE into out_of_scope_domains.
    """
    validated = validate_scope_prefix(prefix)
    now = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.execute(
            "INSERT OR IGNORE INTO out_of_scope_domains"
            " (id, project_id, domain, created_at)"
            " VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), project_id, validated, now),
        )
        conn.commit()
        return cursor.rowcount == 1


def add_domain(db_path: Path, project_id: str, domain: str) -> bool:
    """Alias for add_prefix (legacy name)."""
    return add_prefix(db_path, project_id, domain)


def remove_prefix(db_path: Path, project_id: str, prefix: str) -> bool:
    """
    Purpose:
        Remove one out-of-scope prefix.
    Output:
        True if a row was deleted.
    Side effects:
        DELETE from out_of_scope_domains.
    """
    # Match stored form: validate when possible so user input normalizes
    # the same way as add; fall back to stripped raw for exact stored match.
    try:
        key = validate_scope_prefix(prefix)
    except ScopeParseError:
        key = prefix.strip()

    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.execute(
            "DELETE FROM out_of_scope_domains"
            " WHERE project_id = ? AND domain = ?",
            (project_id, key),
        )
        conn.commit()
        return cursor.rowcount > 0


def remove_domain(db_path: Path, project_id: str, domain: str) -> bool:
    """Alias for remove_prefix (legacy name)."""
    return remove_prefix(db_path, project_id, domain)


def clear_prefixes(db_path: Path, project_id: str) -> int:
    """
    Purpose:
        Remove all out-of-scope prefixes for a project.
    Output:
        Number of rows deleted.
    Side effects:
        DELETE all rows for project_id.
    """
    if not db_path.exists():
        return 0
    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.execute(
            "DELETE FROM out_of_scope_domains WHERE project_id = ?",
            (project_id,),
        )
        conn.commit()
        return cursor.rowcount


def add_prefixes_atomic(
    db_path: Path,
    project_id: str,
    prefixes: list[str],
) -> tuple[int, int]:
    """
    Purpose:
        Insert many already-validated prefixes in one transaction.
    Input:
        prefixes — validated via scope_io / validate_scope_prefix.
    Output:
        (inserted_count, already_present_count).
    Side effects:
        Multiple INSERT OR IGNORE in one transaction.
    """
    now = datetime.now(timezone.utc).isoformat()
    inserted = 0
    skipped = 0
    with sqlite3.connect(str(db_path)) as conn:
        for prefix in prefixes:
            validated = validate_scope_prefix(prefix)
            cursor = conn.execute(
                "INSERT OR IGNORE INTO out_of_scope_domains"
                " (id, project_id, domain, created_at)"
                " VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), project_id, validated, now),
            )
            if cursor.rowcount == 1:
                inserted += 1
            else:
                skipped += 1
        conn.commit()
    return inserted, skipped
