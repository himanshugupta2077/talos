"""
Module: talos.projects.annotations

Purpose:
    CRUD for endpoint safety annotations.
    Allows users to tag endpoints as 'logout' or 'dangerous' to prevent
    unsafe automated replay.

    Valid tags:
        logout    — never replay this endpoint (any mode).
        dangerous — skip in automated replay; allowed manually.

    Absence of both tags means the endpoint is safe (default state).

Dependencies: sqlite3, pathlib, talos.projects.db
Data flow:
    endpoint_cli   → add_annotation / remove_annotation / clear_annotations / get_annotations
    replay.engine  → get_annotations (read-only guard before execution)
    replay.auth_strip → get_annotations (read-only guard before execution)
Side effects:
    - add_annotation, remove_annotation, clear_annotations write to endpoint_annotations.
    - get_annotations is read-only after the migration check.
"""

import sqlite3
from pathlib import Path

from talos.projects.db import migrate_project_db


# Tags recognised by the system.  Any other value is rejected at the boundary.
_VALID_TAGS: frozenset[str] = frozenset({"logout", "dangerous"})


def add_annotation(db_path: Path, endpoint_id: str, tag: str) -> None:
    """
    Purpose:
        Add a safety tag to an endpoint.  No-op if the tag already exists.
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the target endpoint.
        tag         — Must be one of: 'logout', 'dangerous'.
    Output:
        None
    Side effects:
        Inserts one row into endpoint_annotations (INSERT OR IGNORE — idempotent).
    """
    if tag not in _VALID_TAGS:
        raise ValueError(
            f"Invalid annotation tag: '{tag}'. Valid tags: {sorted(_VALID_TAGS)}"
        )
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO endpoint_annotations (endpoint_id, tag, created_at)
            VALUES (?, ?, datetime('now'))
            """,
            (endpoint_id, tag),
        )
        conn.commit()


def remove_annotation(db_path: Path, endpoint_id: str, tag: str) -> None:
    """
    Purpose:
        Remove a safety tag from an endpoint.  No-op if the tag is not present.
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the target endpoint.
        tag         — Tag to remove.
    Output:
        None
    Side effects:
        Deletes the matching row from endpoint_annotations if it exists.
    """
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "DELETE FROM endpoint_annotations WHERE endpoint_id = ? AND tag = ?",
            (endpoint_id, tag),
        )
        conn.commit()


def clear_annotations(db_path: Path, endpoint_id: str) -> None:
    """
    Purpose:
        Remove all annotations from an endpoint, restoring the default safe state.
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the target endpoint.
    Output:
        None
    Side effects:
        Deletes all rows for the endpoint from endpoint_annotations.
    """
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "DELETE FROM endpoint_annotations WHERE endpoint_id = ?",
            (endpoint_id,),
        )
        conn.commit()


def get_annotations(db_path: Path, endpoint_id: str) -> frozenset:
    """
    Purpose:
        Return all active annotation tags for an endpoint.
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the target endpoint.
    Output:
        frozenset of tag strings.  Empty frozenset if no annotations exist or
        the database does not exist yet.
    Side effects:
        Calls migrate_project_db to ensure the annotations table is present.
        Read-only after migration.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return frozenset()
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT tag FROM endpoint_annotations WHERE endpoint_id = ?",
            (endpoint_id,),
        ).fetchall()
    return frozenset(row[0] for row in rows)
