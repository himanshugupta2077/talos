"""
Module: talos.projects.annotations

Purpose:
    Public interface for endpoint safety tags (logout, dangerous).

    Previously backed by the endpoint_annotations table.  As of schema v24
    these flags live in endpoint_policy.dangerous and endpoint_policy.logout.
    This module is retained as the single entry point so all callers
    (replay engine, scheduler, BAC engine) continue to work unchanged.

    Supported tags:
        logout    — never replay this endpoint in any mode.
        dangerous — skip in automated replay; manual replay is still allowed.

    Absence of both flags means the endpoint is safe (default state).

Dependencies: pathlib, talos.projects.policy
Data flow:
    replay.engine  → get_annotations() — read-only guard before execution
    replay.auth_strip → get_annotations() — read-only guard before execution
    scheduler.scheduler → get_annotations() — pre-check before job execution
    bac.engine → get_annotations() — guard before BAC replay
    endpoint_cli → add_annotation / remove_annotation / clear_annotations
Side effects:
    - add_annotation, remove_annotation, clear_annotations write to endpoint_policy.
    - get_annotations is read-only.
"""

from pathlib import Path

from talos.projects.db import migrate_project_db
from talos.projects.policy import set_dangerous, set_logout


# Tags recognised at the public boundary.
_VALID_TAGS: frozenset[str] = frozenset({"logout", "dangerous"})


def add_annotation(db_path: Path, endpoint_id: str, tag: str) -> None:
    """
    Purpose:
        Set a safety flag on an endpoint.  No-op if already set.
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the target endpoint.
        tag         — 'logout' or 'dangerous'.
    Output: None.
    Side effects:
        Upserts endpoint_policy row; sets the corresponding boolean column.
    Raises:
        ValueError when tag is not one of the supported values.
    """
    if tag not in _VALID_TAGS:
        raise ValueError(
            f"Invalid annotation tag: '{tag}'. Valid tags: {sorted(_VALID_TAGS)}"
        )
    if tag == "logout":
        set_logout(db_path, endpoint_id, logout=True)
    else:
        set_dangerous(db_path, endpoint_id, dangerous=True)


def remove_annotation(db_path: Path, endpoint_id: str, tag: str) -> None:
    """
    Purpose:
        Clear a safety flag from an endpoint.  No-op if not set.
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the target endpoint.
        tag         — Tag to remove ('logout' or 'dangerous').
    Output: None.
    Side effects:
        Updates endpoint_policy row; clears the corresponding boolean column.
    """
    if tag == "logout":
        set_logout(db_path, endpoint_id, logout=False)
    elif tag == "dangerous":
        set_dangerous(db_path, endpoint_id, dangerous=False)


def clear_annotations(db_path: Path, endpoint_id: str) -> None:
    """
    Purpose:
        Clear both safety flags from an endpoint, restoring the default safe state.
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the target endpoint.
    Output: None.
    Side effects:
        Clears dangerous=0 and logout=0 on the endpoint_policy row.
    """
    set_dangerous(db_path, endpoint_id, dangerous=False)
    set_logout(db_path, endpoint_id, logout=False)


def get_annotations(db_path: Path, endpoint_id: str) -> frozenset:
    """
    Purpose:
        Return the active safety flags for an endpoint as a frozenset of tag strings.
    Input:
        db_path     — Path to the project's talos.db.
        endpoint_id — UUID of the target endpoint.
    Output:
        frozenset of tag strings (subset of {'logout', 'dangerous'}).
        Empty frozenset when no policy row exists or both flags are clear.
    Side effects:
        Calls migrate_project_db to ensure the schema is current.
        Read-only after migration.
    """
    import sqlite3

    migrate_project_db(db_path)
    if not db_path.exists():
        return frozenset()

    uri = f"file:{db_path}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True) as conn:
            row = conn.execute(
                "SELECT dangerous, logout FROM endpoint_policy WHERE endpoint_id = ?",
                (endpoint_id,),
            ).fetchone()
    except sqlite3.OperationalError:
        # Table may not exist on a very old DB that hasn't been migrated yet.
        return frozenset()

    if row is None:
        return frozenset()

    tags = set()
    if row[0]:   # dangerous
        tags.add("dangerous")
    if row[1]:   # logout
        tags.add("logout")
    return frozenset(tags)
