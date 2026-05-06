"""
Module: talos.projects.auth

Purpose:
    CRUD operations for the per-project auth configuration.
    Auth config is a set of cookie names and header names that constitute
    authentication credentials for the target application.
    Used by the auth-bypass replay engine to strip auth from requests.

    This is global per project — not tied to specific endpoints.
    Values are names only (e.g. "sessionid", "Authorization").
    Actual credential values are never stored here.

Dependencies: sqlite3, pathlib
Data flow:
    auth_cli / auth_strip → functions here → project SQLite (auth_config table)
Side effects:
    - Write operations mutate auth_config rows.
    - Read operations are connection-scoped with no persistent state.
"""

import sqlite3
from pathlib import Path


# ------------------------------------------------------------------ #
# Read operations                                                      #
# ------------------------------------------------------------------ #

def get_auth_config(db_path: Path) -> dict:
    """
    Purpose:
        Load the current auth config as a structured dict.
    Input:
        db_path — absolute Path to the project's talos.db.
    Output:
        Dict with keys:
            'cookies' — sorted list of cookie name strings.
            'headers' — sorted list of header name strings.
        Returns empty lists when nothing is configured.
    Side effects: None (read-only).
    """
    if not db_path.exists():
        return {"cookies": [], "headers": []}

    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT type, name FROM auth_config ORDER BY type, name"
        ).fetchall()

    cookies = sorted(name for t, name in rows if t == "cookie")
    headers = sorted(name for t, name in rows if t == "header")
    return {"cookies": cookies, "headers": headers}


# ------------------------------------------------------------------ #
# Write operations                                                     #
# ------------------------------------------------------------------ #

def set_auth_fields(
    db_path: Path,
    cookies: list[str],
    headers: list[str],
) -> None:
    """
    Purpose:
        Merge new cookie and header names into the auth config.
        Existing entries are preserved — this is additive, not a replacement.
        Use clear_auth_config() first to replace the full config.
    Input:
        db_path — absolute Path to the project's talos.db.
        cookies — list of cookie names to add (e.g. ["sessionid", "auth_token"]).
        headers — list of header names to add (e.g. ["Authorization"]).
    Output: None
    Side effects:
        Inserts (type, name) rows into auth_config.
        INSERT OR IGNORE — duplicate names are silently skipped.
    """
    with sqlite3.connect(str(db_path)) as conn:
        for name in cookies:
            conn.execute(
                "INSERT OR IGNORE INTO auth_config (type, name) VALUES ('cookie', ?)",
                (name,),
            )
        for name in headers:
            conn.execute(
                "INSERT OR IGNORE INTO auth_config (type, name) VALUES ('header', ?)",
                (name,),
            )
        conn.commit()


def clear_auth_config(db_path: Path) -> None:
    """
    Purpose:
        Remove all auth config entries for this project.
    Input:
        db_path — absolute Path to the project's talos.db.
    Output: None
    Side effects:
        Deletes all rows from auth_config.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("DELETE FROM auth_config")
        conn.commit()
