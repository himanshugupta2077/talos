"""
Module: talos.projects.attack_config

Purpose:
    Read/write helpers for the attack_config table in the per-project DB.
    Currently manages a single boolean key: 'unauth_auto_run'.

    Also manages the attack_host_exclusions table: per-attack host/path blocklist that
    prevents specific hosts or host+path prefixes from being tested even when in-scope.

    Also provides: get_untested_endpoint_ids — returns endpoint IDs that have
    no completed auth_test_result and no pending/running auth_test scheduler job,
    filtered to exclude hosts present in attack_host_exclusions for 'unauth'.
    This is the canonical source of truth for the unauth auto-enqueue decision.

Dependencies: sqlite3, pathlib
Data flow:
    scheduler.scheduler → get_unauth_auto_run, get_untested_endpoint_ids
    ui.api.attacks      → get_unauth_auto_run, set_unauth_auto_run
    projects.attack_cli → add/remove/list_unauth_excluded_hosts
Side effects:
    set_unauth_auto_run — writes attack_config table.
    add/remove_unauth_excluded_host — writes attack_host_exclusions table.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from talos.projects.db import migrate_project_db


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _connect_rw(db_path: Path) -> sqlite3.Connection:
    """
    Purpose: Open a read-write SQLite connection with row_factory set.
    Input:   db_path — absolute Path to the project's talos.db.
    Output:  sqlite3.Connection. Caller responsible for closing.
    Side effects: Opens a file descriptor.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def _connect_ro(db_path: Path) -> sqlite3.Connection:
    """
    Purpose: Open a read-only SQLite connection.
    Input:   db_path — absolute Path to the project's talos.db.
    Output:  sqlite3.Connection in ro mode.
    Side effects: Opens a file descriptor.
    """
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


# ------------------------------------------------------------------ #
# auto_run flag                                                        #
# ------------------------------------------------------------------ #

def get_unauth_auto_run(db_path: Path) -> bool:
    """
    Purpose:
        Read the unauth_auto_run flag from attack_config.
        Returns False if the key is absent (default off).
    Input:   db_path — Path to the project's talos.db.
    Output:  True when auto_run is enabled; False otherwise.
    Side effects: Calls migrate_project_db to ensure attack_config exists.
    """
    migrate_project_db(db_path)
    with _connect_ro(db_path) as conn:
        row = conn.execute(
            "SELECT value FROM attack_config WHERE key = 'unauth_auto_run'"
        ).fetchone()
        if row is None:
            return False
        return row["value"] == "1"


def set_unauth_auto_run(db_path: Path, enabled: bool) -> None:
    """
    Purpose:
        Persist the unauth_auto_run flag into attack_config.
        Uses UPSERT so it is safe on first write.
    Input:
        db_path — Path to the project's talos.db.
        enabled — True to enable; False to disable.
    Output: None.
    Side effects:
        - Calls migrate_project_db to ensure attack_config exists.
        - Inserts or replaces one row in attack_config.
    """
    migrate_project_db(db_path)
    value = "1" if enabled else "0"
    with _connect_rw(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO attack_config (key, value) VALUES ('unauth_auto_run', ?)",
            (value,),
        )
        conn.commit()


# ------------------------------------------------------------------ #
# Untested endpoint discovery                                          #
# ------------------------------------------------------------------ #

def get_untested_endpoint_ids(db_path: Path, project_id: str) -> list[str]:
    """
    Purpose:
        Return UUIDs of all endpoints that have:
          - no completed auth_test_result row linked via flows.endpoint_id, AND
          - no pending or running auth_test scheduler_job, AND
          - a host NOT in attack_host_exclusions for attack='unauth'.

        Used by the scheduler auto-enqueue loop to find unprocessed targets.
    Input:
        db_path    — Path to the project's talos.db.
        project_id — Project UUID; scopes the endpoint query.
    Output:
        List of endpoint UUID strings.  Empty when all are tested or in-queue.
    Side effects: None (read-only after migration).
    """
    migrate_project_db(db_path)
    with _connect_ro(db_path) as conn:
        rows = conn.execute(
            """
            SELECT e.id
            FROM endpoints e
            WHERE e.project_id = ?
              AND NOT EXISTS (
                  SELECT 1
                  FROM auth_test_results atr
                  JOIN flows f ON f.id = atr.replay_flow_id
                  WHERE f.endpoint_id = e.id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM scheduler_jobs sj
                  WHERE sj.endpoint_id = e.id
                    AND sj.job_type = 'auth_test'
                    AND sj.status IN ('pending', 'running')
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM attack_host_exclusions axe
                  WHERE axe.attack = 'unauth'
                    AND axe.host = e.host
                    AND (
                        axe.path = ''
                        OR e.normalized_path = axe.path
                        OR e.normalized_path LIKE axe.path || '/%'
                    )
              )
            """,
            (project_id,),
        ).fetchall()
        return [r["id"] for r in rows]


# ------------------------------------------------------------------ #
# Unauth host exclusions                                               #
# ------------------------------------------------------------------ #

_UNAUTH = "unauth"


def add_unauth_exclusion(db_path: Path, host: str, path: str = "") -> bool:
    """
    Purpose:
        Add a host (or host+path prefix) to the unauth attack exclusion list.
        No-op (returns False) if the entry is already excluded.
    Input:
        db_path — Path to the project's talos.db.
        host    — Hostname string (e.g. 'api.internal.example.com').
        path    — Optional path prefix (e.g. '/api/v1').  Empty string means
                  all paths on that host are excluded.
    Output:
        True when inserted; False when already present.
    Side effects:
        Calls migrate_project_db; inserts one row into attack_host_exclusions.
    """
    migrate_project_db(db_path)
    host = host.strip().lower()
    path = path.strip()
    created_at = datetime.now(timezone.utc).isoformat()
    with _connect_rw(db_path) as conn:
        cursor = conn.execute(
            "INSERT OR IGNORE INTO attack_host_exclusions (attack, host, path, created_at)"
            " VALUES (?, ?, ?, ?)",
            (_UNAUTH, host, path, created_at),
        )
        conn.commit()
        return cursor.rowcount == 1


# Keep old name as an alias so callers not yet updated continue to work.
def add_unauth_excluded_host(db_path: Path, host: str) -> bool:
    return add_unauth_exclusion(db_path, host, path="")


def remove_unauth_exclusion(db_path: Path, host: str, path: str = "") -> bool:
    """
    Purpose:
        Remove a host (or host+path prefix) from the unauth attack exclusion list.
    Input:
        db_path — Path to the project's talos.db.
        host    — Hostname string.
        path    — Path prefix that was excluded, or '' for host-level.
    Output:
        True when deleted; False when not found.
    Side effects:
        Calls migrate_project_db; deletes one row from attack_host_exclusions.
    """
    migrate_project_db(db_path)
    host = host.strip().lower()
    path = path.strip()
    with _connect_rw(db_path) as conn:
        cursor = conn.execute(
            "DELETE FROM attack_host_exclusions WHERE attack = ? AND host = ? AND path = ?",
            (_UNAUTH, host, path),
        )
        conn.commit()
        return cursor.rowcount == 1


# Keep old name as an alias so callers not yet updated continue to work.
def remove_unauth_excluded_host(db_path: Path, host: str) -> bool:
    return remove_unauth_exclusion(db_path, host, path="")


def list_unauth_excluded_hosts(db_path: Path) -> list[dict]:
    """
    Purpose:
        Return all entries excluded from the unauth attack test, ordered by host then path.
    Input:
        db_path — Path to the project's talos.db.
    Output:
        List of dicts with keys: host, path, created_at.
    Side effects:
        Calls migrate_project_db (read-only after that).
    """
    migrate_project_db(db_path)
    with _connect_ro(db_path) as conn:
        rows = conn.execute(
            "SELECT host, path, created_at FROM attack_host_exclusions"
            " WHERE attack = ? ORDER BY host ASC, path ASC",
            (_UNAUTH,),
        ).fetchall()
        return [{"host": r["host"], "path": r["path"], "created_at": r["created_at"]} for r in rows]
