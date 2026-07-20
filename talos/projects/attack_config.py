"""
Module: talos.projects.attack_config

Purpose:
    Read/write helpers for the attack_config table in the per-project DB.
    Currently manages a single boolean key: 'unauth_auto_run'.

    Also provides: get_untested_endpoint_ids — returns endpoint IDs that have
    no completed auth_test_result and no pending/running auth_test scheduler job,
    filtered to qualified=1 endpoints via the Endpoint Policy system.
    This is the canonical source of truth for the unauth auto-enqueue decision.

    CLI surface (CLI-005): talos attack unauth config [show] [--auto-run on|off]
    reads and writes unauth_auto_run via get_unauth_auto_run / set_unauth_auto_run.

    Endpoint inclusion/exclusion is fully owned by the Endpoint Policy system.
    The attack_host_exclusions table is retained for legacy data but is no longer
    consulted by this module.

Dependencies: sqlite3, pathlib
Data flow:
    scheduler.scheduler → get_unauth_auto_run, get_untested_endpoint_ids
    unauth CLI config  → get_unauth_auto_run, set_unauth_auto_run
Side effects:
    set_unauth_auto_run — writes attack_config table.
"""

import sqlite3
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
        Read the effective unauth_auto_run flag via layered configuration
        (defaults → global → legacy SQLite / project.yaml).
        Returns False when unset (default off).
    Input:   db_path — Path to the project's talos.db.
    Output:  True when auto_run is enabled; False otherwise.
    Side effects: May migrate the project DB through the legacy bridge.
    """
    from talos.configuration.manager import ConfigurationManager
    from talos.config import TalosConfig

    if not db_path.exists() and not (db_path.parent / "project.yaml").exists():
        return False
    mgr = ConfigurationManager(TalosConfig.from_env().data_dir)
    effective = mgr.load(project_data_dir=db_path.parent)
    return bool(effective.attack.unauth_auto_run)


def set_unauth_auto_run(db_path: Path, enabled: bool) -> None:
    """
    Purpose:
        Persist the unauth_auto_run flag into attack_config and project.yaml.
        Uses UPSERT so it is safe on first write.
    Input:
        db_path — Path to the project's talos.db.
        enabled — True to enable; False to disable.
    Output: None.
    Side effects:
        - Calls migrate_project_db to ensure attack_config exists.
        - Inserts or replaces one row in attack_config.
        - Dual-writes attack.unauth_auto_run into project.yaml.
    """
    migrate_project_db(db_path)
    value = "1" if enabled else "0"
    with _connect_rw(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO attack_config (key, value) VALUES ('unauth_auto_run', ?)",
            (value,),
        )
        conn.commit()
    try:
        from talos.configuration.io import load_yaml_file, project_config_path, save_yaml_file
        from talos.configuration.merge import set_path

        path = project_config_path(db_path.parent)
        current = load_yaml_file(path) if path.exists() else {}
        current = set_path(current, "attack.unauth_auto_run", bool(enabled))
        save_yaml_file(path, current)
    except Exception:
        pass


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
            JOIN endpoint_policy ep ON ep.endpoint_id = e.id
            WHERE e.project_id = ?
              AND ep.qualified = 1
              AND ep.logout    = 0
              AND ep.dangerous = 0
              AND ep.excluded  = 0
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
            """,
            (project_id,),
        ).fetchall()
        return [r["id"] for r in rows]

