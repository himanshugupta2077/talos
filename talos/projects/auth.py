"""
Module: talos.projects.auth

Purpose:
    CRUD operations for the per-project auth configuration and the
    role-based session management system.

    Auth config (auth_config table):
        A set of cookie and header names that constitute authentication
        credentials for the target application.  Used by the auth-bypass
        replay engine to strip auth from requests.  Values are names only
        (e.g. "sessionid", "Authorization"); actual credential values are
        never stored here.

    Auth flow config (auth_flow_config table):
        Per-role ordered list of login flows with associated Python extractor
        scripts.  Each extractor receives the replay response and returns a
        dict of {artifact_name: value} pairs.  Multiple flows are supported
        so that complex multi-step authentication can be modelled.

    Role auth state (role_auth_state table):
        Current authentication key-value pairs for each role after a
        successful refresh.  Each key matches a name in auth_config.
        Consumed by the BAC engine to inject correct auth values into
        attack requests.

    Session health config (session_health_config table):
        Per-role TTL, expiry signals, and validation endpoint configuration
        for the Session Health Engine.

    Session health control flows (session_health_control_flows table):
        Harmless authenticated flows used as Layer 4 health probes.

    Session suspicion state (session_suspicion_state table):
        Runtime suspicion counter and last validation timestamp per role.

    Legacy tables (role_auth, role_session_tokens):
        Retained for schema compatibility.  Not used by new code paths.

Dependencies: sqlite3, pathlib, uuid, datetime
Data flow:
    auth_cli / auth_config_cli / session_health → functions here → project SQLite
Side effects:
    Write operations mutate the relevant tables.
    Read operations are connection-scoped with no persistent state.
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


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


def unset_auth_fields(
    db_path: Path,
    cookies: list[str],
    headers: list[str],
) -> None:
    """
    Purpose:
        Remove specific cookie and header names from the auth config.
    Input:
        db_path — absolute Path to the project's talos.db.
        cookies — list of cookie names to remove.
        headers — list of header names to remove.
    Output: None
    Side effects:
        Deletes matching (type, name) rows from auth_config.
    """
    with sqlite3.connect(str(db_path)) as conn:
        for name in cookies:
            conn.execute(
                "DELETE FROM auth_config WHERE type = 'cookie' AND name = ?",
                (name,),
            )
        for name in headers:
            conn.execute(
                "DELETE FROM auth_config WHERE type = 'header' AND name = ?",
                (name,),
            )
        conn.commit()


# ------------------------------------------------------------------ #
# Role auth — login / checkpoint flow assignments                      #
# ------------------------------------------------------------------ #

def set_login_flow(db_path: Path, role_id: str, flow_id: str) -> None:
    """
    Purpose:
        Assign a login flow to a role.  Replayed to obtain a new session token.
        Upserts the role_auth row — creates it if absent, updates if present.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the target role.
        flow_id — UUID of the captured login flow.
    Output: None
    Side effects:
        Inserts or updates the login_flow_id column in role_auth.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO role_auth (role_id, login_flow_id, checkpoint_flow_id)
            VALUES (?, ?, NULL)
            ON CONFLICT(role_id) DO UPDATE SET login_flow_id = excluded.login_flow_id
            """,
            (role_id, flow_id),
        )
        conn.commit()


def set_checkpoint_flow(db_path: Path, role_id: str, flow_id: str) -> None:
    """
    Purpose:
        Assign a checkpoint flow to a role.  Replayed to validate an existing
        session token; 200 means valid, 401/403 means dead.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the target role.
        flow_id — UUID of the captured checkpoint flow.
    Output: None
    Side effects:
        Inserts or updates the checkpoint_flow_id column in role_auth.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO role_auth (role_id, login_flow_id, checkpoint_flow_id)
            VALUES (?, NULL, ?)
            ON CONFLICT(role_id) DO UPDATE SET checkpoint_flow_id = excluded.checkpoint_flow_id
            """,
            (role_id, flow_id),
        )
        conn.commit()


def get_role_auth(db_path: Path, role_id: str) -> Optional[dict]:
    """
    Purpose:
        Load the login and checkpoint flow assignments for a role.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the target role.
    Output:
        Dict with keys 'login_flow_id' and 'checkpoint_flow_id' (either may be
        None when not yet assigned), or None if no row exists for this role.
    Side effects: None (read-only).
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT login_flow_id, checkpoint_flow_id FROM role_auth WHERE role_id = ?",
            (role_id,),
        ).fetchone()
    return dict(row) if row else None


# ------------------------------------------------------------------ #
# Role session tokens — storage and activation                         #
# ------------------------------------------------------------------ #

def store_session_token(db_path: Path, role_id: str, token: str) -> str:
    """
    Purpose:
        Persist a newly generated session token for a role and mark it active.
        All previously active tokens for the role are deactivated first so that
        at most one token per role is active at any time.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the role this token belongs to.
        token   — Raw session token string (e.g. a JWT).
    Output:
        The UUID assigned to the new token row.
    Side effects:
        - Deactivates existing active tokens for the role.
        - Inserts a new row in role_session_tokens with active=1.
    """
    token_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "UPDATE role_session_tokens SET active = 0 WHERE role_id = ?",
            (role_id,),
        )
        conn.execute(
            """
            INSERT INTO role_session_tokens (id, role_id, token, created_at, active)
            VALUES (?, ?, ?, ?, 1)
            """,
            (token_id, role_id, token, now),
        )
        conn.commit()
    return token_id


def activate_session_token(db_path: Path, role_id: str, token_id: str) -> bool:
    """
    Purpose:
        Set a specific stored token as the active token for a role.
        Deactivates all other tokens for the role first.
    Input:
        db_path  — absolute Path to the project's talos.db.
        role_id  — UUID of the role.
        token_id — UUID of the token to activate.
    Output:
        True if the token was found and activated; False if not found or the
        token does not belong to the given role.
    Side effects:
        Updates active column in role_session_tokens.
    """
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT id FROM role_session_tokens WHERE id = ? AND role_id = ?",
            (token_id, role_id),
        ).fetchone()
        if row is None:
            return False
        conn.execute(
            "UPDATE role_session_tokens SET active = 0 WHERE role_id = ?",
            (role_id,),
        )
        conn.execute(
            "UPDATE role_session_tokens SET active = 1 WHERE id = ?",
            (token_id,),
        )
        conn.commit()
    return True


def get_active_session_token(db_path: Path, role_id: str) -> Optional[dict]:
    """
    Purpose:
        Return the currently active session token for a role, if one exists.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the role.
    Output:
        Dict with keys 'id', 'token', 'created_at', or None when no active
        token exists for the role.
    Side effects: None (read-only).
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT id, token, created_at
            FROM role_session_tokens
            WHERE role_id = ? AND active = 1
            LIMIT 1
            """,
            (role_id,),
        ).fetchone()
    return dict(row) if row else None


def list_session_tokens(db_path: Path, role_id: str) -> list[dict]:
    """
    Purpose:
        Return all stored session tokens for a role, newest first.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the role.
    Output:
        List of dicts with keys 'id', 'token', 'created_at', 'active'.
        Empty list when no tokens exist.
    Side effects: None (read-only).
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, token, created_at, active
            FROM role_session_tokens
            WHERE role_id = ?
            ORDER BY created_at DESC
            """,
            (role_id,),
        ).fetchall()
    return [dict(r) for r in rows]


# ================================================================== #
# Auth flow config — multi-flow extractor model                        #
# ================================================================== #

def list_auth_flow_configs(db_path: Path, role_id: str) -> list[dict]:
    """
    Purpose:
        Return all auth flow configs for a role, ordered by sort_order.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the target role.
    Output:
        List of dicts with keys 'id', 'role_id', 'flow_id',
        'extractor_code' (may be None), 'sort_order', 'created_at'.
        Empty list when no flows are configured.
    Side effects: None (read-only).
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, role_id, flow_id, extractor_code, sort_order, created_at
            FROM auth_flow_config
            WHERE role_id = ?
            ORDER BY sort_order ASC, created_at ASC
            """,
            (role_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def add_auth_flow(db_path: Path, role_id: str, flow_id: str) -> str:
    """
    Purpose:
        Add a flow to a role's auth config.
        Sort order is assigned as max(existing) + 1 for this role.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the target role.
        flow_id — UUID of the login flow to add.
    Output:
        UUID of the new auth_flow_config row.
    Side effects:
        Inserts a row into auth_flow_config.
        Raises sqlite3.IntegrityError if (role_id, flow_id) already exists.
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    config_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT COALESCE(MAX(sort_order), -1) FROM auth_flow_config WHERE role_id = ?",
            (role_id,),
        ).fetchone()
        next_order = (row[0] + 1) if row else 0
        conn.execute(
            """
            INSERT INTO auth_flow_config
                (id, role_id, flow_id, extractor_code, sort_order, created_at)
            VALUES (?, ?, ?, NULL, ?, ?)
            """,
            (config_id, role_id, flow_id, next_order, now),
        )
        conn.commit()
    return config_id


def remove_auth_flow(db_path: Path, role_id: str, flow_id: str) -> bool:
    """
    Purpose:
        Remove a flow from a role's auth config.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the target role.
        flow_id — UUID of the flow to remove.
    Output:
        True if a row was deleted; False if the flow was not configured.
    Side effects:
        Deletes one row from auth_flow_config.
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.execute(
            "DELETE FROM auth_flow_config WHERE role_id = ? AND flow_id = ?",
            (role_id, flow_id),
        )
        conn.commit()
    return cursor.rowcount > 0


def set_flow_extractor(
    db_path: Path, role_id: str, flow_id: str, code: str
) -> bool:
    """
    Purpose:
        Set (or replace) the Python extractor code for a specific flow in a
        role's auth config.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the role.
        flow_id — UUID of the flow whose extractor to update.
        code    — Full Python source; must define extract(response) → dict.
    Output:
        True if the row was updated; False if the (role_id, flow_id) row
        does not exist.
    Side effects:
        Updates extractor_code in auth_flow_config.
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.execute(
            """
            UPDATE auth_flow_config
            SET extractor_code = ?
            WHERE role_id = ? AND flow_id = ?
            """,
            (code, role_id, flow_id),
        )
        conn.commit()
    return cursor.rowcount > 0


def get_flow_extractor(
    db_path: Path, role_id: str, flow_id: str
) -> Optional[str]:
    """
    Purpose:
        Return the extractor code for a specific (role, flow) pair.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the role.
        flow_id — UUID of the flow.
    Output:
        Python source string if set; None if the row doesn't exist or
        extractor_code is NULL.
    Side effects: None (read-only).
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT extractor_code FROM auth_flow_config WHERE role_id = ? AND flow_id = ?",
            (role_id, flow_id),
        ).fetchone()
    if row is None:
        return None
    return row[0]


def remove_flow_extractor(db_path: Path, role_id: str, flow_id: str) -> bool:
    """
    Purpose:
        Clear the extractor code for a specific (role, flow) pair.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the role.
        flow_id — UUID of the flow.
    Output:
        True if a row was updated; False if not found.
    Side effects:
        Sets extractor_code to NULL in auth_flow_config.
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.execute(
            "UPDATE auth_flow_config SET extractor_code = NULL WHERE role_id = ? AND flow_id = ?",
            (role_id, flow_id),
        )
        conn.commit()
    return cursor.rowcount > 0


# ================================================================== #
# Role auth state — current extracted key-value pairs                  #
# ================================================================== #

def get_role_auth_state(db_path: Path, role_id: str) -> dict:
    """
    Purpose:
        Return the current auth key-value state for a role.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the role.
    Output:
        Dict with two keys:
            'state'        — {artifact_name: value} mapping (may be empty).
            'collected_at' — UTC ISO-8601 string of the most recent refresh,
                             or None when no state exists.
    Side effects: None (read-only).
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT key, value, collected_at FROM role_auth_state WHERE role_id = ?",
            (role_id,),
        ).fetchall()
    if not rows:
        return {"state": {}, "collected_at": None}
    state = {r["key"]: r["value"] for r in rows}
    collected_at = rows[0]["collected_at"]
    return {"state": state, "collected_at": collected_at}


def store_role_auth_state(
    db_path: Path,
    role_id: str,
    state: dict[str, str],
    collected_at: str,
) -> None:
    """
    Purpose:
        Replace the entire auth state for a role with new key-value pairs.
        All previous state rows for the role are deleted and replaced.
    Input:
        db_path      — absolute Path to the project's talos.db.
        role_id      — UUID of the role.
        state        — {artifact_name: value} dict from extractor merge.
        collected_at — UTC ISO-8601 string to stamp on every row.
    Output: None
    Side effects:
        Deletes existing role_auth_state rows for the role.
        Inserts new rows.
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "DELETE FROM role_auth_state WHERE role_id = ?",
            (role_id,),
        )
        for key, value in state.items():
            conn.execute(
                """
                INSERT INTO role_auth_state (role_id, key, value, collected_at)
                VALUES (?, ?, ?, ?)
                """,
                (role_id, key, value, collected_at),
            )
        conn.commit()


# ================================================================== #
# Session health config — TTL, expiry signals, validation endpoint     #
# ================================================================== #

_DEFAULT_HEALTH_CONFIG: dict = {
    "ttl_seconds": 1200,
    "refresh_before_seconds": 120,
    "expiry_body_signals": [],
    "expiry_header_signals": {},
    "expiry_status_codes": [],
    "validation_endpoint_url": None,
    "validation_expected_status": 200,
    "validation_body_contains": [],
    "validation_body_not_contains": [],
}


def get_session_health_config(db_path: Path, role_id: str) -> dict:
    """
    Purpose:
        Return the session health config for a role.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the role.
    Output:
        Dict with keys:
            ttl_seconds, refresh_before_seconds,
            expiry_body_signals (list), expiry_header_signals (dict),
            expiry_status_codes (list), validation_endpoint_url (str|None),
            validation_expected_status (int),
            validation_body_contains (list), validation_body_not_contains (list).
        Returns defaults when no row exists for the role.
    Side effects: None (read-only).
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM session_health_config WHERE role_id = ?",
            (role_id,),
        ).fetchone()
    if row is None:
        return dict(_DEFAULT_HEALTH_CONFIG)
    d = dict(row)
    # Deserialise JSON fields.
    for key in ("expiry_body_signals", "expiry_status_codes",
                "validation_body_contains", "validation_body_not_contains"):
        d[key] = json.loads(d[key]) if d[key] else []
    d["expiry_header_signals"] = json.loads(d["expiry_header_signals"]) if d["expiry_header_signals"] else {}
    return d


def set_session_health_config(db_path: Path, role_id: str, **kwargs) -> None:
    """
    Purpose:
        Upsert the session health config for a role.
        Merges kwargs into the existing row; missing fields keep their current
        (or default) values.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the role.
        **kwargs — Any subset of the session_health_config columns:
            ttl_seconds (int), refresh_before_seconds (int),
            expiry_body_signals (list), expiry_header_signals (dict),
            expiry_status_codes (list), validation_endpoint_url (str|None),
            validation_expected_status (int),
            validation_body_contains (list), validation_body_not_contains (list).
    Output: None
    Side effects:
        Inserts or updates the session_health_config row for the role.
        JSON-serialises list/dict fields before storage.
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)

    current = get_session_health_config(db_path, role_id)
    current.update(kwargs)

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO session_health_config (
                role_id, ttl_seconds, refresh_before_seconds,
                expiry_body_signals, expiry_header_signals, expiry_status_codes,
                validation_endpoint_url, validation_expected_status,
                validation_body_contains, validation_body_not_contains
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                role_id,
                current["ttl_seconds"],
                current["refresh_before_seconds"],
                json.dumps(current["expiry_body_signals"]),
                json.dumps(current["expiry_header_signals"]),
                json.dumps(current["expiry_status_codes"]),
                current["validation_endpoint_url"],
                current["validation_expected_status"],
                json.dumps(current["validation_body_contains"]),
                json.dumps(current["validation_body_not_contains"]),
            ),
        )
        conn.commit()


# ================================================================== #
# Session health control flows — Layer 4 health probes                 #
# ================================================================== #

def list_session_health_control_flows(db_path: Path, role_id: str) -> list[str]:
    """
    Purpose:
        Return all control flow IDs configured for a role.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the role.
    Output:
        List of flow UUID strings.  Empty when none are configured.
    Side effects: None (read-only).
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT flow_id FROM session_health_control_flows WHERE role_id = ?",
            (role_id,),
        ).fetchall()
    return [r[0] for r in rows]


def add_session_health_control_flow(
    db_path: Path, role_id: str, flow_id: str
) -> bool:
    """
    Purpose:
        Add a control flow for session health validation.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the role.
        flow_id — UUID of the control flow.
    Output:
        True if inserted; False if already present.
    Side effects:
        Inserts into session_health_control_flows.
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.execute(
            "INSERT OR IGNORE INTO session_health_control_flows (role_id, flow_id) VALUES (?, ?)",
            (role_id, flow_id),
        )
        conn.commit()
    return cursor.rowcount > 0


def remove_session_health_control_flow(
    db_path: Path, role_id: str, flow_id: str
) -> bool:
    """
    Purpose:
        Remove a control flow from session health validation.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the role.
        flow_id — UUID of the control flow.
    Output:
        True if deleted; False if not found.
    Side effects:
        Deletes from session_health_control_flows.
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.execute(
            "DELETE FROM session_health_control_flows WHERE role_id = ? AND flow_id = ?",
            (role_id, flow_id),
        )
        conn.commit()
    return cursor.rowcount > 0


# ================================================================== #
# Session suspicion state — runtime health tracking                    #
# ================================================================== #

def get_suspicion_state(db_path: Path, role_id: str) -> dict:
    """
    Purpose:
        Return the current suspicion state for a role.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the role.
    Output:
        Dict with keys 'suspicion_count' (int) and 'last_checked_at' (str|None).
        Returns defaults (count=0, checked=None) when no row exists.
    Side effects: None (read-only).
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT suspicion_count, last_checked_at FROM session_suspicion_state WHERE role_id = ?",
            (role_id,),
        ).fetchone()
    if row is None:
        return {"suspicion_count": 0, "last_checked_at": None}
    return dict(row)


def increment_suspicion(db_path: Path, role_id: str) -> int:
    """
    Purpose:
        Increment the suspicion counter for a role by 1.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the role.
    Output:
        New suspicion count after increment.
    Side effects:
        Upserts the session_suspicion_state row.
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO session_suspicion_state (role_id, suspicion_count, last_checked_at)
            VALUES (?, 1, NULL)
            ON CONFLICT(role_id) DO UPDATE
                SET suspicion_count = suspicion_count + 1
            """,
            (role_id,),
        )
        conn.commit()
        row = conn.execute(
            "SELECT suspicion_count FROM session_suspicion_state WHERE role_id = ?",
            (role_id,),
        ).fetchone()
    return row[0] if row else 1


def reset_suspicion(db_path: Path, role_id: str) -> None:
    """
    Purpose:
        Reset the suspicion counter to 0 and record the validation timestamp.
    Input:
        db_path — absolute Path to the project's talos.db.
        role_id — UUID of the role.
    Output: None
    Side effects:
        Upserts session_suspicion_state with count=0 and last_checked_at=now.
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO session_suspicion_state (role_id, suspicion_count, last_checked_at)
            VALUES (?, 0, ?)
            ON CONFLICT(role_id) DO UPDATE
                SET suspicion_count = 0, last_checked_at = excluded.last_checked_at
            """,
            (role_id, now),
        )
        conn.commit()
