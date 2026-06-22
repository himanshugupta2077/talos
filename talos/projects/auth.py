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

    Role auth (role_auth table):
        Per-role login and checkpoint flow assignments.  The login flow is
        replayed to obtain a fresh session token; the checkpoint flow is
        replayed to validate whether an existing token is still active.

    Role session tokens (role_session_tokens table):
        Generated session tokens extracted from login flow replays.
        Multiple tokens per role can be stored; at most one is marked active.

Dependencies: sqlite3, pathlib
Data flow:
    auth_cli / auth_strip → functions here → project SQLite
Side effects:
    - Write operations mutate auth_config / role_auth / role_session_tokens rows.
    - Read operations are connection-scoped with no persistent state.
"""

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
