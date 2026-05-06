"""
Module: talos.replay.db

Purpose:
    Data access layer for the replay engine.
    Reads flows and endpoints to supply replay input.
    Writes replayed flows (source=auto_replay) linked to their original.
    Calls migrate_project_db before any read or write to ensure the schema
    is at v7 (replay columns present) on databases created before this feature.

Dependencies: sqlite3, json, pathlib
Data flow:
    replay/engine.py → functions here → project SQLite
Side effects:
    - get_flow_for_replay, get_best_flow_for_endpoint: read-only after migration.
    - insert_replayed_flow: inserts one row into flows.
    - All functions call migrate_project_db(db_path) on entry to handle
      pre-v7 databases transparently.
"""

import json
import sqlite3
from pathlib import Path
from typing import Optional

from talos.projects.db import migrate_project_db


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _connect_rw(db_path: Path) -> sqlite3.Connection:
    """
    Purpose: Open a read-write SQLite connection with row_factory set.
    Input:   db_path — absolute Path to the project's talos.db.
    Output:  sqlite3.Connection. Caller is responsible for closing.
    Side effects: Opens file descriptor.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def _connect_ro(db_path: Path) -> sqlite3.Connection:
    """
    Purpose: Open a read-only SQLite connection with row_factory set.
    Input:   db_path — absolute Path to the project's talos.db.
    Output:  sqlite3.Connection (read-only URI mode). Caller must close.
    Side effects: Opens file descriptor.
    """
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


# ------------------------------------------------------------------ #
# Read operations                                                      #
# ------------------------------------------------------------------ #

def get_flow_for_replay(db_path: Path, flow_id: str) -> Optional[dict]:
    """
    Purpose:
        Fetch all fields needed to reconstruct and replay a stored flow.
    Input:
        db_path — absolute Path to the project's talos.db.
        flow_id — UUID string of the target flow.
    Output:
        Full flow dict, or None if the flow does not exist.
    Side effects:
        Calls migrate_project_db to ensure replay columns exist.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return None
    with _connect_ro(db_path) as conn:
        row = conn.execute(
            """
            SELECT id, method, url, host, path, query,
                   request_headers, request_cookies,
                   request_body, request_body_truncated,
                   status_code, response_body, response_headers, content_type,
                   endpoint_id, role_id, module_id,
                   source
            FROM flows
            WHERE id = ?
            """,
            (flow_id,),
        ).fetchone()
    return dict(row) if row else None


def get_best_flow_for_endpoint(db_path: Path, endpoint_id: str) -> Optional[dict]:
    """
    Purpose:
        Select the most recent proxy_capture flow with status_code=200 for a
        given endpoint.  This is the flow used for exact replay.
    Input:
        db_path     — absolute Path to the project's talos.db.
        endpoint_id — UUID string of the target endpoint.
    Output:
        Flow dict with all fields needed for replay, or None when no qualifying
        flow exists (no 200 OK proxy_capture flow for this endpoint).
    Side effects:
        Calls migrate_project_db to ensure replay columns exist.

    Selection rule:
        status_code = 200 AND source = 'proxy_capture'
        Ordered by captured_at DESC — most recent first.
        LIMIT 1 — exactly one flow selected.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return None
    with _connect_ro(db_path) as conn:
        row = conn.execute(
            """
            SELECT id, method, url, host, path, query,
                   request_headers, request_cookies,
                   request_body, request_body_truncated,
                   status_code, endpoint_id, role_id, module_id,
                   source
            FROM flows
            WHERE endpoint_id = ?
              AND status_code = 200
              AND source = 'proxy_capture'
            ORDER BY captured_at DESC
            LIMIT 1
            """,
            (endpoint_id,),
        ).fetchone()
    return dict(row) if row else None


def get_endpoint_by_id(db_path: Path, endpoint_id: str) -> Optional[dict]:
    """
    Purpose:
        Fetch a single endpoint record for display in CLI feedback.
    Input:
        db_path     — absolute Path to the project's talos.db.
        endpoint_id — UUID string.
    Output:
        Endpoint dict, or None if not found.
    Side effects: None (read-only; assumes migration already done by caller).
    """
    if not db_path.exists():
        return None
    with _connect_ro(db_path) as conn:
        row = conn.execute(
            "SELECT id, method, host, normalized_path FROM endpoints WHERE id = ?",
            (endpoint_id,),
        ).fetchone()
    return dict(row) if row else None


# ------------------------------------------------------------------ #
# Write operations                                                     #
# ------------------------------------------------------------------ #

def insert_replayed_flow(db_path: Path, flow: dict) -> None:
    """
    Purpose:
        Persist a replayed flow to the flows table.
        The flow dict must already carry source='auto_replay', original_flow_id,
        and all request/response fields.  This function performs no validation
        beyond structural — caller (engine.py) owns correctness.
    Input:
        db_path — absolute Path to the project's talos.db.
        flow    — dict with all fields for the flows INSERT (see columns below).
    Output:
        None
    Side effects:
        Inserts one row into flows.
        Raises sqlite3.Error on DB write failure — caller handles.

    Columns written:
        id, project_id, captured_at, response_end, method, url, host, path,
        query, request_headers, request_cookies, request_body,
        request_body_truncated, status_code, response_headers, response_body,
        response_body_truncated, content_type, session_id, endpoint_id,
        role_id, module_id, tags, source, original_flow_id, replay_error,
        replay_reason
    """
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO flows (
                id, project_id, captured_at, response_end,
                method, url, host, path, query,
                request_headers, request_cookies,
                request_body, request_body_truncated,
                status_code,
                response_headers, response_body, response_body_truncated,
                content_type, session_id, endpoint_id,
                role_id, module_id, tags,
                source, original_flow_id, replay_error, replay_reason
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?,
                ?, ?,
                ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?
            )
            """,
            (
                flow["id"],
                flow["project_id"],
                flow["captured_at"],
                flow.get("response_end"),
                flow["method"],
                flow["url"],
                flow["host"],
                flow["path"],
                flow.get("query", ""),
                # Ensure headers/cookies are stored as JSON strings.
                _to_json(flow.get("request_headers", {})),
                _to_json(flow.get("request_cookies", {})),
                flow.get("request_body"),           # BLOB or None
                1 if flow.get("request_body_truncated") else 0,
                flow.get("status_code"),            # None on connection failure
                _to_json(flow.get("response_headers", {})),
                flow.get("response_body"),          # BLOB or None
                1 if flow.get("response_body_truncated") else 0,
                flow.get("content_type", ""),
                None,                               # session_id: not resolved for replays
                flow.get("endpoint_id"),
                flow["role_id"],
                flow["module_id"],
                "[]",                               # tags: empty for replay flows
                flow["source"],
                flow["original_flow_id"],
                flow.get("replay_error"),
                flow.get("replay_reason"),
            ),
        )
        conn.commit()


def _to_json(value: object) -> str:
    """
    Purpose:
        Ensure a value is a JSON string for storage in a TEXT column.
        Already-serialised strings are returned as-is to avoid double-encoding.
    Input:   value — dict or already-serialised JSON string.
    Output:  JSON string.
    Side effects: None.
    """
    if isinstance(value, str):
        return value
    return json.dumps(value)


# ------------------------------------------------------------------ #
# Diff operations                                                      #
# ------------------------------------------------------------------ #

def insert_replay_diff(db_path: Path, diff_row: dict) -> None:
    """
    Purpose:
        Persist a diff result to the replay_diffs table.
        Called immediately after insert_replayed_flow in the engine.
    Input:
        db_path  — absolute Path to the project's talos.db.
        diff_row — dict with keys:
                     replay_flow_id   (str)          — PK; UUID of the replay flow.
                     original_flow_id (str)          — UUID of the source flow.
                     verdict          (str)          — SAME | DIFFERENT | ERROR.
                     status_changed   (bool/int)     — 1 or 0.
                     status_diff      (str or None)  — e.g. "200→403" or NULL.
                     length_diff      (int)          — signed byte delta.
    Output: None
    Side effects:
        Inserts one row into replay_diffs.
        Raises sqlite3.Error on write failure — caller handles.
    """
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO replay_diffs (
                replay_flow_id, original_flow_id,
                verdict, status_changed, status_diff, length_diff
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                diff_row["replay_flow_id"],
                diff_row["original_flow_id"],
                diff_row["verdict"],
                1 if diff_row["status_changed"] else 0,
                diff_row.get("status_diff"),
                diff_row["length_diff"],
            ),
        )
        conn.commit()


def insert_auth_test_result(db_path: Path, result_row: dict) -> None:
    """
    Purpose:
        Persist an auth-bypass test verdict to the auth_test_results table.
        Called immediately after insert_replay_diff in auth_strip._execute_stripped_replay.
    Input:
        db_path    — absolute Path to the project's talos.db.
        result_row — dict with keys:
                       replay_flow_id   (str) — PK; UUID of the auth-test replay flow.
                       original_flow_id (str) — UUID of the source flow.
                       verdict          (str) — SECURE | BYPASS | UNKNOWN.
    Output: None
    Side effects:
        Inserts one row into auth_test_results.
        Raises sqlite3.Error on write failure — caller handles.
    """
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO auth_test_results (
                replay_flow_id, original_flow_id, verdict
            ) VALUES (?, ?, ?)
            """,
            (
                result_row["replay_flow_id"],
                result_row["original_flow_id"],
                result_row["verdict"],
            ),
        )
        conn.commit()
