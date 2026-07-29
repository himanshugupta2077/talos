"""
Module: talos.intruder.db

Purpose:
    CRUD for intruder_sessions and intruder_results. No DDL — schema lives
    exclusively in talos.projects.db.

Dependencies: json, sqlite3, uuid, datetime, pathlib
Data flow:
    CLI / engine / scheduler → db helpers → project SQLite
Side effects:
    - INSERT/UPDATE/DELETE on intruder_* tables
    - migrate_project_db on entry for older projects
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from talos.projects.db import migrate_project_db


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect(db_path: Path, *, busy_timeout_ms: int = 5000) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=busy_timeout_ms / 1000.0)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _ensure_migrated(db_path: Path) -> None:
    migrate_project_db(db_path)


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), default=str)


def _json_loads(raw: Any, default: Any = None) -> Any:
    if raw is None or raw == "":
        return default if default is not None else {}
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return default if default is not None else {}


def create_session(
    db_path: Path,
    project_id: str,
    *,
    name: str = "",
    base_flow_id: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    config: Optional[dict[str, Any]] = None,
    status: str = "draft",
    schema_version: int = 1,
) -> dict[str, Any]:
    """
    Purpose: Insert a new Intruder session row.
    Output: session dict.
    """
    _ensure_migrated(db_path)
    sid = str(uuid.uuid4())
    now = _now_iso()
    cfg = config or {}
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO intruder_sessions (
                id, project_id, name, status, base_flow_id, endpoint_id,
                config_json, checkpoint_json, progress_json, job_id,
                control_flag, created_at, updated_at, started_at, finished_at,
                failure_reason, schema_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, '{}', '{}', NULL, NULL, ?, ?, NULL, NULL, NULL, ?)
            """,
            (
                sid,
                project_id,
                name or "",
                status,
                base_flow_id,
                endpoint_id,
                _json_dumps(cfg),
                now,
                now,
                schema_version,
            ),
        )
        conn.commit()
    return get_session(db_path, sid)  # type: ignore[return-value]


def get_session(db_path: Path, session_id: str) -> Optional[dict[str, Any]]:
    """Load one session by full UUID or unique prefix."""
    _ensure_migrated(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM intruder_sessions WHERE id = ?",
            (session_id,),
        ).fetchone()
        if row is None and len(session_id) >= 8:
            rows = conn.execute(
                "SELECT * FROM intruder_sessions WHERE id LIKE ?",
                (session_id + "%",),
            ).fetchall()
            if len(rows) == 1:
                row = rows[0]
            else:
                return None
        if row is None:
            return None
        return _session_row(row)


def list_sessions(
    db_path: Path,
    project_id: str,
    *,
    status: Optional[str] = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    _ensure_migrated(db_path)
    sql = "SELECT * FROM intruder_sessions WHERE project_id = ?"
    params: list[Any] = [project_id]
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY updated_at DESC LIMIT ?"
    params.append(limit)
    with _connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_session_row(r) for r in rows]


def list_paused_session_ids(db_path: Path, project_id: str) -> list[str]:
    """IDs of sessions currently paused (for scheduler resume warning)."""
    _ensure_migrated(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id FROM intruder_sessions WHERE project_id = ? AND status = 'paused'",
            (project_id,),
        ).fetchall()
    return [r["id"] for r in rows]


def update_session(
    db_path: Path,
    session_id: str,
    *,
    name: Optional[str] = None,
    status: Optional[str] = None,
    base_flow_id: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    config: Optional[dict[str, Any]] = None,
    checkpoint: Optional[dict[str, Any]] = None,
    progress: Optional[dict[str, Any]] = None,
    job_id: Optional[str] = ...,  # type: ignore[assignment]
    control_flag: Optional[str] = ...,  # type: ignore[assignment]
    started_at: Optional[str] = ...,  # type: ignore[assignment]
    finished_at: Optional[str] = ...,  # type: ignore[assignment]
    failure_reason: Optional[str] = ...,  # type: ignore[assignment]
) -> Optional[dict[str, Any]]:
    """
    Partial update. Use ellipsis (...) sentinel for job_id/control_flag/etc
    when the field should be left unchanged; pass None to clear nullable cols.
    """
    _ensure_migrated(db_path)
    sets: list[str] = ["updated_at = ?"]
    params: list[Any] = [_now_iso()]

    if name is not None:
        sets.append("name = ?")
        params.append(name)
    if status is not None:
        sets.append("status = ?")
        params.append(status)
    if base_flow_id is not None:
        sets.append("base_flow_id = ?")
        params.append(base_flow_id)
    if endpoint_id is not None:
        sets.append("endpoint_id = ?")
        params.append(endpoint_id)
    if config is not None:
        sets.append("config_json = ?")
        params.append(_json_dumps(config))
    if checkpoint is not None:
        sets.append("checkpoint_json = ?")
        params.append(_json_dumps(checkpoint))
    if progress is not None:
        sets.append("progress_json = ?")
        params.append(_json_dumps(progress))
    if job_id is not ...:
        sets.append("job_id = ?")
        params.append(job_id)
    if control_flag is not ...:
        sets.append("control_flag = ?")
        params.append(control_flag)
    if started_at is not ...:
        sets.append("started_at = ?")
        params.append(started_at)
    if finished_at is not ...:
        sets.append("finished_at = ?")
        params.append(finished_at)
    if failure_reason is not ...:
        sets.append("failure_reason = ?")
        params.append(failure_reason)

    params.append(session_id)
    with _connect(db_path) as conn:
        conn.execute(
            f"UPDATE intruder_sessions SET {', '.join(sets)} WHERE id = ?",
            params,
        )
        conn.commit()
    return get_session(db_path, session_id)


def set_control_flag(
    db_path: Path,
    session_id: str,
    flag: Optional[str],
) -> None:
    update_session(db_path, session_id, control_flag=flag)


def delete_session(db_path: Path, session_id: str) -> bool:
    """Delete session and cascaded results. Returns True if a row was removed."""
    _ensure_migrated(db_path)
    with _connect(db_path) as conn:
        # Explicit results delete for DBs without CASCADE enforcement.
        conn.execute("DELETE FROM intruder_results WHERE session_id = ?", (session_id,))
        cur = conn.execute("DELETE FROM intruder_sessions WHERE id = ?", (session_id,))
        conn.commit()
        return cur.rowcount > 0


def insert_results_batch(
    db_path: Path,
    session_id: str,
    results: list[dict[str, Any]],
    *,
    checkpoint: Optional[dict[str, Any]] = None,
    progress: Optional[dict[str, Any]] = None,
    status: Optional[str] = None,
) -> int:
    """
    Purpose:
        Insert result rows + optionally update checkpoint/progress in one
        transaction. Uses INSERT OR IGNORE for at-least-once crash recovery.
    Output:
        Number of rows newly inserted (ignores ignored).
    """
    if not results and checkpoint is None and progress is None and status is None:
        return 0
    _ensure_migrated(db_path)
    now = _now_iso()
    inserted = 0
    with _connect(db_path) as conn:
        for r in results:
            rid = r.get("id") or str(uuid.uuid4())
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO intruder_results (
                    id, session_id, attempt_index, variables_json,
                    status_code, success, failure_reason, duration_ms,
                    body_length, word_count, line_count, body_hash,
                    fingerprint_json, metrics_json, interesting,
                    match_tags_json, grepped_json, flow_id, created_at
                ) VALUES (
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?
                )
                """,
                (
                    rid,
                    session_id,
                    int(r["attempt_index"]),
                    _json_dumps(r.get("variables") or {}),
                    r.get("status_code"),
                    1 if r.get("success") else 0,
                    r.get("failure_reason"),
                    r.get("duration_ms"),
                    r.get("body_length"),
                    r.get("word_count"),
                    r.get("line_count"),
                    r.get("body_hash"),
                    _json_dumps(r.get("fingerprint") or {}),
                    _json_dumps(r.get("metrics") or {}),
                    1 if r.get("interesting") else 0,
                    _json_dumps(r.get("match_tags") or []),
                    _json_dumps(r.get("grepped") or {}),
                    r.get("flow_id"),
                    r.get("created_at") or now,
                ),
            )
            if cur.rowcount:
                inserted += 1

        sets = ["updated_at = ?"]
        params: list[Any] = [now]
        if checkpoint is not None:
            sets.append("checkpoint_json = ?")
            params.append(_json_dumps(checkpoint))
        if progress is not None:
            sets.append("progress_json = ?")
            params.append(_json_dumps(progress))
        if status is not None:
            sets.append("status = ?")
            params.append(status)
        params.append(session_id)
        conn.execute(
            f"UPDATE intruder_sessions SET {', '.join(sets)} WHERE id = ?",
            params,
        )
        conn.commit()
    return inserted


def list_results(
    db_path: Path,
    session_id: str,
    *,
    interesting_only: bool = False,
    limit: int = 200,
    offset: int = 0,
    min_attempt: Optional[int] = None,
    max_attempt: Optional[int] = None,
    status_code: Optional[int] = None,
) -> list[dict[str, Any]]:
    _ensure_migrated(db_path)
    sql = "SELECT * FROM intruder_results WHERE session_id = ?"
    params: list[Any] = [session_id]
    if interesting_only:
        sql += " AND interesting = 1"
    if min_attempt is not None:
        sql += " AND attempt_index >= ?"
        params.append(min_attempt)
    if max_attempt is not None:
        sql += " AND attempt_index <= ?"
        params.append(max_attempt)
    if status_code is not None:
        sql += " AND status_code = ?"
        params.append(status_code)
    sql += " ORDER BY attempt_index ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    with _connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_result_row(r) for r in rows]


def get_result(
    db_path: Path,
    session_id: str,
    attempt_index: int,
) -> Optional[dict[str, Any]]:
    _ensure_migrated(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM intruder_results WHERE session_id = ? AND attempt_index = ?",
            (session_id, attempt_index),
        ).fetchone()
    return _result_row(row) if row else None


def count_results(db_path: Path, session_id: str, *, interesting_only: bool = False) -> int:
    _ensure_migrated(db_path)
    sql = "SELECT COUNT(*) AS c FROM intruder_results WHERE session_id = ?"
    params: list[Any] = [session_id]
    if interesting_only:
        sql += " AND interesting = 1"
    with _connect(db_path) as conn:
        row = conn.execute(sql, params).fetchone()
    return int(row["c"]) if row else 0


def _to_json(value: object) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value if value is not None else {}, default=str)


def insert_intruder_flow(
    db_path: Path,
    flow: dict[str, Any],
) -> None:
    """
    Purpose:
        Insert a flows row for an interesting Intruder attempt without
        invoking error_intel or passive hooks (design Key Decision 25).
    """
    _ensure_migrated(db_path)
    with _connect(db_path) as conn:
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
                source, original_flow_id, replay_error, replay_reason, flow_meta
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?,
                ?, ?,
                ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?, ?
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
                _to_json(flow.get("request_headers", {})),
                _to_json(flow.get("request_cookies", {})),
                flow.get("request_body"),
                1 if flow.get("request_body_truncated") else 0,
                flow.get("status_code"),
                _to_json(flow.get("response_headers", {})),
                flow.get("response_body"),
                1 if flow.get("response_body_truncated") else 0,
                flow.get("content_type", ""),
                None,
                flow.get("endpoint_id"),
                flow["role_id"],
                flow["module_id"],
                "[]",
                "intruder",
                flow.get("original_flow_id"),
                flow.get("replay_error"),
                "intruder",
                _to_json(flow.get("flow_meta") or {}),
            ),
        )
        conn.commit()


def load_flow(db_path: Path, flow_id: str) -> Optional[dict[str, Any]]:
    """Load a flows row as a plain dict (for baseline snapshot)."""
    _ensure_migrated(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM flows WHERE id = ?",
            (flow_id,),
        ).fetchone()
        if row is None and len(flow_id) >= 8:
            rows = conn.execute(
                "SELECT * FROM flows WHERE id LIKE ?",
                (flow_id + "%",),
            ).fetchall()
            if len(rows) == 1:
                row = rows[0]
        if row is None:
            return None
        return dict(row)


def load_endpoint_normalized_path(
    db_path: Path,
    endpoint_id: Optional[str],
) -> Optional[str]:
    if not endpoint_id:
        return None
    _ensure_migrated(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT normalized_path FROM endpoints WHERE id = ?",
            (endpoint_id,),
        ).fetchone()
    return row["normalized_path"] if row else None


def _session_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "project_id": row["project_id"],
        "name": row["name"] or "",
        "status": row["status"],
        "base_flow_id": row["base_flow_id"],
        "endpoint_id": row["endpoint_id"],
        "config": _json_loads(row["config_json"], {}),
        "checkpoint": _json_loads(row["checkpoint_json"], {}),
        "progress": _json_loads(row["progress_json"], {}),
        "job_id": row["job_id"],
        "control_flag": row["control_flag"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "failure_reason": row["failure_reason"],
        "schema_version": row["schema_version"],
    }


def _result_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "session_id": row["session_id"],
        "attempt_index": row["attempt_index"],
        "variables": _json_loads(row["variables_json"], {}),
        "status_code": row["status_code"],
        "success": bool(row["success"]),
        "failure_reason": row["failure_reason"],
        "duration_ms": row["duration_ms"],
        "body_length": row["body_length"],
        "word_count": row["word_count"],
        "line_count": row["line_count"],
        "body_hash": row["body_hash"],
        "fingerprint": _json_loads(row["fingerprint_json"], {}),
        "metrics": _json_loads(row["metrics_json"], {}),
        "interesting": bool(row["interesting"]),
        "match_tags": _json_loads(row["match_tags_json"], []),
        "grepped": _json_loads(row["grepped_json"], {}),
        "flow_id": row["flow_id"],
        "created_at": row["created_at"],
    }
