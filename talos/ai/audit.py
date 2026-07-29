"""
Module: talos.ai.audit

Purpose:
    Append-only audit log for AI session and project-level events
    (start/stop, mode changes, validate/execute, policy rejects).

Dependencies: json, sqlite3, uuid, pathlib, talos.projects.db
Data flow:
    WorkflowEngine / Policy / Executor → record_event → ai_audit_events
Side effects:
    INSERT into ai_audit_events; may call migrate_project_db.
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
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def record_event(
    db_path: Path,
    project_id: str,
    event_type: str,
    payload: dict[str, Any],
    *,
    session_id: Optional[str] = None,
) -> str:
    """
    Purpose:
        Persist one audit event. Payload must already be free of secrets
        the operator would not want on disk (callers redact first).
    Input:
        db_path     — project SQLite path.
        project_id  — owning project.
        event_type  — short machine label (e.g. session.start).
        payload     — JSON-serializable dict.
        session_id  — optional AI session id.
    Output:
        Event id (UUID string).
    Side effects:
        INSERT ai_audit_events; migrate_project_db if needed.
    """
    migrate_project_db(db_path)
    event_id = str(uuid.uuid4())
    created = _now_iso()
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO ai_audit_events
                (id, session_id, project_id, event_type, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                session_id,
                project_id,
                event_type,
                json.dumps(payload, sort_keys=True, default=str),
                created,
            ),
        )
        conn.commit()
    return event_id


def list_events(
    db_path: Path,
    project_id: str,
    *,
    session_id: Optional[str] = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """
    Purpose:
        List audit events newest-first for a project, optional session filter.
    Output:
        List of dicts: id, session_id, project_id, event_type, payload, created_at.
    Side effects: migrate_project_db; read-only otherwise.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return []
    limit = max(1, min(int(limit), 1000))
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        if session_id:
            rows = conn.execute(
                """
                SELECT id, session_id, project_id, event_type, payload_json, created_at
                FROM ai_audit_events
                WHERE project_id = ? AND session_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (project_id, session_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, session_id, project_id, event_type, payload_json, created_at
                FROM ai_audit_events
                WHERE project_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (project_id, limit),
            ).fetchall()
    results: list[dict[str, Any]] = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except json.JSONDecodeError:
            payload = {"_raw": row["payload_json"]}
        results.append(
            {
                "id": row["id"],
                "session_id": row["session_id"],
                "project_id": row["project_id"],
                "event_type": row["event_type"],
                "payload": payload,
                "created_at": row["created_at"],
            }
        )
    return results
