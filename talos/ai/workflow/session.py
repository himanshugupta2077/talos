"""
Module: talos.ai.workflow.session

Purpose:
    Persist and load AI agent sessions with frozen project pin, budgets,
    and one-active-session-per-project enforcement.

Dependencies: json, sqlite3, uuid, pathlib, talos.ai.models, talos.projects.db
Data flow:
    WorkflowEngine → session helpers → ai_sessions / ai_project_prefs tables
Side effects:
    INSERT/UPDATE ai_sessions and ai_project_prefs; migrate_project_db.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from talos.ai.models import (
    AutonomyMode,
    BudgetLimits,
    BudgetUsage,
    AgentSession,
    SessionStatus,
    parse_mode,
)
from talos.projects.db import migrate_project_db


class SessionError(Exception):
    """Base error for AI session operations."""


class ActiveSessionExists(SessionError):
    """Another AI session is already active for this project."""

    def __init__(self, existing_session_id: str):
        self.existing_session_id = existing_session_id
        super().__init__(
            f"An active AI session already exists: {existing_session_id}. "
            "Stop it first or pass --force-stop-existing."
        )


class SessionNotFound(SessionError):
    """Requested session id does not exist for this project."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _row_to_session(row: sqlite3.Row, db_path: Path) -> AgentSession:
    try:
        budgets_raw = json.loads(row["budgets_json"] or "{}")
    except json.JSONDecodeError:
        budgets_raw = {}
    try:
        usage_raw = json.loads(row["usage_json"] or "{}")
    except json.JSONDecodeError:
        usage_raw = {}
    return AgentSession(
        session_id=row["id"],
        project_id=row["project_id"],
        goal=row["goal"] or "",
        mode=parse_mode(row["mode"]),
        status=SessionStatus(row["status"]),
        pinned_project_id=row["pinned_project_id"],
        data_dir=Path(row["data_dir"]),
        db_path=db_path,
        budgets=BudgetLimits.from_dict(budgets_raw),
        usage=BudgetUsage.from_dict(usage_raw),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        scope_snapshot_json=row["scope_snapshot_json"],
    )


def get_active_session(db_path: Path, project_id: str) -> Optional[AgentSession]:
    """
    Purpose: Return the active AI session for a project, if any.
    Side effects: migrate_project_db.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return None
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT * FROM ai_sessions
            WHERE project_id = ? AND status = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (project_id, SessionStatus.ACTIVE.value),
        ).fetchone()
    if row is None:
        return None
    return _row_to_session(row, db_path)


def get_session(
    db_path: Path,
    project_id: str,
    session_id: str,
) -> AgentSession:
    """
    Purpose: Load a session by id (must belong to project_id).
    Raises: SessionNotFound.
    """
    migrate_project_db(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM ai_sessions WHERE id = ? AND project_id = ?",
            (session_id, project_id),
        ).fetchone()
    if row is None:
        raise SessionNotFound(f"AI session not found: {session_id}")
    return _row_to_session(row, db_path)


def create_session(
    db_path: Path,
    *,
    project_id: str,
    data_dir: Path,
    goal: str,
    mode: AutonomyMode = AutonomyMode.SUGGEST_ONLY,
    force_stop_existing: bool = False,
    scope_snapshot: Optional[dict[str, Any]] = None,
    budgets: Optional[BudgetLimits] = None,
) -> AgentSession:
    """
    Purpose:
        Create a new active AI session pinned to project_id.
        Enforces one active session per project unless force_stop_existing.
    Output:
        New AgentSession (status=active).
    Side effects:
        May stop existing active session; INSERT ai_sessions.
    Raises:
        ActiveSessionExists when another session is active and force is false.
    """
    migrate_project_db(db_path)
    existing = get_active_session(db_path, project_id)
    if existing is not None:
        if not force_stop_existing:
            raise ActiveSessionExists(existing.session_id)
        stop_session(db_path, project_id, existing.session_id)

    session_id = str(uuid.uuid4())
    now = _now_iso()
    limits = budgets or BudgetLimits()
    usage = BudgetUsage()
    scope_json = (
        json.dumps(scope_snapshot, sort_keys=True) if scope_snapshot is not None else None
    )

    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO ai_sessions (
                id, project_id, goal, mode, status,
                pinned_project_id, data_dir, scope_snapshot_json,
                budgets_json, usage_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                project_id,
                goal or "",
                mode.value,
                SessionStatus.ACTIVE.value,
                project_id,
                str(data_dir),
                scope_json,
                json.dumps(limits.to_dict(), sort_keys=True),
                json.dumps(usage.to_dict(), sort_keys=True),
                now,
                now,
            ),
        )
        conn.commit()

    return get_session(db_path, project_id, session_id)


def stop_session(
    db_path: Path,
    project_id: str,
    session_id: str,
    *,
    status: SessionStatus = SessionStatus.STOPPED,
) -> AgentSession:
    """
    Purpose: Mark a session stopped (or completed / halted_budget).
    Does not cancel scheduler jobs.
    """
    session = get_session(db_path, project_id, session_id)
    if session.status in (
        SessionStatus.STOPPED,
        SessionStatus.COMPLETED,
    ) and status == SessionStatus.STOPPED:
        return session

    now = _now_iso()
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE ai_sessions
            SET status = ?, updated_at = ?
            WHERE id = ? AND project_id = ?
            """,
            (status.value, now, session_id, project_id),
        )
        conn.commit()
    return get_session(db_path, project_id, session_id)


def resume_session(
    db_path: Path,
    project_id: str,
    session_id: str,
) -> AgentSession:
    """
    Purpose:
        Re-open a stopped/paused session with the same pin.
        Does not reset budgets. Fails if another session is already active.
    """
    session = get_session(db_path, project_id, session_id)
    if session.status == SessionStatus.ACTIVE:
        return session
    if session.status == SessionStatus.HALTED_BUDGET:
        raise SessionError(
            "Session is halted on budget. Run 'talos ai reset-budget' before resume."
        )
    if session.pinned_project_id != project_id:
        raise SessionError(
            "Session pin does not match the effective project; cannot resume."
        )

    existing = get_active_session(db_path, project_id)
    if existing is not None and existing.session_id != session_id:
        raise ActiveSessionExists(existing.session_id)

    now = _now_iso()
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE ai_sessions
            SET status = ?, updated_at = ?
            WHERE id = ? AND project_id = ?
            """,
            (SessionStatus.ACTIVE.value, now, session_id, project_id),
        )
        conn.commit()
    return get_session(db_path, project_id, session_id)


def update_session_usage(
    db_path: Path,
    project_id: str,
    session_id: str,
    usage: BudgetUsage,
    *,
    status: Optional[SessionStatus] = None,
) -> AgentSession:
    """Persist usage counters and optional status transition."""
    now = _now_iso()
    with _connect(db_path) as conn:
        if status is not None:
            conn.execute(
                """
                UPDATE ai_sessions
                SET usage_json = ?, status = ?, updated_at = ?
                WHERE id = ? AND project_id = ?
                """,
                (
                    json.dumps(usage.to_dict(), sort_keys=True),
                    status.value,
                    now,
                    session_id,
                    project_id,
                ),
            )
        else:
            conn.execute(
                """
                UPDATE ai_sessions
                SET usage_json = ?, updated_at = ?
                WHERE id = ? AND project_id = ?
                """,
                (
                    json.dumps(usage.to_dict(), sort_keys=True),
                    now,
                    session_id,
                    project_id,
                ),
            )
        conn.commit()
    return get_session(db_path, project_id, session_id)


def update_session_mode(
    db_path: Path,
    project_id: str,
    session_id: str,
    mode: AutonomyMode,
) -> AgentSession:
    """Update autonomy mode on an existing session."""
    now = _now_iso()
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE ai_sessions
            SET mode = ?, updated_at = ?
            WHERE id = ? AND project_id = ?
            """,
            (mode.value, now, session_id, project_id),
        )
        conn.commit()
    return get_session(db_path, project_id, session_id)


def reset_budget(
    db_path: Path,
    project_id: str,
    session_id: str,
) -> AgentSession:
    """
    Purpose:
        Zero usage counters. If status was halted_budget, return to active
        (only when no other active session exists for the project).
    """
    session = get_session(db_path, project_id, session_id)
    usage = BudgetUsage()
    new_status = session.status
    if session.status == SessionStatus.HALTED_BUDGET:
        existing = get_active_session(db_path, project_id)
        if existing is None or existing.session_id == session_id:
            new_status = SessionStatus.ACTIVE
    return update_session_usage(
        db_path, project_id, session_id, usage, status=new_status
    )


def resolve_session_id(
    db_path: Path,
    project_id: str,
    session_id: Optional[str],
) -> AgentSession:
    """
    Purpose:
        Resolve explicit session id or fall back to the active session.
    Raises:
        SessionNotFound / SessionError when none is available.
    """
    if session_id:
        return get_session(db_path, project_id, session_id)
    active = get_active_session(db_path, project_id)
    if active is None:
        raise SessionNotFound(
            "No active AI session. Run 'talos ai start' or pass a session id."
        )
    return active


# ------------------------------------------------------------------ #
# Project prefs (auto-aggressive ack)                                  #
# ------------------------------------------------------------------ #


def get_project_prefs(db_path: Path, project_id: str) -> dict[str, Any]:
    """Return ai_project_prefs row or empty defaults."""
    migrate_project_db(db_path)
    if not db_path.exists():
        return {
            "project_id": project_id,
            "auto_aggressive_ack_at": None,
            "auto_aggressive_ack_by": None,
            "updated_at": None,
        }
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM ai_project_prefs WHERE project_id = ?",
            (project_id,),
        ).fetchone()
    if row is None:
        return {
            "project_id": project_id,
            "auto_aggressive_ack_at": None,
            "auto_aggressive_ack_by": None,
            "updated_at": None,
        }
    return dict(row)


def has_auto_aggressive_ack(db_path: Path, project_id: str) -> bool:
    prefs = get_project_prefs(db_path, project_id)
    return bool(prefs.get("auto_aggressive_ack_at"))


def set_auto_aggressive_ack(
    db_path: Path,
    project_id: str,
    *,
    ack_by: str = "operator",
) -> None:
    """Persist once-per-project auto-aggressive acknowledgement."""
    migrate_project_db(db_path)
    now = _now_iso()
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO ai_project_prefs
                (project_id, auto_aggressive_ack_at, auto_aggressive_ack_by, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(project_id) DO UPDATE SET
                auto_aggressive_ack_at = excluded.auto_aggressive_ack_at,
                auto_aggressive_ack_by = excluded.auto_aggressive_ack_by,
                updated_at = excluded.updated_at
            """,
            (project_id, now, ack_by, now),
        )
        conn.commit()


def clear_auto_aggressive_ack(db_path: Path, project_id: str) -> None:
    """Revoke auto-aggressive acknowledgement for a project."""
    migrate_project_db(db_path)
    now = _now_iso()
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO ai_project_prefs
                (project_id, auto_aggressive_ack_at, auto_aggressive_ack_by, updated_at)
            VALUES (?, NULL, NULL, ?)
            ON CONFLICT(project_id) DO UPDATE SET
                auto_aggressive_ack_at = NULL,
                auto_aggressive_ack_by = NULL,
                updated_at = excluded.updated_at
            """,
            (project_id, now),
        )
        conn.commit()
