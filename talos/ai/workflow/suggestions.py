"""
Module: talos.ai.workflow.suggestions

Purpose:
    Immutable ActionSuggestion store. INSERT-only for tool_name / arguments;
    never UPDATE arguments_json after insert.

Dependencies: json, sqlite3, talos.ai.models, talos.projects.db
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from talos.ai.models import ActionSuggestion
from talos.projects.db import migrate_project_db


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _canonical_args(arguments: dict[str, Any]) -> str:
    return json.dumps(arguments or {}, sort_keys=True, separators=(",", ":"), default=str)


def _row_to_suggestion(row: sqlite3.Row) -> ActionSuggestion:
    try:
        args = json.loads(row["arguments_json"] or "{}")
    except json.JSONDecodeError:
        args = {}
    if not isinstance(args, dict):
        args = {}
    return ActionSuggestion(
        suggestion_id=row["id"],
        session_id=row["session_id"],
        tool_name=row["tool_name"],
        arguments=args,
        reason=row["rationale"],
        cli_preview=row["cli_preview"],
        created_at=row["created_at"] or "",
        display_risk=row["display_risk"],
    )


def record_suggestions(
    db_path: Path,
    suggestions: list[ActionSuggestion],
) -> list[ActionSuggestion]:
    """
    Purpose:
        Persist immutable suggestions (append-only). Returns the same list.
    Side effects:
        INSERT into ai_suggestions; migrate_project_db.
    """
    if not suggestions:
        return []
    migrate_project_db(db_path)
    with _connect(db_path) as conn:
        for s in suggestions:
            created = s.created_at or _now_iso()
            conn.execute(
                "INSERT INTO ai_suggestions "
                "(id, session_id, tool_name, arguments_json, rationale, "
                "cli_preview, display_risk, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    s.suggestion_id,
                    s.session_id,
                    s.tool_name,
                    _canonical_args(s.arguments),
                    s.reason,
                    s.cli_preview,
                    s.display_risk,
                    created,
                ),
            )
        conn.commit()
    return suggestions


def get_suggestion(
    db_path: Path,
    suggestion_id: str,
    *,
    session_id: Optional[str] = None,
) -> Optional[ActionSuggestion]:
    migrate_project_db(db_path)
    with _connect(db_path) as conn:
        if session_id:
            row = conn.execute(
                "SELECT * FROM ai_suggestions WHERE id = ? AND session_id = ?",
                (suggestion_id, session_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM ai_suggestions WHERE id = ?",
                (suggestion_id,),
            ).fetchone()
    return _row_to_suggestion(row) if row else None


def list_suggestions(
    db_path: Path,
    session_id: str,
    *,
    limit: int = 100,
) -> list[ActionSuggestion]:
    migrate_project_db(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM ai_suggestions WHERE session_id = ? "
            "ORDER BY created_at DESC LIMIT ?",
            (session_id, max(1, min(limit, 500))),
        ).fetchall()
    return [_row_to_suggestion(r) for r in rows]
