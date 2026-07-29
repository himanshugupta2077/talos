"""
Module: talos.ai.workflow.plans

Purpose:
    ExecutionPlan store and status state machine. Plans are created by
    PolicyValidator (via engine); this module only persists state transitions.
    Capability tokens are process-local; DB stores token hash only.

Dependencies: json, hashlib, sqlite3, talos.ai.models
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from talos.ai.models import Capability, ExecutionPlan
from talos.projects.db import migrate_project_db

# Terminal plan states (no further approve).
TERMINAL_PLAN_STATUSES = frozenset(
    {
        "executed",
        "failed",
        "denied",
        "superseded",
        "expired",
        "rejected",
        "interrupted",
    }
)

NON_TERMINAL_PLAN_STATUSES = frozenset(
    {
        "pending_approval",
        "authorized",
        "executing",
    }
)


class PlanStatus(str, Enum):
    PENDING_APPROVAL = "pending_approval"
    AUTHORIZED = "authorized"
    EXECUTING = "executing"
    EXECUTED = "executed"
    FAILED = "failed"
    DENIED = "denied"
    SUPERSEDED = "superseded"
    EXPIRED = "expired"
    REJECTED = "rejected"
    INTERRUPTED = "interrupted"


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def insert_plan(
    db_path: Path,
    plan: ExecutionPlan,
    *,
    status: str = PlanStatus.PENDING_APPROVAL.value,
    failure_reason: Optional[str] = None,
) -> None:
    """Persist a sealed plan row (token stored as hash only)."""
    migrate_project_db(db_path)
    caps = sorted(c.value for c in plan.required_capabilities)
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT INTO ai_execution_plans "
            "(id, suggestion_id, session_id, tool_name, arguments_json, "
            "capabilities_json, status, policy_meta_json, capability_token_hash, "
            "failure_reason, created_at, decided_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                plan.plan_id,
                plan.suggestion_id,
                plan.session_id,
                plan.tool_name,
                json.dumps(plan.arguments or {}, sort_keys=True, default=str),
                json.dumps(caps),
                status,
                json.dumps(plan.policy_meta or {}, sort_keys=True, default=str),
                hash_token(plan.capability_token) if plan.capability_token else None,
                failure_reason,
                plan.created_at or _now_iso(),
                None,
            ),
        )
        conn.commit()


def insert_rejected_plan(
    db_path: Path,
    *,
    plan_id: str,
    suggestion_id: str,
    session_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    reason: str,
) -> None:
    """Record a policy rejection linked to a suggestion (no capability token)."""
    migrate_project_db(db_path)
    now = _now_iso()
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT INTO ai_execution_plans "
            "(id, suggestion_id, session_id, tool_name, arguments_json, "
            "capabilities_json, status, policy_meta_json, capability_token_hash, "
            "failure_reason, created_at, decided_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                plan_id,
                suggestion_id,
                session_id,
                tool_name,
                json.dumps(arguments or {}, sort_keys=True, default=str),
                "[]",
                PlanStatus.REJECTED.value,
                "{}",
                None,
                reason,
                now,
                now,
            ),
        )
        conn.commit()


def get_plan_row(db_path: Path, plan_id: str) -> Optional[dict[str, Any]]:
    migrate_project_db(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM ai_execution_plans WHERE id = ?",
            (plan_id,),
        ).fetchone()
    if row is None:
        return None
    return dict(row)


def set_plan_status(
    db_path: Path,
    plan_id: str,
    status: str,
    *,
    failure_reason: Optional[str] = None,
    decided: bool = True,
) -> None:
    migrate_project_db(db_path)
    now = _now_iso() if decided else None
    with _connect(db_path) as conn:
        if decided:
            conn.execute(
                "UPDATE ai_execution_plans SET status = ?, failure_reason = COALESCE(?, failure_reason), "
                "decided_at = COALESCE(decided_at, ?) WHERE id = ?",
                (status, failure_reason, now, plan_id),
            )
        else:
            conn.execute(
                "UPDATE ai_execution_plans SET status = ?, failure_reason = COALESCE(?, failure_reason) "
                "WHERE id = ?",
                (status, failure_reason, plan_id),
            )
        conn.commit()


def list_plans(
    db_path: Path,
    session_id: str,
    *,
    status: Optional[str] = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    migrate_project_db(db_path)
    with _connect(db_path) as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM ai_execution_plans WHERE session_id = ? AND status = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (session_id, status, max(1, min(limit, 500))),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM ai_execution_plans WHERE session_id = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (session_id, max(1, min(limit, 500))),
            ).fetchall()
    return [dict(r) for r in rows]


def list_pending_plans(db_path: Path, session_id: str) -> list[dict[str, Any]]:
    return list_plans(
        db_path, session_id, status=PlanStatus.PENDING_APPROVAL.value, limit=200
    )


def latest_pending_for_suggestion(
    db_path: Path,
    suggestion_id: str,
) -> Optional[dict[str, Any]]:
    migrate_project_db(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM ai_execution_plans WHERE suggestion_id = ? "
            "AND status = ? ORDER BY created_at DESC LIMIT 1",
            (suggestion_id, PlanStatus.PENDING_APPROVAL.value),
        ).fetchone()
    return dict(row) if row else None


def deny_plans_for_suggestion(
    db_path: Path,
    suggestion_id: str,
    *,
    reason: Optional[str] = None,
) -> int:
    """Deny all non-terminal plans for a suggestion. Returns count updated."""
    migrate_project_db(db_path)
    now = _now_iso()
    with _connect(db_path) as conn:
        cur = conn.execute(
            "UPDATE ai_execution_plans SET status = ?, failure_reason = ?, decided_at = ? "
            "WHERE suggestion_id = ? AND status IN (?, ?, ?)",
            (
                PlanStatus.DENIED.value,
                reason or "denied by operator",
                now,
                suggestion_id,
                PlanStatus.PENDING_APPROVAL.value,
                PlanStatus.AUTHORIZED.value,
                PlanStatus.EXECUTING.value,
            ),
        )
        conn.commit()
        return int(cur.rowcount or 0)


def plan_row_to_public(row: dict[str, Any]) -> dict[str, Any]:
    """Serialize a plan row without token hash for CLI."""
    try:
        args = json.loads(row.get("arguments_json") or "{}")
    except json.JSONDecodeError:
        args = {}
    try:
        caps = json.loads(row.get("capabilities_json") or "[]")
    except json.JSONDecodeError:
        caps = []
    try:
        meta = json.loads(row.get("policy_meta_json") or "{}")
    except json.JSONDecodeError:
        meta = {}
    return {
        "plan_id": row.get("id"),
        "suggestion_id": row.get("suggestion_id"),
        "session_id": row.get("session_id"),
        "tool_name": row.get("tool_name"),
        "arguments": args,
        "capabilities": caps,
        "status": row.get("status"),
        "policy_meta": meta,
        "failure_reason": row.get("failure_reason"),
        "created_at": row.get("created_at"),
        "decided_at": row.get("decided_at"),
    }


def capabilities_from_json(raw: str) -> frozenset[Capability]:
    try:
        items = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return frozenset()
    out: set[Capability] = set()
    for item in items:
        try:
            out.add(Capability(item))
        except ValueError:
            continue
    return frozenset(out)
