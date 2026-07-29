"""
Module: talos.ai.workflow.task_tree

Purpose:
    Pentesting Task Tree (PTT) — hierarchical engagement nodes for planner
    frontier packing. Owned by Workflow Engine (not the planner).
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from talos.projects.db import migrate_project_db

OPEN_STATUSES = frozenset({"pending", "in_progress", "blocked"})
ALL_STATUSES = frozenset(
    {"pending", "in_progress", "blocked", "done", "cancelled"}
)
FRONTIER_CAP = 20


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@dataclass
class TaskNode:
    node_id: str
    session_id: str
    project_id: str
    parent_id: Optional[str]
    title: str
    status: str
    hypothesis: Optional[str]
    evidence_refs: dict[str, Any]
    suggested_tools: list[str]
    priority: int
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "session_id": self.session_id,
            "project_id": self.project_id,
            "parent_id": self.parent_id,
            "title": self.title,
            "status": self.status,
            "hypothesis": self.hypothesis,
            "evidence_refs": self.evidence_refs,
            "suggested_tools": self.suggested_tools,
            "priority": self.priority,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def _row_to_node(row: sqlite3.Row) -> TaskNode:
    try:
        evidence = json.loads(row["evidence_refs_json"] or "{}")
    except json.JSONDecodeError:
        evidence = {}
    if not isinstance(evidence, dict):
        evidence = {}
    try:
        tools = json.loads(row["suggested_tools_json"] or "[]")
    except json.JSONDecodeError:
        tools = []
    if not isinstance(tools, list):
        tools = []
    return TaskNode(
        node_id=row["node_id"],
        session_id=row["session_id"],
        project_id=row["project_id"],
        parent_id=row["parent_id"],
        title=row["title"] or "",
        status=row["status"] or "pending",
        hypothesis=row["hypothesis"],
        evidence_refs=evidence,
        suggested_tools=[str(t) for t in tools],
        priority=int(row["priority"] or 0),
        created_at=row["created_at"] or "",
        updated_at=row["updated_at"] or "",
    )


def list_nodes(
    db_path: Path,
    session_id: str,
    *,
    status: Optional[str] = None,
    limit: int = 100,
) -> list[TaskNode]:
    migrate_project_db(db_path)
    with _connect(db_path) as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM ai_task_nodes WHERE session_id = ? AND status = ? "
                "ORDER BY priority DESC, updated_at DESC LIMIT ?",
                (session_id, status, max(1, min(limit, 500))),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM ai_task_nodes WHERE session_id = ? "
                "ORDER BY priority DESC, updated_at DESC LIMIT ?",
                (session_id, max(1, min(limit, 500))),
            ).fetchall()
    return [_row_to_node(r) for r in rows]


def frontier(
    db_path: Path,
    session_id: str,
    *,
    cap: int = FRONTIER_CAP,
) -> list[dict[str, Any]]:
    """
    Purpose:
        Open high-priority nodes for planner packing (cap 20 by design).
    """
    migrate_project_db(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM ai_task_nodes WHERE session_id = ? "
            "AND status IN ('pending', 'in_progress', 'blocked') "
            "ORDER BY priority DESC, updated_at DESC LIMIT ?",
            (session_id, max(1, min(cap, FRONTIER_CAP))),
        ).fetchall()
    return [_row_to_node(r).to_dict() for r in rows]


def get_node(db_path: Path, node_id: str) -> Optional[TaskNode]:
    migrate_project_db(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM ai_task_nodes WHERE node_id = ?",
            (node_id,),
        ).fetchone()
    return _row_to_node(row) if row else None


def upsert_node(
    db_path: Path,
    *,
    session_id: str,
    project_id: str,
    title: str,
    node_id: Optional[str] = None,
    parent_id: Optional[str] = None,
    status: str = "pending",
    hypothesis: Optional[str] = None,
    evidence_refs: Optional[dict[str, Any]] = None,
    suggested_tools: Optional[list[str]] = None,
    priority: int = 0,
) -> TaskNode:
    """
    Purpose:
        Create or update a PTT node. Existing node_id must belong to session.
    """
    migrate_project_db(db_path)
    status_clean = (status or "pending").lower()
    if status_clean not in ALL_STATUSES:
        raise ValueError(
            f"Invalid task status '{status}'. Valid: {', '.join(sorted(ALL_STATUSES))}"
        )
    title_clean = (title or "").strip()
    if not title_clean:
        raise ValueError("Task title is required")
    if len(title_clean) > 500:
        title_clean = title_clean[:500]

    now = _now_iso()
    evidence = evidence_refs if isinstance(evidence_refs, dict) else {}
    tools = [str(t) for t in (suggested_tools or [])][:20]

    with _connect(db_path) as conn:
        if node_id:
            existing = conn.execute(
                "SELECT * FROM ai_task_nodes WHERE node_id = ? AND session_id = ?",
                (node_id, session_id),
            ).fetchone()
            if existing is None:
                raise ValueError(f"Task node not found in session: {node_id}")
            conn.execute(
                "UPDATE ai_task_nodes SET parent_id = ?, title = ?, status = ?, "
                "hypothesis = ?, evidence_refs_json = ?, suggested_tools_json = ?, "
                "priority = ?, updated_at = ? WHERE node_id = ?",
                (
                    parent_id if parent_id is not None else existing["parent_id"],
                    title_clean,
                    status_clean,
                    hypothesis if hypothesis is not None else existing["hypothesis"],
                    json.dumps(evidence, sort_keys=True, default=str),
                    json.dumps(tools),
                    int(priority),
                    now,
                    node_id,
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM ai_task_nodes WHERE node_id = ?", (node_id,)
            ).fetchone()
            return _row_to_node(row)

        new_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO ai_task_nodes "
            "(node_id, session_id, project_id, parent_id, title, status, "
            "hypothesis, evidence_refs_json, suggested_tools_json, priority, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                new_id,
                session_id,
                project_id,
                parent_id,
                title_clean,
                status_clean,
                hypothesis,
                json.dumps(evidence, sort_keys=True, default=str),
                json.dumps(tools),
                int(priority),
                now,
                now,
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM ai_task_nodes WHERE node_id = ?", (new_id,)
        ).fetchone()
        return _row_to_node(row)
