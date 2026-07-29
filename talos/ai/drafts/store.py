"""
Module: talos.ai.drafts.store

Purpose:
    Persist ai_draft_findings and promote to real findings via create_finding.
    Never confirms findings; promote leaves status TRIAGING.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from talos.findings.db import (
    add_evidence,
    add_timeline_event,
    create_finding,
    update_finding_notes,
)
from talos.findings.model import (
    ATTACK_DISPLAY,
    EVIDENCE_TYPE_ANALYST_NOTE,
    EVIDENCE_TYPE_ENDPOINT,
    EVIDENCE_TYPE_ORIGINAL_FLOW,
    TIMELINE_ACTOR_ANALYST,
)
from talos.projects.db import migrate_project_db

ALLOWED_ATTACK_TYPES: frozenset[str] = frozenset(ATTACK_DISPLAY.keys())

MAX_TITLE = 200
MAX_DESCRIPTION = 8000

STATUS_DRAFT = "draft"
STATUS_PROMOTED = "promoted"
STATUS_REJECTED = "rejected"


class DraftsError(Exception):
    """Draft validation or promote error."""


@dataclass
class DraftFinding:
    id: str
    project_id: str
    session_id: Optional[str]
    title: str
    description: str
    vulnerability_class: str
    attack_type: str
    endpoint_id: str
    evidence_refs: dict[str, Any]
    confidence: float
    cluster_key: Optional[str]
    status: str
    promoted_finding_id: Optional[str]
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "session_id": self.session_id,
            "title": self.title,
            "description": self.description,
            "vulnerability_class": self.vulnerability_class,
            "attack_type": self.attack_type,
            "endpoint_id": self.endpoint_id,
            "evidence_refs": dict(self.evidence_refs),
            "confidence": self.confidence,
            "cluster_key": self.cluster_key,
            "status": self.status,
            "promoted_finding_id": self.promoted_finding_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _row_to_draft(row: sqlite3.Row) -> DraftFinding:
    try:
        refs = json.loads(row["evidence_refs_json"] or "{}")
    except json.JSONDecodeError:
        refs = {}
    if not isinstance(refs, dict):
        refs = {}
    return DraftFinding(
        id=row["id"],
        project_id=row["project_id"],
        session_id=row["session_id"],
        title=row["title"] or "",
        description=row["description"] or "",
        vulnerability_class=row["vulnerability_class"] or "",
        attack_type=row["attack_type"] or "ai_draft",
        endpoint_id=row["endpoint_id"] or "",
        evidence_refs=refs,
        confidence=float(row["confidence"] or 0.0),
        cluster_key=row["cluster_key"],
        status=row["status"] or STATUS_DRAFT,
        promoted_finding_id=row["promoted_finding_id"],
        created_at=row["created_at"] or "",
        updated_at=row["updated_at"] or "",
    )


def _endpoint_exists(conn: sqlite3.Connection, project_id: str, endpoint_id: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM endpoints WHERE id = ? AND project_id = ? LIMIT 1",
        (endpoint_id, project_id),
    ).fetchone()
    return row is not None


def _normalize_evidence_refs(
    refs: Any, endpoint_id: str
) -> dict[str, Any]:
    if refs is None:
        refs = {}
    if not isinstance(refs, dict):
        raise DraftsError("evidence_refs must be an object")
    endpoint_ids = refs.get("endpoint_ids") or []
    if not isinstance(endpoint_ids, list):
        raise DraftsError("evidence_refs.endpoint_ids must be an array")
    eids = [str(x) for x in endpoint_ids if x]
    if endpoint_id not in eids:
        eids.append(endpoint_id)
    out: dict[str, Any] = {
        "endpoint_ids": eids,
        "flow_ids": [str(x) for x in (refs.get("flow_ids") or []) if x][:50],
        "finding_ids": [str(x) for x in (refs.get("finding_ids") or []) if x][:50],
        "param_uuids": [str(x) for x in (refs.get("param_uuids") or []) if x][:50],
    }
    return out


def create_draft(
    db_path: Path,
    project_id: str,
    *,
    title: str,
    description: str,
    endpoint_id: str,
    attack_type: str = "ai_draft",
    vulnerability_class: str = "",
    evidence_refs: Optional[dict[str, Any]] = None,
    confidence: float = 0.5,
    cluster_key: Optional[str] = None,
    session_id: Optional[str] = None,
) -> DraftFinding:
    migrate_project_db(db_path)
    title = (title or "").strip()
    description = (description or "").strip()
    endpoint_id = (endpoint_id or "").strip()
    attack_type = (attack_type or "ai_draft").strip()
    if not title:
        raise DraftsError("title is required")
    if len(title) > MAX_TITLE:
        raise DraftsError(f"title exceeds {MAX_TITLE} chars")
    if not description:
        raise DraftsError("description is required")
    if len(description) > MAX_DESCRIPTION:
        raise DraftsError(f"description exceeds {MAX_DESCRIPTION} chars")
    if not endpoint_id:
        raise DraftsError("endpoint_id is required")
    if attack_type not in ALLOWED_ATTACK_TYPES:
        raise DraftsError(
            f"unknown attack_type '{attack_type}'. "
            f"Allowed: {', '.join(sorted(ALLOWED_ATTACK_TYPES))}"
        )
    try:
        conf = float(confidence)
    except (TypeError, ValueError) as exc:
        raise DraftsError("confidence must be a number") from exc
    conf = max(0.0, min(1.0, conf))
    refs = _normalize_evidence_refs(evidence_refs, endpoint_id)

    now = _now_iso()
    draft_id = str(uuid.uuid4())
    with _connect(db_path) as conn:
        if not _endpoint_exists(conn, project_id, endpoint_id):
            raise DraftsError(f"endpoint not found in project: {endpoint_id}")
        conn.execute(
            """
            INSERT INTO ai_draft_findings (
                id, project_id, session_id, title, description,
                vulnerability_class, attack_type, endpoint_id,
                evidence_refs_json, confidence, cluster_key, status,
                promoted_finding_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
            """,
            (
                draft_id,
                project_id,
                session_id,
                title,
                description,
                (vulnerability_class or "").strip()[:128],
                attack_type,
                endpoint_id,
                json.dumps(refs, sort_keys=True),
                conf,
                (cluster_key or None),
                STATUS_DRAFT,
                now,
                now,
            ),
        )
        conn.commit()
    draft = get_draft(db_path, project_id, draft_id)
    assert draft is not None
    return draft


def get_draft(
    db_path: Path, project_id: str, draft_id: str
) -> Optional[DraftFinding]:
    migrate_project_db(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT * FROM ai_draft_findings
            WHERE id = ? AND project_id = ?
            """,
            (draft_id, project_id),
        ).fetchone()
    return _row_to_draft(row) if row else None


def list_drafts(
    db_path: Path,
    project_id: str,
    *,
    status: Optional[str] = None,
    limit: int = 50,
) -> list[DraftFinding]:
    migrate_project_db(db_path)
    limit = max(1, min(int(limit), 200))
    sql = "SELECT * FROM ai_draft_findings WHERE project_id = ?"
    params: list[Any] = [project_id]
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY updated_at DESC LIMIT ?"
    params.append(limit)
    with _connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_draft(r) for r in rows]


def reject_draft(db_path: Path, project_id: str, draft_id: str) -> DraftFinding:
    migrate_project_db(db_path)
    draft = get_draft(db_path, project_id, draft_id)
    if draft is None:
        raise DraftsError(f"draft not found: {draft_id}")
    if draft.status != STATUS_DRAFT:
        raise DraftsError(f"draft status is {draft.status}, expected draft")
    now = _now_iso()
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE ai_draft_findings
            SET status = ?, updated_at = ?
            WHERE id = ? AND project_id = ?
            """,
            (STATUS_REJECTED, now, draft_id, project_id),
        )
        conn.commit()
    out = get_draft(db_path, project_id, draft_id)
    assert out is not None
    return out


def promote_draft(
    db_path: Path,
    project_id: str,
    draft_id: str,
    *,
    attack_type: Optional[str] = None,
) -> dict[str, Any]:
    """
    Purpose:
        Promote draft → create_finding (TRIAGING) + notes + timeline + evidence.
        Never confirms. Actor is analyst (operator authority).
    Output:
        {draft, finding_id}
    """
    migrate_project_db(db_path)
    draft = get_draft(db_path, project_id, draft_id)
    if draft is None:
        raise DraftsError(f"draft not found: {draft_id}")
    if draft.status != STATUS_DRAFT:
        raise DraftsError(f"draft status is {draft.status}, expected draft")

    atype = (attack_type or draft.attack_type or "ai_draft").strip()
    if atype not in ALLOWED_ATTACK_TYPES:
        raise DraftsError(f"unknown attack_type '{atype}'")

    with _connect(db_path) as conn:
        if not _endpoint_exists(conn, project_id, draft.endpoint_id):
            raise DraftsError(
                f"endpoint no longer exists: {draft.endpoint_id}"
            )
        refs = draft.evidence_refs or {}
        eids = refs.get("endpoint_ids") or []
        if draft.endpoint_id not in eids:
            raise DraftsError(
                "evidence_refs.endpoint_ids must contain draft endpoint_id"
            )

    finding_id = create_finding(
        db_path,
        project_id=project_id,
        attack_type=atype,
        verdict="AI_DRAFT_PROMOTED",
        endpoint_id=draft.endpoint_id,
        title=draft.title,
        cluster_key=draft.cluster_key,
    )
    update_finding_notes(db_path, finding_id, draft.description)
    add_timeline_event(
        db_path,
        finding_id,
        event=(
            f"Promoted from AI draft {draft.id} "
            f"(confidence={draft.confidence})"
        ),
        actor=TIMELINE_ACTOR_ANALYST,
    )
    add_evidence(
        db_path,
        finding_id,
        EVIDENCE_TYPE_ENDPOINT,
        draft.endpoint_id,
        "AI draft endpoint",
        {"source": "ai_draft", "draft_id": draft.id},
    )
    for flow_id in (refs.get("flow_ids") or [])[:20]:
        add_evidence(
            db_path,
            finding_id,
            EVIDENCE_TYPE_ORIGINAL_FLOW,
            str(flow_id),
            "AI draft flow ref",
            {"source": "ai_draft"},
        )
    # Optional analyst note with vulnerability_class / confidence
    add_evidence(
        db_path,
        finding_id,
        EVIDENCE_TYPE_ANALYST_NOTE,
        None,
        "AI draft metadata",
        {
            "vulnerability_class": draft.vulnerability_class,
            "confidence": draft.confidence,
            "draft_id": draft.id,
            "attack_type": atype,
        },
    )

    now = _now_iso()
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE ai_draft_findings
            SET status = ?, promoted_finding_id = ?, attack_type = ?,
                updated_at = ?
            WHERE id = ? AND project_id = ?
            """,
            (STATUS_PROMOTED, finding_id, atype, now, draft_id, project_id),
        )
        conn.commit()

    updated = get_draft(db_path, project_id, draft_id)
    assert updated is not None
    return {"draft": updated.to_dict(), "finding_id": finding_id}
