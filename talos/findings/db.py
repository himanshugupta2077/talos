"""
Module: talos.findings.db

Purpose:
    All SQLite CRUD operations for the Findings subsystem.
    Operates on the per-project talos.db database.

    Tables owned (defined in talos.projects.db DDL):
        findings              — one row per vulnerability instance.
        finding_evidence      — evidence references attached to findings.
        finding_timeline      — immutable ordered event log per finding.
        finding_groups        — user-created named collections.
        finding_group_members — many-to-many findings ↔ groups.

    Finding relationships (PRIMARY / LINKED):
        relation_type      — 'PRIMARY' | 'LINKED'
        parent_finding_id  — set only for LINKED; always points at PRIMARY
        cluster_key        — deterministic cluster identity (e.g. UNAUTH:<ep>)

    A partial unique index enforces at most one PRIMARY per cluster_key.
    create_finding() uses a transaction + IntegrityError retry so concurrent
    workers cannot create duplicate PRIMARY findings for the same cluster.

    Every function accepts a db_path and opens+closes its own connection
    (same pattern as the rest of the codebase).  No persistent connections.

Dependencies: sqlite3, uuid, datetime, json, pathlib
              talos.findings.model (status / relation / evidence-type constants)
Data flow:
    talos.findings.creator  → create_finding, add_evidence, add_timeline_event
    talos.findings.cli      → list_findings, get_finding, update_finding_status,
                              create_group, add_to_group, …
Side effects:
    All write functions commit to the SQLite database.
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from talos.findings.model import (
    FINDING_STATUS_TRIAGING,
    FINDING_STATUS_DUPLICATE,
    RELATION_TYPE_PRIMARY,
    RELATION_TYPE_LINKED,
    TIMELINE_ACTOR_SYSTEM,
    TIMELINE_ACTOR_ANALYST,
)


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _now() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _connect(db_path: Path) -> sqlite3.Connection:
    """Open a WAL-mode connection with foreign keys enforced."""
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def _row_to_dict(row: sqlite3.Row) -> dict:
    """Convert a Row to a plain dict, filling relationship defaults for safety."""
    d = dict(row)
    d.setdefault("relation_type", RELATION_TYPE_PRIMARY)
    d.setdefault("parent_finding_id", None)
    d.setdefault("cluster_key", None)
    return d


# ------------------------------------------------------------------ #
# Cluster identity                                                     #
# ------------------------------------------------------------------ #

def build_cluster_key(
    attack_module: str,
    endpoint_id: Optional[str],
    attacker_role_id: Optional[str] = None,
    target_role_id: Optional[str] = None,
) -> Optional[str]:
    """
    Purpose:
        Build a deterministic cluster identity for finding grouping.
        Attack-specific creators own the key shape; the generic DB layer
        only stores and enforces PRIMARY uniqueness on the key.

    Cluster shapes:
        unauth     → UNAUTH:<endpoint_id>
        auth_test  → AUTH_TEST:<endpoint_id>
        bac        → BAC:<endpoint_id>:<attacker_role_id>:<target_role_id>
        other      → <MODULE>:<endpoint_id>

    Input:
        attack_module    — 'bac' | 'auth_test' | 'unauth' | …
        endpoint_id      — target endpoint UUID; if missing, returns None
                           (finding is created as standalone PRIMARY).
        attacker_role_id — BAC only.
        target_role_id   — BAC only.
    Output:
        cluster_key string, or None when clustering is not possible.
    """
    if not endpoint_id:
        return None

    module = (attack_module or "").lower()
    if module == "unauth":
        return f"UNAUTH:{endpoint_id}"
    if module == "auth_test":
        return f"AUTH_TEST:{endpoint_id}"
    if module == "bac":
        ar = attacker_role_id or "-"
        tr = target_role_id or "-"
        return f"BAC:{endpoint_id}:{ar}:{tr}"
    return f"{module.upper()}:{endpoint_id}"


# ------------------------------------------------------------------ #
# Finding CRUD                                                         #
# ------------------------------------------------------------------ #

def create_finding(
    db_path: Path,
    project_id: str,
    attack_type: str,
    verdict: str,
    endpoint_id: Optional[str],
    title: str,
    cluster_key: Optional[str] = None,
) -> str:
    """
    Purpose:
        Insert a new finding row in TRIAGING status, assigning PRIMARY or
        LINKED based on the cluster_key.

    Cluster behaviour:
        - If cluster_key is None: always create a standalone PRIMARY.
        - If a PRIMARY already exists for cluster_key: create LINKED child.
        - If no PRIMARY exists: create PRIMARY.
        - On concurrent PRIMARY race (unique index violation): re-fetch the
          winning PRIMARY and create LINKED instead.

    Input:
        db_path      — path to talos.db.
        project_id   — project UUID slug.
        attack_type  — 'bac' | 'auth_test' | 'unauth'.
        verdict      — verdict string that triggered creation.
        endpoint_id  — FK to endpoints.id; may be None.
        title        — short human-readable summary.
        cluster_key  — deterministic cluster identity; may be None.
    Output:
        New finding UUID (str).
    Side effects:
        Inserts into findings table; commits.
    """
    now = _now()

    with _connect(db_path) as conn:
        parent_id: Optional[str] = None
        relation_type = RELATION_TYPE_PRIMARY

        if cluster_key:
            existing = conn.execute(
                """
                SELECT id FROM findings
                WHERE cluster_key = ? AND relation_type = ?
                LIMIT 1
                """,
                (cluster_key, RELATION_TYPE_PRIMARY),
            ).fetchone()
            if existing:
                parent_id = existing["id"]
                relation_type = RELATION_TYPE_LINKED

        finding_id = str(uuid.uuid4())
        try:
            conn.execute(
                """
                INSERT INTO findings
                    (id, project_id, attack_type, verdict, endpoint_id, status,
                     duplicate_of, relation_type, parent_finding_id, cluster_key,
                     created_at, updated_at, title, notes)
                VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, '')
                """,
                (
                    finding_id, project_id, attack_type, verdict,
                    endpoint_id, FINDING_STATUS_TRIAGING,
                    relation_type, parent_id, cluster_key,
                    now, now, title,
                ),
            )
        except sqlite3.IntegrityError:
            # Race: another worker created the PRIMARY for this cluster.
            # Fall back to LINKED under the newly created PRIMARY.
            if not cluster_key:
                raise
            primary = conn.execute(
                """
                SELECT id FROM findings
                WHERE cluster_key = ? AND relation_type = ?
                LIMIT 1
                """,
                (cluster_key, RELATION_TYPE_PRIMARY),
            ).fetchone()
            if primary is None:
                raise
            finding_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO findings
                    (id, project_id, attack_type, verdict, endpoint_id, status,
                     duplicate_of, relation_type, parent_finding_id, cluster_key,
                     created_at, updated_at, title, notes)
                VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, '')
                """,
                (
                    finding_id, project_id, attack_type, verdict,
                    endpoint_id, FINDING_STATUS_TRIAGING,
                    RELATION_TYPE_LINKED, primary["id"], cluster_key,
                    now, now, title,
                ),
            )

    return finding_id


def get_finding(db_path: Path, finding_id: str) -> Optional[dict]:
    """
    Purpose:
        Fetch a single finding by UUID.
    Output:
        Dict of all finding columns, or None if not found.
    """
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
    return _row_to_dict(row) if row else None


def get_primary_by_cluster(db_path: Path, cluster_key: str) -> Optional[dict]:
    """
    Purpose:
        Fetch the PRIMARY finding for a cluster_key, if any.
    """
    if not cluster_key:
        return None
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT * FROM findings
            WHERE cluster_key = ? AND relation_type = ?
            LIMIT 1
            """,
            (cluster_key, RELATION_TYPE_PRIMARY),
        ).fetchone()
    return _row_to_dict(row) if row else None


def list_findings(
    db_path: Path,
    project_id: str,
    status: Optional[str] = None,
    relation_type: Optional[str] = None,
) -> list[dict]:
    """
    Purpose:
        Return findings for a project, optionally filtered by status and/or
        relation_type (PRIMARY / LINKED).

    Input:
        status         — if supplied, only findings with this status.
        relation_type  — if supplied, only findings with this relation_type.
                         Callers that want the default main-list view should
                         pass RELATION_TYPE_PRIMARY.
    Output:
        List of finding dicts ordered by created_at DESC.
        Each PRIMARY row may include linked_count (number of LINKED children).
    """
    clauses = ["project_id = ?"]
    params: list = [project_id]
    if status:
        clauses.append("status = ?")
        params.append(status)
    if relation_type:
        clauses.append("relation_type = ?")
        params.append(relation_type)

    where = " AND ".join(clauses)
    with _connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM findings WHERE {where} ORDER BY created_at DESC",
            params,
        ).fetchall()
        results = [_row_to_dict(r) for r in rows]

        # Attach linked_count for PRIMARY rows shown in list views.
        primary_ids = [
            r["id"] for r in results
            if r.get("relation_type", RELATION_TYPE_PRIMARY) == RELATION_TYPE_PRIMARY
        ]
        counts: dict[str, int] = {}
        if primary_ids:
            placeholders = ",".join("?" * len(primary_ids))
            count_rows = conn.execute(
                f"""
                SELECT parent_finding_id, COUNT(*) AS cnt
                FROM findings
                WHERE parent_finding_id IN ({placeholders})
                  AND relation_type = ?
                GROUP BY parent_finding_id
                """,
                (*primary_ids, RELATION_TYPE_LINKED),
            ).fetchall()
            counts = {r["parent_finding_id"]: r["cnt"] for r in count_rows}

    for r in results:
        if r.get("relation_type", RELATION_TYPE_PRIMARY) == RELATION_TYPE_PRIMARY:
            r["linked_count"] = counts.get(r["id"], 0)
        else:
            r["linked_count"] = 0
    return results


def list_linked_findings(db_path: Path, parent_finding_id: str) -> list[dict]:
    """
    Purpose:
        Return all LINKED findings whose parent is parent_finding_id.
    Output:
        List of finding dicts ordered by created_at ASC (cluster order).
    """
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT * FROM findings
            WHERE parent_finding_id = ? AND relation_type = ?
            ORDER BY created_at ASC
            """,
            (parent_finding_id, RELATION_TYPE_LINKED),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def count_linked_findings(db_path: Path, parent_finding_id: str) -> int:
    """Return the number of LINKED children of a PRIMARY finding."""
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS cnt FROM findings
            WHERE parent_finding_id = ? AND relation_type = ?
            """,
            (parent_finding_id, RELATION_TYPE_LINKED),
        ).fetchone()
    return int(row["cnt"]) if row else 0


def update_finding_status(
    db_path: Path,
    finding_id: str,
    new_status: str,
    duplicate_of: Optional[str] = None,
) -> bool:
    """
    Purpose:
        Update the status (and optionally duplicate_of) of a finding.
    Input:
        new_status   — one of FINDING_STATUS_* constants.
        duplicate_of — UUID of the canonical finding; required when
                       new_status == FINDING_STATUS_DUPLICATE.
    Output:
        True if a row was updated; False if finding_id not found.
    Side effects:
        Updates findings.status, findings.duplicate_of, findings.updated_at.
        Does NOT cascade to linked findings — status is independent by default.
    """
    now = _now()
    with _connect(db_path) as conn:
        cur = conn.execute(
            """
            UPDATE findings
            SET status = ?, duplicate_of = ?, updated_at = ?
            WHERE id = ?
            """,
            (new_status, duplicate_of, now, finding_id),
        )
    return cur.rowcount > 0


def update_finding_notes(db_path: Path, finding_id: str, notes: str) -> bool:
    """
    Purpose:
        Replace the free-form notes field on a finding.
    Output:
        True if updated; False if not found.
    """
    now = _now()
    with _connect(db_path) as conn:
        cur = conn.execute(
            "UPDATE findings SET notes = ?, updated_at = ? WHERE id = ?",
            (notes, now, finding_id),
        )
    return cur.rowcount > 0


# ------------------------------------------------------------------ #
# Evidence CRUD                                                        #
# ------------------------------------------------------------------ #

def add_evidence(
    db_path: Path,
    finding_id: str,
    evidence_type: str,
    reference_id: Optional[str],
    label: str,
    data: Optional[dict] = None,
) -> str:
    """
    Purpose:
        Attach one evidence item to a finding.
    Input:
        finding_id    — UUID of the parent finding.
        evidence_type — one of EVIDENCE_TYPE_* constants.
        reference_id  — UUID of the referenced DB object (may be None).
        label         — short human-readable description.
        data          — optional structured dict stored as JSON.
    Output:
        New evidence row UUID.
    Side effects:
        Inserts into finding_evidence; commits.
    """
    eid = str(uuid.uuid4())
    now = _now()
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO finding_evidence
                (id, finding_id, evidence_type, reference_id, label, data, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                eid, finding_id, evidence_type, reference_id,
                label, json.dumps(data or {}), now,
            ),
        )
    return eid


def list_evidence(db_path: Path, finding_id: str) -> list[dict]:
    """
    Purpose:
        Return all evidence items for a finding ordered by creation time.
    """
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM finding_evidence WHERE finding_id = ? ORDER BY created_at ASC",
            (finding_id,),
        ).fetchall()
    return [dict(r) for r in rows]


# ------------------------------------------------------------------ #
# Timeline CRUD                                                        #
# ------------------------------------------------------------------ #

def add_timeline_event(
    db_path: Path,
    finding_id: str,
    event: str,
    actor: str = TIMELINE_ACTOR_SYSTEM,
    occurred_at: Optional[str] = None,
) -> str:
    """
    Purpose:
        Append an immutable event to a finding's timeline.
    Input:
        finding_id  — UUID of the parent finding.
        event       — human-readable event description.
        actor       — TIMELINE_ACTOR_SYSTEM | TIMELINE_ACTOR_ANALYST.
        occurred_at — ISO-8601 timestamp to record the event under; defaults to
                      "now".  Used when reconstructing a finding's timeline from
                      real historical timestamps (flow captured_at, job
                      started_at, etc.) instead of the time the finding itself
                      was created.
    Output:
        New timeline row UUID.
    Side effects:
        Inserts into finding_timeline; commits.
    """
    tid = str(uuid.uuid4())
    when = occurred_at or _now()
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO finding_timeline (id, finding_id, event, actor, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (tid, finding_id, event, actor, when),
        )
    return tid


def list_timeline(db_path: Path, finding_id: str) -> list[dict]:
    """
    Purpose:
        Return all timeline events for a finding in chronological order.
    """
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM finding_timeline WHERE finding_id = ? ORDER BY created_at ASC",
            (finding_id,),
        ).fetchall()
    return [dict(r) for r in rows]


# ------------------------------------------------------------------ #
# Finding Groups CRUD                                                  #
# ------------------------------------------------------------------ #

def create_group(db_path: Path, project_id: str, name: str) -> str:
    """
    Purpose:
        Create a new named finding group.
    Input:
        name — human-readable group label; must be unique within the project.
    Output:
        New group UUID.
    Raises:
        sqlite3.IntegrityError if a group with the same name already exists.
    Side effects:
        Inserts into finding_groups; commits.
    """
    gid = str(uuid.uuid4())
    now = _now()
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT INTO finding_groups (id, project_id, name, created_at) VALUES (?, ?, ?, ?)",
            (gid, project_id, name, now),
        )
    return gid


def get_group(db_path: Path, group_id: str) -> Optional[dict]:
    """Return a group dict by UUID, or None."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM finding_groups WHERE id = ?", (group_id,)
        ).fetchone()
    return dict(row) if row else None


def get_group_by_name(db_path: Path, project_id: str, name: str) -> Optional[dict]:
    """Return a group dict by project + name, or None."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM finding_groups WHERE project_id = ? AND name = ?",
            (project_id, name),
        ).fetchone()
    return dict(row) if row else None


def list_groups(db_path: Path, project_id: str) -> list[dict]:
    """
    Purpose:
        Return all groups for a project with member counts.
    Output:
        List of dicts: group columns + 'member_count' integer.
    """
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT g.*, COUNT(m.finding_id) AS member_count
            FROM finding_groups g
            LEFT JOIN finding_group_members m ON m.group_id = g.id
            WHERE g.project_id = ?
            GROUP BY g.id
            ORDER BY g.created_at ASC
            """,
            (project_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def delete_group(db_path: Path, group_id: str, remove_findings: bool = False) -> int:
    """
    Purpose:
        Delete a finding group.
    Input:
        remove_findings — if True, also delete the findings that belong
                          to this group (and their evidence/timeline).
                          if False (default), only the group and membership
                          rows are removed; findings are preserved.
    Output:
        Number of findings deleted (0 unless remove_findings=True).
    Side effects:
        Deletes from finding_groups (and finding_group_members via CASCADE).
        Optionally deletes findings and their evidence/timeline rows.
    """
    deleted = 0
    with _connect(db_path) as conn:
        if remove_findings:
            fids = [
                r[0]
                for r in conn.execute(
                    "SELECT finding_id FROM finding_group_members WHERE group_id = ?",
                    (group_id,),
                ).fetchall()
            ]
            for fid in fids:
                conn.execute("DELETE FROM finding_evidence WHERE finding_id = ?", (fid,))
                conn.execute("DELETE FROM finding_timeline WHERE finding_id = ?", (fid,))
                conn.execute("DELETE FROM finding_group_members WHERE finding_id = ?", (fid,))
                conn.execute("DELETE FROM findings WHERE id = ?", (fid,))
                deleted += 1
        conn.execute("DELETE FROM finding_groups WHERE id = ?", (group_id,))
    return deleted


def add_to_group(db_path: Path, group_id: str, finding_id: str) -> bool:
    """
    Purpose:
        Add a finding to a group.
    Output:
        True if inserted; False if already a member (no-op).
    """
    now = _now()
    with _connect(db_path) as conn:
        try:
            conn.execute(
                "INSERT INTO finding_group_members (group_id, finding_id, added_at) VALUES (?, ?, ?)",
                (group_id, finding_id, now),
            )
        except sqlite3.IntegrityError:
            return False
    return True


def remove_from_group(db_path: Path, group_id: str, finding_id: str) -> bool:
    """
    Purpose:
        Remove a finding from a group.
    Output:
        True if a row was deleted; False if membership did not exist.
    """
    with _connect(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM finding_group_members WHERE group_id = ? AND finding_id = ?",
            (group_id, finding_id),
        )
    return cur.rowcount > 0


def list_group_findings(db_path: Path, group_id: str) -> list[dict]:
    """Return all findings belonging to a group ordered by creation time."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT f.*
            FROM findings f
            JOIN finding_group_members m ON m.finding_id = f.id
            WHERE m.group_id = ?
            ORDER BY f.created_at DESC
            """,
            (group_id,),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def list_duplicates_of(db_path: Path, finding_id: str) -> list[dict]:
    """
    Purpose:
        Return all findings that reference finding_id as their duplicate_of.
    Used when displaying a canonical finding to also list its duplicates.
    """
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE duplicate_of = ? ORDER BY created_at DESC",
            (finding_id,),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]
