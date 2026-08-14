"""
Module: talos.auth_session.db

Purpose:
    CRUD for ``auth_session_bindings``, ``auth_session_candidates``, and
    ``auth_session_results`` (Phases 2–3).

    Status ownership (design):
        pending → approved|rejected   — CLI
        failed|done → approved        — CLI re-test
        approved → running            — scheduler (or run --right-now)
        running → done|failed         — scheduler settle (or right-now settle)

Dependencies: hashlib, json, sqlite3, uuid, datetime; models; projects.db
Data flow: CLI / candidates / engine / scheduler → functions here → project SQLite
Side effects: DB reads and writes; migrate_project_db on entry for writes.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from talos.auth_session.models import (
    AUTH_SESSION_VERDICTS,
    CANDIDATE_STATUSES,
    KNOWN_AUTH_TYPES,
    KNOWN_LOCATIONS,
    RUNNABLE_STATUSES,
    STATUS_APPROVED,
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_REJECTED,
    STATUS_RUNNING,
    AuthSessionBinding,
    AuthSessionCandidate,
    AuthSessionResult,
)
from talos.projects.db import migrate_project_db

# Approve may re-open failed/done for re-test (design lifecycle).
APPROVE_SOURCE_STATUSES: frozenset[str] = frozenset({
    STATUS_PENDING,
    STATUS_FAILED,
    STATUS_DONE,
})
REJECT_SOURCE_STATUSES: frozenset[str] = frozenset({STATUS_PENDING})
# Scheduler claims pending (or leftover approved) candidates before engine runs.
RUN_SOURCE_STATUSES: frozenset[str] = frozenset(RUNNABLE_STATUSES)
# Settle from running / approved (right-now race) / pending (recovery when
# operator unapproved after enqueue but before claim — see unapprove guard).
SETTLE_SOURCE_STATUSES: frozenset[str] = frozenset({
    STATUS_RUNNING,
    STATUS_APPROVED,
    STATUS_PENDING,
})


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect(db_path: Path, *, rw: bool = True) -> sqlite3.Connection:
    if rw:
        conn = sqlite3.connect(str(db_path))
    else:
        uri = f"file:{db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def token_fingerprint(raw_token: str) -> str:
    """
    Purpose:
        Short display fingerprint of a compact token (never store full token
        on candidate rows). Format: ``prefix…hash10``.
    Input:
        raw_token — compact JWT without scheme
    Output:
        fingerprint string
    Side effects: None.
    """
    text = (raw_token or "").strip()
    if not text:
        return ""
    prefix = text[:12]
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}…{digest}"


def _row_to_binding(row: sqlite3.Row) -> AuthSessionBinding:
    return AuthSessionBinding(
        id=row["id"],
        location=row["location"],
        name=row["name"],
        auth_type=row["auth_type"],
        role_id=row["role_id"],
        config_json=row["config_json"] or "{}",
        created_at=row["created_at"] or "",
        updated_at=row["updated_at"] or "",
    )


def _row_to_candidate(row: sqlite3.Row) -> AuthSessionCandidate:
    return AuthSessionCandidate(
        id=row["id"],
        binding_id=row["binding_id"],
        baseline_flow_id=row["baseline_flow_id"],
        auth_type=row["auth_type"],
        test_id=row["test_id"],
        test_family=row["test_family"],
        title=row["title"],
        mutation_summary=row["mutation_summary"],
        status=row["status"],
        endpoint_id=row["endpoint_id"],
        token_fingerprint=row["token_fingerprint"],
        risk_hint=row["risk_hint"],
        reject_reason=row["reject_reason"],
        skip_reason=row["skip_reason"],
        meta_json=row["meta_json"] or "{}",
        created_at=row["created_at"] or "",
        updated_at=row["updated_at"] or "",
    )


def _row_to_result(row: sqlite3.Row) -> AuthSessionResult:
    return AuthSessionResult(
        replay_flow_id=row["replay_flow_id"],
        original_flow_id=row["original_flow_id"],
        candidate_id=row["candidate_id"],
        binding_id=row["binding_id"],
        auth_type=row["auth_type"],
        test_id=row["test_id"],
        verdict=row["verdict"],
        endpoint_id=row["endpoint_id"],
        test_family=row["test_family"],
        mutation_summary=row["mutation_summary"],
        original_status=row["original_status"],
        replay_status=row["replay_status"],
        diff_verdict=row["diff_verdict"],
        matched_section=row["matched_section"],
        matched_group=row["matched_group"],
        matched_rules=row["matched_rules"],
        failure_reason=row["failure_reason"],
        created_at=row["created_at"] or "",
    )


# ------------------------------------------------------------------ #
# Bindings                                                             #
# ------------------------------------------------------------------ #


def insert_binding(
    db_path: Path,
    *,
    location: str,
    name: str,
    auth_type: str,
    role_id: Optional[str] = None,
    config_json: str = "{}",
    binding_id: Optional[str] = None,
) -> AuthSessionBinding:
    """
    Purpose:
        Insert a new auth_session binding.
    Input:
        location — header | cookie
        name — field name (must already exist in auth_config; caller checks)
        auth_type — jwt (v1)
        role_id — optional preferred role UUID
        config_json — optional suite overrides JSON
    Output:
        AuthSessionBinding
    Side effects: DB write.
    Raises:
        ValueError on invalid location/type or empty name
        sqlite3.IntegrityError on UNIQUE (location, name)
    """
    migrate_project_db(db_path)
    loc = (location or "").strip().lower()
    field = (name or "").strip()
    atype = (auth_type or "").strip().lower()
    if loc not in KNOWN_LOCATIONS:
        raise ValueError(f"location must be one of {sorted(KNOWN_LOCATIONS)}")
    if not field:
        raise ValueError("name must be non-empty")
    if atype not in KNOWN_AUTH_TYPES:
        raise ValueError(
            f"auth_type must be one of {sorted(KNOWN_AUTH_TYPES)}; got {auth_type!r}"
        )
    # Headers: refuse case-only duplicates (HTTP names are case-insensitive).
    # UNIQUE(location, name) alone would allow both Authorization and authorization.
    if loc == "header":
        existing = get_binding_by_field(db_path, loc, field)
        if existing is not None:
            raise ValueError(
                f"binding already exists for header {existing.name!r} "
                f"(case-insensitive match for {field!r})"
            )

    bid = binding_id or str(uuid.uuid4())
    now = _now_utc()
    cfg = config_json if config_json and config_json.strip() else "{}"
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO auth_session_bindings
                (id, location, name, auth_type, role_id, config_json,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (bid, loc, field, atype, role_id, cfg, now, now),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM auth_session_bindings WHERE id = ?",
            (bid,),
        ).fetchone()
    assert row is not None
    return _row_to_binding(row)


def get_binding(db_path: Path, binding_id: str) -> Optional[AuthSessionBinding]:
    """Fetch one binding by id, or None."""
    if not db_path.exists():
        return None
    migrate_project_db(db_path)
    with _connect(db_path, rw=False) as conn:
        row = conn.execute(
            "SELECT * FROM auth_session_bindings WHERE id = ?",
            (binding_id,),
        ).fetchone()
    return _row_to_binding(row) if row else None


def get_binding_by_field(
    db_path: Path,
    location: str,
    name: str,
) -> Optional[AuthSessionBinding]:
    """
    Fetch binding by UNIQUE (location, name).

    Headers are matched case-insensitively (HTTP header names are
    case-insensitive). Cookies use exact name match first, then a
    case-insensitive fallback for operator typos.
    """
    if not db_path.exists():
        return None
    migrate_project_db(db_path)
    loc = (location or "").strip().lower()
    field = (name or "").strip()
    if not field:
        return None
    with _connect(db_path, rw=False) as conn:
        if loc == "header":
            # Case-insensitive header field names.
            row = conn.execute(
                """
                SELECT * FROM auth_session_bindings
                WHERE location = ? AND lower(name) = lower(?)
                """,
                (loc, field),
            ).fetchone()
        else:
            row = conn.execute(
                """
                SELECT * FROM auth_session_bindings
                WHERE location = ? AND name = ?
                """,
                (loc, field),
            ).fetchone()
            if row is None:
                # Soft fallback for operator typos (cookie names are
                # case-sensitive on the wire; exact match preferred).
                row = conn.execute(
                    """
                    SELECT * FROM auth_session_bindings
                    WHERE location = ? AND lower(name) = lower(?)
                    """,
                    (loc, field),
                ).fetchone()
    return _row_to_binding(row) if row else None


def list_bindings(db_path: Path) -> list[AuthSessionBinding]:
    """List all bindings ordered by location, name."""
    if not db_path.exists():
        return []
    migrate_project_db(db_path)
    with _connect(db_path, rw=False) as conn:
        rows = conn.execute(
            """
            SELECT * FROM auth_session_bindings
            ORDER BY location, name
            """
        ).fetchall()
    return [_row_to_binding(r) for r in rows]


def update_binding(
    db_path: Path,
    binding_id: str,
    *,
    role_id: Optional[str] = None,
    clear_role: bool = False,
    config_json: Optional[str] = None,
    auth_type: Optional[str] = None,
) -> Optional[AuthSessionBinding]:
    """
    Purpose:
        Update optional fields on an existing binding.
    Side effects: DB write.
    """
    migrate_project_db(db_path)
    binding = get_binding(db_path, binding_id)
    if binding is None:
        return None
    now = _now_utc()
    new_role = binding.role_id
    if clear_role:
        new_role = None
    elif role_id is not None:
        new_role = role_id
    new_cfg = binding.config_json if config_json is None else config_json
    new_type = binding.auth_type
    if auth_type is not None:
        atype = auth_type.strip().lower()
        if atype not in KNOWN_AUTH_TYPES:
            raise ValueError(f"unsupported auth_type {auth_type!r}")
        new_type = atype
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE auth_session_bindings
            SET role_id = ?, config_json = ?, auth_type = ?, updated_at = ?
            WHERE id = ?
            """,
            (new_role, new_cfg, new_type, now, binding_id),
        )
        conn.commit()
    return get_binding(db_path, binding_id)


def count_candidates_for_binding(
    db_path: Path,
    binding_id: str,
) -> dict[str, int]:
    """
    Purpose:
        Count candidates per status for a binding (unbind guards).
    Output:
        dict status → count (only statuses with rows > 0, plus total)
    """
    if not db_path.exists():
        return {"total": 0}
    migrate_project_db(db_path)
    with _connect(db_path, rw=False) as conn:
        rows = conn.execute(
            """
            SELECT status, COUNT(*) AS n
            FROM auth_session_candidates
            WHERE binding_id = ?
            GROUP BY status
            """,
            (binding_id,),
        ).fetchall()
    out: dict[str, int] = {r["status"]: int(r["n"]) for r in rows}
    out["total"] = sum(v for k, v in out.items() if k != "total")
    return out


def binding_has_results(db_path: Path, binding_id: str) -> bool:
    """True if any auth_session_results reference this binding_id."""
    if not db_path.exists():
        return False
    migrate_project_db(db_path)
    with _connect(db_path, rw=False) as conn:
        row = conn.execute(
            """
            SELECT 1 FROM auth_session_results
            WHERE binding_id = ?
            LIMIT 1
            """,
            (binding_id,),
        ).fetchone()
    return row is not None


def delete_binding(db_path: Path, binding_id: str) -> bool:
    """
    Purpose:
        Hard-delete a binding. Caller must enforce unbind rules first.
        FK RESTRICT will raise if candidates still reference the binding.
    Output:
        True if a row was deleted.
    Side effects: DB write.
    """
    migrate_project_db(db_path)
    with _connect(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM auth_session_bindings WHERE id = ?",
            (binding_id,),
        )
        conn.commit()
        return cur.rowcount > 0


def cascade_reject_pending_for_binding(
    db_path: Path,
    binding_id: str,
    *,
    reason: str = "binding_unbound",
) -> int:
    """
    Purpose:
        Reject all pending candidates for a binding (unbind --force path).
        Does not touch approved/running/done/failed.
    Output:
        Number of rows updated.
    Side effects: DB write.
    """
    migrate_project_db(db_path)
    now = _now_utc()
    with _connect(db_path) as conn:
        cur = conn.execute(
            """
            UPDATE auth_session_candidates
            SET status = ?, reject_reason = ?, updated_at = ?
            WHERE binding_id = ? AND status = ?
            """,
            (STATUS_REJECTED, reason, now, binding_id, STATUS_PENDING),
        )
        # Also mark rejected already-rejected is no-op; leave rejected as-is.
        # Delete only pending/rejected candidates after cascade so RESTRICT lifts.
        conn.execute(
            """
            DELETE FROM auth_session_candidates
            WHERE binding_id = ? AND status IN (?, ?)
            """,
            (binding_id, STATUS_PENDING, STATUS_REJECTED),
        )
        conn.commit()
        return cur.rowcount


def cascade_delete_binding(
    db_path: Path,
    binding_id: str,
) -> dict[str, Any]:
    """
    Purpose:
        Remove a binding and its candidates/results. Refuses while any
        candidate is still ``running``.
    Output:
        ``{ok, reason?, deleted_results, deleted_candidates}``
    Side effects: DB deletes.
    """
    migrate_project_db(db_path)
    counts = count_candidates_for_binding(db_path, binding_id)
    running = int(counts.get(STATUS_RUNNING) or 0)
    if running:
        return {
            "ok": False,
            "reason": f"binding has {running} running candidate(s)",
            "deleted_results": 0,
            "deleted_candidates": 0,
        }
    with _connect(db_path) as conn:
        res_cur = conn.execute(
            "DELETE FROM auth_session_results WHERE binding_id = ?",
            (binding_id,),
        )
        cand_cur = conn.execute(
            "DELETE FROM auth_session_candidates WHERE binding_id = ?",
            (binding_id,),
        )
        conn.execute(
            "DELETE FROM auth_session_bindings WHERE id = ?",
            (binding_id,),
        )
        conn.commit()
        return {
            "ok": True,
            "deleted_results": int(res_cur.rowcount or 0),
            "deleted_candidates": int(cand_cur.rowcount or 0),
        }


def list_target_flows(
    db_path: Path,
    *,
    binding_id: Optional[str] = None,
) -> list[dict[str, Any]]:
    """
    Purpose:
        Unique baseline flows that currently have JWT test candidates.
    """
    if not db_path.exists():
        return []
    migrate_project_db(db_path)
    params: list[Any] = []
    sql = """
        SELECT c.baseline_flow_id AS flow_id,
               c.binding_id AS binding_id,
               c.endpoint_id AS endpoint_id,
               COUNT(*) AS test_count,
               SUM(CASE WHEN c.status IN ('pending', 'approved') THEN 1 ELSE 0 END)
                   AS runnable_count,
               SUM(CASE WHEN c.status = 'running' THEN 1 ELSE 0 END) AS running_count,
               MAX(c.created_at) AS created_at,
               f.method AS method,
               f.path AS path,
               f.host AS host,
               f.url AS url,
               f.status_code AS status_code
        FROM auth_session_candidates c
        LEFT JOIN flows f ON f.id = c.baseline_flow_id
    """
    if binding_id:
        sql += " WHERE c.binding_id = ?"
        params.append(binding_id)
    sql += """
        GROUP BY c.baseline_flow_id, c.binding_id, c.endpoint_id,
                 f.method, f.path, f.host, f.url, f.status_code
        ORDER BY created_at ASC
    """
    with _connect(db_path, rw=False) as conn:
        rows = conn.execute(sql, params).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        out.append({
            "flow_id": row["flow_id"],
            "binding_id": row["binding_id"],
            "endpoint_id": row["endpoint_id"],
            "test_count": int(row["test_count"] or 0),
            "runnable_count": int(row["runnable_count"] or 0),
            "running_count": int(row["running_count"] or 0),
            "created_at": row["created_at"] or "",
            "method": row["method"] or "",
            "path": row["path"] or "",
            "host": row["host"] or "",
            "url": row["url"] or "",
            "status_code": row["status_code"],
        })
    return out


def delete_candidates_for_flow(
    db_path: Path,
    *,
    flow_id: str,
    binding_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Purpose:
        Delete JWT test rows for one target flow. Refuses if any are running.
    """
    migrate_project_db(db_path)
    clauses = ["baseline_flow_id = ?"]
    params: list[Any] = [flow_id]
    if binding_id:
        clauses.append("binding_id = ?")
        params.append(binding_id)
    where = " AND ".join(clauses)
    with _connect(db_path) as conn:
        running = conn.execute(
            f"SELECT COUNT(*) AS n FROM auth_session_candidates "
            f"WHERE {where} AND status = ?",
            (*params, STATUS_RUNNING),
        ).fetchone()
        n_running = int(running["n"] if running else 0)
        if n_running:
            return {
                "ok": False,
                "reason": f"{n_running} candidate(s) still running",
                "deleted": 0,
            }
        cur = conn.execute(
            f"DELETE FROM auth_session_candidates WHERE {where}",
            params,
        )
        conn.commit()
        return {"ok": True, "deleted": int(cur.rowcount or 0)}


# ------------------------------------------------------------------ #
# Candidates                                                           #
# ------------------------------------------------------------------ #


def insert_candidate(
    db_path: Path,
    *,
    binding_id: str,
    baseline_flow_id: str,
    auth_type: str,
    test_id: str,
    test_family: str,
    title: str,
    mutation_summary: str,
    endpoint_id: Optional[str] = None,
    token_fingerprint: Optional[str] = None,
    risk_hint: Optional[str] = None,
    status: str = STATUS_PENDING,
    meta: Optional[dict[str, Any]] = None,
    candidate_id: Optional[str] = None,
) -> AuthSessionCandidate:
    """
    Purpose:
        Insert one candidate row (insert-if-absent callers use get-or-skip).
    Side effects: DB write.
    Raises:
        sqlite3.IntegrityError on UNIQUE (binding_id, test_id, baseline_flow_id)
    """
    migrate_project_db(db_path)
    if status not in CANDIDATE_STATUSES:
        raise ValueError(f"invalid status {status!r}")
    cid = candidate_id or str(uuid.uuid4())
    now = _now_utc()
    meta_json = json.dumps(meta or {}, separators=(",", ":"), ensure_ascii=True)
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO auth_session_candidates (
                id, binding_id, endpoint_id, baseline_flow_id, auth_type,
                test_id, test_family, title, mutation_summary,
                token_fingerprint, risk_hint, status, reject_reason,
                skip_reason, meta_json, created_at, updated_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?
            )
            """,
            (
                cid,
                binding_id,
                endpoint_id,
                baseline_flow_id,
                auth_type,
                test_id,
                test_family,
                title,
                mutation_summary,
                token_fingerprint,
                risk_hint,
                status,
                meta_json,
                now,
                now,
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM auth_session_candidates WHERE id = ?",
            (cid,),
        ).fetchone()
    assert row is not None
    return _row_to_candidate(row)


def get_candidate(
    db_path: Path,
    candidate_id: str,
) -> Optional[AuthSessionCandidate]:
    """Fetch one candidate by id."""
    if not db_path.exists():
        return None
    migrate_project_db(db_path)
    with _connect(db_path, rw=False) as conn:
        row = conn.execute(
            "SELECT * FROM auth_session_candidates WHERE id = ?",
            (candidate_id,),
        ).fetchone()
    return _row_to_candidate(row) if row else None


def get_candidate_by_key(
    db_path: Path,
    binding_id: str,
    test_id: str,
    baseline_flow_id: str,
) -> Optional[AuthSessionCandidate]:
    """Fetch by UNIQUE (binding_id, test_id, baseline_flow_id)."""
    if not db_path.exists():
        return None
    migrate_project_db(db_path)
    with _connect(db_path, rw=False) as conn:
        row = conn.execute(
            """
            SELECT * FROM auth_session_candidates
            WHERE binding_id = ? AND test_id = ? AND baseline_flow_id = ?
            """,
            (binding_id, test_id, baseline_flow_id),
        ).fetchone()
    return _row_to_candidate(row) if row else None


def list_candidates(
    db_path: Path,
    *,
    status: Optional[str] = None,
    statuses: Optional[list[str]] = None,
    endpoint_id: Optional[str] = None,
    binding_id: Optional[str] = None,
    test_ids: Optional[list[str]] = None,
    families: Optional[list[str]] = None,
    candidate_ids: Optional[list[str]] = None,
    limit: Optional[int] = None,
) -> list[AuthSessionCandidate]:
    """
    Purpose:
        List candidates with optional filters (AND across dimensions).
        Multiple test_ids / families use OR within that dimension.
    Side effects: Read-only after migrate.
    """
    if not db_path.exists():
        return []
    migrate_project_db(db_path)
    clauses: list[str] = []
    params: list[Any] = []

    if candidate_ids:
        placeholders = ",".join("?" for _ in candidate_ids)
        clauses.append(f"id IN ({placeholders})")
        params.extend(candidate_ids)

    status_list: list[str] = []
    if status:
        status_list.append(status)
    if statuses:
        status_list.extend(statuses)
    if status_list:
        placeholders = ",".join("?" for _ in status_list)
        clauses.append(f"status IN ({placeholders})")
        params.extend(status_list)

    if endpoint_id:
        clauses.append("endpoint_id = ?")
        params.append(endpoint_id)
    if binding_id:
        clauses.append("binding_id = ?")
        params.append(binding_id)
    if test_ids:
        placeholders = ",".join("?" for _ in test_ids)
        clauses.append(f"test_id IN ({placeholders})")
        params.extend(test_ids)
    if families:
        placeholders = ",".join("?" for _ in families)
        clauses.append(f"test_family IN ({placeholders})")
        params.extend(families)

    sql = "SELECT * FROM auth_session_candidates"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY created_at ASC, test_id ASC"
    if limit is not None and limit > 0:
        sql += f" LIMIT {int(limit)}"

    with _connect(db_path, rw=False) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_candidate(r) for r in rows]


def force_refresh_candidate(
    db_path: Path,
    candidate_id: str,
    *,
    title: str,
    mutation_summary: str,
    risk_hint: Optional[str],
    test_family: str,
    token_fingerprint: Optional[str] = None,
    meta: Optional[dict[str, Any]] = None,
) -> Optional[AuthSessionCandidate]:
    """
    Purpose:
        Reset a pending or rejected candidate to pending with refreshed
        suite metadata. Refuses other statuses (caller should check).
    Side effects: DB write.
    """
    migrate_project_db(db_path)
    cand = get_candidate(db_path, candidate_id)
    if cand is None:
        return None
    if cand.status not in (STATUS_PENDING, STATUS_REJECTED):
        return None
    now = _now_utc()
    meta_json = json.dumps(meta or {}, separators=(",", ":"), ensure_ascii=True)
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE auth_session_candidates
            SET status = ?,
                title = ?,
                mutation_summary = ?,
                risk_hint = ?,
                test_family = ?,
                token_fingerprint = COALESCE(?, token_fingerprint),
                reject_reason = NULL,
                skip_reason = NULL,
                meta_json = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                STATUS_PENDING,
                title,
                mutation_summary,
                risk_hint,
                test_family,
                token_fingerprint,
                meta_json,
                now,
                candidate_id,
            ),
        )
        conn.commit()
    return get_candidate(db_path, candidate_id)


def set_candidate_status(
    db_path: Path,
    candidate_id: str,
    new_status: str,
    *,
    reject_reason: Optional[str] = None,
    allowed_from: Optional[frozenset[str]] = None,
) -> Optional[AuthSessionCandidate]:
    """
    Purpose:
        Transition candidate status when current status is in allowed_from.
    Input:
        new_status — target status
        reject_reason — set when rejecting
        allowed_from — source statuses permitted (default: any)
    Output:
        Updated candidate or None if missing / wrong source status.
    Side effects: DB write.
    """
    migrate_project_db(db_path)
    if new_status not in CANDIDATE_STATUSES:
        raise ValueError(f"invalid status {new_status!r}")
    cand = get_candidate(db_path, candidate_id)
    if cand is None:
        return None
    if allowed_from is not None and cand.status not in allowed_from:
        return None
    now = _now_utc()
    with _connect(db_path) as conn:
        if new_status == STATUS_REJECTED:
            conn.execute(
                """
                UPDATE auth_session_candidates
                SET status = ?, reject_reason = ?, updated_at = ?
                WHERE id = ?
                """,
                (new_status, reject_reason, now, candidate_id),
            )
        elif new_status == STATUS_APPROVED:
            conn.execute(
                """
                UPDATE auth_session_candidates
                SET status = ?, reject_reason = NULL, updated_at = ?
                WHERE id = ?
                """,
                (new_status, now, candidate_id),
            )
        else:
            conn.execute(
                """
                UPDATE auth_session_candidates
                SET status = ?, updated_at = ?
                WHERE id = ?
                """,
                (new_status, now, candidate_id),
            )
        conn.commit()
    return get_candidate(db_path, candidate_id)


def approve_candidates(
    db_path: Path,
    candidate_ids: list[str],
) -> tuple[list[str], list[str]]:
    """
    Purpose:
        Approve candidates whose status is pending|failed|done.
    Output:
        (approved_ids, skipped_ids)
    Side effects: DB write.
    """
    approved: list[str] = []
    skipped: list[str] = []
    for cid in candidate_ids:
        result = set_candidate_status(
            db_path, cid, STATUS_APPROVED, allowed_from=APPROVE_SOURCE_STATUSES
        )
        if result is not None and result.status == STATUS_APPROVED:
            approved.append(cid)
        else:
            skipped.append(cid)
    return approved, skipped


def reject_candidates(
    db_path: Path,
    candidate_ids: list[str],
    *,
    reason: Optional[str] = None,
) -> tuple[list[str], list[str]]:
    """
    Purpose:
        Reject candidates whose status is pending only.
    Output:
        (rejected_ids, skipped_ids)
    Side effects: DB write.
    """
    rejected: list[str] = []
    skipped: list[str] = []
    for cid in candidate_ids:
        result = set_candidate_status(
            db_path,
            cid,
            STATUS_REJECTED,
            reject_reason=reason,
            allowed_from=REJECT_SOURCE_STATUSES,
        )
        if result is not None and result.status == STATUS_REJECTED:
            rejected.append(cid)
        else:
            skipped.append(cid)
    return rejected, skipped


# Unapprove: design lifecycle optional transition approved → pending.
UNAPPROVE_SOURCE_STATUSES: frozenset[str] = frozenset({STATUS_APPROVED})


def has_active_auth_session_job_for_candidate(
    db_path: Path,
    candidate_id: str,
) -> bool:
    """
    Purpose:
        True if a pending/running ``auth_session_attack`` job references this
        candidate_id in meta (blocks unapprove while work is queued/in-flight).
    Side effects: None (read-only after migrate).
    """
    if not candidate_id or not db_path.exists():
        return False
    migrate_project_db(db_path)
    from talos.scheduler.job import AUTH_SESSION_ATTACK

    with _connect(db_path, rw=False) as conn:
        row = conn.execute(
            """
            SELECT 1
            FROM scheduler_jobs
            WHERE job_type = ?
              AND status IN ('pending', 'running')
              AND json_extract(meta, '$.candidate_id') = ?
            LIMIT 1
            """,
            (AUTH_SESSION_ATTACK, candidate_id),
        ).fetchone()
    return row is not None


def unapprove_candidates(
    db_path: Path,
    candidate_ids: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """
    Purpose:
        Move approved candidates back to pending so operators can re-review
        or unbind (without --force cascade of only soft statuses).

        Design state machine: ``approved → pending`` (optional unapprove).
        Does **not** touch running/done/failed/rejected.

        Refuses candidates that still have a pending/running
        ``auth_session_attack`` job (would leave status stuck if job later
        settles while candidate is pending).
    Output:
        (unapproved_ids, skipped_ids, blocked_active_job_ids)
    Side effects: DB write.
    """
    done: list[str] = []
    skipped: list[str] = []
    blocked: list[str] = []
    for cid in candidate_ids:
        if has_active_auth_session_job_for_candidate(db_path, cid):
            blocked.append(cid)
            continue
        result = set_candidate_status(
            db_path,
            cid,
            STATUS_PENDING,
            allowed_from=UNAPPROVE_SOURCE_STATUSES,
        )
        if result is not None and result.status == STATUS_PENDING:
            done.append(cid)
        else:
            skipped.append(cid)
    return done, skipped, blocked


def mark_candidate_running(
    db_path: Path,
    candidate_id: str,
) -> Optional[AuthSessionCandidate]:
    """
    Purpose:
        Transition candidate pending|approved → running (scheduler claim / right-now).
    Output:
        Updated candidate, or None if missing / wrong source status.
    Side effects: DB write.
    """
    return set_candidate_status(
        db_path,
        candidate_id,
        STATUS_RUNNING,
        allowed_from=RUN_SOURCE_STATUSES,
    )


def mark_candidate_done(
    db_path: Path,
    candidate_id: str,
) -> Optional[AuthSessionCandidate]:
    """
    Purpose:
        Transition candidate running / approved / pending → done after successful
        settle (pending allowed as recovery if unapproved after enqueue).
    Side effects: DB write.
    """
    return set_candidate_status(
        db_path,
        candidate_id,
        STATUS_DONE,
        allowed_from=SETTLE_SOURCE_STATUSES,
    )


def mark_candidate_failed(
    db_path: Path,
    candidate_id: str,
    *,
    skip_reason: Optional[str] = None,
) -> Optional[AuthSessionCandidate]:
    """
    Purpose:
        Transition candidate running (or approved) → failed after settle error
        or pre-execution skip. Optional skip_reason stored for operator display.
    Side effects: DB write.
    """
    migrate_project_db(db_path)
    cand = get_candidate(db_path, candidate_id)
    if cand is None:
        return None
    if cand.status not in SETTLE_SOURCE_STATUSES:
        return None
    now = _now_utc()
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE auth_session_candidates
            SET status = ?,
                skip_reason = COALESCE(?, skip_reason),
                updated_at = ?
            WHERE id = ?
            """,
            (STATUS_FAILED, skip_reason, now, candidate_id),
        )
        conn.commit()
    return get_candidate(db_path, candidate_id)


# ------------------------------------------------------------------ #
# Results                                                              #
# ------------------------------------------------------------------ #


def insert_result(
    db_path: Path,
    *,
    replay_flow_id: str,
    original_flow_id: str,
    candidate_id: str,
    binding_id: str,
    auth_type: str,
    test_id: str,
    verdict: str,
    endpoint_id: Optional[str] = None,
    test_family: Optional[str] = None,
    mutation_summary: Optional[str] = None,
    original_status: Optional[int] = None,
    replay_status: Optional[int] = None,
    diff_verdict: Optional[str] = None,
    matched_section: Optional[str] = None,
    matched_group: Optional[str] = None,
    matched_rules: Optional[str] = None,
    failure_reason: Optional[str] = None,
    created_at: Optional[str] = None,
) -> AuthSessionResult:
    """
    Purpose:
        Persist one auth_session_results row (1:1 with replay_flow_id).
        Called from the engine after mutate → send → diff (not findings).
    Side effects: DB write.
    Raises:
        ValueError on invalid verdict
        sqlite3.Error on write failure (caller handles)
    """
    migrate_project_db(db_path)
    if verdict not in AUTH_SESSION_VERDICTS:
        raise ValueError(
            f"verdict must be one of {sorted(AUTH_SESSION_VERDICTS)}; got {verdict!r}"
        )
    now = created_at or _now_utc()
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO auth_session_results (
                replay_flow_id, original_flow_id, endpoint_id,
                candidate_id, binding_id, auth_type, test_id, test_family,
                mutation_summary, original_status, replay_status,
                diff_verdict, verdict, matched_section, matched_group,
                matched_rules, failure_reason, created_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                replay_flow_id,
                original_flow_id,
                endpoint_id,
                candidate_id,
                binding_id,
                auth_type,
                test_id,
                test_family,
                mutation_summary,
                original_status,
                replay_status,
                diff_verdict,
                verdict,
                matched_section,
                matched_group,
                matched_rules,
                failure_reason,
                now,
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM auth_session_results WHERE replay_flow_id = ?",
            (replay_flow_id,),
        ).fetchone()
    assert row is not None
    return _row_to_result(row)


def get_result(
    db_path: Path,
    replay_flow_id: str,
) -> Optional[AuthSessionResult]:
    """Fetch one result by replay_flow_id PK."""
    if not db_path.exists():
        return None
    migrate_project_db(db_path)
    with _connect(db_path, rw=False) as conn:
        row = conn.execute(
            "SELECT * FROM auth_session_results WHERE replay_flow_id = ?",
            (replay_flow_id,),
        ).fetchone()
    return _row_to_result(row) if row else None


def list_results(
    db_path: Path,
    *,
    endpoint_id: Optional[str] = None,
    candidate_id: Optional[str] = None,
    binding_id: Optional[str] = None,
    test_ids: Optional[list[str]] = None,
    families: Optional[list[str]] = None,
    verdict: Optional[str] = None,
    original_flow_id: Optional[str] = None,
    limit: Optional[int] = None,
) -> list[AuthSessionResult]:
    """
    Purpose:
        List results with optional filters (AND across dimensions).
    Side effects: Read-only after migrate.
    """
    if not db_path.exists():
        return []
    migrate_project_db(db_path)
    clauses: list[str] = []
    params: list[Any] = []

    if endpoint_id:
        clauses.append("endpoint_id = ?")
        params.append(endpoint_id)
    if candidate_id:
        clauses.append("candidate_id = ?")
        params.append(candidate_id)
    if binding_id:
        clauses.append("binding_id = ?")
        params.append(binding_id)
    if original_flow_id:
        clauses.append("original_flow_id = ?")
        params.append(original_flow_id)
    if verdict:
        clauses.append("verdict = ?")
        params.append(verdict)
    if test_ids:
        placeholders = ",".join("?" for _ in test_ids)
        clauses.append(f"test_id IN ({placeholders})")
        params.extend(test_ids)
    if families:
        placeholders = ",".join("?" for _ in families)
        clauses.append(f"test_family IN ({placeholders})")
        params.extend(families)

    sql = "SELECT * FROM auth_session_results"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY created_at DESC, test_id ASC"
    if limit is not None and limit > 0:
        sql += f" LIMIT {int(limit)}"

    with _connect(db_path, rw=False) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_result(r) for r in rows]


# ------------------------------------------------------------------ #
# Scheduler job dedupe (KD17)                                          #
# ------------------------------------------------------------------ #


def has_pending_auth_session_duplicate(
    db_path: Path,
    *,
    flow_id: str,
    test_id: str,
    binding_id: str,
) -> bool:
    """
    Purpose:
        True if a pending/running ``auth_session_attack`` job already exists
        with the same flow_id + meta.test_id + meta.binding_id (json_extract).

        Do **not** use ``sched_db.has_pending_duplicate`` alone — it ignores
        meta and would collapse distinct test_ids on the same baseline flow.
    Side effects: None (read-only after migrate).
    """
    if not db_path.exists():
        return False
    migrate_project_db(db_path)
    # Import constant locally to avoid hard dependency cycle at module load.
    from talos.scheduler.job import AUTH_SESSION_ATTACK

    with _connect(db_path, rw=False) as conn:
        row = conn.execute(
            """
            SELECT 1
            FROM scheduler_jobs
            WHERE job_type = ?
              AND flow_id = ?
              AND status IN ('pending', 'running')
              AND json_extract(meta, '$.test_id') = ?
              AND json_extract(meta, '$.binding_id') = ?
            LIMIT 1
            """,
            (AUTH_SESSION_ATTACK, flow_id, test_id, binding_id),
        ).fetchone()
    return row is not None

