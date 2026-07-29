"""
Module: talos.send.db

Purpose:
    Data access for Repeater (send) Phase 1.
    Thin wrappers over flows / replay helpers — no separate sessions table.

    History query:
        WHERE original_flow_id = ? AND source IN ('manual_send','ai_send')
        ORDER BY captured_at

Dependencies: sqlite3, json, pathlib, talos.projects.db, talos.replay.db
Data flow:
    engine / CLI → functions here → project SQLite
Side effects:
    - Reads: get_flow_for_send, resolve_root_flow_id, list_send_history, get_flow_show
    - Writes: none (inserts go through talos.replay.db.insert_replayed_flow)
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional

from talos.projects.db import migrate_project_db
from talos.replay import db as replay_db

SEND_SOURCES: frozenset[str] = frozenset({"manual_send", "ai_send"})


def _connect_ro(db_path: Path) -> sqlite3.Connection:
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def get_flow_for_send(db_path: Path, flow_id: str) -> Optional[dict]:
    """
    Purpose:
        Load a flow with all fields needed to fork a draft and resolve lineage.
        Extends replay get_flow_for_replay with original_flow_id + flow_meta.
    Input:
        db_path — project talos.db path.
        flow_id — UUID of parent/baseline flow.
    Output:
        Flow dict or None.
    Side effects:
        migrate_project_db on entry.
    """
    base = replay_db.get_flow_for_replay(db_path, flow_id)
    if base is None:
        return None

    migrate_project_db(db_path)
    if not db_path.exists():
        return base

    with _connect_ro(db_path) as conn:
        row = conn.execute(
            """
            SELECT original_flow_id, flow_meta, project_id,
                   request_body, response_body, response_headers,
                   status_code, content_type, source, captured_at
            FROM flows
            WHERE id = ?
            """,
            (flow_id,),
        ).fetchone()
    if row is None:
        return base

    base["original_flow_id"] = row["original_flow_id"]
    base["project_id"] = row["project_id"]
    base["source"] = row["source"] or base.get("source")
    base["captured_at"] = row["captured_at"] or base.get("captured_at")
    # Prefer full bodies from this wider select when present.
    if row["request_body"] is not None:
        base["request_body"] = row["request_body"]
    if row["response_body"] is not None:
        base["response_body"] = row["response_body"]
    if row["response_headers"] is not None:
        base["response_headers"] = row["response_headers"]
    if row["status_code"] is not None:
        base["status_code"] = row["status_code"]
    if row["content_type"] is not None:
        base["content_type"] = row["content_type"]

    meta = row["flow_meta"]
    if isinstance(meta, str):
        try:
            base["flow_meta"] = json.loads(meta) if meta else {}
        except (ValueError, TypeError):
            base["flow_meta"] = {}
    else:
        base["flow_meta"] = meta or {}
    return base


def resolve_root_flow_id(flow: dict) -> str:
    """
    Purpose:
        Resolve the root capture id for lineage.
        If the flow already has original_flow_id, use it; else the flow is root.
    """
    orig = flow.get("original_flow_id")
    if orig:
        return str(orig)
    return str(flow["id"])


def list_send_history(
    db_path: Path,
    root_flow_id: str,
    *,
    limit: int = 100,
) -> list[dict]:
    """
    Purpose:
        List send executions whose original_flow_id equals the resolved root.
    Input:
        db_path       — project talos.db.
        root_flow_id  — baseline/root UUID (or any flow; resolved to root).
        limit         — max rows (default 100).
    Output:
        List of dicts ordered by captured_at ASC (oldest first).
    Side effects: migrate; read-only.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return []

    # Resolve --from to root: if the id is itself a send/replay, use its root.
    parent = get_flow_for_send(db_path, root_flow_id)
    if parent is not None:
        root = resolve_root_flow_id(parent)
    else:
        root = root_flow_id

    sources = tuple(sorted(SEND_SOURCES))
    placeholders = ",".join("?" * len(sources))
    with _connect_ro(db_path) as conn:
        rows = conn.execute(
            f"""
            SELECT id, method, url, host, path, query,
                   status_code, source, original_flow_id, replay_reason,
                   replay_error, captured_at, flow_meta,
                   request_body, response_body
            FROM flows
            WHERE original_flow_id = ?
              AND source IN ({placeholders})
            ORDER BY captured_at ASC
            LIMIT ?
            """,
            (root, *sources, max(1, limit)),
        ).fetchall()

    results: list[dict] = []
    for row in rows:
        d = dict(row)
        req_body = d.pop("request_body", None)
        resp_body = d.pop("response_body", None)
        d["request_body_len"] = len(req_body) if req_body else 0
        d["response_body_len"] = len(resp_body) if resp_body else 0
        meta_raw = d.pop("flow_meta", "{}")
        try:
            meta = json.loads(meta_raw) if isinstance(meta_raw, str) else (meta_raw or {})
        except (ValueError, TypeError):
            meta = {}
        d["flow_meta"] = meta if isinstance(meta, dict) else {}
        d["parent_flow_id"] = d["flow_meta"].get("parent_flow_id")
        results.append(d)
    return results


def get_flow_show(db_path: Path, flow_id: str) -> Optional[dict]:
    """
    Purpose:
        Load a flow for `talos send show` (request + response summary).
    Input:
        db_path, flow_id
    Output:
        Dict with request/response fields and sizes, or None.
    Side effects: migrate; read-only.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return None
    with _connect_ro(db_path) as conn:
        row = conn.execute(
            """
            SELECT id, method, url, host, path, query,
                   request_headers, request_cookies,
                   request_body, response_body, response_headers,
                   status_code, content_type, source,
                   original_flow_id, replay_reason, replay_error,
                   flow_meta, captured_at, endpoint_id, role_id, module_id,
                   length(request_body)  AS request_body_len,
                   length(response_body) AS response_body_len
            FROM flows
            WHERE id = ?
            """,
            (flow_id,),
        ).fetchone()
    if row is None:
        return None
    d = dict(row)
    meta_raw = d.get("flow_meta") or "{}"
    try:
        d["flow_meta"] = json.loads(meta_raw) if isinstance(meta_raw, str) else meta_raw
    except (ValueError, TypeError):
        d["flow_meta"] = {}
    return d
