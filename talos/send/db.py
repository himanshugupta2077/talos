"""
Module: talos.send.db

Purpose:
    Data access for Repeater (send) Phase 1–2.
    Thin wrappers over flows / replay helpers — no separate sessions table.

    History query:
        WHERE original_flow_id = ? AND source IN ('manual_send','ai_send')
        optional filters: session_id (flow_meta JSON), parent, source, limit

    Note update (Phase 2 exception):
        UPDATE flow_meta.note on send sources only — never on proxy_capture.

Dependencies: sqlite3, json, pathlib, talos.projects.db, talos.replay.db
Data flow:
    engine / CLI → functions here → project SQLite
Side effects:
    - Reads: get_flow_for_send, resolve_root_flow_id, list_send_history, get_flow_show
    - Writes: update_send_note (send rows only); export writes files
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from talos.projects.db import migrate_project_db
from talos.replay import db as replay_db
from talos.send import draft as draft_mod
from talos.send.raw_http import serialize_request

SEND_SOURCES: frozenset[str] = frozenset({"manual_send", "ai_send"})


def _duration_ms(captured_at, response_end) -> Optional[int]:
    """Compute HTTP interval ms when both timestamps parse; else None."""
    if not captured_at or not response_end:
        return None
    try:
        start = datetime.fromisoformat(str(captured_at).replace("Z", "+00:00"))
        end = datetime.fromisoformat(str(response_end).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return max(0, int((end - start).total_seconds() * 1000))


def _connect_ro(db_path: Path) -> sqlite3.Connection:
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _connect_rw(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
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
    session_id: Optional[str] = None,
    parent_flow_id: Optional[str] = None,
    source: Optional[str] = None,
) -> list[dict]:
    """
    Purpose:
        List send executions whose original_flow_id equals the resolved root.
        Optional filters: session_id (flow_meta), parent_flow_id, source.
    Input:
        db_path       — project talos.db.
        root_flow_id  — baseline/root UUID (or any flow; resolved to root).
        limit         — max rows (default 100).
        session_id    — filter flow_meta.session_id when set.
        parent_flow_id — filter flow_meta.parent_flow_id when set.
        source        — manual_send | ai_send when set.
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

    if source is not None:
        if source not in SEND_SOURCES:
            return []
        sources = (source,)
    else:
        sources = tuple(sorted(SEND_SOURCES))
    placeholders = ",".join("?" * len(sources))
    limit_n = max(1, limit)

    # Prefer SQL-side filters on flow_meta (json_extract) so session/parent
    # history is correct under large trees — not "oldest N then post-filter".
    where = [
        "original_flow_id = ?",
        f"source IN ({placeholders})",
    ]
    params: list[object] = [root, *sources]
    if session_id is not None:
        where.append("json_extract(flow_meta, '$.session_id') = ?")
        params.append(session_id)
    if parent_flow_id is not None:
        where.append("json_extract(flow_meta, '$.parent_flow_id') = ?")
        params.append(parent_flow_id)
    params.append(limit_n)

    sql = f"""
        SELECT id, method, url, host, path, query,
               status_code, source, original_flow_id, replay_reason,
               replay_error, captured_at, response_end, flow_meta,
               request_body, response_body
        FROM flows
        WHERE {" AND ".join(where)}
        ORDER BY captured_at ASC
        LIMIT ?
    """

    with _connect_ro(db_path) as conn:
        try:
            rows = conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError:
            # Fallback without JSON1: scan all matching sends then filter.
            rows = conn.execute(
                f"""
                SELECT id, method, url, host, path, query,
                       status_code, source, original_flow_id, replay_reason,
                       replay_error, captured_at, response_end, flow_meta,
                       request_body, response_body
                FROM flows
                WHERE original_flow_id = ?
                  AND source IN ({placeholders})
                ORDER BY captured_at ASC
                """,
                (root, *sources),
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
        if not isinstance(meta, dict):
            meta = {}
        d["flow_meta"] = meta
        d["parent_flow_id"] = meta.get("parent_flow_id")
        d["session_id"] = meta.get("session_id")
        d["note"] = meta.get("note")
        d["verdict"] = meta.get("verdict")
        d["profile"] = meta.get("profile")
        d["profile_index"] = meta.get("profile_index")
        d["profile_count"] = meta.get("profile_count")
        d["duration_ms"] = _duration_ms(d.get("captured_at"), d.get("response_end"))

        if session_id is not None and d.get("session_id") != session_id:
            continue
        if parent_flow_id is not None and d.get("parent_flow_id") != parent_flow_id:
            continue
        results.append(d)
        if len(results) >= limit_n:
            break
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
                   flow_meta, captured_at, response_end,
                   endpoint_id, role_id, module_id,
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
    d["duration_ms"] = _duration_ms(d.get("captured_at"), d.get("response_end"))
    return d


def update_send_note(
    db_path: Path,
    flow_id: str,
    note: str,
) -> tuple[bool, str]:
    """
    Purpose:
        Update flow_meta.note on a send execution only (never proxy_capture).
    Output:
        (ok, error_message). error_message empty on success.
    Side effects:
        UPDATE flows.flow_meta for send sources only.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return False, "database not found"

    with _connect_rw(db_path) as conn:
        row = conn.execute(
            "SELECT source, flow_meta FROM flows WHERE id = ?",
            (flow_id,),
        ).fetchone()
        if row is None:
            return False, f"Flow '{flow_id}' not found."
        source = row["source"] or ""
        if source not in SEND_SOURCES:
            return False, (
                f"Flow '{flow_id}' has source={source!r}; "
                "note updates are only allowed on manual_send / ai_send rows."
            )
        try:
            meta = json.loads(row["flow_meta"]) if row["flow_meta"] else {}
        except (ValueError, TypeError):
            meta = {}
        if not isinstance(meta, dict):
            meta = {}
        meta["note"] = note
        conn.execute(
            "UPDATE flows SET flow_meta = ? WHERE id = ?",
            (json.dumps(meta), flow_id),
        )
        conn.commit()
    return True, ""


def export_flow_http(
    db_path: Path,
    flow_id: str,
    out_dir: Path,
) -> dict:
    """
    Purpose:
        Write request.http (+ response.http or response.bin) under out_dir.
    Output:
        Dict with paths and sizes.
    Raises:
        FileNotFoundError if flow missing; OSError on write failure.
    Side effects: creates out_dir; writes files.
    """
    flow = get_flow_for_send(db_path, flow_id)
    if flow is None:
        raise FileNotFoundError(f"Flow '{flow_id}' not found.")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    headers = flow.get("request_headers")
    if isinstance(headers, str):
        try:
            headers = json.loads(headers) if headers else {}
        except (ValueError, TypeError):
            headers = {}
    if not isinstance(headers, dict):
        headers = {}

    body = flow.get("request_body")
    if isinstance(body, str):
        body = body.encode("utf-8", errors="replace")

    req_bytes = serialize_request(
        method=flow.get("method") or "GET",
        url=flow.get("url") or "",
        headers=dict(headers),
        body=body if body else None,
    )
    req_path = out_dir / "request.http"
    req_path.write_bytes(req_bytes)

    resp_body = flow.get("response_body")
    if isinstance(resp_body, str):
        resp_body = resp_body.encode("utf-8", errors="replace")
    resp_headers = flow.get("response_headers")
    if isinstance(resp_headers, str):
        try:
            resp_headers = json.loads(resp_headers) if resp_headers else {}
        except (ValueError, TypeError):
            resp_headers = {}
    if not isinstance(resp_headers, dict):
        resp_headers = {}

    status = flow.get("status_code")
    status_line = f"HTTP/1.1 {status if status is not None else 0}\r\n"
    resp_parts: list[bytes] = [status_line.encode("ascii", errors="replace")]
    for name, value in resp_headers.items():
        resp_parts.append(
            f"{name}: {value}\r\n".encode("utf-8", errors="replace")
        )
    resp_parts.append(b"\r\n")
    if resp_body:
        resp_parts.append(bytes(resp_body))
    resp_bytes = b"".join(resp_parts)

    # Prefer .http when body looks like text; else .bin still with headers.
    resp_path = out_dir / "response.http"
    try:
        if resp_body and b"\x00" in bytes(resp_body):
            resp_path = out_dir / "response.bin"
    except Exception:  # noqa: BLE001
        pass
    resp_path.write_bytes(resp_bytes)

    return {
        "flow_id": flow_id,
        "out_dir": str(out_dir),
        "request_path": str(req_path),
        "response_path": str(resp_path),
        "request_bytes": len(req_bytes),
        "response_bytes": len(resp_bytes),
        "status_code": status,
        "method": flow.get("method"),
        "url": flow.get("url"),
    }


def build_send_tree(
    db_path: Path,
    root_flow_id: str,
    *,
    limit: int = 200,
) -> list[str]:
    """
    Purpose:
        Build ASCII parent→child lines for send executions under a root.
    Output:
        List of display lines (empty when no executions).
    """
    rows = list_send_history(db_path, root_flow_id, limit=limit)
    if not rows:
        return []

    parent = get_flow_for_send(db_path, root_flow_id)
    root = resolve_root_flow_id(parent) if parent else root_flow_id

    by_parent: dict[str, list[dict]] = {}
    for r in rows:
        p = r.get("parent_flow_id") or root
        by_parent.setdefault(str(p), []).append(r)

    lines: list[str] = [f"{root}  (root)"]

    def _walk(node_id: str, prefix: str) -> None:
        children = by_parent.get(node_id, [])
        for i, child in enumerate(children):
            last = i == len(children) - 1
            branch = "└── " if last else "├── "
            st = child.get("status_code")
            st_s = str(st) if st is not None else "—"
            verd = child.get("verdict") or "—"
            note = child.get("note") or child.get("replay_reason") or ""
            note_s = f"  {note}" if note else ""
            lines.append(
                f"{prefix}{branch}{child['id']}  "
                f"[{st_s}/{verd}]{note_s}"
            )
            next_prefix = prefix + ("    " if last else "│   ")
            _walk(child["id"], next_prefix)

    _walk(root, "")
    # Also walk from intermediate parents that were not under root id key
    # (e.g. parent is a send id already walked via children).
    return lines


def materialize_draft_path(
    db_path: Path,
    flow_id: str,
    raw_out: Optional[Path] = None,
) -> tuple[dict, Path, bytes]:
    """
    Purpose:
        Load flow, build draft, write raw HTTP file (shared by from / edit).
    Output:
        (draft, path, raw_bytes)
    Raises:
        FileNotFoundError when flow missing.
    """
    flow = get_flow_for_send(db_path, flow_id)
    if flow is None:
        raise FileNotFoundError(f"Flow '{flow_id}' not found.")
    draft = draft_mod.draft_from_flow(flow)
    raw = draft_mod.draft_to_raw_bytes(draft)
    if raw_out is not None:
        out_path = Path(raw_out).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(raw)
    else:
        import tempfile

        tmp = tempfile.NamedTemporaryFile(
            prefix=f"talos-send-{flow_id[:8]}-",
            suffix=".http",
            delete=False,
        )
        tmp.write(raw)
        tmp.close()
        out_path = Path(tmp.name)
    return draft, out_path, raw
