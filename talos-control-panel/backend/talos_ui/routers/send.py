"""
Control Panel Repeater API (`/api/send`).

Purpose:
    First-class Mode 2 send surface for the Control Panel. Maps 1:1 onto
    ``talos.send`` engine/db helpers without redesigning send semantics.

Architecture exception (documented in docs/control-panel/cli-integration.md):
    Send mutations call ``talos.send.engine`` / ``talos.send.db`` **in-process**
    (not CLI wrap) so raw bodies and multi-send timeouts stay reliable.
    Must not open ad-hoc SQL. Must return synthetic ``steps`` for CommandLog.
    Reads import Python packages the same way as error-intel / IV.

Data flow:
    UI serializeDraft → raw_base64 → POST /once → send_once(raw_message=…)
    Draft/history/diff are pure reads over project SQLite via talos.send.db.
"""

from __future__ import annotations

import base64
import json
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .. import config, db

router = APIRouter(prefix="/api/send", tags=["send"])

VALID_SOURCES = frozenset({"manual_send", "ai_send"})
MAX_PROFILE_N = 50


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #


def _ensure_talos_on_path() -> None:
    root = str(config.TALOS_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def _db_path(project_id: str) -> Path:
    record = db.get_project_record(project_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found")
    return config.project_db_path(project_id, record)


def _duration_ms(captured_at, response_end) -> Optional[int]:
    if not captured_at or not response_end:
        return None
    try:
        start = datetime.fromisoformat(str(captured_at).replace("Z", "+00:00"))
        end = datetime.fromisoformat(str(response_end).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return max(0, int((end - start).total_seconds() * 1000))


def _decode_body(value) -> tuple[Optional[str], Optional[str], str]:
    """
    Returns (utf8_text_or_none, base64_or_none, encoding).
    Binary / invalid UTF-8 → base64 encoding with text=None.
    """
    if value is None:
        return None, None, "utf8"
    if isinstance(value, str):
        return value, None, "utf8"
    raw = bytes(value)
    try:
        return raw.decode("utf-8"), None, "utf8"
    except UnicodeDecodeError:
        return None, base64.b64encode(raw).decode("ascii"), "base64"


def _header_map(headers) -> dict[str, str]:
    if isinstance(headers, dict):
        return {str(k): str(v) for k, v in headers.items()}
    if isinstance(headers, str):
        parsed = db.safe_json(headers, {}) or {}
        if isinstance(parsed, dict):
            return {str(k): str(v) for k, v in parsed.items()}
    return {}


def _cookie_map(cookies) -> dict[str, str]:
    if isinstance(cookies, dict):
        return {str(k): str(v) for k, v in cookies.items()}
    if isinstance(cookies, str):
        parsed = db.safe_json(cookies, {}) or {}
        if isinstance(parsed, dict):
            return {str(k): str(v) for k, v in parsed.items()}
    return {}


def _encode_raw_message(raw: bytes) -> dict[str, Any]:
    """Dual storage for full HTTP message (utf8 text or base64)."""
    try:
        text = raw.decode("utf-8")
        return {
            "raw": text,
            "raw_base64": None,
            "raw_encoding": "utf8",
        }
    except UnicodeDecodeError:
        return {
            "raw": None,
            "raw_base64": base64.b64encode(raw).decode("ascii"),
            "raw_encoding": "base64",
        }


def _http_side(
    *,
    method: Optional[str] = None,
    url: Optional[str] = None,
    host: Optional[str] = None,
    path: Optional[str] = None,
    query: Optional[str] = None,
    headers: Any = None,
    cookies: Any = None,
    body: Any = None,
    status_code: Optional[int] = None,
    content_type: Optional[str] = None,
    side: Literal["request", "response"] = "request",
) -> dict[str, Any]:
    body_text, body_b64, body_enc = _decode_body(body)
    out: dict[str, Any] = {
        "headers": _header_map(headers),
        "body": body_text,
        "body_base64": body_b64,
        "body_encoding": body_enc,
        "body_len": (
            len(body)
            if isinstance(body, (bytes, bytearray))
            else (len(body.encode("utf-8", errors="replace")) if isinstance(body, str) else 0)
        ),
    }
    if side == "request":
        out.update(
            {
                "method": method or "GET",
                "url": url or "",
                "host": host or "",
                "path": path or "/",
                "query": query or "",
                "cookies": _cookie_map(cookies),
            }
        )
    else:
        out.update(
            {
                "status_code": status_code,
                "content_type": content_type or "",
            }
        )
    return out


def _synthetic_step(
    *,
    cmd_str: str,
    ok: bool,
    duration_ms: int,
    stdout: str = "",
    stderr: str = "",
) -> dict[str, Any]:
    return {
        "cmd": [],
        "cmd_str": cmd_str,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": 0 if ok else 1,
        "duration_ms": duration_ms,
        "ok": ok,
    }


def _summarize_outcomes(outcomes: list[Any]) -> str:
    parts: list[str] = []
    for o in outcomes:
        eid = getattr(o, "execution_flow_id", None) or "—"
        st = getattr(o, "status_code", None)
        verd = getattr(o, "verdict", None) or "—"
        ok = getattr(o, "success", False)
        parts.append(
            f"{eid[:8]} status={st if st is not None else '—'} "
            f"verdict={verd} ok={ok}"
        )
    return "\n".join(parts)


def _first_failure(outcomes: list[Any]) -> str:
    for o in outcomes:
        reason = getattr(o, "failure_reason", None)
        if reason:
            return str(reason)
    return ""


def _hydrate_outcome(
    outcome: Any,
    db_path: Path,
    *,
    include_bodies: bool = True,
) -> dict[str, Any]:
    """Map SendOutcome (+ optional stored flow) to SendOutcomeDto."""
    _ensure_talos_on_path()
    from talos.send import db as send_db

    dto: dict[str, Any] = {
        "execution_flow_id": outcome.execution_flow_id,
        "parent_flow_id": outcome.parent_flow_id,
        "original_flow_id": outcome.original_flow_id,
        "status_code": outcome.status_code,
        "success": outcome.success,
        "failure_reason": outcome.failure_reason,
        "verdict": outcome.verdict,
        "request_body_len": outcome.request_body_len,
        "response_body_len": outcome.response_body_len,
        "source": outcome.source,
        "session_id": outcome.session_id,
        "profile": outcome.profile,
        "profile_index": outcome.profile_index,
        "profile_count": outcome.profile_count,
        "note": outcome.note,
        "duration_ms": None,
        "normalizers": [],
    }
    eid = outcome.execution_flow_id
    if not eid:
        return dto

    flow = send_db.get_flow_for_send(db_path, eid)
    if flow is None:
        show = send_db.get_flow_show(db_path, eid)
        if show is None:
            return dto
        flow = show

    meta = flow.get("flow_meta") or {}
    if isinstance(meta, str):
        try:
            meta = json.loads(meta) if meta else {}
        except (ValueError, TypeError):
            meta = {}
    if not isinstance(meta, dict):
        meta = {}

    dto["duration_ms"] = flow.get("duration_ms") or _duration_ms(
        flow.get("captured_at"), flow.get("response_end")
    )
    norms = meta.get("normalizers") or []
    dto["normalizers"] = list(norms) if isinstance(norms, list) else []

    if include_bodies:
        dto["response"] = _http_side(
            headers=flow.get("response_headers"),
            body=flow.get("response_body"),
            status_code=flow.get("status_code"),
            content_type=flow.get("content_type"),
            side="response",
        )
        dto["request_as_sent"] = _http_side(
            method=flow.get("method"),
            url=flow.get("url"),
            host=flow.get("host"),
            path=flow.get("path"),
            query=flow.get("query"),
            headers=flow.get("request_headers"),
            cookies=flow.get("request_cookies"),
            body=flow.get("request_body"),
            side="request",
        )
    return dto


def _history_row(r: dict) -> dict[str, Any]:
    return {
        "id": r.get("id"),
        "parent_flow_id": r.get("parent_flow_id"),
        "session_id": r.get("session_id"),
        "method": r.get("method") or "GET",
        "url": r.get("url") or "",
        "status_code": r.get("status_code"),
        "source": r.get("source") or "",
        "verdict": r.get("verdict"),
        "note": r.get("note"),
        "profile": r.get("profile"),
        "profile_index": r.get("profile_index"),
        "profile_count": r.get("profile_count"),
        "request_body_len": r.get("request_body_len") or 0,
        "response_body_len": r.get("response_body_len") or 0,
        "captured_at": r.get("captured_at") or "",
        "replay_error": r.get("replay_error"),
        "duration_ms": r.get("duration_ms"),
    }


def _build_tree_nodes(rows: list[dict], root_id: str) -> list[dict]:
    """Structured parent→child nodes for the history tree view."""
    by_parent: dict[str, list[dict]] = {}
    for r in rows:
        p = str(r.get("parent_flow_id") or root_id)
        by_parent.setdefault(p, []).append(r)

    def walk(node_id: str, depth: int = 0) -> list[dict]:
        out: list[dict] = []
        for child in by_parent.get(node_id, []):
            cid = str(child.get("id"))
            out.append(
                {
                    "id": cid,
                    "parent_flow_id": child.get("parent_flow_id"),
                    "depth": depth,
                    "method": child.get("method") or "GET",
                    "url": child.get("url") or "",
                    "status_code": child.get("status_code"),
                    "verdict": child.get("verdict"),
                    "session_id": child.get("session_id"),
                    "note": child.get("note"),
                    "captured_at": child.get("captured_at") or "",
                    "duration_ms": child.get("duration_ms"),
                    "children": walk(cid, depth + 1),
                }
            )
        return out

    return walk(root_id, 0)


def _decode_raw_edit(edit: "SendEditBody") -> bytes:
    if edit.raw_base64:
        try:
            return base64.b64decode(edit.raw_base64)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=400, detail=f"invalid raw_base64: {exc}"
            ) from exc
    if edit.raw is not None:
        return edit.raw.encode("utf-8")
    raise HTTPException(
        status_code=400,
        detail="CP v1 accepts edit.raw_base64 or edit.raw only",
    )


def _precondition_http(outcome: Any) -> None:
    """Raise 404/409 when engine did not insert a flow (precondition)."""
    if outcome.execution_flow_id is not None:
        return
    reason = outcome.failure_reason or "send_failed"
    if reason == "flow_not_found":
        raise HTTPException(status_code=404, detail=f"Flow not found: {outcome.parent_flow_id}")
    if reason == "endpoint_annotated_logout":
        raise HTTPException(
            status_code=409,
            detail="Endpoint is annotated logout — send is blocked",
        )
    if reason.startswith("invalid_source"):
        raise HTTPException(status_code=400, detail=reason)
    # Other pre-insert failures (raw parse, edit error, etc.)
    raise HTTPException(status_code=400, detail=str(reason))


# ------------------------------------------------------------------ #
# Request models                                                       #
# ------------------------------------------------------------------ #


class SendEditBody(BaseModel):
    raw_base64: Optional[str] = None
    raw: Optional[str] = None
    # Structured fields rejected in v1 when no raw present (validated in route).
    headers: Optional[dict[str, str]] = None
    remove_headers: Optional[list[str]] = None
    query: Optional[dict[str, str]] = None
    json_sets: Optional[dict[str, Any]] = None
    method: Optional[str] = None
    url: Optional[str] = None
    body: Optional[str] = None


class SendProfileOnce(BaseModel):
    type: Literal["once"] = "once"


class SendProfileRepeat(BaseModel):
    type: Literal["repeat"] = "repeat"
    n: int = Field(ge=1, le=MAX_PROFILE_N)
    delay_ms: int = Field(default=0, ge=0)


class SendProfileParallel(BaseModel):
    type: Literal["parallel"] = "parallel"
    n: int = Field(ge=1, le=MAX_PROFILE_N)


class SendOnceBody(BaseModel):
    parent_flow_id: str
    source: Literal["manual_send", "ai_send"] = "manual_send"
    reason: Optional[str] = None
    note: Optional[str] = None
    session_id: Optional[str] = None
    update_content_length: bool = True
    edit: SendEditBody
    profile: dict[str, Any] = Field(default_factory=lambda: {"type": "once"})


class NoteBody(BaseModel):
    note: str = ""


class TabOpenBody(BaseModel):
    """Open (create or reuse) a Repeater tab for a parent flow."""

    flow_id: str
    title: Optional[str] = None
    session_id: Optional[str] = None
    force_new: bool = False


class TabRenameBody(BaseModel):
    title: str


class TabTouchBody(BaseModel):
    """Update tab metadata after send / fork / dup (no draft body)."""

    parent_flow_id: Optional[str] = None
    session_id: Optional[str] = None
    clear_session: bool = False
    last_execution_id: Optional[str] = None
    clear_last_execution: bool = False


class TabReorderBody(BaseModel):
    ordered_ids: list[str] = Field(default_factory=list)


# ------------------------------------------------------------------ #
# Reads                                                                #
# ------------------------------------------------------------------ #


@router.get("/draft/{flow_id}")
def get_draft(project_id: str, flow_id: str):
    """Materialize editable draft from a parent flow (no DB write)."""
    _ensure_talos_on_path()
    from talos.projects.annotations import get_annotations
    from talos.send import draft as draft_mod
    from talos.send import db as send_db

    db_path = _db_path(project_id)
    flow = send_db.get_flow_for_send(db_path, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail=f"Flow '{flow_id}' not found")

    draft = draft_mod.draft_from_flow(flow)
    raw = draft_mod.draft_to_raw_bytes(draft)
    raw_fields = _encode_raw_message(raw)

    body = draft.get("request_body")
    body_text, body_b64, body_enc = _decode_body(body)
    body_len = len(body) if isinstance(body, (bytes, bytearray)) else (
        len(body.encode("utf-8", errors="replace")) if isinstance(body, str) else 0
    )

    endpoint_id = draft.get("endpoint_id") or flow.get("endpoint_id")
    annotations: list[str] = []
    if endpoint_id:
        try:
            annotations = sorted(get_annotations(db_path, str(endpoint_id)))
        except Exception:  # noqa: BLE001
            annotations = []

    return {
        "parent_flow_id": draft["parent_flow_id"],
        "original_flow_id": draft["original_flow_id"],
        "method": draft["method"],
        "url": draft["url"],
        "host": draft.get("host") or "",
        "path": draft.get("path") or "/",
        "query": draft.get("query") or "",
        "request_headers": dict(draft.get("request_headers") or {}),
        "request_cookies": dict(draft.get("request_cookies") or {}),
        "request_body": body_text,
        "request_body_base64": body_b64,
        "request_body_encoding": body_enc,
        "request_body_len": body_len,
        "raw": raw_fields["raw"],
        "raw_base64": raw_fields["raw_base64"],
        "raw_encoding": raw_fields["raw_encoding"],
        "endpoint_id": endpoint_id,
        "parent_source": draft.get("parent_source") or flow.get("source"),
        "baseline_status_code": flow.get("status_code"),
        "endpoint_annotations": annotations,
    }


@router.get("/history")
def get_history(
    project_id: str,
    from_flow: str = Query(..., alias="from"),
    session: Optional[str] = None,
    parent: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
):
    _ensure_talos_on_path()
    from talos.send import db as send_db

    db_path = _db_path(project_id)
    parent_flow = send_db.get_flow_for_send(db_path, from_flow)
    root = send_db.resolve_root_flow_id(parent_flow) if parent_flow else from_flow

    rows = send_db.list_send_history(
        db_path,
        from_flow,
        limit=limit,
        session_id=session,
        parent_flow_id=parent,
        source=source,
    )
    return {
        "original_flow_id": root,
        "count": len(rows),
        "executions": [_history_row(r) for r in rows],
    }


@router.get("/tree")
def get_tree(
    project_id: str,
    from_flow: str = Query(..., alias="from"),
    limit: int = Query(200, ge=1, le=500),
):
    _ensure_talos_on_path()
    from talos.send import db as send_db

    db_path = _db_path(project_id)
    parent_flow = send_db.get_flow_for_send(db_path, from_flow)
    root = send_db.resolve_root_flow_id(parent_flow) if parent_flow else from_flow
    rows = send_db.list_send_history(db_path, from_flow, limit=limit)
    lines = send_db.build_send_tree(db_path, from_flow, limit=limit)
    return {
        "original_flow_id": root,
        "count": len(rows),
        "nodes": _build_tree_nodes(rows, root),
        "lines": lines,
    }


@router.get("/show/{flow_id}")
def show_flow(
    project_id: str,
    flow_id: str,
    include_bodies: bool = True,
):
    _ensure_talos_on_path()
    from talos.send import db as send_db

    db_path = _db_path(project_id)
    flow = send_db.get_flow_show(db_path, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail=f"Flow '{flow_id}' not found")

    meta = flow.get("flow_meta") or {}
    if not isinstance(meta, dict):
        meta = {}

    body_req = flow.get("request_body") if include_bodies else None
    body_resp = flow.get("response_body") if include_bodies else None
    req_text, req_b64, req_enc = _decode_body(body_req)
    resp_text, resp_b64, resp_enc = _decode_body(body_resp)

    return {
        "id": flow.get("id"),
        "method": flow.get("method"),
        "url": flow.get("url"),
        "host": flow.get("host"),
        "path": flow.get("path"),
        "query": flow.get("query") or "",
        "status_code": flow.get("status_code"),
        "source": flow.get("source"),
        "original_flow_id": flow.get("original_flow_id"),
        "parent_flow_id": meta.get("parent_flow_id"),
        "session_id": meta.get("session_id"),
        "note": meta.get("note"),
        "verdict": meta.get("verdict"),
        "profile": meta.get("profile"),
        "normalizers": list(meta.get("normalizers") or []),
        "replay_error": flow.get("replay_error"),
        "captured_at": flow.get("captured_at"),
        "response_end": flow.get("response_end"),
        "duration_ms": flow.get("duration_ms"),
        "request_body_len": flow.get("request_body_len") or 0,
        "response_body_len": flow.get("response_body_len") or 0,
        "request_headers": _header_map(flow.get("request_headers")),
        "request_cookies": _cookie_map(flow.get("request_cookies")),
        "request_body": req_text if include_bodies else None,
        "request_body_base64": req_b64 if include_bodies else None,
        "request_body_encoding": req_enc if include_bodies else "utf8",
        "response_headers": _header_map(flow.get("response_headers")),
        "response_body": resp_text if include_bodies else None,
        "response_body_base64": resp_b64 if include_bodies else None,
        "response_body_encoding": resp_enc if include_bodies else "utf8",
        "content_type": flow.get("content_type") or "",
        "endpoint_id": flow.get("endpoint_id"),
        "flow_meta": meta,
    }


@router.get("/diff")
def get_diff(
    project_id: str,
    a: str = Query(..., description="Flow A id"),
    b: str = Query(..., description="Flow B id"),
    side: Literal["request", "response", "both"] = "both",
):
    _ensure_talos_on_path()
    from talos.replay.diff import compute_diff
    from talos.send import db as send_db
    from talos.send.request_diff import compute_request_diff

    db_path = _db_path(project_id)
    flow_a = send_db.get_flow_for_send(db_path, a)
    flow_b = send_db.get_flow_for_send(db_path, b)
    if flow_a is None:
        raise HTTPException(status_code=404, detail=f"Flow '{a}' not found")
    if flow_b is None:
        raise HTTPException(status_code=404, detail=f"Flow '{b}' not found")

    result: dict[str, Any] = {"a": a, "b": b, "side": side}
    if side in ("request", "both"):
        result["request"] = compute_request_diff(flow_a, flow_b)
    if side in ("response", "both"):
        diff = compute_diff(flow_a, flow_b)
        result["response"] = {
            "verdict": diff.verdict,
            "status_changed": diff.status_changed,
            "status_diff": diff.status_diff,
            "length_diff": diff.length_diff,
        }
    return result


# ------------------------------------------------------------------ #
# Mutations                                                            #
# ------------------------------------------------------------------ #


@router.post("/once")
async def send_once_route(project_id: str, body: SendOnceBody):
    """
    Send once / repeat / parallel via in-process engine.
    CP UI always supplies edit.raw_base64 (or edit.raw).
    """
    _ensure_talos_on_path()
    from talos.send.engine import send_once, send_parallel, send_repeat

    # Reject structured-only edit (v1 closed).
    has_raw = bool(body.edit.raw_base64) or body.edit.raw is not None
    structured_keys = (
        body.edit.headers,
        body.edit.remove_headers,
        body.edit.query,
        body.edit.json_sets,
        body.edit.method,
        body.edit.url,
        body.edit.body,
    )
    if not has_raw:
        if any(x is not None for x in structured_keys):
            raise HTTPException(
                status_code=400,
                detail="CP v1 accepts edit.raw_base64 or edit.raw only",
            )
        raise HTTPException(
            status_code=400,
            detail="CP v1 accepts edit.raw_base64 or edit.raw only",
        )

    raw_bytes = _decode_raw_edit(body.edit)
    if body.source not in VALID_SOURCES:
        raise HTTPException(status_code=400, detail=f"invalid source: {body.source}")

    db_path = _db_path(project_id)
    profile = body.profile or {"type": "once"}
    ptype = profile.get("type") or "once"

    kwargs = dict(
        source=body.source,
        reason=body.reason,
        note=body.note,
        session_id=body.session_id,
        update_content_length=body.update_content_length,
        raw_message=raw_bytes,
    )

    t0 = time.perf_counter()
    try:
        if ptype == "once":
            outcome = await send_once(
                body.parent_flow_id, db_path, project_id, **kwargs
            )
            outcomes = [outcome]
            profile_name = "once"
            profile_count = 1
        elif ptype == "repeat":
            n = int(profile.get("n", 1))
            if n < 1 or n > MAX_PROFILE_N:
                raise HTTPException(
                    status_code=400,
                    detail=f"repeat n must be 1..{MAX_PROFILE_N}",
                )
            delay_ms = int(profile.get("delay_ms") or 0)
            multi = await send_repeat(
                body.parent_flow_id,
                db_path,
                project_id,
                n,
                delay_ms=delay_ms,
                **kwargs,
            )
            outcomes = multi.outcomes
            profile_name = "repeat"
            profile_count = multi.profile_count
        elif ptype == "parallel":
            n = int(profile.get("n", 1))
            if n < 1 or n > MAX_PROFILE_N:
                raise HTTPException(
                    status_code=400,
                    detail=f"parallel n must be 1..{MAX_PROFILE_N}",
                )
            multi = await send_parallel(
                body.parent_flow_id,
                db_path,
                project_id,
                n,
                concurrency=None,  # engine default min(n, 10)
                **kwargs,
            )
            outcomes = multi.outcomes
            profile_name = "parallel"
            profile_count = multi.profile_count
        else:
            raise HTTPException(
                status_code=400, detail=f"unknown profile type: {ptype}"
            )
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"send failed: {exc}") from exc

    duration_ms = int((time.perf_counter() - t0) * 1000)

    # Precondition: nothing stored (logout, missing parent, etc.)
    if not any(o.execution_flow_id for o in outcomes):
        # Prefer first outcome's failure classification
        if outcomes:
            _precondition_http(outcomes[0])
        raise HTTPException(status_code=400, detail="send produced no executions")

    ok = all(o.success for o in outcomes) if outcomes else False
    steps = [
        _synthetic_step(
            cmd_str=f"send {profile_name} {body.parent_flow_id}",
            ok=ok,
            duration_ms=duration_ms,
            stdout=_summarize_outcomes(outcomes),
            stderr=_first_failure(outcomes) if not ok else "",
        )
    ]
    hydrated = [_hydrate_outcome(o, db_path) for o in outcomes]
    original = (
        outcomes[0].original_flow_id if outcomes else body.parent_flow_id
    )
    return {
        "steps": steps,
        "result": {
            "profile": profile_name,
            "profile_count": profile_count,
            "original_flow_id": original,
            "parent_flow_id": body.parent_flow_id,
            "outcomes": hydrated,
        },
    }


@router.post("/redo/{flow_id}")
async def redo_route(project_id: str, flow_id: str, body: Optional[NoteBody] = None):
    _ensure_talos_on_path()
    from talos.send.engine import redo_send

    db_path = _db_path(project_id)
    note = body.note if body else None
    t0 = time.perf_counter()
    try:
        outcome = await redo_send(
            flow_id,
            db_path,
            project_id,
            source="manual_send",
            note=note,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"redo failed: {exc}") from exc

    duration_ms = int((time.perf_counter() - t0) * 1000)
    if outcome.execution_flow_id is None:
        _precondition_http(outcome)

    steps = [
        _synthetic_step(
            cmd_str=f"send redo {flow_id}",
            ok=outcome.success,
            duration_ms=duration_ms,
            stdout=_summarize_outcomes([outcome]),
            stderr=outcome.failure_reason or "",
        )
    ]
    return {
        "steps": steps,
        "result": {
            "profile": "once",
            "profile_count": 1,
            "original_flow_id": outcome.original_flow_id,
            "parent_flow_id": outcome.parent_flow_id,
            "outcomes": [_hydrate_outcome(outcome, db_path)],
        },
    }


@router.post("/dup/{flow_id}")
async def dup_route(project_id: str, flow_id: str):
    """
    Logical branch: mint a new session_id for subsequent sends.
    Does not fire HTTP — client stamps session_id on next Send.
    """
    _ensure_talos_on_path()
    from talos.send import db as send_db

    db_path = _db_path(project_id)
    flow = send_db.get_flow_for_send(db_path, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail=f"Flow '{flow_id}' not found")

    root = send_db.resolve_root_flow_id(flow)
    session_id = str(uuid.uuid4())
    steps = [
        _synthetic_step(
            cmd_str=f"send dup {flow_id}",
            ok=True,
            duration_ms=0,
            stdout=f"session_id={session_id}",
        )
    ]
    return {
        "steps": steps,
        "result": {
            "session_id": session_id,
            "parent_flow_id": flow_id,
            "original_flow_id": root,
        },
    }


@router.post("/note/{flow_id}")
async def note_route(project_id: str, flow_id: str, body: NoteBody):
    _ensure_talos_on_path()
    from talos.send import db as send_db

    db_path = _db_path(project_id)
    ok, err = send_db.update_send_note(db_path, flow_id, body.note)
    if not ok:
        if "not found" in err.lower():
            raise HTTPException(status_code=404, detail=err)
        raise HTTPException(status_code=400, detail=err)

    steps = [
        _synthetic_step(
            cmd_str=f"send note {flow_id}",
            ok=True,
            duration_ms=0,
            stdout="note updated",
        )
    ]
    return {
        "steps": steps,
        "result": {"ok": True, "flow_id": flow_id},
    }


@router.post("/export/{flow_id}")
async def export_route(project_id: str, flow_id: str):
    """Return request.http + response.http as base64 for browser download."""
    _ensure_talos_on_path()
    from talos.send import db as send_db
    from talos.send.raw_http import serialize_request

    db_path = _db_path(project_id)
    flow = send_db.get_flow_for_send(db_path, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail=f"Flow '{flow_id}' not found")

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

    steps = [
        _synthetic_step(
            cmd_str=f"send export {flow_id}",
            ok=True,
            duration_ms=0,
            stdout=f"request={len(req_bytes)} response={len(resp_bytes)}",
        )
    ]
    return {
        "steps": steps,
        "result": {
            "flow_id": flow_id,
            "request_http_base64": base64.b64encode(req_bytes).decode("ascii"),
            "response_http_base64": base64.b64encode(resp_bytes).decode("ascii"),
            "request_bytes": len(req_bytes),
            "response_bytes": len(resp_bytes),
        },
    }


# ------------------------------------------------------------------ #
# Repeater tab archive (project DB; metadata only)                     #
# ------------------------------------------------------------------ #


@router.get("/tabs")
def list_tabs(project_id: str):
    """
    Global Repeater tab archive for the project.
    Draft bodies are not stored — UI re-materializes from parent_flow_id.
    """
    _ensure_talos_on_path()
    from talos.send import db as send_db

    db_path = _db_path(project_id)
    tabs = send_db.list_repeater_tabs(db_path, project_id)
    return {"tabs": tabs, "count": len(tabs)}


@router.get("/tabs/{tab_id}")
def get_tab(project_id: str, tab_id: str):
    _ensure_talos_on_path()
    from talos.send import db as send_db

    db_path = _db_path(project_id)
    tab = send_db.get_repeater_tab(db_path, tab_id)
    if tab is None:
        raise HTTPException(status_code=404, detail=f"Repeater tab '{tab_id}' not found")
    return {"tab": tab}


@router.post("/tabs")
async def open_tab(project_id: str, body: TabOpenBody):
    """
    Send to Repeater: create or reuse a sticky tab for flow_id.
    Synthetic steps for CommandLog. No draft body write.
    """
    _ensure_talos_on_path()
    from talos.send import db as send_db

    db_path = _db_path(project_id)
    t0 = time.monotonic()
    try:
        result = send_db.open_repeater_tab(
            db_path,
            project_id,
            body.flow_id,
            title=body.title,
            session_id=body.session_id,
            reuse_same_parent=not body.force_new,
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=404, detail=f"Flow '{body.flow_id}' not found"
        ) from None
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    duration_ms = int((time.monotonic() - t0) * 1000)
    tab = result["tab"]
    action = "reused" if result["reused"] else "opened"
    steps = [
        _synthetic_step(
            cmd_str=f"send tab open {body.flow_id}",
            ok=True,
            duration_ms=duration_ms,
            stdout=f"tab {action} id={tab['id']}",
        )
    ]
    return {
        "steps": steps,
        "result": {
            "tab": tab,
            "created": result["created"],
            "reused": result["reused"],
        },
    }


@router.post("/tabs/{tab_id}/rename")
async def rename_tab(project_id: str, tab_id: str, body: TabRenameBody):
    _ensure_talos_on_path()
    from talos.send import db as send_db

    db_path = _db_path(project_id)
    try:
        tab = send_db.rename_repeater_tab(db_path, tab_id, body.title)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    if tab is None:
        raise HTTPException(status_code=404, detail=f"Repeater tab '{tab_id}' not found")
    steps = [
        _synthetic_step(
            cmd_str=f"send tab rename {tab_id}",
            ok=True,
            duration_ms=0,
            stdout=f"title={tab['title']}",
        )
    ]
    return {"steps": steps, "result": {"tab": tab}}


@router.post("/tabs/{tab_id}/touch")
async def touch_tab(project_id: str, tab_id: str, body: TabTouchBody):
    """Update last_execution / parent / session after send or fork."""
    _ensure_talos_on_path()
    from talos.send import db as send_db

    if body.clear_session and body.session_id:
        raise HTTPException(
            status_code=400,
            detail="Use either session_id or clear_session, not both",
        )
    if body.clear_last_execution and body.last_execution_id:
        raise HTTPException(
            status_code=400,
            detail="Use either last_execution_id or clear_last_execution, not both",
        )
    db_path = _db_path(project_id)
    tab = send_db.touch_repeater_tab(
        db_path,
        tab_id,
        parent_flow_id=body.parent_flow_id,
        session_id=body.session_id,
        last_execution_id=body.last_execution_id,
        clear_session=body.clear_session,
        clear_last_execution=body.clear_last_execution,
    )
    if tab is None:
        raise HTTPException(status_code=404, detail=f"Repeater tab '{tab_id}' not found")
    steps = [
        _synthetic_step(
            cmd_str=f"send tab touch {tab_id}",
            ok=True,
            duration_ms=0,
            stdout="updated",
        )
    ]
    return {"steps": steps, "result": {"tab": tab}}


@router.post("/tabs/reorder")
async def reorder_tabs(project_id: str, body: TabReorderBody):
    _ensure_talos_on_path()
    from talos.send import db as send_db

    db_path = _db_path(project_id)
    tabs = send_db.reorder_repeater_tabs(db_path, project_id, body.ordered_ids)
    steps = [
        _synthetic_step(
            cmd_str="send tab reorder",
            ok=True,
            duration_ms=0,
            stdout=f"count={len(tabs)}",
        )
    ]
    return {"steps": steps, "result": {"tabs": tabs, "count": len(tabs)}}


@router.delete("/tabs/{tab_id}")
async def close_tab(project_id: str, tab_id: str):
    """Close a tab (flows/history kept)."""
    _ensure_talos_on_path()
    from talos.send import db as send_db

    db_path = _db_path(project_id)
    ok = send_db.close_repeater_tab(db_path, tab_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Repeater tab '{tab_id}' not found")
    steps = [
        _synthetic_step(
            cmd_str=f"send tab close {tab_id}",
            ok=True,
            duration_ms=0,
            stdout="closed",
        )
    ]
    return {"steps": steps, "result": {"id": tab_id, "closed": True}}


@router.delete("/tabs")
async def clear_tabs(project_id: str):
    """Close all tabs for the project (flows kept)."""
    _ensure_talos_on_path()
    from talos.send import db as send_db

    db_path = _db_path(project_id)
    n = send_db.clear_repeater_tabs(db_path, project_id)
    steps = [
        _synthetic_step(
            cmd_str="send tab clear",
            ok=True,
            duration_ms=0,
            stdout=f"cleared={n}",
        )
    ]
    return {"steps": steps, "result": {"cleared": n}}
