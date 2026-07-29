"""
Module: talos.send.engine

Purpose:
    Repeater send-once execution (Mode 2 — mutable).

    Load parent flow → build draft → apply edits → normalize → send via
    the same HTTP stack as exact replay (httpx, 30s timeout, no redirects,
    project upstream proxy) → INSERT a new flow (never UPDATE parent) →
    compute_diff vs root capture (or parent when root missing).

    Sources: manual_send | ai_send only. Never auto_replay / manual_replay.

Design constraints:
    - Captured flows stay immutable.
    - Store request as actually prepared for send (headers after normalizers).
    - Failed network sends still insert a flow with replay_error.
    - Logout annotation blocks send; dangerous is allowed for manual/AI.

Dependencies: asyncio patterns via httpx, uuid, datetime, json
              talos.replay.db, talos.replay.diff, talos.projects.proxy_config,
              talos.projects.annotations, talos.send.*
Data flow:
    CLI → send_once(parent_id, patches…) → SendOutcome
Side effects:
    - Outbound HTTP request.
    - One new flows row + optional replay_diffs row.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

import talos.replay.db as replay_db
from talos.projects.annotations import get_annotations
from talos.projects.proxy_config import get_upstream_url
from talos.replay.diff import DiffResult, compute_diff
from talos.send import draft as draft_mod
from talos.send import db as send_db
from talos.send.normalize import apply_content_length

logger = logging.getLogger(__name__)

# Match exact-replay timeout so behaviour is comparable.
_SEND_TIMEOUT = httpx.Timeout(30.0)

VALID_SOURCES: frozenset[str] = frozenset({"manual_send", "ai_send"})


@dataclass
class SendOutcome:
    """
    Purpose:
        Result of a single send-once attempt for CLI / automation.

    Fields:
        execution_flow_id — new flow UUID (None only if never stored).
        parent_flow_id    — flow forked from.
        original_flow_id  — root capture id.
        status_code       — HTTP status or None on network failure.
        success           — True when an HTTP response was received.
        failure_reason    — error label; None on success.
        verdict           — SAME | DIFFERENT | ERROR (None if flow not found).
        request_body_len  — bytes of body as sent.
        response_body_len — bytes of response body (0 when absent).
        source            — manual_send | ai_send.
    """

    execution_flow_id: Optional[str]
    parent_flow_id: str
    original_flow_id: str
    status_code: Optional[int]
    success: bool
    failure_reason: Optional[str]
    verdict: Optional[str]
    request_body_len: int = 0
    response_body_len: int = 0
    source: str = "manual_send"


async def send_once(
    parent_flow_id: str,
    db_path: Path,
    project_id: str,
    *,
    source: str = "manual_send",
    reason: Optional[str] = None,
    update_content_length: bool = True,
    method: Optional[str] = None,
    url: Optional[str] = None,
    headers: Optional[list[tuple[str, str]]] = None,
    remove_headers: Optional[list[str]] = None,
    query_params: Optional[list[tuple[str, str]]] = None,
    body: Optional[bytes] = None,
    body_set: bool = False,
    raw_message: Optional[bytes] = None,
) -> SendOutcome:
    """
    Purpose:
        Fork a draft from parent_flow_id, apply edits, send once, persist.
    Input:
        parent_flow_id — baseline or previous execution to fork from.
        db_path        — project talos.db.
        project_id     — stamped on the new flow.
        source         — manual_send | ai_send.
        reason         — optional label stored as replay_reason.
        update_content_length — default True (Burp-like CL fix).
        Structured / raw edit kwargs — see draft.apply_*.
    Output:
        SendOutcome.
    Side effects:
        HTTP send; INSERT new flow; INSERT replay_diff best-effort.
    """
    if source not in VALID_SOURCES:
        return SendOutcome(
            execution_flow_id=None,
            parent_flow_id=parent_flow_id,
            original_flow_id=parent_flow_id,
            status_code=None,
            success=False,
            failure_reason=f"invalid_source:{source}",
            verdict=None,
            source=source,
        )

    parent = send_db.get_flow_for_send(db_path, parent_flow_id)
    if parent is None:
        return SendOutcome(
            execution_flow_id=None,
            parent_flow_id=parent_flow_id,
            original_flow_id=parent_flow_id,
            status_code=None,
            success=False,
            failure_reason="flow_not_found",
            verdict=None,
            source=source,
        )

    root_id = send_db.resolve_root_flow_id(parent)

    # Annotation guards: logout always blocks; dangerous allowed for send sources.
    endpoint_id: Optional[str] = parent.get("endpoint_id")
    if endpoint_id:
        tags = get_annotations(db_path, endpoint_id)
        if "logout" in tags:
            return SendOutcome(
                execution_flow_id=None,
                parent_flow_id=parent_flow_id,
                original_flow_id=root_id,
                status_code=None,
                success=False,
                failure_reason="endpoint_annotated_logout",
                verdict=None,
                source=source,
            )

    # Build draft and apply edits.
    draft = draft_mod.draft_from_flow(parent)
    edit_mode = "structured"
    if raw_message is not None:
        try:
            draft = draft_mod.apply_raw_message(draft, raw_message)
            edit_mode = "raw"
        except ValueError as exc:
            return SendOutcome(
                execution_flow_id=None,
                parent_flow_id=parent_flow_id,
                original_flow_id=root_id,
                status_code=None,
                success=False,
                failure_reason=f"raw_parse_error: {exc}",
                verdict=None,
                source=source,
            )

    draft = draft_mod.apply_structured_patches(
        draft,
        method=method,
        url=url,
        headers=headers,
        remove_headers=remove_headers,
        query_params=query_params,
        body=body,
        body_set=body_set,
    )
    if any(
        x is not None
        for x in (method, url, headers, remove_headers, query_params)
    ) or body_set:
        # Structured patches after raw still count as hybrid; prefer structured
        # only when no raw was used, else keep raw if that was primary.
        if raw_message is None:
            edit_mode = "structured"
        else:
            edit_mode = "raw"

    # Normalize Content-Length policy.
    headers_out = dict(draft.get("request_headers") or {})
    body_out: Optional[bytes] = draft.get("request_body")
    normalizers = apply_content_length(
        headers_out,
        body_out,
        enabled=update_content_length,
    )

    # When CL update is off, send headers/body exactly as draft specifies.
    # When on, headers_out already has correct CL (or no CL for empty body).
    # For the on path we still strip CL from the wire request and let httpx
    # set it only if we did not set it — we set it explicitly so stored
    # headers match. Pass headers_out as-is either way.
    send_headers = dict(headers_out)

    execution_id = str(uuid.uuid4())
    send_time = datetime.now(timezone.utc).isoformat()
    req_len = len(body_out) if body_out else 0

    flow_meta = {
        "kind": "send",
        "parent_flow_id": parent_flow_id,
        "update_content_length": bool(update_content_length),
        "edit_mode": edit_mode,
        "normalizers": list(normalizers),
    }

    stored: dict = {
        "id": execution_id,
        "project_id": project_id,
        "captured_at": send_time,
        "response_end": None,
        "method": draft["method"],
        "url": draft["url"],
        "host": draft["host"],
        "path": draft["path"],
        "query": draft.get("query") or "",
        # As-sent headers after normalization.
        "request_headers": json.dumps(send_headers),
        "request_cookies": json.dumps(draft.get("request_cookies") or {}),
        "request_body": body_out,
        "request_body_truncated": 0,
        "status_code": None,
        "response_headers": "{}",
        "response_body": None,
        "response_body_truncated": 0,
        "content_type": "",
        "endpoint_id": draft.get("endpoint_id") or parent.get("endpoint_id"),
        "role_id": draft.get("role_id") or parent["role_id"],
        "module_id": draft.get("module_id") or parent["module_id"],
        "source": source,
        "original_flow_id": root_id,
        "replay_error": None,
        "replay_reason": reason,
        "flow_meta": flow_meta,
    }

    failure_reason: Optional[str] = None

    try:
        async with httpx.AsyncClient(
            verify=False,
            proxy=get_upstream_url(db_path),
            follow_redirects=False,
            timeout=_SEND_TIMEOUT,
        ) as client:
            resp = await client.request(
                method=draft["method"],
                url=draft["url"],
                headers=send_headers,
                content=body_out,
            )

        response_end = datetime.now(timezone.utc).isoformat()
        resp_body: Optional[bytes] = resp.content if resp.content else None
        stored.update(
            {
                "response_end": response_end,
                "status_code": resp.status_code,
                "response_headers": json.dumps(dict(resp.headers)),
                "response_body": resp_body,
                "content_type": resp.headers.get("content-type", ""),
            }
        )
    except httpx.ConnectError as exc:
        failure_reason = f"connection_error: {exc}"
        stored["replay_error"] = "connection_error"
    except httpx.TimeoutException as exc:
        failure_reason = f"timeout: {exc}"
        stored["replay_error"] = "timeout"
    except httpx.HTTPError as exc:
        failure_reason = f"http_error: {exc}"
        stored["replay_error"] = "http_error"
    except Exception as exc:  # noqa: BLE001
        failure_reason = f"unexpected_error: {exc}"
        stored["replay_error"] = "unexpected_error"

    # Always persist — success or failure (same contract as exact replay).
    replay_db.insert_replayed_flow(db_path, stored)

    # Diff vs root capture when available, else vs parent.
    baseline = _load_diff_baseline(db_path, root_id, parent)
    diff: DiffResult = compute_diff(baseline, stored)
    try:
        replay_db.insert_replay_diff(
            db_path,
            {
                "replay_flow_id": execution_id,
                "original_flow_id": root_id,
                "verdict": diff.verdict,
                "status_changed": diff.status_changed,
                "status_diff": diff.status_diff,
                "length_diff": diff.length_diff,
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Failed to store diff for send %s: %s", execution_id, exc
        )

    resp_len = len(stored["response_body"]) if stored.get("response_body") else 0

    return SendOutcome(
        execution_flow_id=execution_id,
        parent_flow_id=parent_flow_id,
        original_flow_id=root_id,
        status_code=stored.get("status_code"),
        success=failure_reason is None,
        failure_reason=failure_reason,
        verdict=diff.verdict,
        request_body_len=req_len,
        response_body_len=resp_len,
        source=source,
    )


def _load_diff_baseline(
    db_path: Path,
    root_id: str,
    parent: dict,
) -> dict:
    """
    Purpose:
        Prefer the root capture for response diff; fall back to parent.
    """
    if root_id and root_id != parent.get("id"):
        root = send_db.get_flow_for_send(db_path, root_id)
        if root is not None:
            return root
    return parent
