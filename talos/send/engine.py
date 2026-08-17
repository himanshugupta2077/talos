"""
Module: talos.send.engine

Purpose:
    Repeater send execution (Mode 2 — mutable).

    Load parent flow → build draft → apply edits → normalize → send via
    the same HTTP stack as exact replay (httpx, 30s timeout, no redirects,
    project upstream proxy) → INSERT a new flow (never UPDATE parent) →
    compute_diff vs root capture (or parent when root missing).

    Sources: manual_send | ai_send only. Never auto_replay / manual_replay.

    Phase 2:
        - flow_meta: session_id, note, profile, profile_index/count, verdict
        - send_repeat / send_parallel wrappers around send_once
        - redo_send: re-fire as-sent request without re-edits

Design constraints:
    - Captured flows stay immutable.
    - Store request as actually prepared for send (headers after normalizers).
    - Failed network sends still insert a flow with replay_error.
    - Logout annotation blocks send; dangerous is allowed for manual/AI.
    - Hard caps: repeat/parallel N ≤ 50; parallel concurrency ≤ 10.

Dependencies: asyncio, httpx, uuid, datetime, json
              talos.replay.db, talos.replay.diff, talos.projects.proxy_config,
              talos.projects.annotations, talos.send.*
Data flow:
    CLI → send_once / send_multi / redo_send → SendOutcome(s)
Side effects:
    - Outbound HTTP request(s).
    - One new flows row per attempt + optional replay_diffs row.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

import talos.replay.db as replay_db
from talos.projects.annotations import get_annotations
from talos.proxy.http_client import create_async_client
from talos.replay.diff import DiffResult, compute_diff
from talos.send import draft as draft_mod
from talos.send import db as send_db
from talos.send.normalize import apply_content_length

logger = logging.getLogger(__name__)

# Match exact-replay timeout so behaviour is comparable.
_SEND_TIMEOUT = httpx.Timeout(30.0)

VALID_SOURCES: frozenset[str] = frozenset({"manual_send", "ai_send"})

# Phase 2 hard caps (documented in CLI help / cheat sheet).
MAX_PROFILE_N = 50
MAX_PARALLEL_CONCURRENCY = 10


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
        session_id        — optional investigation branch id.
        profile           — once | repeat | parallel.
        profile_index     — 0-based index within a multi-send profile.
        profile_count     — total attempts in the profile.
        note              — optional operator note stored in flow_meta.
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
    session_id: Optional[str] = None
    profile: str = "once"
    profile_index: int = 0
    profile_count: int = 1
    note: Optional[str] = None


@dataclass
class MultiSendOutcome:
    """Aggregate result for --repeat / --parallel profiles."""

    parent_flow_id: str
    original_flow_id: str
    profile: str
    profile_count: int
    session_id: Optional[str]
    outcomes: list[SendOutcome] = field(default_factory=list)

    @property
    def execution_flow_ids(self) -> list[str]:
        return [o.execution_flow_id for o in self.outcomes if o.execution_flow_id]

    @property
    def any_stored(self) -> bool:
        return bool(self.execution_flow_ids)

    @property
    def all_success(self) -> bool:
        return bool(self.outcomes) and all(o.success for o in self.outcomes)


async def send_once(
    parent_flow_id: str,
    db_path: Path,
    project_id: str,
    *,
    source: str = "manual_send",
    reason: Optional[str] = None,
    note: Optional[str] = None,
    session_id: Optional[str] = None,
    update_content_length: bool = True,
    method: Optional[str] = None,
    url: Optional[str] = None,
    headers: Optional[list[tuple[str, str]]] = None,
    remove_headers: Optional[list[str]] = None,
    query_params: Optional[list[tuple[str, str]]] = None,
    remove_query: Optional[list[str]] = None,
    cookies: Optional[list[tuple[str, str]]] = None,
    remove_cookies: Optional[list[str]] = None,
    path: Optional[str] = None,
    host: Optional[str] = None,
    sync_host_header: bool = True,
    json_sets: Optional[list[tuple[str, str]]] = None,
    body: Optional[bytes] = None,
    body_set: bool = False,
    raw_message: Optional[bytes] = None,
    profile: str = "once",
    profile_index: int = 0,
    profile_count: int = 1,
    # When True (redo path): draft from parent as-is; skip structured/raw patches
    # and force update_content_length=False so as-sent bytes are re-fired.
    exact_as_sent: bool = False,
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
        note           — optional note stored in flow_meta.note.
        session_id     — optional branch id stored in flow_meta.session_id.
        update_content_length — default True (Burp-like CL fix).
        Structured / raw edit kwargs — see draft.apply_*.
        profile / profile_index / profile_count — multi-send metadata.
        exact_as_sent  — redo mode: no re-edit, no CL re-normalize.
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
            session_id=session_id,
            profile=profile,
            profile_index=profile_index,
            profile_count=profile_count,
            note=note,
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
            session_id=session_id,
            profile=profile,
            profile_index=profile_index,
            profile_count=profile_count,
            note=note,
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
                session_id=session_id,
                profile=profile,
                profile_index=profile_index,
                profile_count=profile_count,
                note=note,
            )

    # Build draft and apply edits.
    draft = draft_mod.draft_from_flow(parent)
    edit_mode = "structured"
    cl_enabled = update_content_length

    if exact_as_sent:
        # Re-fire stored request as-is (redo). Do not re-normalize CL.
        edit_mode = "raw"
        cl_enabled = False
    else:
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
                    session_id=session_id,
                    profile=profile,
                    profile_index=profile_index,
                    profile_count=profile_count,
                    note=note,
                )

        try:
            draft = draft_mod.apply_structured_patches(
                draft,
                method=method,
                url=url,
                headers=headers,
                remove_headers=remove_headers,
                query_params=query_params,
                remove_query=remove_query,
                cookies=cookies,
                remove_cookies=remove_cookies,
                path=path,
                host=host,
                sync_host_header=sync_host_header,
                json_sets=json_sets,
                body=body,
                body_set=body_set,
            )
        except ValueError as exc:
            return SendOutcome(
                execution_flow_id=None,
                parent_flow_id=parent_flow_id,
                original_flow_id=root_id,
                status_code=None,
                success=False,
                failure_reason=f"edit_error: {exc}",
                verdict=None,
                source=source,
                session_id=session_id,
                profile=profile,
                profile_index=profile_index,
                profile_count=profile_count,
                note=note,
            )

        structured_used = any(
            x is not None
            for x in (
                method,
                url,
                headers,
                remove_headers,
                query_params,
                remove_query,
                cookies,
                remove_cookies,
                path,
                host,
                json_sets,
            )
        ) or body_set
        if structured_used:
            if raw_message is None:
                edit_mode = "structured"
            else:
                edit_mode = "hybrid"

    # Normalize Content-Length policy.
    headers_out = dict(draft.get("request_headers") or {})
    body_out: Optional[bytes] = draft.get("request_body")
    normalizers = apply_content_length(
        headers_out,
        body_out,
        enabled=cl_enabled,
    )

    send_headers = dict(headers_out)

    execution_id = str(uuid.uuid4())
    send_time = datetime.now(timezone.utc).isoformat()
    req_len = len(body_out) if body_out else 0

    flow_meta: dict = {
        "kind": "send",
        "parent_flow_id": parent_flow_id,
        "update_content_length": bool(cl_enabled),
        "edit_mode": edit_mode,
        "normalizers": list(normalizers),
        "profile": profile,
        "profile_index": int(profile_index),
        "profile_count": int(profile_count),
    }
    if session_id:
        flow_meta["session_id"] = session_id
    if note:
        flow_meta["note"] = note

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
        async with create_async_client(
            db_path,
            timeout=_SEND_TIMEOUT,
            follow_redirects=False,
            verify=False,
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

    # Diff vs root capture when available, else vs parent — compute before
    # insert so we can store verdict on flow_meta for history lists.
    baseline = _load_diff_baseline(db_path, root_id, parent)
    diff: DiffResult = compute_diff(baseline, stored)
    flow_meta["verdict"] = diff.verdict
    stored["flow_meta"] = flow_meta

    # Always persist — success or failure (same contract as exact replay).
    replay_db.insert_replayed_flow(db_path, stored)

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
        session_id=session_id,
        profile=profile,
        profile_index=profile_index,
        profile_count=profile_count,
        note=note,
    )


async def send_repeat(
    parent_flow_id: str,
    db_path: Path,
    project_id: str,
    n: int,
    *,
    delay_ms: int = 0,
    **kwargs,
) -> MultiSendOutcome:
    """
    Purpose:
        Sequential N× send of the same draft (after edits). Hard cap N ≤ 50.
    """
    n = _validate_profile_n(n)
    session_id = kwargs.get("session_id")
    outcomes: list[SendOutcome] = []
    root_id = parent_flow_id
    for i in range(n):
        outcome = await send_once(
            parent_flow_id,
            db_path,
            project_id,
            profile="repeat",
            profile_index=i,
            profile_count=n,
            **kwargs,
        )
        outcomes.append(outcome)
        if outcome.original_flow_id:
            root_id = outcome.original_flow_id
        if delay_ms > 0 and i < n - 1:
            await asyncio.sleep(delay_ms / 1000.0)
    return MultiSendOutcome(
        parent_flow_id=parent_flow_id,
        original_flow_id=root_id,
        profile="repeat",
        profile_count=n,
        session_id=session_id,
        outcomes=outcomes,
    )


async def send_parallel(
    parent_flow_id: str,
    db_path: Path,
    project_id: str,
    n: int,
    *,
    concurrency: Optional[int] = None,
    **kwargs,
) -> MultiSendOutcome:
    """
    Purpose:
        Concurrent N× send of the same draft. Concurrency ≤ min(N, 10). Cap N ≤ 50.
    """
    n = _validate_profile_n(n)
    conc = concurrency if concurrency is not None else min(n, MAX_PARALLEL_CONCURRENCY)
    conc = max(1, min(conc, MAX_PARALLEL_CONCURRENCY, n))
    session_id = kwargs.get("session_id")
    sem = asyncio.Semaphore(conc)

    async def _one(i: int) -> SendOutcome:
        async with sem:
            return await send_once(
                parent_flow_id,
                db_path,
                project_id,
                profile="parallel",
                profile_index=i,
                profile_count=n,
                **kwargs,
            )

    outcomes = list(await asyncio.gather(*[_one(i) for i in range(n)]))
    # Preserve index order (gather already does).
    root_id = parent_flow_id
    for o in outcomes:
        if o.original_flow_id:
            root_id = o.original_flow_id
            break
    return MultiSendOutcome(
        parent_flow_id=parent_flow_id,
        original_flow_id=root_id,
        profile="parallel",
        profile_count=n,
        session_id=session_id,
        outcomes=outcomes,
    )


async def redo_send(
    execution_flow_id: str,
    db_path: Path,
    project_id: str,
    *,
    source: str = "manual_send",
    reason: Optional[str] = None,
    note: Optional[str] = None,
    session_id: Optional[str] = None,
) -> SendOutcome:
    """
    Purpose:
        Re-send the exact as-sent request of a previous send (or any flow).
        New child row; parent = that execution; no re-edits / no CL re-fix.
    """
    return await send_once(
        execution_flow_id,
        db_path,
        project_id,
        source=source,
        reason=reason,
        note=note,
        session_id=session_id,
        exact_as_sent=True,
        profile="once",
        profile_index=0,
        profile_count=1,
    )


def _validate_profile_n(n: int) -> int:
    if not isinstance(n, int) or n < 1:
        raise ValueError(f"--repeat/--parallel N must be >= 1 (got {n!r})")
    if n > MAX_PROFILE_N:
        raise ValueError(
            f"--repeat/--parallel N must be <= {MAX_PROFILE_N} (got {n})"
        )
    return n


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
