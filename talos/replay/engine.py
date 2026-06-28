"""
Module: talos.replay.engine

Purpose:
    Core async replay execution layer.
    Given a flow_id or endpoint_id, reconstructs the original HTTP request
    exactly as captured, sends it, and stores the result as a new flow
    (source=auto_replay) linked to the original.

    This is Mode 1 — exact replay.  No mutation, no header stripping,
    no token refresh.  The original request is sent unchanged.

Design constraints (hard — do not violate):
    - No mutation of request fields.
    - No header stripping.
    - No token regeneration.
    - No retries (deterministic behaviour).
    - Redirects disabled (clarity; no scope drift).
    - Failed replays are stored, not silently discarded.

Dependencies: asyncio, httpx, json, uuid, datetime, pathlib
              talos.replay.db
Data flow:
    CLI → replay_flow / replay_endpoint
        → _execute_replay
            → httpx.AsyncClient.request()
            → replay_db.insert_replayed_flow()
Side effects:
    - Sends outbound HTTP request.
    - Writes one new flow row per call to the project database.
"""

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

import talos.replay.db as replay_db
from talos.projects.annotations import get_annotations
from talos.replay.diff import DiffResult, compute_diff

# Single shared timeout for all replay requests.
# 30 s is generous enough for slow targets without hanging indefinitely.
_REPLAY_TIMEOUT = httpx.Timeout(30.0)


# ------------------------------------------------------------------ #
# Public result type                                                   #
# ------------------------------------------------------------------ #

@dataclass
class ReplayOutcome:
    """
    Purpose:
        Carries the result of a single replay attempt back to the CLI.

    Fields:
        original_flow_id  — UUID of the flow that was replayed.
        replayed_flow_id  — UUID of the newly stored replay flow, or None if
                            the replay could not be stored (DB failure).
        status_code       — HTTP status code from the replay response, or None
                            when a network-level error prevented a response.
        success           — True when an HTTP response was received (any status).
                            False only on connection/timeout/unexpected errors.
        failure_reason    — Human-readable error description; None on success.
        verdict           — Diff verdict: SAME | DIFFERENT | ERROR.
                            None only when the flow was never reached (flow_not_found
                            / no_qualifying_flow).
    """
    original_flow_id: str
    replayed_flow_id: Optional[str]
    status_code: Optional[int]
    success: bool
    failure_reason: Optional[str]
    verdict: Optional[str]


# ------------------------------------------------------------------ #
# Public replay entry points                                           #
# ------------------------------------------------------------------ #

async def replay_flow(
    flow_id: str,
    db_path: Path,
    project_id: str,
    source: str = "auto_replay",
    replay_reason: Optional[str] = None,
) -> ReplayOutcome:
    """
    Purpose:
        Replay a stored flow exactly as captured.
    Input:
        flow_id      — UUID of the source flow.
        db_path      — Path to the project's talos.db.
        project_id   — Project identifier; stamped on the new replay flow.
        source       — Flow source label for the stored replay row.
                       'manual_replay' for user-triggered calls;
                       'auto_replay' for system-triggered calls.
        replay_reason — Optional label describing why this replay was triggered
                        (e.g. 'testing', 'bac_test', 'idor_test', 'validation').
                        NULL when not provided.
    Output:
        ReplayOutcome describing success or failure.
    Side effects:
        Sends an HTTP request; writes one replay flow to the DB.
    """
    flow = replay_db.get_flow_for_replay(db_path, flow_id)
    if flow is None:
        return ReplayOutcome(
            original_flow_id=flow_id,
            replayed_flow_id=None,
            status_code=None,
            success=False,
            failure_reason="flow_not_found",
            verdict=None,
        )

    # Guard: check endpoint annotations before sending.
    # logout  → blocked in all modes (manual and auto).
    # dangerous → blocked only for auto_replay; manual callers may override.
    endpoint_id: Optional[str] = flow.get("endpoint_id")
    if endpoint_id:
        tags = get_annotations(db_path, endpoint_id)
        if "logout" in tags:
            return ReplayOutcome(
                original_flow_id=flow_id,
                replayed_flow_id=None,
                status_code=None,
                success=False,
                failure_reason="endpoint_annotated_logout",
                verdict=None,
            )
        if "dangerous" in tags and source == "auto_replay":
            return ReplayOutcome(
                original_flow_id=flow_id,
                replayed_flow_id=None,
                status_code=None,
                success=False,
                failure_reason="endpoint_annotated_dangerous",
                verdict=None,
            )

    return await _execute_replay(flow, db_path, project_id, source, replay_reason)


async def replay_endpoint(
    endpoint_id: str,
    db_path: Path,
    project_id: str,
    source: str = "auto_replay",
    replay_reason: Optional[str] = None,
) -> ReplayOutcome:
    """
    Purpose:
        Select the best qualifying flow for an endpoint and replay it.
        Best = most recent proxy_capture flow with status_code=200.
    Input:
        endpoint_id  — UUID of the target endpoint.
        db_path      — Path to the project's talos.db.
        project_id   — Project identifier; stamped on the new replay flow.
        source       — Flow source label for the stored replay row.
                       'manual_replay' for user-triggered calls;
                       'auto_replay' for system-triggered calls.
        replay_reason — Optional label describing why this replay was triggered.
    Output:
        ReplayOutcome.  failure_reason='no_qualifying_flow' when the endpoint
        has no 200 OK proxy_capture flow — caller should surface this to the user.
    Side effects:
        Sends an HTTP request; writes one replay flow to the DB on success.
    """
    # Guard: check endpoint annotations before selecting a flow.
    # logout  → blocked in all modes.
    # dangerous → blocked only for auto_replay.
    tags = get_annotations(db_path, endpoint_id)
    if "logout" in tags:
        return ReplayOutcome(
            original_flow_id="",
            replayed_flow_id=None,
            status_code=None,
            success=False,
            failure_reason="endpoint_annotated_logout",
            verdict=None,
        )
    if "dangerous" in tags and source == "auto_replay":
        return ReplayOutcome(
            original_flow_id="",
            replayed_flow_id=None,
            status_code=None,
            success=False,
            failure_reason="endpoint_annotated_dangerous",
            verdict=None,
        )

    flow = replay_db.get_best_flow_for_endpoint(db_path, endpoint_id)
    if flow is None:
        return ReplayOutcome(
            original_flow_id="",
            replayed_flow_id=None,
            status_code=None,
            success=False,
            failure_reason="no_qualifying_flow",
            verdict=None,
        )
    return await _execute_replay(flow, db_path, project_id, source, replay_reason)


# ------------------------------------------------------------------ #
# Internal execution                                                   #
# ------------------------------------------------------------------ #

async def _execute_replay(
    flow: dict,
    db_path: Path,
    project_id: str,
    source: str,
    replay_reason: Optional[str],
    flow_meta: Optional[dict] = None,
) -> ReplayOutcome:
    """
    Purpose:
        Send the exact stored HTTP request and persist the result.
        Called by both replay_flow and replay_endpoint after flow selection.
    Input:
        flow          — flow dict from replay_db with all request fields.
        db_path       — Path to the project's talos.db.
        project_id    — Project identifier for the new replay row.
        source        — 'manual_replay' | 'auto_replay' | 'iv_scan' — origin.
        replay_reason — Optional reason label (e.g. 'testing', 'bac_test',
                        'input_validation').
        flow_meta     — Optional structured metadata dict stored as JSON on the
                        replay flow.  Used by IV and future attack modules to
                        make every replay flow self-describing.
    Output:
        ReplayOutcome.
    Side effects:
        Sends outbound HTTP request.
        Writes one new flow row via replay_db.insert_replayed_flow.
    """
    original_flow_id: str = flow["id"]

    # Deserialise headers from JSON string (stored as TEXT in DB).
    # Cookies are already embedded in the Cookie request header, so we do
    # not separately handle request_cookies — they arrive with the headers.
    raw_headers: object = flow.get("request_headers", "{}")
    headers: dict = (
        json.loads(raw_headers)
        if isinstance(raw_headers, str)
        else dict(raw_headers)
    )

    body: Optional[bytes] = flow.get("request_body")  # BLOB or None from DB

    replayed_flow_id = str(uuid.uuid4())
    replay_time = datetime.now(timezone.utc).isoformat()

    # Pre-build the replay row with request fields from the original.
    # Response fields are filled in after the HTTP call completes.
    # On connection failure they remain at their default (None / empty).
    replayed: dict = {
        "id": replayed_flow_id,
        "project_id": project_id,
        "captured_at": replay_time,       # replay start time
        "response_end": None,
        "method": flow["method"],
        "url": flow["url"],
        "host": flow["host"],
        "path": flow["path"],
        "query": flow.get("query", ""),
        "request_headers": flow.get("request_headers", "{}"),
        "request_cookies": flow.get("request_cookies", "{}"),
        "request_body": body,
        "request_body_truncated": flow.get("request_body_truncated", 0),
        "status_code": None,
        "response_headers": "{}",
        "response_body": None,
        "response_body_truncated": 0,
        "content_type": "",
        "endpoint_id": flow.get("endpoint_id"),
        # Preserve capture-time identity — replay inherits original role/module
        # so access-control analysis can correlate results correctly.
        "role_id": flow["role_id"],
        "module_id": flow["module_id"],
        "source": source,
        "original_flow_id": original_flow_id,
        "replay_error": None,
        "replay_reason": replay_reason,
        "flow_meta": flow_meta or {},
    }

    failure_reason: Optional[str] = None

    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=_REPLAY_TIMEOUT,
        ) as client:
            resp = await client.request(
                method=flow["method"],
                url=flow["url"],
                headers=headers,
                content=body,   # raw bytes — no encoding or transformation
            )

        response_end = datetime.now(timezone.utc).isoformat()
        resp_body: Optional[bytes] = resp.content if resp.content else None

        replayed.update(
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
        replayed["replay_error"] = "connection_error"

    except httpx.TimeoutException as exc:
        failure_reason = f"timeout: {exc}"
        replayed["replay_error"] = "timeout"

    except httpx.HTTPError as exc:
        # Covers protocol errors and invalid responses that prevented
        # httpx from returning a usable Response object.
        failure_reason = f"http_error: {exc}"
        replayed["replay_error"] = "http_error"

    except Exception as exc:  # noqa: BLE001
        failure_reason = f"unexpected_error: {exc}"
        replayed["replay_error"] = "unexpected_error"

    # Store every replay attempt — success or failure.
    # Failures are stored with NULL status_code and a replay_error label.
    # This ensures replay history is complete and auditable.
    replay_db.insert_replayed_flow(db_path, replayed)

    # Compute diff and store result immediately after the replay is written.
    # This is done outside the try/except above so a diff failure never
    # masks a replay error — the diff is best-effort.
    diff: DiffResult = compute_diff(flow, replayed)
    try:
        replay_db.insert_replay_diff(db_path, {
            "replay_flow_id": replayed_flow_id,
            "original_flow_id": original_flow_id,
            "verdict": diff.verdict,
            "status_changed": diff.status_changed,
            "status_diff": diff.status_diff,
            "length_diff": diff.length_diff,
        })
    except Exception as exc:  # noqa: BLE001
        # Diff storage failure is non-fatal.  The replay flow is already
        # committed.  Log and continue so the caller gets a valid outcome.
        import logging
        logging.getLogger(__name__).error(
            "Failed to store diff for replay %s: %s", replayed_flow_id, exc
        )

    return ReplayOutcome(
        original_flow_id=original_flow_id,
        replayed_flow_id=replayed_flow_id,
        status_code=replayed.get("status_code"),
        success=failure_reason is None,
        failure_reason=failure_reason,
        verdict=diff.verdict,
    )


# ------------------------------------------------------------------ #
# Mutated replay (used by Input Validation and future attack modules)  #
# ------------------------------------------------------------------ #

async def replay_with_mutation(
    original_flow: dict,
    mutations: dict,
    db_path: Path,
    project_id: str,
    source: str = "auto_replay",
    replay_reason: Optional[str] = "input_validation",
    flow_meta: Optional[dict] = None,
) -> ReplayOutcome:
    """
    Purpose:
        Apply field-level mutations to a base flow and replay the result.
        Used by Input Validation to inject probe payloads before execution.
        Every mutated request produces an independent replay flow in the DB.
    Input:
        original_flow — base flow dict (from replay_db.get_flow_for_replay).
        mutations     — dict with any subset of {url, request_headers,
                        request_body} containing the mutated values.
        db_path       — Path to the project's talos.db.
        project_id    — Project identifier.
        source        — Flow source label ('iv_scan' for Input Validation).
        replay_reason — Optional reason string stored on the replay flow.
        flow_meta     — Structured metadata dict stored as JSON on the replay
                        flow (generated_by, analysis, payload, param_uuid, etc.).
    Output:
        ReplayOutcome — same as _execute_replay.
    Side effects:
        Sends one outbound HTTP request; writes one flow row to the DB.
    """
    mutated = dict(original_flow)
    # Apply only the keys provided in mutations dict.
    for key in ("url", "request_headers", "request_body"):
        if key in mutations:
            mutated[key] = mutations[key]
    # Rebuild host/path/query from the mutated URL so the stored row is correct.
    if "url" in mutations:
        from urllib.parse import urlparse as _up
        parsed = _up(mutations["url"])
        mutated["host"] = parsed.hostname or original_flow.get("host", "")
        mutated["path"] = parsed.path or "/"
        mutated["query"] = parsed.query or ""
    return await _execute_replay(
        mutated, db_path, project_id, source, replay_reason, flow_meta
    )
