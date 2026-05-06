"""
Module: talos.replay.auth_strip

Purpose:
    Type 2 replay: clone a captured flow, strip auth credentials, send,
    compare, and produce an auth-bypass verdict.

    Type 1 = exact replay (talos.replay.engine).
    Type 2 = exact replay minus auth fields — detects endpoints that work
             without authentication.

    This is the first real attack capability in the system.

Design constraints:
    - Never delete the Cookie header entirely.  Only remove matching keys.
    - Header matching is case-insensitive (HTTP spec).
    - Auth stripping is a pure transformation.  No inference, no guessing.
    - Uses the same replay engine and diff engine as Type 1.

Verdict rules (auth_test_result — evaluated in order):
    SECURE  — replay status in {401, 403} or is a redirect (3xx).
    BYPASS  — replay status == 200.
    UNKNOWN — replay error, timeout, 5xx, or original status was not 200.

Dependencies: json, httpx, uuid, datetime, asyncio
              talos.projects.auth, talos.replay.db, talos.replay.diff
Data flow:
    auth_cli.cmd_auth_test → run_auth_bypass_test
        → _strip_auth(flow, auth_config)
        → _execute_stripped_replay(stripped_flow, db_path, project_id)
            → httpx request
            → replay_db.insert_replayed_flow
            → replay_db.insert_replay_diff
            → replay_db.insert_auth_test_result
Side effects:
    - Sends outbound HTTP request.
    - Writes one replay flow, one diff row, one auth_test_result row per call.
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
from talos.projects.auth import get_auth_config
from talos.replay.diff import DiffResult, compute_diff

import logging

_log = logging.getLogger(__name__)

_REPLAY_TIMEOUT = httpx.Timeout(30.0)


# ------------------------------------------------------------------ #
# Public result type                                                   #
# ------------------------------------------------------------------ #

@dataclass
class AuthTestOutcome:
    """
    Purpose:
        Result of a single auth-bypass test sent to the CLI.

    Fields:
        original_flow_id  — UUID of the source flow.
        replayed_flow_id  — UUID of the stored replay flow, or None on DB error.
        original_status   — HTTP status code of the original flow.
        replay_status     — HTTP status code from the stripped replay, or None
                            on network-level failure.
        diff_verdict      — Structural diff result: SAME | DIFFERENT | ERROR.
        auth_verdict      — Auth bypass decision: SECURE | BYPASS | UNKNOWN.
        failure_reason    — Human-readable error string; None on success.
    """
    original_flow_id: str
    replayed_flow_id: Optional[str]
    original_status: Optional[int]
    replay_status: Optional[int]
    diff_verdict: Optional[str]
    auth_verdict: str
    failure_reason: Optional[str]


# ------------------------------------------------------------------ #
# Public entry point                                                   #
# ------------------------------------------------------------------ #

async def run_auth_bypass_test(
    endpoint_id: str,
    db_path: Path,
    project_id: str,
) -> AuthTestOutcome:
    """
    Purpose:
        Select the best 200 OK proxy_capture flow for an endpoint, strip auth
        credentials, replay, diff, and store the auth-bypass verdict.
    Input:
        endpoint_id — UUID of the target endpoint.
        db_path     — Path to the project's talos.db.
        project_id  — Project identifier for the new replay row.
    Output:
        AuthTestOutcome with diff_verdict and auth_verdict.
    Side effects:
        Sends HTTP request; writes replay flow + diff + auth_test_result to DB.
    """
    # Guard: check endpoint annotations before proceeding.
    # Auth bypass tests are always auto_replay — both logout and dangerous block.
    tags = get_annotations(db_path, endpoint_id)
    if "logout" in tags:
        return AuthTestOutcome(
            original_flow_id="",
            replayed_flow_id=None,
            original_status=None,
            replay_status=None,
            diff_verdict=None,
            auth_verdict="UNKNOWN",
            failure_reason="endpoint_annotated_logout",
        )
    if "dangerous" in tags:
        return AuthTestOutcome(
            original_flow_id="",
            replayed_flow_id=None,
            original_status=None,
            replay_status=None,
            diff_verdict=None,
            auth_verdict="UNKNOWN",
            failure_reason="endpoint_annotated_dangerous",
        )

    flow = replay_db.get_best_flow_for_endpoint(db_path, endpoint_id)
    if flow is None:
        return AuthTestOutcome(
            original_flow_id="",
            replayed_flow_id=None,
            original_status=None,
            replay_status=None,
            diff_verdict=None,
            auth_verdict="UNKNOWN",
            failure_reason="no_qualifying_flow",
        )

    auth_config = get_auth_config(db_path)
    if not auth_config["cookies"] and not auth_config["headers"]:
        return AuthTestOutcome(
            original_flow_id=flow["id"],
            replayed_flow_id=None,
            original_status=flow.get("status_code"),
            replay_status=None,
            diff_verdict=None,
            auth_verdict="UNKNOWN",
            failure_reason="auth_config_empty",
        )

    return await _execute_stripped_replay(flow, auth_config, db_path, project_id)


# ------------------------------------------------------------------ #
# Internal execution                                                   #
# ------------------------------------------------------------------ #

async def _execute_stripped_replay(
    flow: dict,
    auth_config: dict,
    db_path: Path,
    project_id: str,
) -> AuthTestOutcome:
    """
    Purpose:
        Strip auth from a flow, send the request, and persist all results.
    Input:
        flow        — full flow dict from replay_db (includes response fields).
        auth_config — dict with 'cookies' and 'headers' name lists.
        db_path     — Path to the project's talos.db.
        project_id  — Project identifier for the new replay row.
    Output:
        AuthTestOutcome.
    Side effects:
        Sends outbound HTTP request.
        Writes replay flow, diff row, and auth_test_result row.
    """
    original_flow_id: str = flow["id"]
    stripped_headers, stripped_cookies_raw = _strip_auth(flow, auth_config)

    replayed_flow_id = str(uuid.uuid4())
    replay_time = datetime.now(timezone.utc).isoformat()

    body: Optional[bytes] = flow.get("request_body")

    replayed: dict = {
        "id": replayed_flow_id,
        "project_id": project_id,
        "captured_at": replay_time,
        "response_end": None,
        "method": flow["method"],
        "url": flow["url"],
        "host": flow["host"],
        "path": flow["path"],
        "query": flow.get("query", ""),
        # Store the stripped versions so the replay row is auditable.
        "request_headers": json.dumps(stripped_headers),
        "request_cookies": json.dumps(stripped_cookies_raw),
        "request_body": body,
        "request_body_truncated": flow.get("request_body_truncated", 0),
        "status_code": None,
        "response_headers": "{}",
        "response_body": None,
        "response_body_truncated": 0,
        "content_type": "",
        "endpoint_id": flow.get("endpoint_id"),
        "role_id": flow["role_id"],
        "module_id": flow["module_id"],
        "source": "auto_replay",
        "original_flow_id": original_flow_id,
        "replay_error": None,
        "replay_reason": "auth_test",
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
                headers=stripped_headers,
                content=body,
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
        failure_reason = f"http_error: {exc}"
        replayed["replay_error"] = "http_error"

    except Exception as exc:  # noqa: BLE001
        failure_reason = f"unexpected_error: {exc}"
        replayed["replay_error"] = "unexpected_error"

    replay_db.insert_replayed_flow(db_path, replayed)

    # Diff: compare original vs stripped replay.
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
        _log.error("Failed to store diff for auth test replay %s: %s", replayed_flow_id, exc)

    # Auth verdict.
    auth_verdict = _compute_auth_verdict(
        original_status=flow.get("status_code"),
        replay_status=replayed.get("status_code"),
        replay_error=replayed.get("replay_error"),
    )
    try:
        replay_db.insert_auth_test_result(db_path, {
            "replay_flow_id": replayed_flow_id,
            "original_flow_id": original_flow_id,
            "verdict": auth_verdict,
        })
    except Exception as exc:  # noqa: BLE001
        _log.error("Failed to store auth test result for replay %s: %s", replayed_flow_id, exc)

    return AuthTestOutcome(
        original_flow_id=original_flow_id,
        replayed_flow_id=replayed_flow_id,
        original_status=flow.get("status_code"),
        replay_status=replayed.get("status_code"),
        diff_verdict=diff.verdict,
        auth_verdict=auth_verdict,
        failure_reason=failure_reason,
    )


# ------------------------------------------------------------------ #
# Auth stripping                                                       #
# ------------------------------------------------------------------ #

def _strip_auth(flow: dict, auth_config: dict) -> tuple[dict, dict]:
    """
    Purpose:
        Return (headers, cookies) with auth fields removed.
        The Cookie header is rebuilt with auth cookie names removed, not deleted.
        Header matching is case-insensitive.
    Input:
        flow        — flow dict with 'request_headers' (JSON string) and
                      'request_cookies' (JSON string).
        auth_config — dict with 'cookies' (list[str]) and 'headers' (list[str]).
    Output:
        Tuple of (stripped_headers dict, stripped_cookies dict).
        Both are plain dicts — not JSON strings.
    Side effects: None.
    """
    raw_headers = flow.get("request_headers", "{}")
    headers: dict = json.loads(raw_headers) if isinstance(raw_headers, str) else dict(raw_headers)

    raw_cookies = flow.get("request_cookies", "{}")
    cookies: dict = json.loads(raw_cookies) if isinstance(raw_cookies, str) else dict(raw_cookies)

    auth_header_names_lower = {n.lower() for n in auth_config["headers"]}
    auth_cookie_names = set(auth_config["cookies"])

    # Strip auth headers (case-insensitive).
    stripped_headers = {
        k: v for k, v in headers.items()
        if k.lower() not in auth_header_names_lower
    }

    # Strip auth cookies from the parsed cookies dict.
    stripped_cookies = {
        k: v for k, v in cookies.items()
        if k not in auth_cookie_names
    }

    # Rebuild the Cookie header in stripped_headers from the remaining cookies.
    # This keeps non-auth cookies intact and ensures Cookie header reflects
    # the stripped_cookies dict.
    if auth_cookie_names:
        remaining_cookie_str = "; ".join(
            f"{k}={v}" for k, v in stripped_cookies.items()
        )
        if remaining_cookie_str:
            stripped_headers["cookie"] = remaining_cookie_str
        else:
            # All cookies were auth — remove Cookie header entirely.
            stripped_headers.pop("cookie", None)
            stripped_headers.pop("Cookie", None)

    return stripped_headers, stripped_cookies


# ------------------------------------------------------------------ #
# Verdict computation                                                  #
# ------------------------------------------------------------------ #

def _compute_auth_verdict(
    original_status: Optional[int],
    replay_status: Optional[int],
    replay_error: Optional[str],
) -> str:
    """
    Purpose:
        Produce an auth-bypass verdict from replay outcomes.
    Input:
        original_status — HTTP status of the original captured flow.
        replay_status   — HTTP status of the stripped replay, or None on error.
        replay_error    — Replay error label, or None on success.
    Output:
        'SECURE' | 'BYPASS' | 'UNKNOWN'
    Side effects: None.

    Rules (evaluated in order):
        1. Network/protocol error → UNKNOWN.
        2. Original was not 200 → UNKNOWN (baseline unreliable).
        3. Replay status 401 or 403 → SECURE.
        4. Replay status 3xx (redirect) → SECURE (redirect to login assumed).
        5. Replay status 200 → BYPASS.
        6. All other cases → UNKNOWN.
    """
    if replay_error:
        return "UNKNOWN"

    if original_status != 200:
        return "UNKNOWN"

    if replay_status in (401, 403):
        return "SECURE"

    if replay_status is not None and 300 <= replay_status < 400:
        return "SECURE"

    if replay_status == 200:
        return "BYPASS"

    # 5xx, 4xx other than 401/403, None, etc.
    return "UNKNOWN"
