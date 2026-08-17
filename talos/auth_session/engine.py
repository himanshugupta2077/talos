"""
Module: talos.auth_session.engine

Purpose:
    Authentication & Session Testing execution engine (Phase 3).

    One scheduler job / invocation mutates **exactly one** ``test_id``,
    sends **one** new outbound HTTP request (KD14), stores the replay flow,
    structural diff, and ``auth_session_results`` row, then returns
    ``AuthSessionOutcome``.

    Responsibility split (KD16):
        Engine  — load, mutate, send, persist flow/diff/result, score verdict.
                  Does **not** create findings or mark scheduler_jobs terminal.
        Scheduler settle — candidate running→done|failed; job terminal state;
                           findings from settle via findings_bridge.

Pipeline:
    1. Load candidate + baseline flow
    2. Endpoint policy re-check (qualified, not excluded/logout/dangerous)
    3. Load binding; extract TokenContext
    4. analyzer.apply(ctx, test_id) → MutatedToken  (exactly one test_id)
    5. Auth invariant: mutated field value ≠ original field value
    6. Apply mutation to request headers/cookies only
    7. httpx send (no redirects, no retries, 30s timeout, project upstream)
    8. insert_replayed_flow + insert_replay_diff
    9. score: decision filter (if present) then heuristic fallback
   10. insert_auth_session_result (1:1 with replay_flow_id)
   11. return AuthSessionOutcome

Design constraints (hard):
    - No retries; redirects disabled.
    - Do not mutate non-owned fields.
    - Re-check endpoint policy at execution time.
    - Original credential must not be used unchanged.
    - One outbound flow per candidate/testcase (KD14).
    - Stdlib JWT mutators only (KD5) — already in analyzer.apply.

Meta dict keys (from run enqueue):
    candidate_id, binding_id, auth_type, test_id, test_family,
    baseline_flow_id, endpoint_id (optional)

Dependencies:
    talos.auth_session.db / extract / types / verdict / decision_filter
    talos.projects.proxy_config / endpoint_policy
    talos.replay.db / diff
    httpx
Data flow:
    scheduler → execute_auth_session_job → mutate → httpx → store → outcome
Side effects:
    Outbound HTTP; writes replay flow, diff, auth_session_results.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

import talos.replay.db as replay_db
from talos.auth_session import db as as_db
from talos.auth_session.extract import (
    extract_token_context,
    find_latest_token_context,
    get_auth_field_value,
    token_context_from_raw,
)
from talos.auth_session.models import (
    LOCATION_COOKIE,
    LOCATION_HEADER,
    VERDICT_UNKNOWN,
    AuthSessionOutcome,
    MutatedToken,
)
from talos.auth_session.decision_filter import (
    ResponseData,
    evaluate_response,
    load_filter,
)
from talos.auth_session.types import get_analyzer
from talos.auth_session.verdict import score_verdict
from talos.proxy.http_client import create_async_client
from talos.replay.diff import DiffResult, compute_diff

_log = logging.getLogger(__name__)
_REPLAY_TIMEOUT = httpx.Timeout(30.0)


# ------------------------------------------------------------------ #
# Public entry point                                                   #
# ------------------------------------------------------------------ #


async def execute_auth_session_job(
    flow_id: str,
    meta: dict,
    db_path: Path,
    project_id: str,
) -> AuthSessionOutcome:
    """
    Purpose:
        Execute a single auth-session attack job end-to-end for one test_id.
    Input:
        flow_id    — baseline flow UUID (same as candidate.baseline_flow_id)
        meta       — deserialized job meta (candidate_id, binding_id, test_id, …)
        db_path    — project talos.db
        project_id — project id stamped on replay flows
    Output:
        AuthSessionOutcome (never creates findings; never marks scheduler job)
    Side effects:
        Outbound HTTP; writes replay flow, diff, result row.
    """
    candidate_id: str = str(meta.get("candidate_id") or "")
    endpoint_id_meta: Optional[str] = meta.get("endpoint_id")

    # candidate_id is the sole required meta key — binding/test_id/family are
    # authoritative on the candidate row (meta may be partial after requeue).
    if not candidate_id:
        return _fail(
            flow_id=flow_id,
            test_id=str(meta.get("test_id") or "unknown"),
            binding_id=str(meta.get("binding_id") or ""),
            candidate_id="",
            auth_type=str(meta.get("auth_type") or "jwt"),
            endpoint_id=endpoint_id_meta,
            reason="auth_session_meta_incomplete",
        )

    candidate = as_db.get_candidate(db_path, candidate_id)
    if candidate is None:
        return _fail(
            flow_id=flow_id,
            test_id=str(meta.get("test_id") or "unknown"),
            binding_id=str(meta.get("binding_id") or ""),
            candidate_id=candidate_id,
            auth_type=str(meta.get("auth_type") or "jwt"),
            endpoint_id=endpoint_id_meta,
            reason="candidate_not_found",
        )

    # Prefer authoritative candidate row over meta for ids/family.
    test_id = candidate.test_id
    binding_id = candidate.binding_id
    auth_type = candidate.auth_type
    test_family = candidate.test_family
    baseline_flow_id = candidate.baseline_flow_id or flow_id
    if baseline_flow_id != flow_id:
        _log.warning(
            "[auth_session] job flow_id=%s differs from candidate baseline=%s; "
            "using candidate baseline",
            flow_id[:8],
            baseline_flow_id[:8],
        )

    flow = replay_db.get_flow_for_replay(db_path, baseline_flow_id)
    if flow is None:
        return _fail(
            flow_id=baseline_flow_id,
            test_id=test_id,
            binding_id=binding_id,
            candidate_id=candidate_id,
            auth_type=auth_type,
            endpoint_id=candidate.endpoint_id or endpoint_id_meta,
            reason="flow_not_found",
        )

    endpoint_id: Optional[str] = (
        candidate.endpoint_id
        or flow.get("endpoint_id")
        or endpoint_id_meta
    )

    # Guard: full endpoint policy re-check (defence-in-depth).
    if endpoint_id:
        skip_reason = _endpoint_policy_pre_check(db_path, project_id, endpoint_id)
        if skip_reason:
            return _fail(
                flow_id=baseline_flow_id,
                test_id=test_id,
                binding_id=binding_id,
                candidate_id=candidate_id,
                auth_type=auth_type,
                endpoint_id=endpoint_id,
                reason=skip_reason,
            )

    binding = as_db.get_binding(db_path, binding_id)
    if binding is None:
        return _fail(
            flow_id=baseline_flow_id,
            test_id=test_id,
            binding_id=binding_id,
            candidate_id=candidate_id,
            auth_type=auth_type,
            endpoint_id=endpoint_id,
            reason="binding_not_found",
        )

    ctx, skip = _resolve_token_context(
        flow=flow,
        binding=binding,
        meta=meta,
        db_path=db_path,
        project_id=project_id,
    )
    if ctx is None:
        return _fail(
            flow_id=baseline_flow_id,
            test_id=test_id,
            binding_id=binding_id,
            candidate_id=candidate_id,
            auth_type=auth_type,
            endpoint_id=endpoint_id,
            reason=skip or "token_not_detectable",
        )

    try:
        analyzer = get_analyzer(binding.auth_type)
    except KeyError:
        return _fail(
            flow_id=baseline_flow_id,
            test_id=test_id,
            binding_id=binding_id,
            candidate_id=candidate_id,
            auth_type=auth_type,
            endpoint_id=endpoint_id,
            reason=f"unsupported_auth_type:{binding.auth_type}",
        )

    config = _load_binding_config(binding.config_json)
    try:
        mutated: MutatedToken = analyzer.apply(ctx, test_id, config)
    except Exception as exc:  # noqa: BLE001
        return _fail(
            flow_id=baseline_flow_id,
            test_id=test_id,
            binding_id=binding_id,
            candidate_id=candidate_id,
            auth_type=auth_type,
            endpoint_id=endpoint_id,
            reason=f"mutation_error:{exc}",
        )

    # Invariant: must not send the original credential unchanged.
    if mutated.new_header_or_cookie_value == ctx.original_header_value:
        # Elevate-role no-op when already elevated can legitimately return the
        # same token; treat as skip (no HTTP) so we never claim a false weak.
        return _fail(
            flow_id=baseline_flow_id,
            test_id=test_id,
            binding_id=binding_id,
            candidate_id=candidate_id,
            auth_type=auth_type,
            endpoint_id=endpoint_id,
            reason="mutation_noop_same_token",
        )

    try:
        modified = _apply_token_mutation(flow, binding.location, binding.name, mutated)
    except Exception as exc:  # noqa: BLE001
        return _fail(
            flow_id=baseline_flow_id,
            test_id=test_id,
            binding_id=binding_id,
            candidate_id=candidate_id,
            auth_type=auth_type,
            endpoint_id=endpoint_id,
            reason=f"apply_mutation_error:{exc}",
        )

    # Double-check field-level invariant after apply.
    try:
        _assert_field_changed(flow, modified, binding.location, binding.name)
    except ValueError as exc:
        return _fail(
            flow_id=baseline_flow_id,
            test_id=test_id,
            binding_id=binding_id,
            candidate_id=candidate_id,
            auth_type=auth_type,
            endpoint_id=endpoint_id,
            reason=f"auth_invariant:{exc}",
        )

    return await _send_and_store(
        original_flow=flow,
        modified=modified,
        mutated=mutated,
        candidate_id=candidate_id,
        binding_id=binding_id,
        auth_type=auth_type,
        test_id=test_id,
        test_family=test_family,
        endpoint_id=endpoint_id,
        db_path=db_path,
        project_id=project_id,
    )


# ------------------------------------------------------------------ #
# Token source (custom JWT → latest captured → baseline flow)          #
# ------------------------------------------------------------------ #


def _resolve_token_context(
    *,
    flow: dict,
    binding,
    meta: dict,
    db_path: Path,
    project_id: str,
):
    """
    Purpose:
        Prefer an operator-supplied JWT, else the newest captured JWT
        for this binding, else the token on the baseline flow.
    """
    custom = str(meta.get("custom_jwt") or "").strip()
    if custom:
        ctx, skip = token_context_from_raw(custom, binding)
        if ctx is None:
            return None, skip or "custom_jwt_not_detectable"
        return ctx, None

    ctx, _src_flow, skip = find_latest_token_context(
        db_path, project_id, binding
    )
    if ctx is not None:
        return ctx, None

    ctx, flow_skip = extract_token_context(flow, binding)
    if ctx is not None:
        return ctx, None
    return None, skip or flow_skip or "token_not_detectable"


# ------------------------------------------------------------------ #
# Mutation apply                                                       #
# ------------------------------------------------------------------ #


def _load_binding_config(config_json: str) -> dict[str, Any]:
    if not config_json or not config_json.strip():
        return {}
    try:
        data = json.loads(config_json)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _load_headers(flow: dict) -> dict:
    raw = flow.get("request_headers", "{}")
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}
    return dict(raw or {})


def _load_cookies(flow: dict) -> dict:
    raw = flow.get("request_cookies", "{}")
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}
    return dict(raw or {})


def _set_header_case_preserving(
    headers: dict[str, Any],
    name: str,
    value: str,
) -> dict[str, Any]:
    """Set header value, keeping existing casing of the key when present."""
    target = name.lower()
    out = dict(headers)
    for key in list(out.keys()):
        if str(key).lower() == target:
            out[key] = value
            return out
    out[name] = value
    return out


def _set_cookie(
    cookies: dict[str, Any],
    name: str,
    value: str,
) -> dict[str, Any]:
    """Set cookie; prefer exact name, else case-insensitive replace."""
    out = dict(cookies)
    if name in out:
        out[name] = value
        return out
    target = name.lower()
    for key in list(out.keys()):
        if str(key).lower() == target:
            out[key] = value
            return out
    out[name] = value
    return out


def _parse_cookie_header_pairs(cookie_header: str) -> dict[str, str]:
    """Parse a Cookie request header into name→value (first occurrence wins)."""
    out: dict[str, str] = {}
    for part in str(cookie_header).split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip()
        if not key or key in out:
            continue
        out[key] = value.strip()
    return out


def _merge_cookies_from_header(
    headers: dict[str, Any],
    cookies: dict[str, Any],
) -> dict[str, Any]:
    """
    Merge Cookie header pairs into the cookies dict.

    Captures often store cookies only on the Cookie header (empty
    ``request_cookies``). Without this merge, mutating one bound cookie and
    rebuilding the header would drop sibling cookies.
    """
    cookie_raw: Any = None
    for key, value in headers.items():
        if str(key).lower() == "cookie":
            cookie_raw = value
            break
    if cookie_raw is None:
        return dict(cookies)
    if isinstance(cookie_raw, list):
        cookie_raw = "; ".join(str(item) for item in cookie_raw if item is not None)
    parsed = _parse_cookie_header_pairs(str(cookie_raw))
    # request_cookies win on key collision (structured store is authoritative).
    merged: dict[str, Any] = dict(parsed)
    for key, value in cookies.items():
        merged[key] = value
    return merged


def _rebuild_cookie_header(headers: dict[str, Any], cookies: dict[str, Any]) -> None:
    """Rebuild Cookie request header from cookies dict (in-place on headers)."""
    # Drop existing Cookie header keys (any casing).
    for key in list(headers.keys()):
        if str(key).lower() == "cookie":
            del headers[key]
    if not cookies:
        return
    parts = [f"{k}={v}" for k, v in cookies.items()]
    headers["Cookie"] = "; ".join(parts)


def _apply_token_mutation(
    flow: dict,
    location: str,
    field_name: str,
    mutated: MutatedToken,
) -> dict:
    """
    Purpose:
        Copy flow and replace only the bound auth field with the mutated value.
        Cookie mutations preserve sibling cookies (including those that lived
        only on the Cookie header).
    Side effects: None (returns new dict).
    """
    m = dict(flow)
    headers = _load_headers(flow)
    cookies = _load_cookies(flow)
    loc = (location or "").strip().lower()
    value = mutated.new_header_or_cookie_value

    if loc == LOCATION_HEADER:
        headers = _set_header_case_preserving(headers, field_name, value)
    elif loc == LOCATION_COOKIE:
        cookies = _merge_cookies_from_header(headers, cookies)
        cookies = _set_cookie(cookies, field_name, value)
        _rebuild_cookie_header(headers, cookies)
    else:
        raise ValueError(f"unknown location {location!r}")

    m["request_headers"] = json.dumps(headers)
    m["request_cookies"] = json.dumps(cookies)
    return m


def _assert_field_changed(
    original_flow: dict,
    modified_flow: dict,
    location: str,
    field_name: str,
) -> None:
    """Fail closed if the bound field still holds the original value."""
    orig = get_auth_field_value(original_flow, location, field_name)
    new = get_auth_field_value(modified_flow, location, field_name)
    if new is None:
        raise ValueError(f"mutated auth value missing on {location} {field_name}")
    if orig is not None and orig == new:
        raise ValueError(f"original auth value survived on {location} {field_name}")


# ------------------------------------------------------------------ #
# Endpoint policy                                                      #
# ------------------------------------------------------------------ #


def _endpoint_policy_pre_check(
    db_path: Path,
    project_id: str,
    endpoint_id: str,
) -> Optional[str]:
    """
    Defence-in-depth: re-resolve effective Endpoint Policy before attack.
    Skip reasons match scheduler _SKIP_REASONS strings.
    """
    import sqlite3

    from talos.projects.policy import get_effective_policy

    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT normalized_path FROM endpoints WHERE id = ?",
            (endpoint_id,),
        ).fetchone()

    if row is None:
        return None

    policy = get_effective_policy(
        db_path, project_id, endpoint_id, row[0]
    )
    if policy.excluded:
        return "endpoint_excluded"
    if policy.logout:
        return "endpoint_annotated_logout"
    if policy.dangerous:
        return "endpoint_annotated_dangerous"
    if not policy.qualified:
        return "endpoint_not_qualified"
    return None


# ------------------------------------------------------------------ #
# HTTP + storage                                                       #
# ------------------------------------------------------------------ #


async def _send_and_store(
    *,
    original_flow: dict,
    modified: dict,
    mutated: MutatedToken,
    candidate_id: str,
    binding_id: str,
    auth_type: str,
    test_id: str,
    test_family: Optional[str],
    endpoint_id: Optional[str],
    db_path: Path,
    project_id: str,
) -> AuthSessionOutcome:
    """Send one mutated request; store flow, diff, result; return outcome."""
    original_flow_id: str = original_flow["id"]
    replayed_flow_id: str = str(uuid.uuid4())
    replay_time: str = datetime.now(timezone.utc).isoformat()

    stored_headers = _load_headers(modified)
    # Multi-value headers: expand lists for httpx (list of (name, value) pairs).
    send_headers: list[tuple[str, str]] = []
    for name, value in stored_headers.items():
        if isinstance(value, list):
            for item in value:
                send_headers.append((str(name), str(item)))
        else:
            send_headers.append((str(name), str(value)))

    body: Optional[bytes] = modified.get("request_body")
    if isinstance(body, str):
        body = body.encode("utf-8", errors="replace")

    mutation_summary = mutated.mutation_summary or ""

    replayed: dict = {
        "id": replayed_flow_id,
        "project_id": project_id,
        "captured_at": replay_time,
        "response_end": None,
        "method": modified.get("method", original_flow["method"]),
        "url": modified.get("url", original_flow["url"]),
        "host": modified.get("host", original_flow["host"]),
        "path": modified.get("path", original_flow["path"]),
        "query": modified.get("query", original_flow.get("query", "")),
        "request_headers": json.dumps(stored_headers),
        "request_cookies": modified.get("request_cookies", "{}"),
        "request_body": body,
        "request_body_truncated": modified.get("request_body_truncated", 0),
        "status_code": None,
        "response_headers": "{}",
        "response_body": None,
        "response_body_truncated": 0,
        "content_type": "",
        "endpoint_id": endpoint_id or original_flow.get("endpoint_id"),
        "role_id": original_flow.get("role_id") or "",
        "module_id": original_flow.get("module_id") or "",
        "source": "auto_replay",
        "original_flow_id": original_flow_id,
        "replay_error": None,
        "replay_reason": "auth_session_attack",
    }

    from talos.burp.outbound import prepare_send_headers
    from talos.burp.trace import ENGINE_AUTH_SESSION

    flow_meta = {
        "attack_module": "auth_session",
        "auth_type": auth_type,
        "test_id": test_id,
        "test_family": test_family,
        "candidate_id": candidate_id,
        "binding_id": binding_id,
        "mutation_summary": mutation_summary,
    }
    send_headers, flow_meta = prepare_send_headers(
        send_headers,
        db_path=db_path,
        engine=ENGINE_AUTH_SESSION,
        flow=replayed,
        extras={
            "technique": auth_type,
            "variant": test_id,
            "analysis": test_family or "",
        },
        endpoint_id=str(endpoint_id or original_flow.get("endpoint_id") or ""),
        host=str(replayed.get("host") or ""),
        flow_meta=flow_meta,
    )
    replayed["flow_meta"] = json.dumps(flow_meta)
    if isinstance(send_headers, dict):
        replayed["request_headers"] = json.dumps(send_headers)

    failure_reason: Optional[str] = None

    try:
        async with create_async_client(
            db_path,
            timeout=_REPLAY_TIMEOUT,
            follow_redirects=False,
            verify=False,
        ) as client:
            resp = await client.request(
                method=replayed["method"],
                url=replayed["url"],
                headers=send_headers,
                content=body,
            )

        response_end = datetime.now(timezone.utc).isoformat()
        resp_body: Optional[bytes] = resp.content if resp.content else None
        replayed.update({
            "response_end": response_end,
            "status_code": resp.status_code,
            "response_headers": json.dumps(dict(resp.headers)),
            "response_body": resp_body,
            "response_body_truncated": len(resp_body) if resp_body else 0,
            "content_type": resp.headers.get("content-type", ""),
        })
        from talos.burp.snapshot import record_send_response

        record_send_response(flow_meta, project_id, resp)

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

    if failure_reason:
        from talos.burp.snapshot import record_send_failure

        record_send_failure(flow_meta, project_id, failure_reason)

    try:
        replay_db.insert_replayed_flow(db_path, replayed)
    except Exception as exc:  # noqa: BLE001
        _log.error(
            "Failed to store auth_session replay flow %s: %s",
            replayed_flow_id,
            exc,
        )
        return AuthSessionOutcome(
            original_flow_id=original_flow_id,
            replayed_flow_id=None,
            original_status=original_flow.get("status_code"),
            replay_status=None,
            diff_verdict="ERROR",
            auth_session_verdict=VERDICT_UNKNOWN,
            test_id=test_id,
            binding_id=binding_id,
            candidate_id=candidate_id,
            auth_type=auth_type,
            endpoint_id=endpoint_id,
            failure_reason=f"db_write_error: {exc}",
        )

    diff: DiffResult = compute_diff(original_flow, replayed)
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
        _log.error(
            "Failed to store diff for auth_session replay %s: %s",
            replayed_flow_id,
            exc,
        )

    scored = _score_replay(
        db_path=db_path,
        replayed=replayed,
        diff_verdict=diff.verdict,
    )

    try:
        as_db.insert_result(
            db_path,
            replay_flow_id=replayed_flow_id,
            original_flow_id=original_flow_id,
            candidate_id=candidate_id,
            binding_id=binding_id,
            auth_type=auth_type,
            test_id=test_id,
            verdict=scored.verdict,
            endpoint_id=endpoint_id,
            test_family=test_family,
            mutation_summary=mutation_summary,
            original_status=original_flow.get("status_code"),
            replay_status=replayed.get("status_code"),
            diff_verdict=diff.verdict,
            matched_section=scored.matched_section,
            matched_group=scored.matched_group,
            matched_rules=scored.matched_rules,
            failure_reason=failure_reason,
        )
    except Exception as exc:  # noqa: BLE001
        _log.error(
            "Failed to store auth_session result for replay %s: %s",
            replayed_flow_id,
            exc,
        )

    return AuthSessionOutcome(
        original_flow_id=original_flow_id,
        replayed_flow_id=replayed_flow_id,
        original_status=original_flow.get("status_code"),
        replay_status=replayed.get("status_code"),
        diff_verdict=diff.verdict,
        auth_session_verdict=scored.verdict,
        test_id=test_id,
        binding_id=binding_id,
        candidate_id=candidate_id,
        auth_type=auth_type,
        endpoint_id=endpoint_id,
        failure_reason=failure_reason,
        matched_section=scored.matched_section,
        matched_group=scored.matched_group,
        matched_rules=scored.matched_rules,
    )


def _score_replay(
    *,
    db_path: Path,
    replayed: dict,
    diff_verdict: Optional[str],
):
    """
    Load decision filter (if any) and score: filter match → else heuristic.
    Does not create findings.
    """
    from talos.auth_session.verdict import VerdictScore

    replay_error = replayed.get("replay_error")
    replay_status = replayed.get("status_code")

    filter_verdict: Optional[str] = None
    filter_section: Optional[str] = None
    filter_group: Optional[str] = None
    filter_rules: Optional[list[str]] = None

    # Only attempt filter when we have a status (score_verdict also guards).
    if not replay_error and replay_status is not None:
        try:
            decision_filter = load_filter(db_path.parent)
        except Exception as exc:  # noqa: BLE001
            _log.warning("[auth_session] decision filter load error: %s", exc)
            decision_filter = None

        if decision_filter is not None:
            headers_raw = replayed.get("response_headers") or "{}"
            if isinstance(headers_raw, str):
                try:
                    headers = json.loads(headers_raw)
                except (json.JSONDecodeError, TypeError, ValueError):
                    headers = {}
            else:
                headers = dict(headers_raw or {})
            if not isinstance(headers, dict):
                headers = {}

            body = replayed.get("response_body")
            if isinstance(body, str):
                body_bytes: Optional[bytes] = body.encode("utf-8", errors="replace")
            else:
                body_bytes = body if isinstance(body, (bytes, bytearray)) else None

            length = int(replayed.get("response_body_truncated") or 0)
            if not length and body_bytes is not None:
                length = len(body_bytes)

            resp_data = ResponseData(
                status=int(replay_status) if replay_status is not None else None,
                headers=headers,
                body=bytes(body_bytes) if body_bytes is not None else None,
                response_length=length,
            )
            decision = evaluate_response(decision_filter, resp_data)
            filter_verdict = decision.verdict
            filter_section = decision.matched_section
            filter_group = decision.matched_group_id
            filter_rules = list(decision.matched_rules or [])

    scored: VerdictScore = score_verdict(
        replay_status=replay_status,
        diff_verdict=diff_verdict,
        replay_error=replay_error,
        filter_verdict=filter_verdict,
        filter_matched_section=filter_section,
        filter_matched_group=filter_group,
        filter_matched_rules=filter_rules,
    )
    return scored


# ------------------------------------------------------------------ #
# Failure helper                                                       #
# ------------------------------------------------------------------ #


def _fail(
    *,
    flow_id: str,
    test_id: str,
    binding_id: str,
    candidate_id: str,
    auth_type: str,
    endpoint_id: Optional[str],
    reason: str,
) -> AuthSessionOutcome:
    """Return a failed outcome without sending HTTP."""
    return AuthSessionOutcome(
        original_flow_id=flow_id,
        replayed_flow_id=None,
        original_status=None,
        replay_status=None,
        diff_verdict=None,
        auth_session_verdict=VERDICT_UNKNOWN,
        test_id=test_id,
        binding_id=binding_id,
        candidate_id=candidate_id,
        auth_type=auth_type,
        endpoint_id=endpoint_id,
        failure_reason=reason,
    )
