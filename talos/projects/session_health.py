"""
Module: talos.projects.session_health

Purpose:
    Session Health Engine — determines whether the attacker's authenticated
    session is still usable during large-scale BAC attack execution.

    The engine implements four independent layers:

    Layer 1 — Time-based refresh (primary; catches 90–95% of expirations).
        Checks whether the auth state age exceeds (ttl - refresh_before).
        If so, triggers a proactive refresh before the token expires.

    Layer 2 — Response-based detection (attached to individual responses).
        Detects expiry signals in a replay response body, headers, or status.
        Never triggers refresh directly; instead increments the suspicion counter.

    Layer 3 — Validation endpoint (runs when suspicion exists).
        Sends a GET to the configured validation URL with current auth state.
        Confirms the session is alive (expected status + body checks).

    Layer 4 — Control flows (strongest health signal).
        Replays a set of stable, authenticated, harmless flows.
        Session is healthy if at least one passes; dead if all fail.
        Used when no validation URL is configured.

    Public API:
        should_refresh(db_path, role_id)
            → True when Layer 1 decides a refresh is needed before the next job.

        observe_response(db_path, role_id, status, headers, body)
            → Increments suspicion if Layer 2 signals are found.
              Returns True if the suspicion count crosses the threshold.

        validate_session(db_path, role_id, project_id, auth_state)
            → Runs Layer 3 or Layer 4.  Returns True when session is alive.

        ensure_healthy(db_path, role_id, project_id)
            → Full health gate: Layer 1 check → optional refresh → suspicion
              check → optional validation.  Returns True when session is
              confirmed healthy and auth state is ready.

        refresh_auth_state(db_path, role_id, project_id)
            → Replays all configured flows, executes extractors, validates
              against auth requirements, and stores the new auth state.
              Returns True on success.

Design constraints:
    - Refresh is always triggered from the scheduler, never from the BAC engine.
    - Layer 2 never triggers refresh directly (avoids false positives).
    - Layer 3/4 runs only when suspicion > 0.
    - All validation calls are read-only from the application's perspective.

Dependencies: asyncio, httpx, json, logging, pathlib
              talos.projects.auth, talos.replay.engine, talos.replay.db
Data flow:
    ReplayScheduler._execute_bac_job
        → ensure_healthy(db_path, role_id, project_id)
        → [Layer 1] should_refresh
        → [refresh_auth_state]
        → [Layer 2] observe_response  (after each replay response)
        → [Layer 3 or 4] validate_session  (when suspicion > 0)
Side effects:
    - refresh_auth_state: sends outbound HTTP; writes role_auth_state.
    - validate_session Layer 3: sends outbound HTTP (no stored writes).
    - validate_session Layer 4: sends outbound HTTP; writes replay flows.
    - observe_response: writes session_suspicion_state (counter only).
"""

import asyncio
import json
import logging
import types
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

from talos.projects.auth import (
    get_auth_config,
    get_role_auth_state,
    store_role_auth_state,
    get_session_health_config,
    list_auth_flow_configs,
    get_flow_extractor,
    list_session_health_control_flows,
    get_suspicion_state,
    increment_suspicion,
    reset_suspicion,
)
import talos.replay.db as replay_db
from talos.replay.engine import replay_flow

_log = logging.getLogger(__name__)

# How many expiry signals before running a validation check.
_SUSPICION_THRESHOLD: int = 3

# Timeout for the Layer 3 validation endpoint request.
_VALIDATION_TIMEOUT = httpx.Timeout(15.0)


# ================================================================== #
# Layer 1 — Time-based refresh                                         #
# ================================================================== #

def should_refresh(db_path: Path, role_id: str) -> bool:
    """
    Purpose:
        Determine whether the auth state for a role should be refreshed before
        the next job.  Compares the age of the stored auth state against
        (ttl_seconds - refresh_before_seconds).
    Input:
        db_path — Path to the project's talos.db.
        role_id — UUID of the role.
    Output:
        True if refresh is needed; False if the token is still fresh.
        Also returns True when no auth state exists at all.
    Side effects: None (read-only).
    """
    state_info = get_role_auth_state(db_path, role_id)

    if not state_info["state"] or state_info["collected_at"] is None:
        # No state stored yet — definitely need a refresh.
        return True

    health_cfg = get_session_health_config(db_path, role_id)
    ttl = health_cfg["ttl_seconds"]
    refresh_before = health_cfg["refresh_before_seconds"]
    refresh_at = ttl - refresh_before

    collected_at_str = state_info["collected_at"]
    try:
        collected_at = datetime.fromisoformat(collected_at_str)
        if collected_at.tzinfo is None:
            collected_at = collected_at.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        # Unparseable timestamp — treat as expired.
        return True

    now = datetime.now(timezone.utc)
    age_seconds = (now - collected_at).total_seconds()

    needs_refresh = age_seconds >= refresh_at
    if needs_refresh:
        _log.info(
            "[session_health] Layer 1: role=%s age=%.0fs >= refresh_at=%.0fs → refresh needed.",
            role_id[:8], age_seconds, refresh_at,
        )
    return needs_refresh


# ================================================================== #
# Layer 2 — Response-based detection                                   #
# ================================================================== #

def observe_response(
    db_path: Path,
    role_id: str,
    status: int,
    headers: dict,
    body: str,
) -> bool:
    """
    Purpose:
        Inspect a replay response for configured expiry signals.
        Increments the suspicion counter if any signal matches.
        Does NOT trigger a refresh directly — only marks the session suspicious.
    Input:
        db_path — Path to the project's talos.db.
        role_id — UUID of the role whose session produced this response.
        status  — HTTP status code.
        headers — Response header dict (any case keys accepted).
        body    — Decoded response body string.
    Output:
        True if the suspicion counter crossed _SUSPICION_THRESHOLD after this
        observation; False otherwise.
        Returns False immediately when no expiry signals are configured.
    Side effects:
        May increment session_suspicion_state for the role.
    """
    health_cfg = get_session_health_config(db_path, role_id)

    body_signals: list = health_cfg["expiry_body_signals"]
    status_codes: list = health_cfg["expiry_status_codes"]
    header_signals: dict = health_cfg["expiry_header_signals"]

    if not body_signals and not status_codes and not header_signals:
        return False

    headers_lower = {k.lower(): v for k, v in headers.items()}
    suspicious = False

    # Check status codes.
    if status in status_codes:
        suspicious = True
        _log.debug(
            "[session_health] Layer 2: role=%s status=%d matched expiry signal.",
            role_id[:8], status,
        )

    # Check body substrings.
    if not suspicious:
        for signal in body_signals:
            if signal in body:
                suspicious = True
                _log.debug(
                    "[session_health] Layer 2: role=%s body signal %r found.",
                    role_id[:8], signal,
                )
                break

    # Check response header values.
    if not suspicious:
        for header_name, expected_values in header_signals.items():
            actual = headers_lower.get(header_name.lower(), "")
            for ev in expected_values:
                if ev in actual:
                    suspicious = True
                    _log.debug(
                        "[session_health] Layer 2: role=%s header signal %s=%r found.",
                        role_id[:8], header_name, ev,
                    )
                    break
            if suspicious:
                break

    if not suspicious:
        return False

    new_count = increment_suspicion(db_path, role_id)
    _log.info(
        "[session_health] Layer 2: role=%s suspicion_count=%d.",
        role_id[:8], new_count,
    )
    return new_count >= _SUSPICION_THRESHOLD


# ================================================================== #
# Layer 3 + 4 — Validation                                            #
# ================================================================== #

def validate_session(
    db_path: Path,
    role_id: str,
    project_id: str,
    auth_state: dict,
) -> bool:
    """
    Purpose:
        Validate whether the session is still alive using Layer 3 (validation
        endpoint) or Layer 4 (control flows), whichever is configured.
        Resets the suspicion counter on success.
    Input:
        db_path    — Path to the project's talos.db.
        role_id    — UUID of the role.
        project_id — Active project UUID.
        auth_state — {artifact_name: value} dict from role_auth_state.
    Output:
        True when the session is confirmed alive; False when dead or
        validation configuration is absent.
    Side effects:
        - Layer 3: sends one outbound HTTP request.
        - Layer 4: sends outbound HTTP for each control flow; writes replay rows.
        - Resets session_suspicion_state on success.
    """
    health_cfg = get_session_health_config(db_path, role_id)
    control_flows = list_session_health_control_flows(db_path, role_id)

    # Prefer Layer 4 (control flows) when configured; fall back to Layer 3.
    if control_flows:
        alive = _validate_via_control_flows(
            db_path, project_id, role_id, auth_state, control_flows, health_cfg
        )
    elif health_cfg.get("validation_endpoint_url"):
        alive = _validate_via_endpoint(auth_state, health_cfg)
    else:
        _log.info(
            "[session_health] No validation configured for role=%s — assuming alive.",
            role_id[:8],
        )
        return True

    if alive:
        reset_suspicion(db_path, role_id)
        _log.info("[session_health] Validation passed for role=%s.", role_id[:8])
    else:
        _log.warning("[session_health] Validation FAILED for role=%s.", role_id[:8])

    return alive


def _validate_via_endpoint(auth_state: dict, health_cfg: dict) -> bool:
    """
    Purpose:
        Send an authenticated GET to the validation URL and check the response.
    Input:
        auth_state — {artifact_name: value} dict.
        health_cfg — session_health_config dict for this role.
    Output:
        True when the response matches all expected conditions.
    Side effects:
        Sends one outbound HTTP GET.
    """
    url = health_cfg["validation_endpoint_url"]
    expected_status = health_cfg["validation_expected_status"]
    body_must_contain: list = health_cfg["validation_body_contains"]
    body_must_not_contain: list = health_cfg["validation_body_not_contains"]

    # Build headers from auth_state — inject all values as headers directly.
    # Values already include any prefix (e.g. "Bearer eyJ...").
    req_headers = {k: v for k, v in auth_state.items() if k.lower() != "cookie"}

    try:
        with httpx.Client(timeout=_VALIDATION_TIMEOUT, follow_redirects=False) as client:
            resp = client.get(url, headers=req_headers)
    except httpx.HTTPError as exc:
        _log.warning("[session_health] Layer 3 request error: %s", exc)
        return False

    if resp.status_code != expected_status:
        _log.info(
            "[session_health] Layer 3: expected %d got %d.",
            expected_status, resp.status_code,
        )
        return False

    body = resp.text
    for phrase in body_must_contain:
        if phrase not in body:
            _log.info("[session_health] Layer 3: body_contains %r not found.", phrase)
            return False

    for phrase in body_must_not_contain:
        if phrase in body:
            _log.info("[session_health] Layer 3: body_not_contains %r found.", phrase)
            return False

    return True


def _validate_via_control_flows(
    db_path: Path,
    project_id: str,
    role_id: str,
    auth_state: dict,
    control_flow_ids: list,
    health_cfg: dict,
) -> bool:
    """
    Purpose:
        Replay each control flow and evaluate how many pass.
        Decision rule: at least one flow must return 200.
    Input:
        db_path          — Path to the project's talos.db.
        project_id       — Active project UUID.
        role_id          — UUID of the role.
        auth_state       — Current auth state dict.
        control_flow_ids — List of flow UUID strings to replay.
        health_cfg       — session_health_config dict.
    Output:
        True if at least one control flow returns 200; False if all fail.
    Side effects:
        Sends outbound HTTP for each control flow; writes replay flow rows.
    """
    passed = 0
    total = len(control_flow_ids)

    for flow_id in control_flow_ids:
        outcome = asyncio.run(
            replay_flow(
                flow_id=flow_id,
                db_path=db_path,
                project_id=project_id,
                source="auto_replay",
                replay_reason="session_health_check",
            )
        )
        if outcome.success and outcome.status_code == 200:
            passed += 1
            _log.debug(
                "[session_health] Layer 4: control flow %s → 200 (pass).",
                flow_id[:8],
            )
        else:
            _log.debug(
                "[session_health] Layer 4: control flow %s → %s (fail).",
                flow_id[:8],
                outcome.status_code,
            )

    _log.info(
        "[session_health] Layer 4: role=%s passed=%d/%d.",
        role_id[:8], passed, total,
    )
    return passed >= 1


# ================================================================== #
# Auth state refresh                                                   #
# ================================================================== #

def refresh_auth_state(
    db_path: Path,
    role_id: str,
    project_id: str,
) -> bool:
    """
    Purpose:
        Replay all configured login flows for a role, execute their extractors,
        merge the results, validate against auth requirements, and store the
        new auth state.  Called by ensure_healthy() and by the CLI 'refresh'.
    Input:
        db_path    — Path to the project's talos.db.
        role_id    — UUID of the role.
        project_id — Active project UUID.
    Output:
        True when refresh succeeded and all required artifacts were collected.
        False on flow replay failure, extractor error, or missing required keys.
    Side effects:
        Sends outbound HTTP for each login flow.
        Writes role_auth_state on success.
    """
    auth_req = get_auth_config(db_path)
    required = set(auth_req["cookies"] + auth_req["headers"])

    configs = list_auth_flow_configs(db_path, role_id)
    if not configs:
        _log.warning(
            "[session_health] refresh: no flows configured for role=%s.", role_id[:8]
        )
        return False

    merged: dict = {}

    for cfg in configs:
        flow_id = cfg["flow_id"]
        code = cfg["extractor_code"]

        if code is None:
            _log.warning(
                "[session_health] refresh: flow %s has no extractor — skipped.",
                flow_id[:8],
            )
            continue

        outcome = asyncio.run(
            replay_flow(
                flow_id=flow_id,
                db_path=db_path,
                project_id=project_id,
                source="auto_replay",
                replay_reason="session_refresh",
            )
        )

        if not outcome.success or outcome.replayed_flow_id is None:
            _log.warning(
                "[session_health] refresh: flow %s replay failed: %s.",
                flow_id[:8], outcome.failure_reason,
            )
            continue

        replayed = replay_db.get_flow_for_replay(db_path, outcome.replayed_flow_id)
        if replayed is None:
            _log.warning(
                "[session_health] refresh: replayed flow not found in DB (flow=%s).",
                flow_id[:8],
            )
            continue

        response = _build_response_obj(replayed)
        artifacts = _run_extractor(code, response)

        if artifacts is None:
            _log.warning(
                "[session_health] refresh: extractor failed for flow %s.",
                flow_id[:8],
            )
            continue

        merged.update(artifacts)

    missing = required - set(merged.keys())
    if missing:
        _log.warning(
            "[session_health] refresh: missing required artifacts: %s.",
            ", ".join(sorted(missing)),
        )
        return False

    collected_at = datetime.now(timezone.utc).isoformat()
    store_role_auth_state(db_path, role_id, merged, collected_at)
    reset_suspicion(db_path, role_id)

    _log.info(
        "[session_health] refresh: role=%s refreshed %d artifact(s).",
        role_id[:8], len(merged),
    )
    return True


# ================================================================== #
# Full health gate (used by scheduler before each BAC job)            #
# ================================================================== #

def ensure_healthy(
    db_path: Path,
    role_id: str,
    project_id: str,
) -> bool:
    """
    Purpose:
        Full session health gate — runs before each BAC job.
        Checks Layer 1 (TTL), optionally refreshes, then checks Layer 2
        suspicion state, and optionally validates (Layer 3/4) if suspicious.
    Input:
        db_path    — Path to the project's talos.db.
        role_id    — UUID of the role.
        project_id — Active project UUID.
    Output:
        True when the session is ready (fresh auth state, no unresolved suspicion).
        False when refresh or validation fails.
    Side effects:
        May trigger refresh_auth_state (outbound HTTP + DB writes).
        May trigger validate_session (outbound HTTP + DB writes).
    """
    # Layer 1: TTL check.
    if should_refresh(db_path, role_id):
        _log.info(
            "[session_health] ensure_healthy: role=%s needs refresh (Layer 1).",
            role_id[:8],
        )
        success = refresh_auth_state(db_path, role_id, project_id)
        if not success:
            _log.warning(
                "[session_health] ensure_healthy: refresh FAILED for role=%s.",
                role_id[:8],
            )
            return False

    # Layer 2 check: if suspicion is high, run validation.
    suspicion = get_suspicion_state(db_path, role_id)
    if suspicion["suspicion_count"] >= _SUSPICION_THRESHOLD:
        _log.info(
            "[session_health] ensure_healthy: role=%s suspicion=%d >= threshold; validating.",
            role_id[:8], suspicion["suspicion_count"],
        )
        state_info = get_role_auth_state(db_path, role_id)
        alive = validate_session(
            db_path, role_id, project_id, state_info["state"]
        )
        if not alive:
            # Session dead — trigger full refresh before giving up.
            _log.info(
                "[session_health] ensure_healthy: validation failed; attempting refresh.",
                role_id[:8],
            )
            success = refresh_auth_state(db_path, role_id, project_id)
            if not success:
                _log.warning(
                    "[session_health] ensure_healthy: refresh after dead session FAILED.",
                )
                return False

    return True


# ================================================================== #
# Internal helpers (shared with auth_config_cli)                       #
# ================================================================== #

def _build_response_obj(flow: dict) -> types.SimpleNamespace:
    """
    Purpose:
        Build a SimpleNamespace from a replayed flow dict for use by extractor
        scripts.  Provides .status, .headers, .body, .cookies.
    Input:  flow — flow dict from replay_db.get_flow_for_replay().
    Output: SimpleNamespace.
    Side effects: None.
    """
    status: int = flow.get("status_code") or 0

    raw_headers = flow.get("response_headers", "{}")
    if isinstance(raw_headers, str):
        try:
            headers: dict = json.loads(raw_headers)
        except (ValueError, TypeError):
            headers = {}
    else:
        headers = dict(raw_headers)
    headers = {k.lower(): v for k, v in headers.items()}

    raw_body = flow.get("response_body", b"")
    if isinstance(raw_body, (bytes, bytearray)):
        body: str = raw_body.decode("utf-8", errors="replace")
    else:
        body = str(raw_body) if raw_body else ""

    raw_cookies = flow.get("request_cookies", "{}")
    if isinstance(raw_cookies, str):
        try:
            cookies: dict = json.loads(raw_cookies)
        except (ValueError, TypeError):
            cookies = {}
    else:
        cookies = dict(raw_cookies)

    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        for part in set_cookie.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                cookies.setdefault(k.strip(), v.strip())

    return types.SimpleNamespace(
        status=status,
        headers=headers,
        body=body,
        cookies=cookies,
    )


def _run_extractor(
    code: str,
    response: types.SimpleNamespace,
) -> Optional[dict]:
    """
    Purpose:
        Execute the extractor code and call extract(response).
    Input:
        code     — Python source of the extractor.
        response — SimpleNamespace passed to extract().
    Output:
        Dict returned by extract(), or None on exception.
    Side effects:
        Logs exceptions.
    """
    ns: dict = {}
    try:
        exec(compile(code, "<extractor>", "exec"), ns)  # noqa: S102
        result = ns["extract"](response)
    except Exception as exc:  # noqa: BLE001
        _log.warning("[session_health] extractor exception: %s", exc)
        return None

    if not isinstance(result, dict):
        _log.warning(
            "[session_health] extractor returned %s, expected dict.",
            type(result).__name__,
        )
        return None

    return {str(k): str(v) for k, v in result.items()}
