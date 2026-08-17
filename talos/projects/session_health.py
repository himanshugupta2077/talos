"""
Module: talos.projects.session_health

Purpose:
    Session Health Engine — determines whether the attacker's authenticated
    session is still usable during large-scale BAC attack execution.

    The engine implements three independent layers:

    Layer 1 — Time-based refresh (primary; catches 90–95% of expirations).
        Checks whether the auth state age exceeds (ttl - refresh_before).
        If so, triggers a proactive refresh before the token expires.

    Layer 2 — Response-based detection (attached to individual responses).
        Detects expiry signals in a replay response body, headers, or status.
        Never triggers refresh directly; instead increments the suspicion counter.

    Layer 3 — Validation flows (runs when suspicion exists, or on demand).
        Replays a configured validation flow with the current auth state
        injected into the request.  Compares the response HTTP status code to
        the original baseline status of that flow.  A match confirms the
        session is alive; a mismatch (e.g. 401, 403, redirect) marks it dead.
        Requires at least one control flow configured via
        'talos auth-config add-control-flow'.  No URL endpoint is used.

    Public API:
        should_refresh(db_path, role_id)
            → True when Layer 1 decides a refresh is needed before the next job.

        observe_response(db_path, role_id, status, headers, body)
            → Increments suspicion if Layer 2 signals are found.
              Returns True if the suspicion count crosses the threshold.

        validate_session(db_path, role_id, project_id, auth_state)
            → Runs Layer 3 validation flows.  Returns True when session is alive.

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
    - Layer 3 runs only when suspicion > 0 (during scans) or on demand (validate/refresh).
    - Validation always injects current auth state — never replays captured credentials.

Dependencies: asyncio, json, logging, pathlib
              talos.projects.auth, talos.replay.engine, talos.replay.db
Data flow:
    ReplayScheduler._execute_bac_job
        → ensure_healthy(db_path, role_id, project_id)
        → [Layer 1] should_refresh
        → [refresh_auth_state]
        → [Layer 2] observe_response  (after each replay response)
        → [Layer 3] validate_session  (when suspicion > 0)
Side effects:
    - refresh_auth_state: sends outbound HTTP; writes role_auth_state.
    - validate_session: sends outbound HTTP for each control flow; writes replay flows.
    - observe_response: writes session_suspicion_state (counter only).
"""

import asyncio
import json
import logging
import types
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

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
from talos.replay.engine import replay_flow, replay_with_mutation

_log = logging.getLogger(__name__)

# How many expiry signals before running a validation check.
_SUSPICION_THRESHOLD: int = 3


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
    # MANUAL provider uses expires_at / ttl_seconds from manual_session_config,
    # not the session_health_config TTL which is for AUTO login flows.
    from talos.projects.auth_provider import (
        get_provider, get_manual_session_expiry,
        PROVIDER_MANUAL,
    )
    provider = get_provider(db_path, role_id)

    if provider == PROVIDER_MANUAL:
        expiry = get_manual_session_expiry(db_path, role_id)
        if expiry is None:
            # No expiry defined — treat as needing user input.
            return True
        health_cfg = get_session_health_config(db_path, role_id)
        refresh_before = health_cfg["refresh_before_seconds"]
        now = datetime.now(timezone.utc)
        remaining = (expiry - now).total_seconds()
        needs_refresh = remaining <= refresh_before
        if needs_refresh:
            _log.info(
                "[session_health] Layer 1 (MANUAL): role=%s remaining=%.0fs <= "
                "refresh_before=%.0fs → refresh needed.",
                role_id[:8], remaining, refresh_before,
            )
        return needs_refresh

    # AUTO provider: compare auth state age against (ttl - refresh_before).
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
    control_flow_ids: list | None = None,
) -> bool:
    """
    Purpose:
        Validate whether the session is still alive using Layer 3 (validation
        flows).  For each configured validation flow: injects the current auth
        state into the request, replays it, and compares the response HTTP
        status code to the original baseline status of that flow.  A match
        confirms the session is alive; a mismatch (e.g. 401, 403, redirect)
        means the session is dead.

        Returns False immediately when no validation flows are configured.
        Resets the suspicion counter on success.
    Input:
        db_path           — Path to the project's talos.db.
        role_id           — UUID of the role.
        project_id        — Active project UUID.
        auth_state        — {artifact_name: value} dict from role_auth_state.
        control_flow_ids  — Optional subset of control flow UUIDs to probe.
                            Default: all configured validation flows for the role.
    Output:
        True when at least one validation flow passes; False otherwise.
    Side effects:
        Sends outbound HTTP for each validation flow; writes replay rows.
        Resets session_suspicion_state on success.
    """
    if control_flow_ids is not None:
        control_flows = list(control_flow_ids)
    else:
        control_flows = list_session_health_control_flows(db_path, role_id)
    if not control_flows:
        _log.warning(
            "[session_health] No validation flows configured for role=%s — "
            "session cannot be confirmed healthy.  Configure a flow with "
            "'talos auth-config add-control-flow <role> <flow_id>'.",
            role_id[:8],
        )
        return False

    alive = _validate_via_control_flows(
        db_path, project_id, role_id, auth_state, control_flows
    )

    if alive:
        reset_suspicion(db_path, role_id)
        _log.info("[session_health] Validation passed for role=%s.", role_id[:8])
    else:
        _log.warning("[session_health] Validation FAILED for role=%s.", role_id[:8])

    return alive


def _build_auth_mutations(
    original_flow: dict,
    auth_cfg: dict,
    auth_state: dict,
) -> dict:
    """
    Purpose:
        Build a mutations dict that replaces auth headers and cookies in
        original_flow's request with values from auth_state.  Used to replay
        a validation flow using the live session credentials rather than the
        originally captured credentials.
    Input:
        original_flow — captured flow dict from replay_db.
        auth_cfg      — {'cookies': list[str], 'headers': list[str]}.
        auth_state    — {artifact_name: value} from role_auth_state.
    Output:
        Mutations dict with 'request_headers' key (plain dict, not JSON string).
        Empty dict when auth_cfg has no configured artifacts.
    Side effects: None (pure transformation).
    """
    if not auth_cfg["cookies"] and not auth_cfg["headers"]:
        return {}

    raw_headers = original_flow.get("request_headers", "{}")
    headers: dict = json.loads(raw_headers) if isinstance(raw_headers, str) else dict(raw_headers)

    raw_cookies = original_flow.get("request_cookies", "{}")
    cookies: dict = json.loads(raw_cookies) if isinstance(raw_cookies, str) else dict(raw_cookies)

    auth_header_names_lower = {n.lower() for n in auth_cfg["headers"]}

    # Replace auth headers (case-insensitive removal, then inject current values).
    headers = {k: v for k, v in headers.items() if k.lower() not in auth_header_names_lower}
    for header_name in auth_cfg["headers"]:
        if header_name in auth_state:
            headers[header_name] = auth_state[header_name]

    # Replace auth cookies with current values from auth_state.
    for cookie_name in auth_cfg["cookies"]:
        if cookie_name in auth_state:
            cookies[cookie_name] = auth_state[cookie_name]

    # Rebuild Cookie header — remove all existing variants to prevent duplicates
    # that would be joined with commas by intermediate proxies.
    if auth_cfg["cookies"]:
        for _k in list(headers.keys()):
            if _k.lower() == "cookie":
                del headers[_k]
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if cookie_str:
            headers["Cookie"] = cookie_str

    return {"request_headers": headers}


def _validate_via_control_flows(
    db_path: Path,
    project_id: str,
    role_id: str,
    auth_state: dict,
    control_flow_ids: list,
) -> bool:
    """
    Purpose:
        Validate the session by replaying each configured validation flow with
        the current auth state injected into the request, then comparing the
        replay response status to the original captured (baseline) status of
        that flow.  A matching status confirms the session is alive.

        Decision rule: at least one flow must produce a response whose status
        code matches the original baseline status.
    Input:
        db_path          — Path to the project's talos.db.
        project_id       — Active project UUID.
        role_id          — UUID of the role (used for logging only).
        auth_state       — {artifact_name: value} from role_auth_state.
        control_flow_ids — List of flow UUID strings to use for validation.
    Output:
        True if at least one flow matches its baseline status; False if all fail.
    Side effects:
        Sends outbound HTTP for each flow; writes replay flow rows.
    """
    auth_cfg = get_auth_config(db_path)
    passed = 0

    for flow_id in control_flow_ids:
        original_flow = replay_db.get_flow_for_replay(db_path, flow_id)
        if original_flow is None:
            _log.warning(
                "[session_health] validation: flow %s not found — skipped.",
                flow_id[:8],
            )
            continue

        baseline_status = original_flow.get("status_code")
        if baseline_status is None:
            _log.warning(
                "[session_health] validation: flow %s has no recorded baseline status — skipped.",
                flow_id[:8],
            )
            continue

        # Inject current auth state so the replay tests the live session, not
        # the originally captured credentials.
        mutations = _build_auth_mutations(original_flow, auth_cfg, auth_state)

        outcome = asyncio.run(
            replay_with_mutation(
                original_flow=original_flow,
                mutations=mutations,
                db_path=db_path,
                project_id=project_id,
                source="auto_replay",
                replay_reason="session_validation",
            )
        )

        if not outcome.success:
            _log.debug(
                "[session_health] validation: flow %s replay error: %s — fail.",
                flow_id[:8], outcome.failure_reason,
            )
            continue

        if outcome.status_code == baseline_status:
            passed += 1
            _log.debug(
                "[session_health] validation: flow %s → %d matches baseline %d — pass.",
                flow_id[:8], outcome.status_code, baseline_status,
            )
        else:
            _log.info(
                "[session_health] validation: flow %s → %d (baseline %d) — fail.",
                flow_id[:8], outcome.status_code, baseline_status,
            )

    _log.info(
        "[session_health] validation: role=%s passed=%d/%d.",
        role_id[:8], passed, len(control_flow_ids),
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
        Refresh the auth state for a role.  Behaviour depends on provider:

        AUTO   — Replay all configured login flows, execute their extractors,
                 merge results, validate against auth requirements, and store
                 the new auth state.

        MANUAL — Load the manually-supplied artifacts from manual_session_config
                 and write them into role_auth_state.  No HTTP requests are
                 sent; no flows are replayed.

    Input:
        db_path    — Path to the project's talos.db.
        role_id    — UUID of the role.
        project_id — Active project UUID (used only for AUTO provider).
    Output:
        True when refresh succeeded and auth state is ready.
        False on failure (flow replay error, extractor error, missing artifacts,
        or expired / absent manual session config).
    Side effects:
        AUTO:   sends outbound HTTP; writes role_auth_state.
        MANUAL: writes role_auth_state from stored config (no HTTP).
    """
    from talos.projects.auth_provider import (
        get_provider, apply_manual_session, PROVIDER_MANUAL,
    )
    provider = get_provider(db_path, role_id)

    if provider == PROVIDER_MANUAL:
        # MANUAL provider: apply artifacts from manual_session_config.
        success = apply_manual_session(db_path, role_id)
        if not success:
            _log.warning(
                "[session_health] refresh (MANUAL): role=%s — session absent, "
                "expired, or missing TTL → WAITING_FOR_USER.",
                role_id[:8],
            )
        else:
            _log.info(
                "[session_health] refresh (MANUAL): role=%s — artifacts applied.",
                role_id[:8],
            )
        return success

    # AUTO provider: replay login flows and extract artifacts.
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
        Full session health gate — runs before each BAC / IV job.

        Platform NTLM-only (no HTTP artifacts): returns True immediately.
        There is no cookie/header session to refresh; the handshake is
        the session.

        AUTO provider path:
            Checks Layer 1 (TTL), optionally refreshes, then checks Layer 2
            suspicion state, and optionally validates (Layer 3/4) if suspicious.

        MANUAL provider path:
            Checks whether the manually-supplied session is still valid by
            applying it (which also checks expiry).  If expired, returns False
            immediately — Talos cannot automatically obtain new credentials.
            Layer 2 suspicion is still fed by observe_response() and triggers
            a validation pass, but refresh is never attempted automatically.

    Input:
        db_path    — Path to the project's talos.db.
        role_id    — UUID of the role.
        project_id — Active project UUID.
    Output:
        True when the session is ready.
        False when refresh or validation fails.
        For MANUAL sessions, False means WAITING_FOR_USER.
    Side effects:
        AUTO:   may trigger refresh_auth_state (outbound HTTP + DB writes).
        MANUAL: reads from manual_session_config; may write role_auth_state.
        Both:   may trigger validate_session (outbound HTTP + DB writes).
    """
    from talos.projects.auth_mechanism import resolve_auth_mechanism
    from talos.projects.auth_provider import get_provider, PROVIDER_MANUAL

    # Connection-bound NTLM has no cookie/header session to refresh.
    mechanism = resolve_auth_mechanism(db_path)
    if mechanism.ntlm_only:
        return True

    provider = get_provider(db_path, role_id)

    # Layer 1: TTL / expiry check.
    if should_refresh(db_path, role_id):
        _log.info(
            "[session_health] ensure_healthy: role=%s needs refresh (Layer 1).",
            role_id[:8],
        )
        if provider == PROVIDER_MANUAL:
            # MANUAL: attempt to re-apply the stored config (checks expiry).
            success = refresh_auth_state(db_path, role_id, project_id)
            if not success:
                _log.warning(
                    "[session_health] ensure_healthy: MANUAL session expired or "
                    "absent for role=%s → WAITING_FOR_USER.",
                    role_id[:8],
                )
                return False
        else:
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
            if provider == PROVIDER_MANUAL:
                # MANUAL: cannot auto-refresh; wait for tester.
                _log.warning(
                    "[session_health] ensure_healthy: MANUAL session validation "
                    "failed for role=%s → WAITING_FOR_USER.",
                    role_id[:8],
                )
                return False
            # AUTO: attempt a full refresh before giving up.
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
