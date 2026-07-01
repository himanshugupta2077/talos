"""
Module: talos.projects.bac.engine

Purpose:
    BAC attack execution engine.
    Receives a flow_id, attack meta dict, and attack type from the scheduler,
    then executes the corresponding mutation and sends the modified request.

    All seven BAC attacks share the same pipeline:
        1. Load the original target-role flow.
        2. Check endpoint annotations (logout/dangerous → skip).
        3. Retrieve the attacker role's active session token.
        4. Verify auth config is present.
        5. Apply the mutation (session swap + optional HTTP modification).
        6. Send the request via httpx (no redirects, no retries).
        7. Store replay flow + diff + bac_result rows in the DB.
        8. Return a BacOutcome.

    Session swap is the foundation: every BAC attack injects the attacker's
    token, and then optionally applies an additional HTTP mutation on top.

Design constraints (hard — do not violate):
    - No retries.
    - Redirects disabled.
    - Endpoint annotations are re-checked here (defence-in-depth over scheduler).
    - No mutation of fields not owned by the attack variant.

Dependencies: asyncio, json, httpx, uuid, pathlib, urllib.parse
              talos.projects.auth, talos.projects.bac.variants
              talos.projects.bac.decision_filter (DecisionResult)
              talos.replay.db, talos.replay.diff
Data flow:
    scheduler._execute_job → execute_bac_job(flow_id, meta, attack_type, db_path, project_id)
        → _apply_mutation → httpx → replay_db writes → BacOutcome
Side effects:
    Sends outbound HTTP; writes replay flow, diff, and bac_result rows to DB.
"""

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

import talos.replay.db as replay_db
from talos.projects.annotations import get_annotations
from talos.projects.auth import get_auth_config, get_role_auth_state
from talos.replay.diff import DiffResult, compute_diff

_log = logging.getLogger(__name__)
_REPLAY_TIMEOUT = httpx.Timeout(30.0)


# ------------------------------------------------------------------ #
# Public result type                                                   #
# ------------------------------------------------------------------ #

@dataclass
class BacOutcome:
    """
    Purpose:
        Result of a single BAC attack attempt.

    Fields:
        original_flow_id — UUID of the source (target-role) flow.
        replayed_flow_id — UUID of the stored attack replay, or None on failure.
        original_status  — HTTP status of the original flow.
        replay_status    — HTTP status from the attack replay, or None on error.
        diff_verdict     — SAME | DIFFERENT | ERROR (structural diff).
        bac_verdict      — POSSIBLE_BAC | SECURE | UNKNOWN.
        attack_type      — BAC job type constant string.
        variant          — Variant name from variants.py.
        failure_reason   — Human-readable error; None on success.
    """

    original_flow_id: str
    replayed_flow_id: Optional[str]
    original_status: Optional[int]
    replay_status: Optional[int]
    diff_verdict: Optional[str]
    bac_verdict: str
    attack_type: str
    variant: str
    failure_reason: Optional[str]


# ------------------------------------------------------------------ #
# Public entry point                                                   #
# ------------------------------------------------------------------ #

async def execute_bac_job(
    flow_id: str,
    meta: dict,
    attack_type: str,
    db_path: Path,
    project_id: str,
) -> BacOutcome:
    """
    Purpose:
        Execute a single BAC attack job end-to-end.
    Input:
        flow_id     — UUID of the original (target-role's) flow to attack.
        meta        — Deserialized job meta dict; must contain:
                        attacker_role_id (str) — role attempting access.
                        target_role_id   (str) — role that legitimately has access.
                        module_id        (str) — module under test.
                        variant          (str) — mutation variant name.
        attack_type — BAC job type constant (e.g. bac_session_swap).
        db_path     — Path to the project's talos.db.
        project_id  — Project identifier.
    Output:
        BacOutcome with verdict.
    Side effects:
        Sends outbound HTTP; writes replay flow, diff, and bac_result rows.
    """
    attacker_role_id: str = meta.get("attacker_role_id", "")
    variant: str = meta.get("variant", "unknown")

    # Load source flow.
    flow = replay_db.get_flow_for_replay(db_path, flow_id)
    if flow is None:
        return _fail(flow_id, attack_type, variant, "flow_not_found")

    # Guard: endpoint annotations.
    endpoint_id: Optional[str] = flow.get("endpoint_id")
    if endpoint_id:
        tags = get_annotations(db_path, endpoint_id)
        if "logout" in tags:
            return _fail(flow_id, attack_type, variant, "endpoint_annotated_logout")
        if "dangerous" in tags:
            return _fail(flow_id, attack_type, variant, "endpoint_annotated_dangerous")

    # Retrieve attacker's current auth state.
    state_info = get_role_auth_state(db_path, attacker_role_id)
    auth_state = state_info["state"]
    if not auth_state:
        return _fail(flow_id, attack_type, variant, "no_active_token")

    # Verify auth config exists.
    auth_config = get_auth_config(db_path)
    if not auth_config["cookies"] and not auth_config["headers"]:
        return _fail(flow_id, attack_type, variant, "auth_config_empty")

    # Apply the mutation.
    try:
        modified = _apply_mutation(
            flow, auth_config, auth_state, attack_type, meta
        )
    except Exception as exc:  # noqa: BLE001
        return _fail(flow_id, attack_type, variant, f"mutation_error: {exc}")

    if modified is None:
        # Variant not applicable to this flow (e.g. method mismatch).
        return _fail(flow_id, attack_type, variant, "variant_not_applicable")

    return await _send_and_store(
        original_flow=flow,
        modified=modified,
        meta=meta,
        attack_type=attack_type,
        variant=variant,
        db_path=db_path,
        project_id=project_id,
    )


# ------------------------------------------------------------------ #
# Mutation pipeline                                                    #
# ------------------------------------------------------------------ #

def _apply_mutation(
    flow: dict,
    auth_config: dict,
    auth_state: dict,
    attack_type: str,
    meta: dict,
) -> Optional[dict]:
    """
    Purpose:
        Build a modified copy of the flow with the attack mutation applied.
        All BAC attacks first inject the attacker's full auth state, then apply
        the type-specific mutation.
    Input:
        flow        — original flow dict from replay_db.
        auth_config — {'cookies': [...], 'headers': [...]}.
        auth_state  — {artifact_name: value} dict from role_auth_state.
        attack_type — BAC job type constant.
        meta        — job metadata dict.
    Output:
        Modified flow dict ready for dispatch, or None when the variant is not
        applicable to this particular flow (e.g., method mismatch).
    Side effects: None (pure transformation).
    """
    from talos.scheduler.job import (
        BAC_SESSION_SWAP, BAC_METHOD_FUZZ, BAC_CONTENT_TYPE,
        BAC_URL_FUZZ, BAC_HEADER_INJECT, BAC_HOST_FUZZ, BAC_ROLE_INJECT,
    )

    m = dict(flow)

    # Deserialize headers and cookies from JSON strings.
    raw_headers = flow.get("request_headers", "{}")
    headers: dict = (
        json.loads(raw_headers) if isinstance(raw_headers, str) else dict(raw_headers)
    )

    raw_cookies = flow.get("request_cookies", "{}")
    cookies: dict = (
        json.loads(raw_cookies) if isinstance(raw_cookies, str) else dict(raw_cookies)
    )

    # Step 1: inject attacker's auth state (foundation for all BAC attacks).
    headers, cookies = _inject_auth_state(headers, cookies, auth_config, auth_state)

    # Step 2: apply attack-type-specific mutation.
    if attack_type == BAC_SESSION_SWAP:
        pass  # token injection is the complete mutation

    elif attack_type == BAC_METHOD_FUZZ:
        result = _mutate_method(m, headers, meta)
        if result is None:
            return None
        m, headers = result

    elif attack_type == BAC_CONTENT_TYPE:
        result = _mutate_content_type(m, headers, meta)
        if result is None:
            return None
        m, headers = result

    elif attack_type == BAC_URL_FUZZ:
        result = _mutate_url(m, meta)
        if result is None:
            return None
        m = result

    elif attack_type == BAC_HEADER_INJECT:
        headers = _mutate_inject_header(m, headers, meta)

    elif attack_type == BAC_HOST_FUZZ:
        headers, m = _mutate_host(headers, m, meta)

    elif attack_type == BAC_ROLE_INJECT:
        result = _mutate_role_params(m, headers, meta)
        if result is None:
            return None
        m, headers = result

    m["request_headers"] = json.dumps(headers)
    m["request_cookies"] = json.dumps(cookies)
    return m


# ------------------------------------------------------------------ #
# Auth state injection                                                  #
# ------------------------------------------------------------------ #

def _inject_auth_state(
    headers: dict,
    cookies: dict,
    auth_config: dict,
    auth_state: dict,
) -> tuple[dict, dict]:
    """
    Purpose:
        Replace configured auth headers and cookies with the attacker's extracted
        artifact values from role_auth_state.
        Each artifact value is injected verbatim — the extractor is responsible
        for including any prefix (e.g. "Bearer " in Authorization values).
    Input:
        headers     — current request headers dict.
        cookies     — current request cookies dict.
        auth_config — {'cookies': [...], 'headers': [...]}.
        auth_state  — {artifact_name: value} dict from role_auth_state.
    Output:
        (headers, cookies) dicts with auth fields replaced.
    Side effects: None.
    """
    headers = dict(headers)
    cookies = dict(cookies)

    auth_header_names_lower = {n.lower() for n in auth_config["headers"]}

    # Remove existing auth headers (case-insensitive), then inject attacker's.
    headers = {k: v for k, v in headers.items() if k.lower() not in auth_header_names_lower}
    for header_name in auth_config["headers"]:
        if header_name in auth_state:
            headers[header_name] = auth_state[header_name]

    # Replace auth cookies with attacker's extracted values.
    for cookie_name in auth_config["cookies"]:
        if cookie_name in auth_state:
            cookies[cookie_name] = auth_state[cookie_name]

    # Rebuild the Cookie request header from the updated cookies dict.
    if auth_config["cookies"]:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if cookie_str:
            headers["cookie"] = cookie_str
        else:
            headers.pop("cookie", None)
            headers.pop("Cookie", None)

    return headers, cookies


# ------------------------------------------------------------------ #
# Attack-type-specific mutations                                       #
# ------------------------------------------------------------------ #

def _mutate_method(
    flow: dict,
    headers: dict,
    meta: dict,
) -> Optional[tuple[dict, dict]]:
    """
    Purpose:
        Apply HTTP method change or inject X-HTTP-Method-Override header.
        Returns None when the variant's from_method does not match the flow.
    """
    from talos.projects.bac.variants import METHOD_FUZZ_VARIANTS

    variant_name = meta.get("variant", "")
    vdef = next((v for v in METHOD_FUZZ_VARIANTS if v["name"] == variant_name), None)
    if vdef is None:
        return None

    m = dict(flow)
    h = dict(headers)

    if vdef["override_header"]:
        # Inject X-HTTP-Method-Override; leave actual method unchanged.
        h["X-HTTP-Method-Override"] = vdef["override_value"]
        return m, h

    # Direct method substitution — only applicable when method matches.
    from_method: Optional[str] = vdef["from_method"]
    if from_method and flow.get("method", "").upper() != from_method.upper():
        return None

    m["method"] = vdef["to_method"]
    return m, h


def _mutate_content_type(
    flow: dict,
    headers: dict,
    meta: dict,
) -> Optional[tuple[dict, dict]]:
    """
    Purpose:
        Replace the Content-Type header value.
        Returns None when from_ct is specified but doesn't match the flow's type.
    """
    from talos.projects.bac.variants import CONTENT_TYPE_VARIANTS

    variant_name = meta.get("variant", "")
    vdef = next((v for v in CONTENT_TYPE_VARIANTS if v["name"] == variant_name), None)
    if vdef is None:
        return None

    m = dict(flow)
    h = dict(headers)
    from_ct: Optional[str] = vdef.get("from_ct")
    to_ct: str = vdef["to_ct"]
    current_ct: str = flow.get("content_type", "") or ""

    if from_ct is not None and from_ct.lower() not in current_ct.lower():
        # Content-type mismatch — variant not applicable to this flow.
        return None

    # Replace Content-Type header (case-insensitive key lookup).
    h_lower = {k.lower(): k for k in h}
    ct_key = h_lower.get("content-type", "Content-Type")
    h[ct_key] = to_ct
    m["content_type"] = to_ct
    return m, h


def _mutate_url(flow: dict, meta: dict) -> Optional[dict]:
    """
    Purpose:
        Apply a URL path transformation.
        Returns None when the transform cannot be applied to this path.
    """
    from talos.projects.bac.variants import URL_FUZZ_VARIANTS

    variant_name = meta.get("variant", "")
    vdef = next((v for v in URL_FUZZ_VARIANTS if v["name"] == variant_name), None)
    if vdef is None:
        return None

    m = dict(flow)
    transform: str = vdef["transform"]
    path: str = flow.get("path", "/") or "/"

    if transform == "trailing_slash":
        if path.endswith("/"):
            return None
        new_path = path + "/"

    elif transform == "double_slash":
        parts = path.split("/", 2)   # ['', 'admin', 'rest']
        if len(parts) < 2 or not parts[1]:
            return None
        rest = "/" + "/".join(parts[2:]) if len(parts) > 2 and parts[2] else ""
        new_path = "/" + parts[1] + "//" + (parts[2] if len(parts) > 2 else "")

    elif transform == "dot_segment":
        parts = path.split("/", 2)
        if len(parts) < 3 or not parts[1]:
            return None
        new_path = "/" + parts[1] + "/./" + parts[2]

    elif transform == "dot_segment_back":
        parts = path.split("/", 2)
        if len(parts) < 2 or not parts[1]:
            return None
        segment = parts[1]
        rest = parts[2] if len(parts) > 2 else ""
        new_path = "/" + segment + "/../" + segment + ("/" + rest if rest else "")

    elif transform == "encoded_path":
        parts = path.split("/", 2)
        if len(parts) < 2 or not parts[1]:
            return None
        first_char = parts[1][0]
        encoded = "%" + format(ord(first_char), "02x")
        new_segment = encoded + parts[1][1:]
        rest = "/" + "/".join(parts[2:]) if len(parts) > 2 else ""
        new_path = "/" + new_segment + rest

    elif transform == "mixed_case":
        parts = path.split("/", 2)
        if len(parts) < 2 or not parts[1]:
            return None
        new_segment = parts[1][0].upper() + parts[1][1:]
        if new_segment == parts[1]:
            return None  # No change — already upper-case first char.
        rest = "/" + "/".join(parts[2:]) if len(parts) > 2 else ""
        new_path = "/" + new_segment + rest

    else:
        return None

    parsed = urlparse(flow.get("url", ""))
    query = flow.get("query", "")
    new_url = urlunparse((
        parsed.scheme, parsed.netloc, new_path,
        parsed.params, query, parsed.fragment,
    ))
    m["path"] = new_path
    m["url"] = new_url
    return m


def _mutate_inject_header(flow: dict, headers: dict, meta: dict) -> dict:
    """
    Purpose:
        Inject a single header for the header-manipulation attack.
        value_source='path'   → use the request path as the header value.
        value_source='static' → use the literal value from the variant definition.
    """
    from talos.projects.bac.variants import HEADER_INJECT_VARIANTS

    variant_name = meta.get("variant", "")
    vdef = next((v for v in HEADER_INJECT_VARIANTS if v["name"] == variant_name), None)
    if vdef is None:
        return headers

    h = dict(headers)
    if vdef["value_source"] == "path":
        h[vdef["header"]] = flow.get("path", "/")
    elif vdef["value_source"] == "static":
        h[vdef["header"]] = vdef["value"]
    return h


def _mutate_host(
    headers: dict,
    flow: dict,
    meta: dict,
) -> tuple[dict, dict]:
    """
    Purpose:
        Replace the Host header and update the URL's netloc component.
    """
    from talos.projects.bac.variants import HOST_FUZZ_VARIANTS

    variant_name = meta.get("variant", "")
    vdef = next((v for v in HOST_FUZZ_VARIANTS if v["name"] == variant_name), None)
    if vdef is None:
        return headers, flow

    h = dict(headers)
    m = dict(flow)
    new_host: str = vdef["host"]

    # Remove any existing Host header (case-insensitive).
    h = {k: v for k, v in h.items() if k.lower() != "host"}
    h["Host"] = new_host

    # Rebuild URL netloc.
    parsed = urlparse(flow.get("url", ""))
    new_url = urlunparse((
        parsed.scheme, new_host, parsed.path,
        parsed.params, parsed.query, parsed.fragment,
    ))
    m["url"] = new_url
    m["host"] = new_host
    return h, m


def _mutate_role_params(
    flow: dict,
    headers: dict,
    meta: dict,
) -> Optional[tuple[dict, dict]]:
    """
    Purpose:
        Inject role-escalation parameters into the query string or headers.
        query_param           → append key=value to query string.
        query_param_duplicate → append key=value1&key=value2 to query string.
        header                → inject key: value header.
    """
    from talos.projects.bac.variants import ROLE_INJECT_VARIANTS

    variant_name = meta.get("variant", "")
    vdef = next((v for v in ROLE_INJECT_VARIANTS if v["name"] == variant_name), None)
    if vdef is None:
        return None

    m = dict(flow)
    h = dict(headers)
    inject_type: str = vdef["inject_type"]

    if inject_type == "query_param":
        params = parse_qs(flow.get("query", ""), keep_blank_values=True)
        params[vdef["key"]] = [vdef["value"]]
        new_query = urlencode(params, doseq=True)
        m["query"] = new_query
        parsed = urlparse(flow.get("url", ""))
        m["url"] = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))

    elif inject_type == "query_param_duplicate":
        params = parse_qs(flow.get("query", ""), keep_blank_values=True)
        params[vdef["key"]] = vdef["values"]
        new_query = urlencode(params, doseq=True)
        m["query"] = new_query
        parsed = urlparse(flow.get("url", ""))
        m["url"] = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))

    elif inject_type == "header":
        h[vdef["key"]] = vdef["value"]

    return m, h


# ------------------------------------------------------------------ #
# HTTP execution and DB storage                                        #
# ------------------------------------------------------------------ #

async def _send_and_store(
    original_flow: dict,
    modified: dict,
    meta: dict,
    attack_type: str,
    variant: str,
    db_path: Path,
    project_id: str,
) -> BacOutcome:
    """
    Purpose:
        Send the modified request, store all results, compute BAC verdict.
    Input:
        original_flow — unmodified flow dict (used for diff comparison).
        modified      — mutated flow dict (used for dispatch).
        meta          — job metadata dict.
        attack_type   — BAC job type constant.
        variant       — variant name string.
        db_path       — Path to project DB.
        project_id    — Project identifier.
    Output:
        BacOutcome.
    Side effects:
        Sends outbound HTTP; writes replay flow, diff, bac_result rows.
    """
    original_flow_id: str = original_flow["id"]
    attacker_role_id: str = meta.get("attacker_role_id", "")
    replayed_flow_id: str = str(uuid.uuid4())
    replay_time: str = datetime.now(timezone.utc).isoformat()

    send_headers: dict = json.loads(modified.get("request_headers", "{}"))
    body: Optional[bytes] = modified.get("request_body")

    # Build the replay flow dict before the HTTP request.
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
        "request_headers": modified.get("request_headers", "{}"),
        "request_cookies": modified.get("request_cookies", "{}"),
        "request_body": body,
        "request_body_truncated": modified.get("request_body_truncated", 0),
        "status_code": None,
        "response_headers": "{}",
        "response_body": None,
        "response_body_truncated": 0,
        "content_type": "",
        "endpoint_id": original_flow.get("endpoint_id"),
        # Record which role performed the attack, not the target role.
        "role_id": attacker_role_id if attacker_role_id else original_flow["role_id"],
        "module_id": original_flow["module_id"],
        "source": "auto_replay",
        "original_flow_id": original_flow_id,
        "replay_error": None,
        "replay_reason": attack_type,
    }

    failure_reason: Optional[str] = None

    try:
        async with httpx.AsyncClient(verify=False,
            follow_redirects=False,
            timeout=_REPLAY_TIMEOUT,
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
            "content_type": resp.headers.get("content-type", ""),
        })

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

    # Persist replay flow.
    try:
        replay_db.insert_replayed_flow(db_path, replayed)
    except Exception as exc:  # noqa: BLE001
        _log.error("Failed to store BAC replay flow %s: %s", replayed_flow_id, exc)
        return BacOutcome(
            original_flow_id=original_flow_id,
            replayed_flow_id=None,
            original_status=original_flow.get("status_code"),
            replay_status=None,
            diff_verdict="ERROR",
            bac_verdict="UNKNOWN",
            attack_type=attack_type,
            variant=variant,
            failure_reason=f"db_write_error: {exc}",
        )

    # Compute and persist diff.
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
        _log.error("Failed to store diff for BAC replay %s: %s", replayed_flow_id, exc)

    # Compute BAC verdict.
    # Network / protocol errors never reach the filter — no HTTP response to evaluate.
    if replayed.get("replay_error"):
        from talos.projects.bac.decision_filter import DecisionResult
        decision: DecisionResult = DecisionResult(
            verdict="UNKNOWN",
            matched_section=None,
            matched_group_id=None,
            matched_rules=[],
        )
    else:
        decision = _compute_bac_verdict_with_filter(
            original_flow=original_flow,
            replayed=replayed,
            project_data_dir=db_path.parent,
        )
    bac_verdict = decision.verdict

    # Persist BAC result.
    try:
        replay_db.insert_bac_result(db_path, {
            "replay_flow_id": replayed_flow_id,
            "original_flow_id": original_flow_id,
            "attack_type": attack_type,
            "variant": variant,
            "attacker_role_id": meta.get("attacker_role_id", ""),
            "target_role_id": meta.get("target_role_id", ""),
            "module_id": meta.get("module_id", ""),
            "verdict": bac_verdict,
            "matched_section": decision.matched_section,
            "matched_group": decision.matched_group_id,
            "matched_rules": (
                json.dumps(decision.matched_rules)
                if decision.matched_rules else None
            ),
        })
    except Exception as exc:  # noqa: BLE001
        _log.error("Failed to store BAC result for replay %s: %s", replayed_flow_id, exc)

    return BacOutcome(
        original_flow_id=original_flow_id,
        replayed_flow_id=replayed_flow_id,
        original_status=original_flow.get("status_code"),
        replay_status=replayed.get("status_code"),
        diff_verdict=diff.verdict,
        bac_verdict=bac_verdict,
        attack_type=attack_type,
        variant=variant,
        failure_reason=failure_reason,
    )


# ------------------------------------------------------------------ #
# Verdict computation                                                  #
# ------------------------------------------------------------------ #

def _compute_bac_verdict_with_filter(
    original_flow: dict,
    replayed: dict,
    project_data_dir: Path,
) -> "DecisionResult":
    """
    Purpose:
        Compute the BAC verdict using the project's decision filter when available,
        falling back to the built-in heuristic when no filter is configured.

        Returns a DecisionResult preserving both the verdict and the evidence
        (matched section, group, and rules) so callers never discard the reasoning.

        Called only when no network/protocol error occurred (replay_error is None).

    Input:
        original_flow    — original flow dict (baseline status for heuristic fallback).
        replayed         — replayed flow dict with status_code, response_headers, response_body.
        project_data_dir — directory containing BAC-decision-filter.yaml (db_path.parent).
    Output:
        DecisionResult with verdict, matched_section, matched_group_id, matched_rules.
    Side effects:
        Reads BAC-decision-filter.yaml from disk on each call.
    """
    from talos.projects.bac.decision_filter import (
        load_filter,
        build_response_data,
        evaluate_response,
        DecisionResult,
    )

    bac_filter = load_filter(project_data_dir)

    if bac_filter is not None:
        response_data = build_response_data(replayed)
        return evaluate_response(bac_filter, response_data)

    # No filter configured — use built-in heuristic; no section/group/rule evidence.
    verdict = _compute_bac_verdict_heuristic(
        original_status=original_flow.get("status_code"),
        replay_status=replayed.get("status_code"),
    )
    return DecisionResult(
        verdict=verdict,
        matched_section=None,
        matched_group_id=None,
        matched_rules=[],
    )


def _compute_bac_verdict_heuristic(
    original_status: Optional[int],
    replay_status: Optional[int],
) -> str:
    """
    Purpose:
        Built-in heuristic BAC verdict used when no BAC-decision-filter.yaml is
        configured.  Applies status-code-only rules.

    Output:
        'POSSIBLE_BAC' | 'SECURE' | 'UNKNOWN'

    Rules (first match wins):
        1. Original was not 200 → UNKNOWN (baseline unreliable).
        2. Replay status 401 or 403 → SECURE.
        3. Replay status 3xx (redirect — assumed login redirect) → SECURE.
        4. Replay status 200 → POSSIBLE_BAC.
        5. All other cases → UNKNOWN.
    """
    if original_status != 200:
        return "UNKNOWN"
    if replay_status in (401, 403):
        return "SECURE"
    if replay_status is not None and 300 <= replay_status < 400:
        return "SECURE"
    if replay_status == 200:
        return "POSSIBLE_BAC"
    return "UNKNOWN"


# ------------------------------------------------------------------ #
# Failure helper                                                       #
# ------------------------------------------------------------------ #

def _fail(
    flow_id: str,
    attack_type: str,
    variant: str,
    reason: str,
) -> BacOutcome:
    """Return a BacOutcome representing a pre-execution failure (no HTTP sent)."""
    return BacOutcome(
        original_flow_id=flow_id,
        replayed_flow_id=None,
        original_status=None,
        replay_status=None,
        diff_verdict=None,
        bac_verdict="UNKNOWN",
        attack_type=attack_type,
        variant=variant,
        failure_reason=reason,
    )
