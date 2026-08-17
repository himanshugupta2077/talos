"""
Module: talos.projects.unauth.engine

Purpose:
    Unauthenticated Access attack execution engine.

    Receives a baseline flow and scheduler metadata, removes all configured
    authentication, applies the selected Unauth technique, optionally applies
    a request mutation, replays the request, and stores the result.

Pipeline:
    1. Load the baseline flow.
    2. Check endpoint annotations.
    3. Load configured authentication fields (HTTP artifacts and/or
       platform NTLM).
    4. Remove all configured HTTP authentication. Platform NTLM is
       disabled on the outbound client (not a header to strip).
    5. Apply the selected Unauth technique.
    6. Apply the optional request mutation.
    7. Verify that no original configured credential survived.
    8. Send the request through httpx.
    9. Store replay flow and diff.
    10. Evaluate and store the Unauth verdict.

Design constraints:
    - Authentication removal is mandatory.
    - Original configured credentials must never survive into a replay.
    - Unauth techniques run only after authentication removal.
    - Duplicate headers must preserve repeated header field names.
    - No retries.
    - Redirects disabled.
    - Endpoint annotations are re-checked before replay.

Meta dict keys:
    technique
        Unauth technique name.

    request_mutation
        Optional BAC request mutation name.

    request_type
        Optional BAC request mutation type.

Dependencies:
    talos.projects.auth
    talos.projects.annotations
    talos.projects.proxy_config
    talos.projects.unauth.variants
    talos.projects.unauth.decision_filter
    talos.projects.bac.engine
    talos.replay.db
    talos.replay.diff

Data flow:
    scheduler
        -> execute_unauth_job
        -> strip configured auth
        -> apply Unauth technique
        -> apply optional request mutation
        -> assert auth invariant
        -> get_upstream_url → httpx replay
        -> store result

Side effects:
    Sends outbound HTTP requests (via project upstream when configured) and
    writes replay, diff, and Unauth result rows to the project database.
"""

import json
import logging
import uuid
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

import talos.replay.db as replay_db
from talos.projects.annotations import get_annotations
from talos.projects.auth import get_auth_config
from talos.projects.auth_mechanism import resolve_auth_mechanism
from talos.proxy.http_client import create_async_client
from talos.replay.diff import DiffResult, compute_diff

_log = logging.getLogger(__name__)
_REPLAY_TIMEOUT = httpx.Timeout(30.0)


# ------------------------------------------------------------------ #
# Public result type                                                   #
# ------------------------------------------------------------------ #

@dataclass
class UnauthOutcome:
    """
    Purpose:
        Result of a single Unauth attack attempt.

    Fields:
        original_flow_id        — UUID of the source flow.
        replayed_flow_id        — UUID of the stored attack replay, or None on failure.
        original_status         — HTTP status of the original flow.
        replay_status           — HTTP status from the attack replay, or None on error.
        diff_verdict            — SAME | DIFFERENT | ERROR.
        unauth_verdict          — BYPASS | SECURE | UNKNOWN.
        auth_mutation_family    — high-level auth mutation family.
        auth_mutation           — specific auth mutation.
        request_mutation_family — request mutation family; None for baseline.
        request_mutation        — specific request mutation; None for baseline.
        failure_reason          — human-readable error; None on success.
    """
    original_flow_id: str
    replayed_flow_id: Optional[str]
    original_status: Optional[int]
    replay_status: Optional[int]
    diff_verdict: Optional[str]
    unauth_verdict: str
    auth_mutation_family: str
    auth_mutation: str
    request_mutation_family: Optional[str]
    request_mutation: Optional[str]
    failure_reason: Optional[str]


# ------------------------------------------------------------------ #
# Public entry point                                                   #
# ------------------------------------------------------------------ #

async def execute_unauth_job(
    flow_id: str,
    meta: dict,
    db_path: Path,
    project_id: str,
) -> UnauthOutcome:
    """
    Purpose:
        Execute a single Unauth attack job end-to-end.
    Input:
        flow_id    — UUID of the baseline flow to mutate and replay.
        meta       — Deserialized job meta dict containing:
                       technique         (str)      — Unauth technique name.
                       request_mutation  (str|None) — optional BAC mutation name.
                       request_type      (str|None) — optional BAC job type.
        db_path    — Path to the project's talos.db.
        project_id — Project identifier.
    Output:
        UnauthOutcome with verdict.
    Side effects:
        Sends outbound HTTP; writes replay flow, diff, and unauth_result rows.
    """
    from talos.projects.unauth.variants import UNAUTH_TECHNIQUE_BY_NAME

    technique_name: str = meta.get("technique", "baseline")
    req_mut_name: Optional[str] = meta.get("request_mutation")
    req_type: Optional[str] = meta.get("request_type")

    technique_vdef = UNAUTH_TECHNIQUE_BY_NAME.get(technique_name)
    if technique_vdef is None:
        return _fail(
            flow_id,
            technique_name,
            req_mut_name,
            f"unknown_unauth_technique:{technique_name}",
        )

    # Load baseline flow.
    flow = replay_db.get_flow_for_replay(db_path, flow_id)
    if flow is None:
        return _fail(flow_id, technique_name, req_mut_name, "flow_not_found")

    # Guard: endpoint annotations.
    endpoint_id: Optional[str] = flow.get("endpoint_id")
    if endpoint_id:
        tags = get_annotations(db_path, endpoint_id)

        if "logout" in tags:
            return _fail(
                flow_id,
                technique_name,
                req_mut_name,
                "endpoint_annotated_logout",
            )
        if "dangerous" in tags:
            return _fail(
                flow_id,
                technique_name,
                req_mut_name,
                "endpoint_annotated_dangerous",
            )

    # Load auth config. Platform NTLM is a first-class session — captured
    # IIS Persistent-Auth requests often have no Authorization header.
    auth_config = get_auth_config(db_path)
    mechanism = resolve_auth_mechanism(db_path)
    if not mechanism.ready:
        return _fail(
            flow_id,
            technique_name,
            req_mut_name,
            "auth_config_empty",
        )
    if (
        mechanism.ntlm_only
        and technique_vdef.get("technique_action", "none") != "none"
    ):
        return _fail(
            flow_id,
            technique_name,
            req_mut_name,
            "unauth_technique_requires_http_artifacts",
        )
    # Mandatory invariant: every Unauth replay starts with all configured
    # authentication removed.
    try:
        modified = _strip_all_auth(flow, auth_config)
    except Exception as exc:  # noqa: BLE001
        return _fail(
            flow_id,
            technique_name,
            req_mut_name,
            f"auth_strip_error:{exc}",
        )

    # Apply the selected Unauth technique only after valid authentication
    # has been removed.
    try:
        modified = _apply_unauth_technique(
            modified,
            flow,
            auth_config,
            technique_vdef,
        )
    except Exception as exc:  # noqa: BLE001
        return _fail(
            flow_id,
            technique_name,
            req_mut_name,
            f"unauth_technique_error:{exc}",
        )

    # Apply request mutations (may be compound '+'-separated).
    # Duplicate-header techniques use an ordered multi-value header
    # representation. BAC request mutations currently operate on a
    # dict-based header representation and cannot safely compose with it.
    if (
        modified.get("_raw_request_headers") is not None
        and req_mut_name
    ):
        return _fail(
            flow_id,
            technique_name,
            req_mut_name,
            "request_mutation_incompatible_with_duplicate_headers",
        )

    # Apply request mutations (may be compound '+'-separated).
    if req_mut_name and req_type:
        req_mut_names = req_mut_name.split("+")
        req_types = req_type.split("+")
        for rname, rtype in zip(req_mut_names, req_types):
            try:
                result = _apply_one_request_mutation(modified, rtype, rname.strip())
                if result is None:
                    return _fail(
                        flow_id,
                        technique_name,
                        req_mut_name,
                        f"request_mutation_not_applicable:{rname}",
                    )
                modified = result
            except Exception as exc:  # noqa: BLE001
                return _fail(
                    flow_id,
                    technique_name,
                    req_mut_name,
                    f"request_mutation_error:{rname}:{exc}",
                )

    try:
        _assert_no_original_auth_survived(
            flow,
            modified,
            auth_config,
        )
    except Exception as exc:  # noqa: BLE001
        return _fail(
            flow_id,
            technique_name,
            req_mut_name,
            f"auth_invariant_violation:{exc}",
        )

    return await _send_and_store(
        original_flow=flow,
        modified=modified,
        meta=meta,
        technique_vdef=technique_vdef,
        req_mut_name=req_mut_name,
        db_path=db_path,
        project_id=project_id,
    )

def _assert_no_original_auth_survived(
    original_flow: dict,
    modified_flow: dict,
    auth_config: dict,
) -> None:
    """
    Fail closed if any original configured authentication credential
    survives into the Unauth replay.
    """
    original_headers = _load_headers(original_flow)
    modified_headers = _load_headers(modified_flow)

    original_cookies = _load_cookies(original_flow)
    modified_cookies = _load_cookies(modified_flow)

    raw_modified_headers = modified_flow.get(
        "_raw_request_headers",
        [],
    )

    configured_headers = {
        str(name).lower()
        for name in auth_config.get("headers", [])
    }

    configured_cookies = {
        str(name).lower()
        for name in auth_config.get("cookies", [])
    }

    original_auth_header_values: set[str] = set()
    original_auth_cookie_values: set[str] = set()

    for key, value in original_headers.items():
        if str(key).lower() in configured_headers:
            original_auth_header_values.add(str(value))

    for key, value in original_cookies.items():
        if str(key).lower() in configured_cookies:
            original_auth_cookie_values.add(str(value))

    for key, value in modified_headers.items():
        if (
            str(key).lower() in configured_headers
            and str(value) in original_auth_header_values
        ):
            raise ValueError(
                f"original auth credential survived in header: {key}"
            )

    for key, value in raw_modified_headers:
        if (
            str(key).lower() in configured_headers
            and str(value) in original_auth_header_values
        ):
            raise ValueError(
                f"original auth credential survived in duplicate header: {key}"
            )

    for key, value in modified_cookies.items():
        if (
            str(key).lower() in configured_cookies
            and str(value) in original_auth_cookie_values
        ):
            raise ValueError(
                f"original auth credential survived in cookie: {key}"
            )

# ------------------------------------------------------------------ #
# Authentication removal and Unauth technique application                                          #
# ------------------------------------------------------------------ #

def _load_headers(flow: dict) -> dict:
    raw_headers = flow.get("request_headers", "{}")
    if isinstance(raw_headers, str):
        return json.loads(raw_headers)
    return dict(raw_headers or {})


def _load_cookies(flow: dict) -> dict:
    raw_cookies = flow.get("request_cookies", "{}")
    if isinstance(raw_cookies, str):
        return json.loads(raw_cookies)
    return dict(raw_cookies or {})


def _strip_all_auth(flow: dict, auth_config: dict) -> dict:
    """
    Mandatory first stage for every Unauth replay.

    Removes every configured authentication header and cookie.

    Header matching is case-insensitive.
    Cookie matching is also case-insensitive.

    The Cookie request header is rebuilt after auth-cookie removal.
    """
    headers = _load_headers(flow)
    cookies = _load_cookies(flow)

    auth_header_names = {
        name.lower()
        for name in auth_config.get("headers", [])
    }

    auth_cookie_names = {
        name.lower()
        for name in auth_config.get("cookies", [])
    }

    headers = {
        key: value
        for key, value in headers.items()
        if key.lower() not in auth_header_names
    }

    cookies = {
        key: value
        for key, value in cookies.items()
        if key.lower() not in auth_cookie_names
    }

    _rebuild_cookie_header(
        headers,
        cookies,
        auth_config,
    )

    modified = dict(flow)
    modified["request_headers"] = json.dumps(headers)
    modified["request_cookies"] = json.dumps(cookies)

    return modified


def _get_original_auth_header_value(
    original_flow: dict,
    header_name: str,
) -> Optional[str]:
    """
    Return the original configured auth header value using
    case-insensitive header-name matching.

    Used only to identify the authentication scheme.
    """
    headers = _load_headers(original_flow)
    target = header_name.lower()

    for key, value in headers.items():
        if key.lower() == target:
            return str(value)

    return None


def _detect_auth_scheme(value: Optional[str]) -> Optional[str]:
    """
    Detect the HTTP authentication scheme from the original value.

    Examples:
        'Bearer abc' -> 'Bearer'
        'Basic abc'  -> 'Basic'
        'Digest ...' -> 'Digest'
    """
    if not value:
        return None

    value = value.strip()
    if not value:
        return None

    parts = value.split(None, 1)
    if len(parts) < 2:
        return None

    scheme = parts[0]

    if not scheme.isalpha():
        return None

    return scheme


def _malformed_auth_value(original_value: Optional[str]) -> str:
    """
    Generate an invalid authentication credential while preserving the
    detected authentication scheme when possible.

    The original credential value is never reused.
    """
    scheme = _detect_auth_scheme(original_value)

    if scheme is None:
        return "invalid_token_xyz_talos"

    if scheme.lower() == "basic":
        invalid_basic = base64.b64encode(
            b"talos:invalid"
        ).decode("ascii")

        return f"{scheme} {invalid_basic}"

    return f"{scheme} invalid_token_xyz_talos"


def _apply_unauth_technique(
    stripped_flow: dict,
    original_flow: dict,
    auth_config: dict,
    technique_vdef: dict,
) -> dict:
    """
    Apply an Unauth technique to a flow that has already had all valid
    authentication removed.

    This function must never restore an original credential value.
    """
    headers = _load_headers(stripped_flow)
    cookies = _load_cookies(stripped_flow)

    action = technique_vdef["technique_action"]

    if action == "none":
        pass

    elif action == "empty":
        for header_name in auth_config.get("headers", []):
            headers[header_name] = ""

        for cookie_name in auth_config.get("cookies", []):
            cookies[cookie_name] = ""

        _rebuild_cookie_header(
            headers,
            cookies,
            auth_config,
        )

    elif action == "malformed":
        for header_name in auth_config.get("headers", []):
            original_value = _get_original_auth_header_value(
                original_flow,
                header_name,
            )

            headers[header_name] = _malformed_auth_value(
                original_value,
            )

        for cookie_name in auth_config.get("cookies", []):
            cookies[cookie_name] = "invalid_token_xyz_talos"

        _rebuild_cookie_header(
            headers,
            cookies,
            auth_config,
        )

    elif action == "null":
        for header_name in auth_config.get("headers", []):
            headers[header_name] = "null"

        for cookie_name in auth_config.get("cookies", []):
            cookies[cookie_name] = "null"

        _rebuild_cookie_header(
            headers,
            cookies,
            auth_config,
        )

    elif action == "whitespace":
        for header_name in auth_config.get("headers", []):
            headers[header_name] = " "

        for cookie_name in auth_config.get("cookies", []):
            cookies[cookie_name] = " "

        _rebuild_cookie_header(
            headers,
            cookies,
            auth_config,
        )

    elif action in {
        "duplicate_empty",
        "duplicate_malformed",
    }:
        # Duplicate headers require an ordered multi-value representation.
        # They cannot be represented safely using the request_headers dict.
        #
        # Store raw duplicate header tuples separately. _send_and_store()
        # must use these tuples when constructing the httpx request.
        raw_headers = [
            (str(key), str(value))
            for key, value in headers.items()
        ]

        for header_name in auth_config.get("headers", []):
            if action == "duplicate_empty":
                raw_headers.append((header_name, ""))
                raw_headers.append((header_name, ""))

            else:
                original_value = _get_original_auth_header_value(
                    original_flow,
                    header_name,
                )

                malformed_value = _malformed_auth_value(
                    original_value,
                )

                raw_headers.append(
                    (header_name, malformed_value)
                )
                raw_headers.append(
                    (header_name, "")
                )

        modified = dict(stripped_flow)
        modified["request_headers"] = json.dumps(headers)
        modified["_raw_request_headers"] = raw_headers
        modified["request_cookies"] = json.dumps(cookies)

        return modified

    else:
        raise ValueError(
            f"unknown unauth technique action: {action}"
        )

    modified = dict(stripped_flow)
    modified["request_headers"] = json.dumps(headers)
    modified["request_cookies"] = json.dumps(cookies)

    return modified


def _rebuild_cookie_header(headers: dict, cookies: dict, auth_config: dict) -> None:
    """
    Purpose:
        Rebuild the Cookie header from the cookies dict.
        Removes all existing Cookie headers first to prevent duplicates.
    Side effects: Modifies headers dict in-place.
    """
    if not auth_config["cookies"]:
        return
    for k in list(headers.keys()):
        if k.lower() == "cookie":
            del headers[k]
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    if cookie_str:
        headers["Cookie"] = cookie_str


# ------------------------------------------------------------------ #
# Request mutation application                                         #
# ------------------------------------------------------------------ #

def _apply_one_request_mutation(
    flow: dict,
    request_type: str,
    request_mutation_name: str,
) -> Optional[dict]:
    """
    Purpose:
        Apply a single BAC-family request mutation to the flow.
        Re-uses the mutation helpers from bac.engine so there is no duplicated logic.
    Input:
        flow                  — current flow dict (already auth-mutated).
        request_type          — BAC job type constant (e.g. 'bac_method_fuzz').
        request_mutation_name — variant name from the BAC variants registry.
    Output:
        Modified flow dict, or None when the variant is not applicable.
    Side effects: None.
    """
    from talos.scheduler.job import (
        BAC_METHOD_FUZZ, BAC_CONTENT_TYPE, BAC_URL_FUZZ,
        BAC_HEADER_INJECT, BAC_HOST_FUZZ, BAC_ROLE_INJECT, BAC_PARSER_CONFUSE,
    )
    from talos.projects.bac import engine as bac_engine

    raw_headers = flow.get("request_headers", "{}")
    headers: dict = json.loads(raw_headers) if isinstance(raw_headers, str) else dict(raw_headers)

    meta_stub = {"variant": request_mutation_name}

    if request_type == BAC_METHOD_FUZZ:
        result = bac_engine._mutate_method(flow, headers, meta_stub)
        if result is None:
            return None
        m, h = result
        m["request_headers"] = json.dumps(h)
        return m

    elif request_type == BAC_CONTENT_TYPE:
        result = bac_engine._mutate_content_type(flow, headers, meta_stub)
        if result is None:
            return None
        m, h = result
        m["request_headers"] = json.dumps(h)
        return m

    elif request_type == BAC_URL_FUZZ:
        return bac_engine._mutate_url(flow, meta_stub)

    elif request_type == BAC_HEADER_INJECT:
        h = bac_engine._mutate_inject_header(flow, headers, meta_stub)
        m = dict(flow)
        m["request_headers"] = json.dumps(h)
        return m

    elif request_type == BAC_HOST_FUZZ:
        h, m = bac_engine._mutate_host(headers, flow, meta_stub)
        m["request_headers"] = json.dumps(h)
        return m

    elif request_type == BAC_ROLE_INJECT:
        result = bac_engine._mutate_role_params(flow, headers, meta_stub)
        if result is None:
            return None
        m, h = result
        m["request_headers"] = json.dumps(h)
        return m

    elif request_type == BAC_PARSER_CONFUSE:
        result = bac_engine._mutate_parser_confuse(flow, headers, meta_stub)
        if result is None:
            return None
        m, h = result
        m["request_headers"] = json.dumps(h)
        return m

    # Unknown request type — not applicable.
    return None


# ------------------------------------------------------------------ #
# HTTP execution and DB storage                                        #
# ------------------------------------------------------------------ #


async def _send_and_store(
    original_flow: dict,
    modified: dict,
    meta: dict,
    technique_vdef: dict,
    req_mut_name: Optional[str],
    db_path: Path,
    project_id: str,
) -> UnauthOutcome:
    """
    Purpose:
        Send the mutated request, store all results, compute Unauth verdict.
    Input:
        original_flow — unmodified flow dict (used for diff comparison).
        modified      — auth+request-mutated flow dict.
        meta          — job metadata dict.
        technique_vdef — Unauth technique definition.
        req_mut_name  — request mutation variant name(s); None for baseline.
        db_path       — Path to project DB.
        project_id    — Project identifier.
    Output:
        UnauthOutcome.
    Side effects:
        Sends outbound HTTP; writes replay flow, diff, unauth_result rows.
    """
    from talos.projects.unauth.decision_filter import (
        load_filter, evaluate_response, heuristic_verdict, ResponseData,
    )

    original_flow_id: str = original_flow["id"]
    replayed_flow_id: str = str(uuid.uuid4())
    replay_time: str = datetime.now(timezone.utc).isoformat()

    auth_mutation_family: str = technique_vdef["mutation_family"]
    auth_mutation_label: str = technique_vdef["mutation"]

    # Derive request mutation family from variant definition if available.
    request_mutation_family: Optional[str] = None
    if req_mut_name:
        from talos.projects.bac.variants import (
            METHOD_FUZZ_VARIANTS, CONTENT_TYPE_VARIANTS, URL_FUZZ_VARIANTS,
            HEADER_INJECT_VARIANTS, HOST_FUZZ_VARIANTS, ROLE_INJECT_VARIANTS,
            PARSER_CONFUSE_VARIANTS,
        )
        all_req_variants = (
            METHOD_FUZZ_VARIANTS + CONTENT_TYPE_VARIANTS + URL_FUZZ_VARIANTS
            + HEADER_INJECT_VARIANTS + HOST_FUZZ_VARIANTS + ROLE_INJECT_VARIANTS
            + PARSER_CONFUSE_VARIANTS
        )
        # For compound mutations, use the first variant's family.
        first_name = req_mut_name.split("+")[0].strip()
        req_vdef = next((v for v in all_req_variants if v["name"] == first_name), None)
        if req_vdef:
            request_mutation_family = req_vdef.get("mutation_family")

    stored_headers: dict = _load_headers(modified)

    raw_request_headers = modified.get("_raw_request_headers")

    if raw_request_headers is not None:
        send_headers = [
            (str(name), str(value))
            for name, value in raw_request_headers
        ]
    else:
        send_headers = [
            (str(name), str(value))
            for name, value in stored_headers.items()
        ]

    stored_request_headers: dict[str, object] = {}

    for name, value in send_headers:
        existing = next(
            (
                key
                for key in stored_request_headers
                if key.lower() == name.lower()
            ),
            None,
        )

        if existing is None:
            stored_request_headers[name] = value
            continue

        current_value = stored_request_headers[existing]

        if isinstance(current_value, list):
            current_value.append(value)
        else:
            stored_request_headers[existing] = [
                current_value,
                value,
            ]

    body: Optional[bytes] = modified.get("request_body")

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
        "request_headers": json.dumps(stored_request_headers),
        "request_cookies": modified.get("request_cookies", "{}"),
        "request_body": body,
        "request_body_truncated": modified.get("request_body_truncated", 0),
        "status_code": None,
        "response_headers": "{}",
        "response_body": None,
        "response_body_truncated": 0,
        "content_type": "",
        "endpoint_id": original_flow.get("endpoint_id"),
        "role_id": original_flow["role_id"],
        "module_id": original_flow["module_id"],
        "source": "auto_replay",
        "original_flow_id": original_flow_id,
        "replay_error": None,
        "replay_reason": "unauth_attack",
    }

    from talos.burp.outbound import prepare_send_headers
    from talos.burp.trace import ENGINE_UNAUTH

    flow_meta = {
        "attack_module": "unauth",
        "auth_mutation_family": auth_mutation_family,
        "auth_mutation": auth_mutation_label,
        "request_mutation_family": request_mutation_family,
        "request_mutation": req_mut_name,
    }
    send_headers, flow_meta = prepare_send_headers(
        send_headers,
        db_path=db_path,
        engine=ENGINE_UNAUTH,
        flow=replayed,
        extras={
            "technique": auth_mutation_label or auth_mutation_family or "unauth",
            "variant": req_mut_name or "",
        },
        endpoint_id=str(original_flow.get("endpoint_id") or ""),
        host=str(replayed.get("host") or ""),
        flow_meta=flow_meta,
    )
    replayed["flow_meta"] = json.dumps(flow_meta)
    if isinstance(send_headers, dict):
        replayed["request_headers"] = json.dumps(send_headers)

    failure_reason: Optional[str] = None

    try:
        # Upstream is project-configured only (proxy_config); None → direct.
        async with create_async_client(
            db_path,
            timeout=_REPLAY_TIMEOUT,
            follow_redirects=False,
            verify=False,
            platform_auth=False,
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

    # Persist replay flow.
    try:
        replay_db.insert_replayed_flow(db_path, replayed)
    except Exception as exc:  # noqa: BLE001
        _log.error("Failed to store unauth replay flow %s: %s", replayed_flow_id, exc)
        return UnauthOutcome(
            original_flow_id=original_flow_id,
            replayed_flow_id=None,
            original_status=original_flow.get("status_code"),
            replay_status=None,
            diff_verdict="ERROR",
            unauth_verdict="UNKNOWN",
            auth_mutation_family=auth_mutation_family,
            auth_mutation=auth_mutation_label,
            request_mutation_family=request_mutation_family,
            request_mutation=req_mut_name,
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
        _log.error("Failed to store diff for unauth replay %s: %s", replayed_flow_id, exc)

    # Compute Unauth verdict via decision filter or heuristics.
    if replayed.get("replay_error"):
        from talos.projects.unauth.decision_filter import UnauthDecisionResult
        decision = UnauthDecisionResult("UNKNOWN", None, None)
    else:
        decision_filter = load_filter(db_path.parent)
        if decision_filter is not None:
            resp_data = ResponseData(
                status=replayed.get("status_code"),
                headers=json.loads(replayed.get("response_headers", "{}")),
                body=replayed.get("response_body"),
                response_length=len(replayed["response_body"]) if replayed.get("response_body") else 0,
            )
            decision = evaluate_response(decision_filter, resp_data)
        else:
            decision = heuristic_verdict(
                original_status=original_flow.get("status_code"),
                replay_status=replayed.get("status_code"),
                replay_error=replayed.get("replay_error"),
            )

    unauth_verdict = decision.verdict

    # Persist unauth result.
    try:
        from talos.replay.db import insert_unauth_result
        insert_unauth_result(db_path, {
            "replay_flow_id": replayed_flow_id,
            "original_flow_id": original_flow_id,
            "endpoint_id": original_flow.get("endpoint_id"),
            "auth_mutation_family": auth_mutation_family,
            "auth_mutation": auth_mutation_label,
            "request_mutation_family": request_mutation_family,
            "request_mutation": req_mut_name,
            "verdict": unauth_verdict,
            "matched_section": decision.matched_section,
            "matched_group": decision.matched_group_id,
            "matched_rules": (
                json.dumps(decision.matched_rules)
                if decision.matched_rules else None
            ),
        })
    except Exception as exc:  # noqa: BLE001
        _log.error("Failed to store unauth result for replay %s: %s", replayed_flow_id, exc)

    return UnauthOutcome(
        original_flow_id=original_flow_id,
        replayed_flow_id=replayed_flow_id,
        original_status=original_flow.get("status_code"),
        replay_status=replayed.get("status_code"),
        diff_verdict=diff.verdict,
        unauth_verdict=unauth_verdict,
        auth_mutation_family=auth_mutation_family,
        auth_mutation=auth_mutation_label,
        request_mutation_family=request_mutation_family,
        request_mutation=req_mut_name,
        failure_reason=failure_reason,
    )


# ------------------------------------------------------------------ #
# Failure helper                                                       #
# ------------------------------------------------------------------ #

def _fail(
    flow_id: str,
    auth_mutation: str,
    req_mutation: Optional[str],
    reason: str,
) -> UnauthOutcome:
    """Return a failed UnauthOutcome without sending any HTTP request."""
    return UnauthOutcome(
        original_flow_id=flow_id,
        replayed_flow_id=None,
        original_status=None,
        replay_status=None,
        diff_verdict=None,
        unauth_verdict="UNKNOWN",
        auth_mutation_family="",
        auth_mutation=auth_mutation,
        request_mutation_family=None,
        request_mutation=req_mutation,
        failure_reason=reason,
    )
