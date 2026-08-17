"""
Module: talos.cors.engine

Purpose:
    Execute one CORS_ATTACK scheduler job:

        1. Load the captured baseline flow (read-only).
        2. Re-check logout / dangerous annotations.
        3. Apply Origin (and optional preflight method/headers).
        4. Send HTTP via httpx (project upstream proxy when configured).
        5. Persist a **new** flow row (unique UUID, original_flow_id set).
        6. Store cors_results and return CorsOutcome.

    The captured baseline is never updated. Each probe is a distinct
    replay flow, matching unauth / BAC / auth-session.

Dependencies: httpx, talos.replay.db, talos.projects.annotations,
              talos.projects.proxy_config, talos.cors.db / payloads / models
Data flow: scheduler / CLI --right-now → execute_cors_job → unique flow
Side effects: outbound HTTP; INSERT flows + cors_results.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

import talos.replay.db as replay_db
from talos.cors.db import insert_cors_result
from talos.cors.models import (
    VERDICT_CORS_MISCONFIG,
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
    CorsOutcome,
)
from talos.cors.payloads import (
    header_value,
    parse_headers,
    target_origin_key,
)
from talos.projects.annotations import get_annotations
from talos.proxy.http_client import create_async_client, encode_outbound_headers

_log = logging.getLogger(__name__)
_REPLAY_TIMEOUT = httpx.Timeout(30.0)

_HOP_BY_HOP = frozenset(
    {
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-connection",
        "te",
        "trailer",
        "upgrade",
    }
)


def _fail(
    flow_id: str,
    *,
    technique: str,
    family: str,
    origin_sent: str,
    host: str,
    endpoint_id: Optional[str],
    original_status: Optional[int],
    reason: str,
) -> CorsOutcome:
    """Purpose: Transport/skip outcome with UNKNOWN verdict and no new flow."""
    return CorsOutcome(
        original_flow_id=flow_id,
        replayed_flow_id=None,
        endpoint_id=endpoint_id,
        host=host,
        technique=technique,
        technique_family=family,
        origin_sent=origin_sent,
        acao=None,
        acac=None,
        reflected=False,
        credentials=False,
        wildcard=False,
        original_status=original_status,
        replay_status=None,
        verdict=VERDICT_UNKNOWN,
        risk_hint="",
        failure_reason=reason,
    )


def _set_header(headers: dict[str, str], name: str, value: str) -> dict[str, str]:
    """
    Purpose:
        Replace a header case-insensitively and drop hop-by-hop fields.
    Output:
        New header map.
    """
    out: dict[str, str] = {}
    want = name.lower()
    for key, existing in headers.items():
        if key.lower() in _HOP_BY_HOP or key.lower() == want:
            continue
        out[key] = existing
    out[name] = value
    return out


def analyze_cors_response(
    *,
    origin_sent: str,
    response_headers: object,
    attacker_controlled: bool,
) -> tuple[bool, bool, bool, Optional[str], Optional[str], str, str]:
    """
    Purpose:
        Decide reflection / credentials / wildcard and the finding verdict.

    Issue only when an attacker-controlled Origin is echoed in ACAO.
    ACAO: * and ACAC: true without that reflection are not issues.

    Input:
        origin_sent          — Origin request header that was sent.
        response_headers     — probe response headers.
        attacker_controlled  — payload.attacker_controlled.
    Output:
        (reflected, credentials, wildcard, acao, acac, verdict, risk_hint)
    """
    headers = parse_headers(response_headers)
    acao = header_value(headers, "access-control-allow-origin")
    acac = header_value(headers, "access-control-allow-credentials")
    wildcard = bool(acao and acao.strip() == "*")
    credentials = bool(acac and acac.strip().lower() == "true")
    reflected = bool(
        attacker_controlled
        and acao is not None
        and not wildcard
        and acao.strip() == (origin_sent or "").strip()
    )

    if not reflected:
        return (
            False,
            credentials,
            wildcard,
            acao,
            acac,
            VERDICT_SECURE,
            "",
        )

    if (origin_sent or "").strip().lower() == "null":
        hint = "null_origin"
    elif credentials:
        hint = "credentials"
    else:
        hint = "reflected_origin"
    return True, credentials, wildcard, acao, acac, VERDICT_CORS_MISCONFIG, hint


async def execute_cors_job(
    flow_id: str,
    meta: dict,
    db_path: Path,
    project_id: str,
) -> CorsOutcome:
    """
    Purpose:
        Run one CORS technique against a captured baseline; store a unique flow.
    Input:
        flow_id    — baseline captured flow UUID.
        meta       — technique, origin_sent, technique_family, method_override, …
        db_path    — project talos.db.
        project_id — stamped on the new flow.
    Output:
        CorsOutcome (verdict set even when HTTP fails).
    Side effects:
        One outbound request; one new flows row; one cors_results row on
        successful store. Baseline row is not modified.
    """
    technique = str(meta.get("technique") or "arbitrary_https")
    family = str(meta.get("technique_family") or "")
    origin_sent = str(meta.get("origin_sent") or "")
    attacker_controlled = bool(meta.get("attacker_controlled", True))
    method_override = meta.get("method_override")
    acr_method = meta.get("acr_method")
    acr_headers = meta.get("acr_headers")

    flow = replay_db.get_flow_for_replay(db_path, flow_id)
    if flow is None:
        return _fail(
            flow_id,
            technique=technique,
            family=family,
            origin_sent=origin_sent,
            host="",
            endpoint_id=None,
            original_status=None,
            reason="flow_not_found",
        )

    endpoint_id: Optional[str] = flow.get("endpoint_id")
    host = target_origin_key(flow.get("url") or "")
    original_status = flow.get("status_code")

    if endpoint_id:
        tags = get_annotations(db_path, endpoint_id)
        if "logout" in tags:
            return _fail(
                flow_id,
                technique=technique,
                family=family,
                origin_sent=origin_sent,
                host=host,
                endpoint_id=endpoint_id,
                original_status=original_status,
                reason="endpoint_annotated_logout",
            )
        if "dangerous" in tags:
            return _fail(
                flow_id,
                technique=technique,
                family=family,
                origin_sent=origin_sent,
                host=host,
                endpoint_id=endpoint_id,
                original_status=original_status,
                reason="endpoint_annotated_dangerous",
            )

    if not origin_sent:
        return _fail(
            flow_id,
            technique=technique,
            family=family,
            origin_sent=origin_sent,
            host=host,
            endpoint_id=endpoint_id,
            original_status=original_status,
            reason="cors_origin_missing",
        )

    headers = parse_headers(flow.get("request_headers"))
    send_headers = _set_header(headers, "Origin", origin_sent)
    if method_override:
        if acr_method:
            send_headers = _set_header(
                send_headers, "Access-Control-Request-Method", str(acr_method)
            )
        if acr_headers:
            send_headers = _set_header(
                send_headers, "Access-Control-Request-Headers", str(acr_headers)
            )

    method = str(method_override or flow.get("method") or "GET").upper()
    body: Optional[bytes] = flow.get("request_body")
    if method == "OPTIONS":
        body = None

    replayed_flow_id = str(uuid.uuid4())
    replay_time = datetime.now(timezone.utc).isoformat()
    replayed: dict = {
        "id": replayed_flow_id,
        "project_id": project_id,
        "captured_at": replay_time,
        "response_end": None,
        "method": method,
        "url": flow.get("url"),
        "host": flow.get("host"),
        "path": flow.get("path"),
        "query": flow.get("query", ""),
        "request_headers": json.dumps(send_headers),
        "request_cookies": flow.get("request_cookies", "{}"),
        "request_body": body,
        "request_body_truncated": flow.get("request_body_truncated", 0),
        "status_code": None,
        "response_headers": "{}",
        "response_body": None,
        "response_body_truncated": 0,
        "content_type": "",
        "endpoint_id": endpoint_id,
        "role_id": flow["role_id"],
        "module_id": flow["module_id"],
        "source": "auto_replay",
        "original_flow_id": flow_id,
        "replay_error": None,
        "replay_reason": "cors_attack",
    }

    from talos.burp.outbound import prepare_send_headers
    from talos.burp.trace import ENGINE_CORS

    flow_meta = {
        "attack_module": "cors",
        "technique": technique,
        "technique_family": family,
        "origin_sent": origin_sent,
        "baseline_origin": meta.get("baseline_origin"),
        "origin_was_present": meta.get("origin_was_present"),
        "nonce": meta.get("nonce"),
        "preflight": bool(method_override),
    }
    send_headers, flow_meta = prepare_send_headers(
        send_headers,
        db_path=db_path,
        engine=ENGINE_CORS,
        flow=replayed,
        extras={
            "technique": technique,
            "variant": family,
            "origin": origin_sent,
        },
        endpoint_id=str(endpoint_id or ""),
        host=str(replayed.get("host") or ""),
        flow_meta=flow_meta,
    )
    replayed["flow_meta"] = json.dumps(flow_meta)
    replayed["request_headers"] = (
        json.dumps(send_headers)
        if isinstance(send_headers, dict)
        else json.dumps(dict(send_headers))
    )

    failure_reason: Optional[str] = None
    try:
        async with create_async_client(
            db_path,
            timeout=_REPLAY_TIMEOUT,
            follow_redirects=False,
            verify=False,
        ) as client:
            resp = await client.request(
                method=method,
                url=replayed["url"],
                headers=encode_outbound_headers(
                    list(send_headers.items())
                    if isinstance(send_headers, dict)
                    else send_headers
                ),
                content=body,
            )
        replayed.update(
            {
                "response_end": datetime.now(timezone.utc).isoformat(),
                "status_code": resp.status_code,
                "response_headers": json.dumps(dict(resp.headers)),
                "response_body": resp.content if resp.content else None,
                "content_type": resp.headers.get("content-type", ""),
            }
        )
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
        _log.error("Failed to store CORS replay flow %s: %s", replayed_flow_id, exc)
        return _fail(
            flow_id,
            technique=technique,
            family=family,
            origin_sent=origin_sent,
            host=host,
            endpoint_id=endpoint_id,
            original_status=original_status,
            reason=f"db_write_error: {exc}",
        )

    if failure_reason:
        outcome = CorsOutcome(
            original_flow_id=flow_id,
            replayed_flow_id=replayed_flow_id,
            endpoint_id=endpoint_id,
            host=host,
            technique=technique,
            technique_family=family,
            origin_sent=origin_sent,
            acao=None,
            acac=None,
            reflected=False,
            credentials=False,
            wildcard=False,
            original_status=original_status,
            replay_status=None,
            verdict=VERDICT_UNKNOWN,
            risk_hint="",
            failure_reason=failure_reason,
        )
    else:
        resp_headers = parse_headers(replayed.get("response_headers"))
        (
            reflected,
            credentials,
            wildcard,
            acao,
            acac,
            verdict,
            risk_hint,
        ) = analyze_cors_response(
            origin_sent=origin_sent,
            response_headers=resp_headers,
            attacker_controlled=attacker_controlled,
        )
        outcome = CorsOutcome(
            original_flow_id=flow_id,
            replayed_flow_id=replayed_flow_id,
            endpoint_id=endpoint_id,
            host=host,
            technique=technique,
            technique_family=family,
            origin_sent=origin_sent,
            acao=acao,
            acac=acac,
            reflected=reflected,
            credentials=credentials,
            wildcard=wildcard,
            original_status=original_status,
            replay_status=replayed.get("status_code"),
            verdict=verdict,
            risk_hint=risk_hint,
            extra_headers={
                "acam": header_value(resp_headers, "access-control-allow-methods"),
                "acah": header_value(resp_headers, "access-control-allow-headers"),
            },
        )

    try:
        insert_cors_result(
            db_path,
            {
                "replay_flow_id": replayed_flow_id,
                "original_flow_id": flow_id,
                "endpoint_id": endpoint_id,
                "host": host,
                "technique": technique,
                "technique_family": family,
                "origin_sent": origin_sent,
                "acao": outcome.acao,
                "acac": outcome.acac,
                "acam": (outcome.extra_headers or {}).get("acam"),
                "acah": (outcome.extra_headers or {}).get("acah"),
                "reflected": outcome.reflected,
                "credentials": outcome.credentials,
                "wildcard": outcome.wildcard,
                "original_status": original_status,
                "replay_status": outcome.replay_status,
                "verdict": outcome.verdict,
                "risk_hint": outcome.risk_hint,
                "failure_reason": outcome.failure_reason,
            },
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning("Failed to store cors_results for %s: %s", replayed_flow_id, exc)

    return outcome
