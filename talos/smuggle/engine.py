"""
Module: talos.smuggle.engine

Purpose:
    Execute one SMUGGLE_ATTACK scheduler job:

        1. Load the captured baseline flow (read-only).
        2. Re-check logout / dangerous annotations.
        3. Connect raw HTTP/1.1 to the origin (NTLM handshake when configured).
        4. Baseline GET → one smuggling probe → follow-up GET.
        5. Persist a **new** flow row (unique UUID, original_flow_id set).
        6. Snapshot the raw probe into the Talos Burp tree.
        7. Store smuggle_results and return SmuggleOutcome.

    The captured baseline is never updated. httpx is not used — framing
    headers must stay malformed.

Dependencies: talos.replay.db, talos.projects.annotations,
              talos.smuggle.db / detect / payloads / transport / models,
              talos.burp
Data flow: scheduler / CLI --right-now → execute_smuggle_job → unique flow
Side effects: outbound TCP/TLS; INSERT flows + smuggle_results; Burp snapshot.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

import talos.replay.db as replay_db
from talos.projects.annotations import get_annotations
from talos.smuggle.candidates import target_origin_key
from talos.smuggle.db import insert_smuggle_result
from talos.smuggle.detect import analyze_smuggle_exchange
from talos.smuggle.models import (
    VERDICT_UNKNOWN,
    SmuggleOutcome,
    SmugglePayload,
)
from talos.smuggle.payloads import generate_smuggle_payloads, render_http_request
from talos.smuggle.transport import (
    RawHttpConnection,
    RawHttpError,
    handshake_ntlm,
    match_ntlm_profile,
    open_raw_connection,
    resolve_origin,
    session_headers_from_capture,
)

_log = logging.getLogger(__name__)

ConnectFn = Callable[..., RawHttpConnection]


def _request_target(path: str, query: str) -> str:
    """Purpose: Path + query for the request line."""
    route = path if (path or "").startswith("/") else f"/{path or ''}"
    if query and "?" not in route:
        return f"{route}?{query}"
    return route or "/"


def _parse_headers(raw: object) -> object:
    if raw is None:
        return {}
    if isinstance(raw, (dict, list, tuple)):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {}
    return {}


def _fail(
    flow_id: str,
    *,
    technique: str,
    family: str,
    canary_path: str,
    host: str,
    method: str,
    path: str,
    endpoint_id: Optional[str],
    original_status: Optional[int],
    reason: str,
    ntlm_used: bool = False,
) -> SmuggleOutcome:
    """Purpose: Transport/skip outcome with UNKNOWN verdict."""
    return SmuggleOutcome(
        original_flow_id=flow_id,
        replayed_flow_id=None,
        endpoint_id=endpoint_id,
        host=host,
        method=method,
        path=path,
        technique=technique,
        technique_family=family,
        canary_path=canary_path,
        ntlm_used=ntlm_used,
        baseline_status=None,
        probe_status=None,
        followup_status=None,
        probe_elapsed_ms=None,
        followup_elapsed_ms=None,
        timeout_hit=False,
        desync_signal="",
        evidence="",
        original_status=original_status,
        verdict=VERDICT_UNKNOWN,
        risk_hint="",
        failure_reason=reason,
    )


def _snapshot_burp(
    *,
    db_path: Path,
    project_id: str,
    replayed: dict,
    payload: SmugglePayload,
    ntlm_used: bool,
    ntlm_profile: str,
    followup_status: Optional[int],
    followup_headers: object,
    followup_body: object,
    failure_reason: Optional[str],
) -> dict:
    """
    Purpose:
        Stamp flow_meta['burp'] and write the raw probe into the snapshot
        so the Talos Burp extension shows the request.
    Output:
        flow_meta dict (also stored on the replay row).
    """
    from talos.burp.outbound import prepare_send_headers
    from talos.burp.snapshot import record_http_response, record_request, record_send_failure
    from talos.burp.trace import ENGINE_SMUGGLE, trace_from_flow_meta

    header_map = {name: value for name, value in payload.headers}
    flow_meta = {
        "attack_module": "smuggle",
        "technique": payload.technique,
        "technique_family": payload.family,
        "canary_path": payload.canary_path,
        "ntlm_used": ntlm_used,
    }
    _headers, flow_meta = prepare_send_headers(
        header_map,
        db_path=db_path,
        engine=ENGINE_SMUGGLE,
        flow=replayed,
        extras={
            "technique": payload.technique,
            "variant": payload.family,
            "auth_mode": "ntlm" if ntlm_used else "http",
            "ntlm_profile": ntlm_profile,
        },
        endpoint_id=str(replayed.get("endpoint_id") or ""),
        host=str(replayed.get("host") or ""),
        flow_meta=flow_meta,
    )
    del _headers
    trace = trace_from_flow_meta(flow_meta)
    if trace is not None:
        record_request(
            trace,
            method=payload.method,
            host=str(replayed.get("host") or ""),
            path=str(replayed.get("path") or "/"),
            url=str(replayed.get("url") or ""),
            headers=list(payload.headers),
            body=payload.body,
        )
        if failure_reason:
            record_send_failure(flow_meta, project_id, failure_reason)
        elif followup_status is not None:
            record_http_response(
                flow_meta,
                project_id=project_id,
                status=int(followup_status),
                headers=followup_headers,
                body=followup_body,
            )
    return flow_meta


def execute_smuggle_job(
    flow_id: str,
    meta: dict,
    db_path: Path,
    project_id: str,
    *,
    connect_fn: Optional[ConnectFn] = None,
) -> SmuggleOutcome:
    """
    Purpose:
        Run one smuggling technique against a captured flow; store a unique flow.
    Input:
        flow_id    — baseline captured flow UUID.
        meta       — technique, nonce, technique_family, …
        db_path    — project talos.db.
        project_id — stamped on the new flow.
        connect_fn — test seam (defaults to open_raw_connection).
    Output:
        SmuggleOutcome (verdict set even when HTTP fails).
    Side effects:
        Outbound raw HTTP; one new flows row; one smuggle_results row;
        Burp snapshot. Baseline row is not modified.
    """
    technique = str(meta.get("technique") or "cl_te")
    family = str(meta.get("technique_family") or "")
    nonce = str(meta.get("nonce") or uuid.uuid4().hex[:8])
    canary_path = str(meta.get("canary_path") or "")

    flow = replay_db.get_flow_for_replay(db_path, flow_id)
    if flow is None:
        return _fail(
            flow_id,
            technique=technique,
            family=family,
            canary_path=canary_path,
            host="",
            method="",
            path="",
            endpoint_id=None,
            original_status=None,
            reason="flow_not_found",
        )

    endpoint_id: Optional[str] = flow.get("endpoint_id")
    method = str(flow.get("method") or "GET").upper()
    path = str(flow.get("path") or "/")
    query = str(flow.get("query") or "")
    url = str(flow.get("url") or "")
    host = target_origin_key(url, str(flow.get("host") or ""))
    original_status = flow.get("status_code")
    target = _request_target(path, query)

    if endpoint_id:
        tags = get_annotations(db_path, endpoint_id)
        if "logout" in tags:
            return _fail(
                flow_id,
                technique=technique,
                family=family,
                canary_path=canary_path,
                host=host,
                method=method,
                path=path,
                endpoint_id=endpoint_id,
                original_status=original_status,
                reason="endpoint_annotated_logout",
            )
        if "dangerous" in tags:
            return _fail(
                flow_id,
                technique=technique,
                family=family,
                canary_path=canary_path,
                host=host,
                method=method,
                path=path,
                endpoint_id=endpoint_id,
                original_status=original_status,
                reason="endpoint_annotated_dangerous",
            )

    try:
        _hostname, _port, _tls, host_header = resolve_origin(url)
    except RawHttpError as exc:
        return _fail(
            flow_id,
            technique=technique,
            family=family,
            canary_path=canary_path,
            host=host,
            method=method,
            path=path,
            endpoint_id=endpoint_id,
            original_status=original_status,
            reason=str(exc),
        )

    ntlm_entry = match_ntlm_profile(db_path, urlparse(url).hostname or flow.get("host") or "")
    ntlm_used = ntlm_entry is not None
    ntlm_profile = ""
    if ntlm_entry is not None:
        ntlm_profile = str(getattr(ntlm_entry, "id", "") or getattr(ntlm_entry, "name", "") or "")

    captured_headers = _parse_headers(flow.get("request_headers"))
    extras = session_headers_from_capture(captured_headers, ntlm=ntlm_used)
    try:
        payloads = generate_smuggle_payloads(
            host=host_header,
            nonce=nonce,
            extra_headers=extras,
            techniques=[technique],
        )
    except ValueError as exc:
        return _fail(
            flow_id,
            technique=technique,
            family=family,
            canary_path=canary_path,
            host=host,
            method=method,
            path=path,
            endpoint_id=endpoint_id,
            original_status=original_status,
            reason=str(exc),
        )
    if not payloads:
        return _fail(
            flow_id,
            technique=technique,
            family=family,
            canary_path=canary_path,
            host=host,
            method=method,
            path=path,
            endpoint_id=endpoint_id,
            original_status=original_status,
            reason="smuggle_payload_missing",
        )
    payload = payloads[0]
    family = payload.family
    canary_path = payload.canary_path

    opener = connect_fn or open_raw_connection
    conn: Optional[RawHttpConnection] = None
    baseline_status: Optional[int] = None
    probe_status: Optional[int] = None
    followup_status: Optional[int] = None
    probe_elapsed: Optional[int] = None
    followup_elapsed: Optional[int] = None
    timeout_hit = False
    extra_response = False
    followup_body: bytes = b""
    followup_headers: list[tuple[str, str]] = []
    failure_reason: Optional[str] = None
    verdict = VERDICT_UNKNOWN
    signal = ""
    evidence = ""
    risk_hint = ""

    try:
        conn = opener(url, timeout=8.0)
        if ntlm_entry is not None:
            handshake_ntlm(
                conn,
                path=target,
                host_header=host_header,
                entry=ntlm_entry,
            )

        session = session_headers_from_capture(captured_headers, ntlm=ntlm_used)
        baseline_headers = [
            ("Host", host_header),
            ("Connection", "keep-alive"),
            ("User-Agent", "Talos-smuggle"),
            *session,
        ]
        conn.sendall(render_http_request("GET", target, baseline_headers))
        baseline = conn.read_response()
        baseline_status = baseline.status or None
        if baseline.timed_out and not baseline.status:
            raise RawHttpError("baseline_timeout")

        raw_probe = render_http_request(
            payload.method, target, list(payload.headers), payload.body
        )
        conn.sendall(raw_probe)
        probe = conn.read_response()
        probe_status = probe.status or None
        probe_elapsed = probe.elapsed_ms
        timeout_hit = bool(probe.timed_out)

        follow_headers = [
            ("Host", host_header),
            ("Connection", "keep-alive"),
            ("User-Agent", "Talos-smuggle"),
            *session,
        ]
        conn.sendall(render_http_request("GET", target, follow_headers))
        followup = conn.read_response()
        followup_status = followup.status or None
        followup_elapsed = followup.elapsed_ms
        followup_body = followup.body
        followup_headers = list(followup.headers)
        if followup.timed_out:
            timeout_hit = True

        try:
            extra = conn.read_response(timeout=0.4)
            if extra.status or extra.body:
                extra_response = True
        except (RawHttpError, OSError):
            extra_response = False

        verdict, signal, evidence, risk_hint = analyze_smuggle_exchange(
            canary_path=canary_path,
            baseline_status=baseline_status,
            probe_status=probe_status,
            followup_status=followup_status,
            followup_body=followup_body,
            followup_headers=followup_headers,
            probe_timed_out=timeout_hit,
            extra_response=extra_response,
        )
    except RawHttpError as exc:
        failure_reason = str(exc)
        verdict = VERDICT_UNKNOWN
    except OSError as exc:
        failure_reason = f"connection_error: {exc}"
        verdict = VERDICT_UNKNOWN
    except Exception as exc:  # noqa: BLE001
        failure_reason = f"unexpected_error: {exc}"
        verdict = VERDICT_UNKNOWN
    finally:
        if conn is not None:
            conn.close()

    replayed_flow_id = str(uuid.uuid4())
    replay_time = datetime.now(timezone.utc).isoformat()
    header_map = {name: value for name, value in payload.headers}
    replayed: dict = {
        "id": replayed_flow_id,
        "project_id": project_id,
        "captured_at": replay_time,
        "response_end": datetime.now(timezone.utc).isoformat(),
        "method": payload.method,
        "url": url,
        "host": flow.get("host"),
        "path": path,
        "query": query,
        "request_headers": json.dumps(header_map),
        "request_cookies": flow.get("request_cookies", "{}"),
        "request_body": payload.body,
        "request_body_truncated": 0,
        "status_code": followup_status or probe_status,
        "response_headers": json.dumps(dict(followup_headers)) if followup_headers else "{}",
        "response_body": followup_body or None,
        "response_body_truncated": 0,
        "content_type": "",
        "endpoint_id": endpoint_id,
        "role_id": flow["role_id"],
        "module_id": flow["module_id"],
        "source": "auto_replay",
        "original_flow_id": flow_id,
        "replay_error": None if not failure_reason else "smuggle_error",
        "replay_reason": "smuggle_attack",
    }

    try:
        flow_meta = _snapshot_burp(
            db_path=db_path,
            project_id=project_id,
            replayed=replayed,
            payload=payload,
            ntlm_used=ntlm_used,
            ntlm_profile=ntlm_profile,
            followup_status=followup_status,
            followup_headers=followup_headers,
            followup_body=followup_body,
            failure_reason=failure_reason,
        )
        replayed["flow_meta"] = json.dumps(flow_meta)
    except Exception as exc:  # noqa: BLE001
        _log.debug("burp snapshot failed for smuggle %s: %s", replayed_flow_id, exc)
        replayed["flow_meta"] = json.dumps(
            {
                "attack_module": "smuggle",
                "technique": technique,
                "canary_path": canary_path,
            }
        )

    try:
        replay_db.insert_replayed_flow(db_path, replayed)
    except Exception as exc:  # noqa: BLE001
        _log.error("Failed to store smuggle replay flow %s: %s", replayed_flow_id, exc)
        return _fail(
            flow_id,
            technique=technique,
            family=family,
            canary_path=canary_path,
            host=host,
            method=method,
            path=path,
            endpoint_id=endpoint_id,
            original_status=original_status,
            reason=f"db_write_error: {exc}",
            ntlm_used=ntlm_used,
        )

    outcome = SmuggleOutcome(
        original_flow_id=flow_id,
        replayed_flow_id=replayed_flow_id,
        endpoint_id=endpoint_id,
        host=host,
        method=method,
        path=path,
        technique=technique,
        technique_family=family,
        canary_path=canary_path,
        ntlm_used=ntlm_used,
        baseline_status=baseline_status,
        probe_status=probe_status,
        followup_status=followup_status,
        probe_elapsed_ms=probe_elapsed,
        followup_elapsed_ms=followup_elapsed,
        timeout_hit=timeout_hit,
        desync_signal=signal,
        evidence=evidence,
        original_status=original_status,
        verdict=verdict,
        risk_hint=risk_hint,
        failure_reason=failure_reason,
    )

    try:
        insert_smuggle_result(
            db_path,
            {
                "replay_flow_id": replayed_flow_id,
                "original_flow_id": flow_id,
                "endpoint_id": endpoint_id,
                "host": host,
                "technique": technique,
                "technique_family": family,
                "canary_path": canary_path,
                "ntlm_used": ntlm_used,
                "probe_status": probe_status,
                "followup_status": followup_status,
                "baseline_status": baseline_status,
                "probe_elapsed_ms": probe_elapsed,
                "followup_elapsed_ms": followup_elapsed,
                "timeout_hit": timeout_hit,
                "desync_signal": signal,
                "evidence": evidence,
                "original_status": original_status,
                "verdict": verdict,
                "risk_hint": risk_hint,
                "failure_reason": failure_reason,
            },
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning("Failed to store smuggle_results for %s: %s", replayed_flow_id, exc)

    return outcome
