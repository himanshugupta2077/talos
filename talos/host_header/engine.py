"""
Module: talos.host_header.engine

Purpose:
    Execute one HOST_HEADER_ATTACK scheduler job:

        1. Load the captured baseline flow (read-only).
        2. Re-check logout / dangerous annotations.
        3. Replace one host-related header with one payload.
        4. Send HTTP via httpx to the **original URL** (Host header may differ).
        5. Persist a **new** flow row (unique UUID, original_flow_id set).
        6. Store host_header_results and return HostHeaderOutcome.

    The captured baseline is never updated. Each probe is a distinct
    replay flow, matching CORS / SQLi / path-traversal.

Dependencies: httpx, time, talos.replay.db, talos.projects.annotations,
              talos.host_header.db / detect / inject / models
Data flow: scheduler / CLI --right-now → execute_host_header_job → unique flow
Side effects: outbound HTTP; INSERT flows + host_header_results.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx

import talos.replay.db as replay_db
from talos.host_header.db import insert_host_header_result
from talos.host_header.detect import analyze_host_header_response
from talos.host_header.inject import InjectionPoint, apply_payload
from talos.host_header.models import (
    CANARY_HOST,
    VERDICT_UNKNOWN,
    HostHeaderOutcome,
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


def _drop_hop_by_hop(headers: dict[str, str]) -> dict[str, str]:
    """Purpose: Strip hop-by-hop headers before send."""
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in _HOP_BY_HOP
    }


def _target_host(url: str, fallback: str = "") -> str:
    """Purpose: scheme://netloc cluster key."""
    parsed = urlparse(url or "")
    scheme = (parsed.scheme or "https").lower()
    netloc = (parsed.netloc or parsed.hostname or fallback or "unknown").lower()
    return f"{scheme}://{netloc}"


def _fail(
    flow_id: str,
    *,
    technique: str,
    family: str,
    location: str,
    param_name: str,
    payload_sent: str,
    original_value: str,
    host: str,
    method: str,
    path: str,
    endpoint_id: Optional[str],
    original_status: Optional[int],
    reason: str,
) -> HostHeaderOutcome:
    """Purpose: Transport/skip outcome with UNKNOWN verdict."""
    return HostHeaderOutcome(
        original_flow_id=flow_id,
        replayed_flow_id=None,
        endpoint_id=endpoint_id,
        host=host,
        method=method,
        path=path,
        technique=technique,
        technique_family=family,
        location=location,
        param_name=param_name,
        payload_sent=payload_sent,
        original_value=original_value,
        original_status=original_status,
        replay_status=None,
        elapsed_ms=None,
        reflected_url="",
        evidence="",
        verdict=VERDICT_UNKNOWN,
        risk_hint="",
        failure_reason=reason,
    )


async def execute_host_header_job(
    flow_id: str,
    meta: dict,
    db_path: Path,
    project_id: str,
) -> HostHeaderOutcome:
    """
    Purpose:
        Run one host-header payload against one header; store a unique flow.
    """
    technique = str(meta.get("technique") or "abs_canary")
    family = str(meta.get("technique_family") or "")
    location = str(meta.get("location") or "header")
    param_name = str(meta.get("param_name") or "")
    payload_sent = str(meta.get("payload_sent") or "")
    original_value = str(meta.get("original_value") or "")
    surface_kind = str(meta.get("surface_kind") or "")
    normalized_path = str(meta.get("normalized_path") or "")
    canary_host = str(meta.get("canary_host") or CANARY_HOST)

    flow = replay_db.get_flow_for_replay(db_path, flow_id)
    if flow is None:
        return _fail(
            flow_id,
            technique=technique,
            family=family,
            location=location,
            param_name=param_name,
            payload_sent=payload_sent,
            original_value=original_value,
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
    host = _target_host(flow.get("url") or "", str(flow.get("host") or ""))
    original_status = flow.get("status_code")

    if endpoint_id:
        tags = get_annotations(db_path, endpoint_id)
        if "logout" in tags:
            return _fail(
                flow_id,
                technique=technique,
                family=family,
                location=location,
                param_name=param_name,
                payload_sent=payload_sent,
                original_value=original_value,
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
                location=location,
                param_name=param_name,
                payload_sent=payload_sent,
                original_value=original_value,
                host=host,
                method=method,
                path=path,
                endpoint_id=endpoint_id,
                original_status=original_status,
                reason="endpoint_annotated_dangerous",
            )

    if not param_name:
        return _fail(
            flow_id,
            technique=technique,
            family=family,
            location=location,
            param_name=param_name,
            payload_sent=payload_sent,
            original_value=original_value,
            host=host,
            method=method,
            path=path,
            endpoint_id=endpoint_id,
            original_status=original_status,
            reason="host_header_point_missing",
        )

    point = InjectionPoint(
        location=location,
        name=param_name,
        original=original_value,
        surface_kind=surface_kind,
        normalized_path=normalized_path,
    )
    try:
        send_url, send_headers, body = apply_payload(
            point,
            payload_sent,
            url=str(flow.get("url") or ""),
            request_headers=flow.get("request_headers"),
            request_body=flow.get("request_body"),
        )
    except Exception as exc:  # noqa: BLE001
        return _fail(
            flow_id,
            technique=technique,
            family=family,
            location=location,
            param_name=param_name,
            payload_sent=payload_sent,
            original_value=original_value,
            host=host,
            method=method,
            path=path,
            endpoint_id=endpoint_id,
            original_status=original_status,
            reason=f"inject_error: {exc}",
        )

    send_headers = _drop_hop_by_hop(send_headers)
    parsed_send = urlparse(send_url)
    send_path = parsed_send.path or path
    send_query = parsed_send.query or ""

    replayed_flow_id = str(uuid.uuid4())
    replay_time = datetime.now(timezone.utc).isoformat()
    replayed: dict = {
        "id": replayed_flow_id,
        "project_id": project_id,
        "captured_at": replay_time,
        "response_end": None,
        "method": method,
        "url": send_url,
        "host": flow.get("host"),
        "path": send_path,
        "query": send_query,
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
        "replay_reason": "host_header_attack",
    }

    from talos.burp.outbound import prepare_send_headers
    from talos.burp.trace import ENGINE_HOST_HEADER

    flow_meta = {
        "attack_module": "host_header",
        "technique": technique,
        "technique_family": family,
        "location": location,
        "param_name": param_name,
        "payload_sent": payload_sent,
    }
    send_headers, flow_meta = prepare_send_headers(
        send_headers,
        db_path=db_path,
        engine=ENGINE_HOST_HEADER,
        flow=replayed,
        extras={
            "technique": technique,
            "variant": family,
            "param": param_name,
            "location": location,
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
    elapsed_s: Optional[float] = None
    started = time.monotonic()
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
        elapsed_s = time.monotonic() - started
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

    if elapsed_s is None:
        elapsed_s = time.monotonic() - started

    if failure_reason:
        from talos.burp.snapshot import record_send_failure

        record_send_failure(flow_meta, project_id, failure_reason)

    try:
        replay_db.insert_replayed_flow(db_path, replayed)
    except Exception as exc:  # noqa: BLE001
        _log.error(
            "Failed to store host-header replay flow %s: %s",
            replayed_flow_id,
            exc,
        )
        return _fail(
            flow_id,
            technique=technique,
            family=family,
            location=location,
            param_name=param_name,
            payload_sent=payload_sent,
            original_value=original_value,
            host=host,
            method=method,
            path=path,
            endpoint_id=endpoint_id,
            original_status=original_status,
            reason=f"db_write_error: {exc}",
        )

    elapsed_ms = int(elapsed_s * 1000) if elapsed_s is not None else None

    if failure_reason:
        outcome = HostHeaderOutcome(
            original_flow_id=flow_id,
            replayed_flow_id=replayed_flow_id,
            endpoint_id=endpoint_id,
            host=host,
            method=method,
            path=send_path,
            technique=technique,
            technique_family=family,
            location=location,
            param_name=param_name,
            payload_sent=payload_sent,
            original_value=original_value,
            original_status=original_status,
            replay_status=None,
            elapsed_ms=elapsed_ms,
            reflected_url="",
            evidence="",
            verdict=VERDICT_UNKNOWN,
            risk_hint="",
            failure_reason=failure_reason,
        )
    else:
        verdict, risk_hint, reflected_url, evidence = analyze_host_header_response(
            baseline_headers=flow.get("response_headers"),
            probe_headers=replayed.get("response_headers"),
            baseline_body=flow.get("response_body"),
            probe_body=replayed.get("response_body"),
            canary_host=canary_host,
            payload_sent=payload_sent,
        )
        outcome = HostHeaderOutcome(
            original_flow_id=flow_id,
            replayed_flow_id=replayed_flow_id,
            endpoint_id=endpoint_id,
            host=host,
            method=method,
            path=send_path,
            technique=technique,
            technique_family=family,
            location=location,
            param_name=param_name,
            payload_sent=payload_sent,
            original_value=original_value,
            original_status=original_status,
            replay_status=replayed.get("status_code"),
            elapsed_ms=elapsed_ms,
            reflected_url=reflected_url,
            evidence=evidence,
            verdict=verdict,
            risk_hint=risk_hint,
        )

    try:
        insert_host_header_result(
            db_path,
            {
                "replay_flow_id": replayed_flow_id,
                "original_flow_id": flow_id,
                "endpoint_id": endpoint_id,
                "host": host,
                "technique": technique,
                "technique_family": family,
                "location": location,
                "param_name": param_name,
                "payload_sent": payload_sent,
                "original_value": original_value,
                "original_status": original_status,
                "replay_status": outcome.replay_status,
                "elapsed_ms": elapsed_ms,
                "reflected_url": outcome.reflected_url,
                "evidence": outcome.evidence,
                "verdict": outcome.verdict,
                "risk_hint": outcome.risk_hint,
                "failure_reason": outcome.failure_reason,
            },
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "Failed to store host_header_results for %s: %s",
            replayed_flow_id,
            exc,
        )

    return outcome
