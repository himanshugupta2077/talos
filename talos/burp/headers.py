"""
Module: talos.burp.headers

Purpose:
    Build and apply the X-Talos-* header contract consumed by the Talos
    Burp extension. Values are sanitized to HTTP header-safe ASCII
    (no CR/LF, no controls).

    Prefer localhost ingest (no headers on the proxied request).
    Fall back to X-Talos-* only when the extension is not listening.

    Attach only when:
        - flow_meta carries a valid burp trace
        - burp.enabled is true
        - an upstream proxy is configured (Direct mode never leaks
          metadata headers to the target)
        - ingest did not accept the trace

Dependencies: talos.burp.config, talos.burp.ingest, talos.burp.trace
Data flow: replay._execute_replay → maybe_apply_burp_headers → ingest or headers
Side effects: May POST to 127.0.0.1 ingest. Config load may happen via process cache.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, Union

from talos.burp.config import (
    DEFAULT_HEADER_PREFIX,
    BurpRuntimeConfig,
    ensure_process_burp_config,
    get_process_burp_config,
)
from talos.burp.ingest import offer_trace
from talos.burp.trace import BurpTrace, normalize_host, trace_from_flow_meta

# Suffixes appended to the configured prefix (default → X-Talos-Engine).
SUFFIX_ENGINE = "Engine"
SUFFIX_GROUP = "Group"
SUFFIX_ENDPOINT = "Endpoint"
SUFFIX_ENDPOINT_ID = "Endpoint-Id"
SUFFIX_HOST = "Host"
SUFFIX_PARAM = "Param"
SUFFIX_LOCATION = "Location"
SUFFIX_ANALYSIS = "Analysis"
SUFFIX_PAYLOAD_TYPE = "Payload-Type"
SUFFIX_TECHNIQUE = "Technique"
SUFFIX_VARIANT = "Variant"
SUFFIX_DETAIL = "Detail"
SUFFIX_PROJECT = "Project"
SUFFIX_PROJECT_NAME = "Project-Name"
SUFFIX_RECORD_ID = "Record-Id"

# Default fully-qualified names (tests + docs). Prefix is still configurable.
HEADER_ENGINE = f"{DEFAULT_HEADER_PREFIX}-{SUFFIX_ENGINE}"
HEADER_GROUP = f"{DEFAULT_HEADER_PREFIX}-{SUFFIX_GROUP}"
HEADER_ENDPOINT = f"{DEFAULT_HEADER_PREFIX}-{SUFFIX_ENDPOINT}"
HEADER_ENDPOINT_ID = f"{DEFAULT_HEADER_PREFIX}-{SUFFIX_ENDPOINT_ID}"
HEADER_HOST = f"{DEFAULT_HEADER_PREFIX}-{SUFFIX_HOST}"
HEADER_PARAM = f"{DEFAULT_HEADER_PREFIX}-{SUFFIX_PARAM}"
HEADER_LOCATION = f"{DEFAULT_HEADER_PREFIX}-{SUFFIX_LOCATION}"
HEADER_ANALYSIS = f"{DEFAULT_HEADER_PREFIX}-{SUFFIX_ANALYSIS}"
HEADER_PAYLOAD_TYPE = f"{DEFAULT_HEADER_PREFIX}-{SUFFIX_PAYLOAD_TYPE}"
HEADER_TECHNIQUE = f"{DEFAULT_HEADER_PREFIX}-{SUFFIX_TECHNIQUE}"
HEADER_VARIANT = f"{DEFAULT_HEADER_PREFIX}-{SUFFIX_VARIANT}"
HEADER_DETAIL = f"{DEFAULT_HEADER_PREFIX}-{SUFFIX_DETAIL}"
HEADER_PROJECT = f"{DEFAULT_HEADER_PREFIX}-{SUFFIX_PROJECT}"
HEADER_PROJECT_NAME = f"{DEFAULT_HEADER_PREFIX}-{SUFFIX_PROJECT_NAME}"
HEADER_RECORD_ID = f"{DEFAULT_HEADER_PREFIX}-{SUFFIX_RECORD_ID}"

_MAX_VALUE_LEN = 512

# Optional extras on BurpTrace.extras → header suffix.
_EXTRA_SUFFIX: dict[str, str] = {
    "param": SUFFIX_PARAM,
    "location": SUFFIX_LOCATION,
    "analysis": SUFFIX_ANALYSIS,
    "payload_type": SUFFIX_PAYLOAD_TYPE,
    "technique": SUFFIX_TECHNIQUE,
    "variant": SUFFIX_VARIANT,
    "detail": SUFFIX_DETAIL,
}

HeaderMap = Union[Mapping[str, object], Sequence[tuple[object, object]]]


def sanitize_prefix(prefix: str) -> str:
    """
    Purpose:
        Keep only HTTP-token characters for the header prefix.
    Input:
        prefix — operator-configured prefix.
    Output:
        Safe prefix, or X-Talos when empty after cleaning.
    Side effects: None.
    """
    cleaned = "".join(
        ch for ch in (prefix or "").strip() if ch.isalnum() or ch == "-"
    ).strip("-")
    return cleaned or DEFAULT_HEADER_PREFIX


def sanitize_header_value(value: object, *, max_len: int = _MAX_VALUE_LEN) -> str:
    """
    Purpose:
        Make a string safe as a single HTTP header value.
    Input:
        value   — any object; converted with str().
        max_len — truncation bound (default 512).
    Output:
        Printable ASCII without CR/LF; empty when nothing remains.
    Side effects: None.
    """
    text = "" if value is None else str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    text = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in text)
    text = " ".join(text.split())
    if len(text) > max_len:
        text = text[:max_len].rstrip()
    return text


def _header_name(prefix: str, suffix: str) -> str:
    return f"{sanitize_prefix(prefix)}-{suffix}"


def build_headers(trace: BurpTrace, prefix: str = DEFAULT_HEADER_PREFIX) -> dict[str, str]:
    """
    Purpose:
        Render a BurpTrace as HTTP headers.
    Input:
        trace  — grouping metadata.
        prefix — header prefix (default X-Talos).
    Output:
        Dict of header name → sanitized value. Required fields only
        when non-empty after sanitization (engine/group/endpoint required).
    Side effects: None.
    """
    headers: dict[str, str] = {}
    required = (
        (SUFFIX_ENGINE, trace.engine),
        (SUFFIX_GROUP, trace.group),
        (SUFFIX_ENDPOINT, trace.endpoint_label),
    )
    for suffix, raw in required:
        value = sanitize_header_value(raw)
        if value:
            headers[_header_name(prefix, suffix)] = value

    optional = (
        (SUFFIX_ENDPOINT_ID, trace.endpoint_id),
        (SUFFIX_HOST, trace.host),
        (SUFFIX_PROJECT, trace.project_id),
        (SUFFIX_PROJECT_NAME, trace.project_name),
        (SUFFIX_RECORD_ID, trace.record_id),
    )
    for suffix, raw in optional:
        value = sanitize_header_value(raw)
        if value:
            headers[_header_name(prefix, suffix)] = value

    for extra_key, suffix in _EXTRA_SUFFIX.items():
        value = sanitize_header_value(trace.extras.get(extra_key, ""))
        if value:
            headers[_header_name(prefix, suffix)] = value
    return headers


def apply_overlay(
    headers: HeaderMap,
    overlay: Mapping[str, str],
) -> HeaderMap:
    """
    Purpose:
        Overlay Talos headers onto a dict or list-of-pairs header map.
    Input:
        headers — existing request headers (dict or [(name, value), …]).
        overlay — Talos metadata headers.
    Output:
        Same container type as input, with overlay applied.
    Side effects: None.
    """
    if not overlay:
        if isinstance(headers, Sequence) and not isinstance(headers, (str, bytes)):
            return list(headers)
        return dict(headers)
    drop = {name.lower() for name in overlay}
    if isinstance(headers, Sequence) and not isinstance(headers, (str, bytes)):
        kept = [
            (str(name), value)
            for name, value in headers
            if str(name).lower() not in drop
        ]
        kept.extend((name, value) for name, value in overlay.items())
        return kept
    merged: dict[str, object] = {
        name: value
        for name, value in dict(headers).items()
        if str(name).lower() not in drop
    }
    merged.update(overlay)
    return merged


def apply_trace_headers(
    headers: HeaderMap,
    trace: BurpTrace,
    *,
    prefix: str = DEFAULT_HEADER_PREFIX,
) -> HeaderMap:
    """
    Purpose:
        Copy headers and overlay Talos metadata (case-preserving overlay).
    Input:
        headers — existing request header map or list of pairs.
        trace   — grouping metadata.
        prefix  — header prefix.
    Output:
        Same container type as input; existing same-name keys replaced.
    Side effects: None.
    """
    return apply_overlay(headers, build_headers(trace, prefix))


def _resolve_config(
    config: Optional[BurpRuntimeConfig],
    project_data_dir: Optional[Path],
) -> BurpRuntimeConfig:
    if config is not None:
        return config
    if project_data_dir is not None:
        return ensure_process_burp_config(project_data_dir)
    return get_process_burp_config()


def maybe_apply_burp_headers(
    headers: HeaderMap,
    flow_meta: Optional[Mapping[str, object]],
    *,
    has_upstream: bool,
    config: Optional[BurpRuntimeConfig] = None,
    project_data_dir: Optional[Path] = None,
    method: str = "",
    host: str = "",
    path: str = "",
    url: str = "",
    body: Any = None,
) -> HeaderMap:
    """
    Purpose:
        Hand the trace to the Burp extension. Prefer localhost ingest
        (no X-Talos-* on the wire). Fall back to headers only when the
        extension is not listening.
    Input:
        headers          — outgoing request headers (dict or list of pairs).
        flow_meta        — replay flow_meta (may contain burp).
        has_upstream     — True when the project has an upstream proxy URL.
        config           — optional pre-resolved knobs (tests).
        project_data_dir — used to load/cache knobs when config is omitted.
        method/host/path — actual upcoming request, used to claim the ingest.
        url/body         — optional request pieces for the on-disk snapshot.
    Output:
        Same header container type. Unchanged when disabled, no upstream,
        no trace, or ingest accepted the trace.
    Side effects: May write ~/.talos/burp/<project>.jsonl; may POST ingest.
    """
    if isinstance(headers, Sequence) and not isinstance(headers, (str, bytes)):
        current: HeaderMap = list(headers)
    else:
        current = dict(headers)
    cfg = _resolve_config(config, project_data_dir)
    if not cfg.enabled:
        return current
    trace = trace_from_flow_meta(flow_meta)
    if trace is None:
        return current
    from talos.burp.snapshot import record_request, resolve_project_identity

    pid, pname = resolve_project_identity(
        project_id=trace.project_id,
        project_name=trace.project_name,
        project_data_dir=project_data_dir,
    )
    if pid and (pid != trace.project_id or (pname and pname != trace.project_name)):
        trace = replace(trace, project_id=pid, project_name=pname or trace.project_name)
        if isinstance(flow_meta, dict):
            burp = flow_meta.get("burp")
            if isinstance(burp, dict):
                burp["project_id"] = trace.project_id
                burp["project_name"] = trace.project_name
    if trace.project_id:
        record_request(
            trace,
            method=method,
            host=normalize_host(host or trace.host),
            path=path,
            url=url,
            headers=current,
            body=body,
        )
    if not has_upstream:
        return current
    if offer_trace(
        trace,
        method=method,
        host=normalize_host(host or trace.host),
        path=path,
    ):
        return current
    return apply_trace_headers(current, trace, prefix=cfg.header_prefix)
