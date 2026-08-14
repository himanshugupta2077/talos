"""
Module: talos.burp.outbound

Purpose:
    One call for attack engines: stamp flow_meta['burp'] and offer the
    trace to the Burp extension (localhost ingest, header fallback).

Dependencies: pathlib; talos.burp.headers, talos.burp.trace;
              talos.projects.proxy_config
Data flow: engine send → prepare_send_headers → httpx headers + flow_meta
Side effects: May load/cache burp config; may read layered proxy config.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Optional

from urllib.parse import urlparse

from talos.burp.headers import HeaderMap, maybe_apply_burp_headers
from talos.burp.snapshot import resolve_project_identity
from talos.burp.trace import attach_burp_trace


def _request_path(flow: Mapping[str, Any]) -> str:
    path = str(flow.get("path") or "").strip()
    if path:
        return path.split("?", 1)[0]
    url = str(flow.get("url") or "").strip()
    if not url:
        return ""
    parsed = urlparse(url if "://" in url else f"http://placeholder{url}")
    return parsed.path or ""


def prepare_send_headers(
    headers: HeaderMap,
    *,
    db_path: Path,
    engine: str,
    flow: Mapping[str, Any],
    extras: Optional[Mapping[str, Any]] = None,
    endpoint_id: str = "",
    host: str = "",
    flow_meta: Optional[dict] = None,
) -> tuple[HeaderMap, dict]:
    """
    Purpose:
        Attach a Burp trace and, when policy allows, overlay metadata headers.
    Input:
        headers     — outgoing request headers (dict or list of pairs).
        db_path     — project talos.db (upstream + burp knobs).
        engine      — stable engine token.
        flow        — method/path/host/endpoint_id source.
        extras      — optional probe fields.
        endpoint_id — Talos endpoint UUID.
        host        — hostname or origin (normalized by attach).
        flow_meta   — existing metadata to mutate; a new dict when omitted.
    Output:
        (headers_for_httpx, flow_meta).
    Side effects: Mutates flow_meta; may read YAML / SQLite for policy.
    """
    meta = flow_meta if flow_meta is not None else {}
    pid, pname = resolve_project_identity(
        project_id=str(flow.get("project_id") or ""),
        db_path=db_path,
    )
    attach_burp_trace(
        meta,
        engine=engine,
        flow=flow,
        endpoint_id=endpoint_id,
        host=host,
        extras=extras,
        project_id=pid,
        project_name=pname,
    )
    from talos.projects.proxy_config import get_upstream_url

    upstream = get_upstream_url(db_path)
    stamped = maybe_apply_burp_headers(
        headers,
        meta,
        has_upstream=bool(upstream),
        project_data_dir=Path(db_path).parent,
        method=str(flow.get("method") or ""),
        host=str(host or flow.get("host") or ""),
        path=_request_path(flow),
        url=str(flow.get("url") or ""),
        body=flow.get("request_body"),
    )
    return stamped, meta
