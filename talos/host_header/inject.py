"""
Module: talos.host_header.inject

Purpose:
    Extract host-related header injection points from a captured flow and
    apply one payload by **replacing** that header. The request URL (TCP
    origin) is never rewritten — that is BAC host-fuzz, not this module.

    v1 surfaces (always offered, even when absent on the capture):
        Host
        X-Forwarded-Host
        X-Host
        X-Forwarded-Server
        X-Original-Host
        X-HTTP-Host-Override
        Forwarded

Dependencies: json, urllib.parse, talos.host_header.models
Data flow: candidates / engine → extract_injection_points / apply_payload
Side effects: None.
"""

from __future__ import annotations

import json
from typing import Optional
from urllib.parse import urlparse

from talos.host_header.models import (
    LOCATION_HEADER,
    SURFACE_HOST,
    SURFACE_OVERRIDE,
    InjectionPoint,
)

HOST_HEADER_NAMES: tuple[str, ...] = (
    "Host",
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-Original-Host",
    "X-HTTP-Host-Override",
    "Forwarded",
)

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


def parse_headers(raw: object) -> dict[str, str]:
    """
    Purpose:
        Normalize stored request headers to a str→str map.
    Output:
        Original key casing kept; last value wins.
    """
    if raw is None:
        return {}
    data = raw
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, str):
        try:
            data = json.loads(raw) if raw.strip() else {}
        except (ValueError, TypeError):
            return {}
    if isinstance(data, dict):
        out: dict[str, str] = {}
        for key, value in data.items():
            if value is None:
                continue
            if isinstance(value, list):
                out[str(key)] = str(value[0]) if value else ""
            else:
                out[str(key)] = str(value)
        return out
    return {}


def header_value(headers: dict[str, str], name: str) -> str:
    """Purpose: Case-insensitive header lookup."""
    want = name.lower()
    for key, value in headers.items():
        if key.lower() == want:
            return value
    return ""


def captured_host(url: str, headers: dict[str, str]) -> str:
    """Purpose: Host header value, else URL netloc."""
    existing = header_value(headers, "Host")
    if existing.strip():
        return existing.strip()
    parsed = urlparse(url or "")
    return parsed.netloc or parsed.hostname or ""


def extract_injection_points(
    *,
    url: str,
    query: str = "",
    request_headers: object = None,
    request_body: object = None,
    normalized_path: str = "",
    include_static_path: bool = False,
) -> list[InjectionPoint]:
    """
    Purpose:
        List every v1 host-related header on a captured request.
    Output:
        Ordered InjectionPoint list (Host first, then overrides).
    """
    del query, request_body, include_static_path
    headers = parse_headers(request_headers)
    orig_host = captured_host(url, headers)
    points: list[InjectionPoint] = []
    for name in HOST_HEADER_NAMES:
        existing = header_value(headers, name)
        if name.lower() == "host":
            original = existing or orig_host
            surface = SURFACE_HOST
        else:
            original = existing
            surface = SURFACE_OVERRIDE
        points.append(
            InjectionPoint(
                location=LOCATION_HEADER,
                name=name,
                original=original,
                surface_kind=surface,
                normalized_path=normalized_path,
            )
        )
    return points


def normalize_param_names(raw: object) -> list[str]:
    """
    Purpose:
        Flatten --header / --param values (repeatable and/or comma-separated).
    Output:
        Deduped names in operator order.
    """
    if raw is None:
        return []
    if isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, (list, tuple, set)):
        items = [str(item) for item in raw]
    else:
        items = [str(raw)]
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        for part in item.split(","):
            name = part.strip()
            if name and name not in seen:
                seen.add(name)
                out.append(name)
    return out


def match_injection_points(
    points: list[InjectionPoint] | tuple[InjectionPoint, ...],
    param_names: list[str],
    *,
    url: str = "",
    normalized_path: str = "",
) -> tuple[list[InjectionPoint], list[str]]:
    """
    Purpose:
        Restrict entry points to operator --header / --param values.
    Input:
        points      — extracted host headers on one flow.
        param_names — header name, or ``header:Name``.
    Output:
        (matched points in catalogue order, names that hit nothing).
    """
    del url, normalized_path
    wanted = normalize_param_names(param_names)
    if not wanted:
        return list(points), []

    pool = list(points)
    matched: list[InjectionPoint] = []
    seen: set[str] = set()
    missing: list[str] = []

    for spec in wanted:
        location: Optional[str] = None
        name = spec
        if ":" in spec:
            prefix, rest = spec.split(":", 1)
            if prefix.lower() in {"header", "host"} and rest:
                location = LOCATION_HEADER
                name = rest
        hits = [
            point
            for point in pool
            if point.name.lower() == name.lower()
            and (location is None or point.location == location)
        ]
        if not hits:
            missing.append(spec)
            continue
        for point in hits:
            key = point.name.lower()
            if key in seen:
                continue
            seen.add(key)
            matched.append(point)
    return matched, missing


def _set_header(headers: dict[str, str], name: str, value: str) -> dict[str, str]:
    """Purpose: Replace a header case-insensitively; drop hop-by-hop."""
    out: dict[str, str] = {}
    want = name.lower()
    for key, existing in headers.items():
        if key.lower() in _HOP_BY_HOP or key.lower() == want:
            continue
        out[key] = existing
    out[name] = value
    return out


def apply_payload(
    point: InjectionPoint,
    payload: str,
    *,
    url: str,
    request_headers: object,
    request_body: object,
) -> tuple[str, dict[str, str], Optional[bytes]]:
    """
    Purpose:
        Replace the target header with ``payload``. URL is unchanged.
    Output:
        (original_url, new_headers, original_body)
    """
    headers = parse_headers(request_headers)
    body: Optional[bytes]
    if request_body is None:
        body = None
    elif isinstance(request_body, (bytes, bytearray)):
        body = bytes(request_body) or None
    elif isinstance(request_body, str):
        body = request_body.encode("utf-8", errors="replace") or None
    else:
        body = None
    new_headers = _set_header(headers, point.name, payload)
    if not header_value(new_headers, "Host"):
        fallback = captured_host(url, headers)
        if fallback:
            new_headers = _set_header(new_headers, "Host", fallback)
    return url, new_headers, body
