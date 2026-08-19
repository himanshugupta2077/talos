"""
Module: talos.sqli.inject

Purpose:
    Extract injectable entry points from a captured flow and apply one
    payload by appending it to the original field value.

    v1 surfaces:
        - query string parameters
        - JSON body object keys and array indexes (including a root array)
        - application/x-www-form-urlencoded fields

    Headers and cookies are skipped (auth artifacts). Path segments are
    skipped in v1.

Dependencies: json, urllib.parse, talos.input_validation.surface
Data flow: candidates / engine → extract_injection_points / apply_payload
Side effects: None.
"""

from __future__ import annotations

import json
from typing import Any, Optional
from urllib.parse import parse_qsl, urlparse

_POINT_LOCATIONS = frozenset({"query", "body"})

from talos.input_validation.surface import (
    LOCATION_BODY,
    LOCATION_QUERY,
    SURFACE_FORM_BODY,
    SURFACE_JSON_BODY,
    SURFACE_QUERY,
    inject_value,
    injection_point_matches_spec,
)
from talos.sqli.models import InjectionPoint


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


def _body_bytes(raw: object) -> bytes:
    """Purpose: Coerce a stored request body to bytes."""
    if raw is None:
        return b""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    if isinstance(raw, str):
        return raw.encode("utf-8", errors="replace")
    return b""


def _content_type(headers: dict[str, str]) -> str:
    """Purpose: Lowercased Content-Type value (no parameters)."""
    for key, value in headers.items():
        if key.lower() == "content-type":
            return value.split(";", 1)[0].strip().lower()
    return ""


def _walk_json(node: Any, prefix: str) -> list[tuple[str, str]]:
    """
    Purpose:
        Emit (json_path, string_value) for every JSON leaf.
    """
    out: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            out.extend(_walk_json(value, path))
        return out
    if isinstance(node, list):
        for idx, value in enumerate(node):
            path = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            out.extend(_walk_json(value, path))
        return out
    if node is None:
        out.append((prefix, ""))
        return out
    out.append((prefix, str(node)))
    return out


def extract_injection_points(
    *,
    url: str,
    query: str = "",
    request_headers: object = None,
    request_body: object = None,
) -> list[InjectionPoint]:
    """
    Purpose:
        List every v1 injectable field on a captured request.
    Output:
        Ordered InjectionPoint list (query first, then body).
    """
    points: list[InjectionPoint] = []
    seen: set[tuple[str, str]] = set()

    parsed = urlparse(url or "")
    query_text = query or parsed.query or ""
    for name, value in parse_qsl(query_text, keep_blank_values=True):
        key = (LOCATION_QUERY, name)
        if key in seen:
            continue
        seen.add(key)
        points.append(
            InjectionPoint(
                location=LOCATION_QUERY,
                name=name,
                original=value,
                surface_kind=SURFACE_QUERY,
            )
        )

    headers = parse_headers(request_headers)
    body = _body_bytes(request_body)
    if not body:
        return points

    ctype = _content_type(headers)
    stripped = body.lstrip()
    if "json" in ctype or stripped[:1] in (b"{", b"["):
        try:
            root = json.loads(body.decode("utf-8", errors="replace"))
        except (ValueError, TypeError):
            root = None
        if isinstance(root, (dict, list)):
            for name, value in _walk_json(root, ""):
                if not name:
                    continue
                key = (LOCATION_BODY, name)
                if key in seen:
                    continue
                seen.add(key)
                points.append(
                    InjectionPoint(
                        location=LOCATION_BODY,
                        name=name,
                        original=value,
                        surface_kind=SURFACE_JSON_BODY,
                    )
                )
            return points

    if "x-www-form-urlencoded" in ctype or b"=" in body[:200]:
        text = body.decode("utf-8", errors="replace")
        for name, value in parse_qsl(text, keep_blank_values=True):
            key = (LOCATION_BODY, name)
            if key in seen:
                continue
            seen.add(key)
            points.append(
                InjectionPoint(
                    location=LOCATION_BODY,
                    name=name,
                    original=value,
                    surface_kind=SURFACE_FORM_BODY,
                )
            )
    return points


def normalize_param_names(raw: object) -> list[str]:
    """
    Purpose:
        Flatten --param values (repeatable and/or comma-separated).
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
) -> tuple[list[InjectionPoint], list[str]]:
    """
    Purpose:
        Restrict entry points to operator --param values.
    Input:
        points      — extracted points on one flow.
        param_names — query key, JSON path, form field, or ``location:name``.
    Output:
        (matched points in request order, names that hit nothing).
    Side effects: None.
    """
    wanted = normalize_param_names(param_names)
    if not wanted:
        return list(points), []

    matched: list[InjectionPoint] = []
    seen: set[tuple[str, str]] = set()
    missing: list[str] = []

    for spec in wanted:
        hits = [
            point
            for point in points
            if injection_point_matches_spec(
                spec,
                point.location,
                point.name,
                allowed_locations=_POINT_LOCATIONS,
            )
        ]
        if not hits:
            missing.append(spec)
            continue
        for point in hits:
            key = (point.location, point.name)
            if key in seen:
                continue
            seen.add(key)
            matched.append(point)
    return matched, missing


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
        Append ``payload`` to the original field and rebuild the request.
    Output:
        (new_url, new_headers, new_body)
    """
    headers = parse_headers(request_headers)
    body = _body_bytes(request_body) or None
    injected = f"{point.original}{payload}"
    new_url, new_headers, new_body = inject_value(
        point.location,
        point.name,
        injected,
        url,
        headers,
        body,
        surface_kind=point.surface_kind,
    )
    return new_url, new_headers, new_body
