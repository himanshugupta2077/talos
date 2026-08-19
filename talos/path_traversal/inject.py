"""
Module: talos.path_traversal.inject

Purpose:
    Extract injectable entry points from a captured flow and apply one
    payload by **replacing** the original field value.

    v1 surfaces:
        - query string parameters
        - JSON body object keys and array indexes (including a root array)
        - application/x-www-form-urlencoded fields
        - multipart filenames
        - path parameters from the endpoint normalized path ({id}) and
          file-like last segments

    Headers and cookies are skipped (auth artifacts).

Dependencies: json, re, urllib.parse, talos.input_validation.surface
Data flow: candidates / engine → extract_injection_points / apply_payload
Side effects: None.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional
from urllib.parse import parse_qsl, quote, unquote, urlparse, urlunparse

from talos.input_validation.surface import (
    LOCATION_BODY,
    LOCATION_PATH,
    LOCATION_QUERY,
    SURFACE_FORM_BODY,
    SURFACE_JSON_BODY,
    SURFACE_MULTIPART_FILENAME,
    SURFACE_PATH,
    SURFACE_QUERY,
    inject_path_param,
    inject_value,
)
from talos.path_traversal.models import InjectionPoint

_POINT_LOCATIONS = frozenset({"query", "body", "path"})

_FILENAME_RE = re.compile(
    rb'name="([^"]+)"[^;]*;\s*filename="([^"]*)"',
    re.IGNORECASE | re.DOTALL,
)
_FILENAME_RE_SWAP = re.compile(
    rb'filename="([^"]*)"[^;]*;\s*name="([^"]+)"',
    re.IGNORECASE | re.DOTALL,
)

_FILE_LIKE_EXT = (
    ".php", ".phtml", ".html", ".htm", ".jsp", ".asp", ".aspx",
    ".txt", ".xml", ".json", ".pdf", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".css", ".js", ".tpl", ".twig", ".conf", ".ini", ".log",
    ".bak", ".zip", ".csv", ".doc", ".docx", ".env",
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


def _path_segments(path: str) -> list[str]:
    """Purpose: Split a URL path into non-empty segments."""
    raw = path or "/"
    segs = [part for part in raw.split("/") if part != ""]
    return segs


def _looks_file_like(segment: str) -> bool:
    """Purpose: Last-path-segment heuristic for download/preview routes."""
    name = unquote(segment or "").split("?", 1)[0].lower()
    if "." not in name or name.endswith("."):
        return False
    return any(name.endswith(ext) for ext in _FILE_LIKE_EXT)


def extract_path_points(
    url: str,
    *,
    normalized_path: str = "",
    include_static: bool = False,
) -> list[InjectionPoint]:
    """
    Purpose:
        Path-parameter entry points from a captured URL.
    Input:
        include_static — also emit every segment (used when --param misses).
    """
    parsed = urlparse(url or "")
    segs = _path_segments(parsed.path or "/")
    if not segs:
        return []
    points: list[InjectionPoint] = []
    seen: set[tuple[str, str]] = set()
    norm = (normalized_path or "").strip()
    norm_segs = _path_segments(norm) if norm else []

    if norm_segs and len(norm_segs) == len(segs):
        for index, (raw, placeholder) in enumerate(zip(segs, norm_segs)):
            if placeholder.startswith("{") and placeholder.endswith("}") and len(placeholder) > 2:
                name = placeholder[1:-1]
                key = (LOCATION_PATH, name)
                if key in seen:
                    continue
                seen.add(key)
                points.append(
                    InjectionPoint(
                        location=LOCATION_PATH,
                        name=name,
                        original=unquote(raw),
                        surface_kind=SURFACE_PATH,
                        path_index=index,
                        normalized_path=norm,
                    )
                )

    last = segs[-1]
    if _looks_file_like(last):
        name = unquote(last)
        key = (LOCATION_PATH, name)
        if key not in seen:
            seen.add(key)
            points.append(
                InjectionPoint(
                    location=LOCATION_PATH,
                    name=name,
                    original=name,
                    surface_kind=SURFACE_PATH,
                    path_index=len(segs) - 1,
                    normalized_path=norm,
                )
            )

    if include_static:
        for index, raw in enumerate(segs):
            name = unquote(raw)
            key = (LOCATION_PATH, name)
            if key in seen:
                continue
            seen.add(key)
            points.append(
                InjectionPoint(
                    location=LOCATION_PATH,
                    name=name,
                    original=name,
                    surface_kind=SURFACE_PATH,
                    path_index=index,
                    normalized_path=norm,
                )
            )
    return points


def _extract_multipart_filenames(body: bytes) -> list[tuple[str, str]]:
    """Purpose: (field name, filename) pairs from a multipart body."""
    if not body:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in _FILENAME_RE.finditer(body):
        name = match.group(1).decode("utf-8", errors="replace")
        filename = match.group(2).decode("utf-8", errors="replace")
        if name and name not in seen:
            seen.add(name)
            out.append((name, filename))
    for match in _FILENAME_RE_SWAP.finditer(body):
        filename = match.group(1).decode("utf-8", errors="replace")
        name = match.group(2).decode("utf-8", errors="replace")
        if name and name not in seen:
            seen.add(name)
            out.append((name, filename))
    return out


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
        List every v1 injectable field on a captured request.
    Output:
        Ordered InjectionPoint list (path, query, then body).
    """
    points: list[InjectionPoint] = []
    seen: set[tuple[str, str]] = set()

    for point in extract_path_points(
        url,
        normalized_path=normalized_path,
        include_static=include_static_path,
    ):
        key = (point.location, point.name)
        if key in seen:
            continue
        seen.add(key)
        points.append(point)

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
    if "multipart/form-data" in ctype:
        for name, filename in _extract_multipart_filenames(body):
            key = (LOCATION_BODY, name)
            if key in seen:
                continue
            seen.add(key)
            points.append(
                InjectionPoint(
                    location=LOCATION_BODY,
                    name=name,
                    original=filename,
                    surface_kind=SURFACE_MULTIPART_FILENAME,
                )
            )
        return points

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
    *,
    url: str = "",
    normalized_path: str = "",
) -> tuple[list[InjectionPoint], list[str]]:
    """
    Purpose:
        Restrict entry points to operator --param values.
    Input:
        points      — extracted points on one flow.
        param_names — query key, JSON path, form field, path param,
                      or ``location:name``.
    Output:
        (matched points in request order, names that hit nothing).
    """
    wanted = normalize_param_names(param_names)
    if not wanted:
        return list(points), []

    pool = list(points)
    extras = extract_path_points(
        url, normalized_path=normalized_path, include_static=True
    )
    seen_pool = {(p.location, p.name) for p in pool}
    for extra in extras:
        key = (extra.location, extra.name)
        if key not in seen_pool:
            seen_pool.add(key)
            pool.append(extra)

    matched: list[InjectionPoint] = []
    seen: set[tuple[str, str]] = set()
    missing: list[str] = []

    for spec in wanted:
        location: Optional[str] = None
        name = spec
        if ":" in spec:
            prefix, rest = spec.split(":", 1)
            if prefix.lower() in _POINT_LOCATIONS and rest:
                location = prefix.lower()
                name = rest
        hits = [
            point
            for point in pool
            if point.name == name and (location is None or point.location == location)
        ]
        if not hits:
            lowered = name.lower()
            hits = [
                point
                for point in pool
                if point.name.lower() == lowered
                and (location is None or point.location == location)
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


def _replace_path_segment(url: str, index: int, value: str) -> str:
    """Purpose: Replace one path segment; encode so httpx does not collapse .."""
    parsed = urlparse(url or "")
    path = parsed.path or "/"
    trailing = path.endswith("/") and path != "/"
    segs = _path_segments(path)
    if index < 0 or index >= len(segs):
        return url
    encoded = quote(str(value), safe="%") if "%" in str(value) else quote(str(value), safe="")
    segs[index] = encoded
    new_path = "/" + "/".join(segs)
    if trailing:
        new_path += "/"
    return urlunparse(parsed._replace(path=new_path))


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
        Replace the original field with ``payload`` and rebuild the request.
    Output:
        (new_url, new_headers, new_body)
    """
    headers = parse_headers(request_headers)
    body = _body_bytes(request_body) or None

    if point.location == LOCATION_PATH:
        if point.normalized_path:
            new_url = inject_path_param(
                url,
                point.name,
                payload,
                normalized_path=point.normalized_path,
            )
            if new_url != url:
                return new_url, headers, body
        if point.path_index is not None:
            return _replace_path_segment(url, point.path_index, payload), headers, body
        return url, headers, body

    new_url, new_headers, new_body = inject_value(
        point.location,
        point.name,
        payload,
        url,
        headers,
        body,
        surface_kind=point.surface_kind,
        normalized_path=point.normalized_path,
    )
    return new_url, new_headers, new_body
