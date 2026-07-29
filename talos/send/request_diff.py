"""
Module: talos.send.request_diff

Purpose:
    Pure request-side comparison for Repeater review (Phase 2).

    Compares method, URL, path, query, headers (case-insensitive names),
    cookies when easy, and body (length + equality; optional unified text
    diff when both sides are UTF-8 text under a size limit).

Dependencies: difflib, json, typing, urllib.parse
Data flow:
    flow_a, flow_b → compute_request_diff → dict for CLI / agents
Side effects: None.
"""

from __future__ import annotations

import difflib
import json
from typing import Any, Optional
from urllib.parse import parse_qsl, urlparse

# Body text unified-diff only when both sides decode and each is under this size.
BODY_TEXT_DIFF_MAX = 256 * 1024


def compute_request_diff(flow_a: dict, flow_b: dict) -> dict[str, Any]:
    """
    Purpose:
        Compare request fields of two flows (baseline vs execution, or two sends).
    Input:
        flow_a, flow_b — flow dicts with method/url/path/query/headers/body.
    Output:
        Structured dict (stable keys for AI):
            method_changed, method_a, method_b
            url_changed, url_a, url_b
            path_changed, path_a, path_b
            query_changed, query_a, query_b, query_added, query_removed, query_changed_keys
            headers: {added, removed, changed}
            cookies: {added, removed, changed} (when parseable)
            body_equal, body_len_a, body_len_b, body_len_delta
            body_text_diff (optional unified diff lines) or None
            changed (bool) — any request field differed
    Side effects: None.
    """
    method_a = (flow_a.get("method") or "").upper()
    method_b = (flow_b.get("method") or "").upper()
    url_a = flow_a.get("url") or ""
    url_b = flow_b.get("url") or ""
    path_a = flow_a.get("path") or _path_from_url(url_a)
    path_b = flow_b.get("path") or _path_from_url(url_b)
    query_a = flow_a.get("query") if flow_a.get("query") is not None else _query_from_url(url_a)
    query_b = flow_b.get("query") if flow_b.get("query") is not None else _query_from_url(url_b)
    query_a = query_a or ""
    query_b = query_b or ""

    headers_a = _as_headers(flow_a.get("request_headers"))
    headers_b = _as_headers(flow_b.get("request_headers"))
    header_diff = _diff_maps_ci(headers_a, headers_b)

    cookies_a = _cookies_from_flow(flow_a, headers_a)
    cookies_b = _cookies_from_flow(flow_b, headers_b)
    cookie_diff = _diff_maps_exact(cookies_a, cookies_b)

    q_a = dict(parse_qsl(query_a, keep_blank_values=True))
    q_b = dict(parse_qsl(query_b, keep_blank_values=True))
    query_added = sorted(k for k in q_b if k not in q_a)
    query_removed = sorted(k for k in q_a if k not in q_b)
    query_changed_keys = sorted(
        k for k in q_a if k in q_b and q_a[k] != q_b[k]
    )

    body_a = _to_bytes(flow_a.get("request_body"))
    body_b = _to_bytes(flow_b.get("request_body"))
    body_equal = body_a == body_b
    body_text_diff = _optional_text_diff(body_a, body_b)

    method_changed = method_a != method_b
    url_changed = url_a != url_b
    path_changed = path_a != path_b
    query_changed = (
        query_a != query_b
        or bool(query_added)
        or bool(query_removed)
        or bool(query_changed_keys)
    )
    headers_changed = bool(
        header_diff["added"] or header_diff["removed"] or header_diff["changed"]
    )
    cookies_changed = bool(
        cookie_diff["added"] or cookie_diff["removed"] or cookie_diff["changed"]
    )

    changed = any(
        [
            method_changed,
            url_changed,
            path_changed,
            query_changed,
            headers_changed,
            cookies_changed,
            not body_equal,
        ]
    )

    return {
        "method_changed": method_changed,
        "method_a": method_a,
        "method_b": method_b,
        "url_changed": url_changed,
        "url_a": url_a,
        "url_b": url_b,
        "path_changed": path_changed,
        "path_a": path_a,
        "path_b": path_b,
        "query_changed": query_changed,
        "query_a": query_a,
        "query_b": query_b,
        "query_added": query_added,
        "query_removed": query_removed,
        "query_changed_keys": query_changed_keys,
        "headers": header_diff,
        "cookies": cookie_diff,
        "body_equal": body_equal,
        "body_len_a": len(body_a),
        "body_len_b": len(body_b),
        "body_len_delta": len(body_b) - len(body_a),
        "body_text_diff": body_text_diff,
        "changed": changed,
    }


def enhance_response_diff(
    flow_a: dict,
    flow_b: dict,
    *,
    verdict: str,
    status_changed: bool,
    status_diff: Optional[str],
    length_diff: int,
) -> dict[str, Any]:
    """
    Purpose:
        Build a richer response-side payload on top of compute_diff verdict fields.
    """
    headers_a = _as_headers(flow_a.get("response_headers"))
    headers_b = _as_headers(flow_b.get("response_headers"))
    header_diff = _diff_maps_ci(headers_a, headers_b)

    ct_a = (
        flow_a.get("content_type")
        or _header_ci(headers_a, "content-type")
        or ""
    )
    ct_b = (
        flow_b.get("content_type")
        or _header_ci(headers_b, "content-type")
        or ""
    )

    body_a = _to_bytes(flow_a.get("response_body"))
    body_b = _to_bytes(flow_b.get("response_body"))
    body_equal = body_a == body_b
    body_text_diff = _optional_text_diff(body_a, body_b)

    return {
        "verdict": verdict,
        "status_changed": status_changed,
        "status_diff": status_diff,
        "status_a": flow_a.get("status_code"),
        "status_b": flow_b.get("status_code"),
        "length_diff": length_diff,
        "body_len_a": len(body_a),
        "body_len_b": len(body_b),
        "body_equal": body_equal,
        "content_type_a": ct_a,
        "content_type_b": ct_b,
        "content_type_changed": ct_a != ct_b,
        "headers": header_diff,
        "body_text_diff": body_text_diff,
    }


# ------------------------------------------------------------------ #
# Internals                                                            #
# ------------------------------------------------------------------ #

def _to_bytes(value: object) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    return bytes(value)


def _as_headers(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    if isinstance(value, str):
        try:
            parsed = json.loads(value) if value else {}
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items()}
        except (ValueError, TypeError):
            return {}
    return {}


def _header_ci(headers: dict[str, str], name: str) -> Optional[str]:
    lower = name.lower()
    for k, v in headers.items():
        if k.lower() == lower:
            return v
    return None


def _path_from_url(url: str) -> str:
    return urlparse(url).path or "/"


def _query_from_url(url: str) -> str:
    return urlparse(url).query or ""


def _cookies_from_flow(flow: dict, headers: dict[str, str]) -> dict[str, str]:
    cookies: dict[str, str] = {}
    raw = flow.get("request_cookies")
    if isinstance(raw, dict):
        cookies.update({str(k): str(v) for k, v in raw.items()})
    elif isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                cookies.update({str(k): str(v) for k, v in parsed.items()})
        except (ValueError, TypeError):
            pass
    cookie_hdr = _header_ci(headers, "cookie") or ""
    for part in cookie_hdr.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            cookies.setdefault(k.strip(), v.strip())
        else:
            cookies.setdefault(part, "")
    return cookies


def _diff_maps_ci(
    a: dict[str, str], b: dict[str, str]
) -> dict[str, Any]:
    """Case-insensitive header diff; report names from side B when changed."""
    a_lower = {k.lower(): (k, v) for k, v in a.items()}
    b_lower = {k.lower(): (k, v) for k, v in b.items()}
    added = sorted(
        [{"name": b_lower[k][0], "value": b_lower[k][1]} for k in b_lower if k not in a_lower],
        key=lambda x: x["name"].lower(),
    )
    removed = sorted(
        [{"name": a_lower[k][0], "value": a_lower[k][1]} for k in a_lower if k not in b_lower],
        key=lambda x: x["name"].lower(),
    )
    changed = []
    for k in sorted(set(a_lower) & set(b_lower)):
        if a_lower[k][1] != b_lower[k][1]:
            changed.append(
                {
                    "name": b_lower[k][0],
                    "value_a": a_lower[k][1],
                    "value_b": b_lower[k][1],
                }
            )
    return {"added": added, "removed": removed, "changed": changed}


def _diff_maps_exact(
    a: dict[str, str], b: dict[str, str]
) -> dict[str, Any]:
    added = sorted(
        [{"name": k, "value": b[k]} for k in b if k not in a],
        key=lambda x: x["name"],
    )
    removed = sorted(
        [{"name": k, "value": a[k]} for k in a if k not in b],
        key=lambda x: x["name"],
    )
    changed = sorted(
        [
            {"name": k, "value_a": a[k], "value_b": b[k]}
            for k in a
            if k in b and a[k] != b[k]
        ],
        key=lambda x: x["name"],
    )
    return {"added": added, "removed": removed, "changed": changed}


def _optional_text_diff(a: bytes, b: bytes) -> Optional[list[str]]:
    """Unified diff lines when both are UTF-8 text and under size limit."""
    if a == b:
        return None
    if len(a) > BODY_TEXT_DIFF_MAX or len(b) > BODY_TEXT_DIFF_MAX:
        return None
    try:
        text_a = a.decode("utf-8")
        text_b = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Skip binary-looking content with many NULs.
    if "\x00" in text_a or "\x00" in text_b:
        return None
    lines = list(
        difflib.unified_diff(
            text_a.splitlines(),
            text_b.splitlines(),
            fromfile="a",
            tofile="b",
            lineterm="",
        )
    )
    return lines or None
