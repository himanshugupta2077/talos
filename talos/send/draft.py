"""
Module: talos.send.draft

Purpose:
    Build and mutate an in-memory request draft forked from an existing flow.
    Drafts are not DB rows — only send_once persists a new flow.

    Edit surfaces:
        • Structured patches (AI-friendly): method, url, header, query, body,
          cookie, path, host, json-set (Phase 2)
        • Raw HTTP file (human-friendly): full message replace via raw_http

    Encoding duality:
        • Structured query/cookie helpers may encode for you.
        • Raw mode applies no encoding magic (what you typed is what you send,
          except Content-Length when the normalizer is on).

Dependencies: json, urllib.parse, talos.send.raw_http
Data flow:
    flow row → draft_from_flow → apply_* → draft dict for engine
Side effects: None (pure transforms; returns new/updated dicts).
"""

from __future__ import annotations

import json
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from talos.send.raw_http import parse_request, serialize_request


# ------------------------------------------------------------------ #
# Draft construction                                                   #
# ------------------------------------------------------------------ #

def draft_from_flow(flow: dict) -> dict:
    """
    Purpose:
        Copy request fields from a stored flow into an editable draft.
    Input:
        flow — flow dict (from get_flow_for_replay / send db helpers).
    Output:
        Draft dict with keys:
            method, url, host, path, query,
            request_headers (dict), request_body (bytes|None),
            request_cookies (dict),
            parent_flow_id, endpoint_id, role_id, module_id,
            original_flow_id (resolved root when known on parent),
            parent_source
    Side effects: None.
    """
    headers = _as_dict(flow.get("request_headers"))
    cookies = _as_dict(flow.get("request_cookies"))
    body = flow.get("request_body")
    if isinstance(body, str):
        body = body.encode("utf-8", errors="replace")
    elif body is not None and not isinstance(body, (bytes, bytearray)):
        body = bytes(body)

    parent_id = flow["id"]
    # Root capture: parent's original_flow_id when set, else parent itself.
    root_id = flow.get("original_flow_id") or parent_id

    return {
        "method": (flow.get("method") or "GET").upper(),
        "url": flow.get("url") or "",
        "host": flow.get("host") or "",
        "path": flow.get("path") or "/",
        "query": flow.get("query") or "",
        "request_headers": dict(headers),
        "request_body": bytes(body) if body is not None else None,
        "request_cookies": dict(cookies),
        "parent_flow_id": parent_id,
        "endpoint_id": flow.get("endpoint_id"),
        "role_id": flow.get("role_id"),
        "module_id": flow.get("module_id"),
        "original_flow_id": root_id,
        "parent_source": flow.get("source"),
        "edit_mode": "structured",
    }


def draft_to_raw_bytes(draft: dict) -> bytes:
    """
    Purpose:
        Serialize a draft to a raw HTTP request message for editing.
    Input:
        draft — draft dict from draft_from_flow / apply_*.
    Output:
        Raw HTTP request bytes.
    Side effects: None.
    """
    return serialize_request(
        method=draft["method"],
        url=draft["url"],
        headers=dict(draft.get("request_headers") or {}),
        body=draft.get("request_body"),
    )


# ------------------------------------------------------------------ #
# Structured patches                                                   #
# ------------------------------------------------------------------ #

def apply_method(draft: dict, method: str) -> dict:
    """Set HTTP method (uppercased)."""
    draft = dict(draft)
    draft["method"] = method.strip().upper()
    draft["edit_mode"] = draft.get("edit_mode") or "structured"
    return draft


def apply_url(draft: dict, url: str) -> dict:
    """
    Purpose:
        Replace the absolute URL and re-derive host/path/query consistently.
        Syncs Host header when present (or adds Host from netloc).
    """
    draft = dict(draft)
    parsed = urlparse(url)
    draft["url"] = url
    draft["host"] = parsed.hostname or draft.get("host") or ""
    draft["path"] = parsed.path or "/"
    draft["query"] = parsed.query or ""
    headers = dict(draft.get("request_headers") or {})
    if parsed.netloc:
        # Replace Host header (case-insensitive).
        headers = _set_header(headers, "Host", parsed.netloc)
    draft["request_headers"] = headers
    draft["edit_mode"] = draft.get("edit_mode") or "structured"
    return draft


def apply_header(draft: dict, name: str, value: str) -> dict:
    """Set or replace a single header (case-insensitive name match)."""
    draft = dict(draft)
    headers = dict(draft.get("request_headers") or {})
    draft["request_headers"] = _set_header(headers, name, value)
    draft["edit_mode"] = draft.get("edit_mode") or "structured"
    return draft


def remove_header(draft: dict, name: str) -> dict:
    """Remove a header by name (case-insensitive)."""
    draft = dict(draft)
    headers = dict(draft.get("request_headers") or {})
    lower = name.lower()
    draft["request_headers"] = {
        k: v for k, v in headers.items() if k.lower() != lower
    }
    draft["edit_mode"] = draft.get("edit_mode") or "structured"
    return draft


def apply_query_param(draft: dict, key: str, value: str) -> dict:
    """
    Purpose:
        Set or replace a query parameter on the draft URL.
        Values are URL-encoded via urlencode (structured-edit encoding).
    """
    draft = dict(draft)
    parsed = urlparse(draft["url"])
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    found = False
    new_pairs: list[tuple[str, str]] = []
    for k, v in pairs:
        if k == key:
            new_pairs.append((key, value))
            found = True
        else:
            new_pairs.append((k, v))
    if not found:
        new_pairs.append((key, value))
    new_query = urlencode(new_pairs, doseq=True)
    new_url = urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            new_query,
            parsed.fragment,
        )
    )
    draft["url"] = new_url
    draft["query"] = new_query
    draft["path"] = parsed.path or "/"
    draft["edit_mode"] = draft.get("edit_mode") or "structured"
    return draft


def apply_body(
    draft: dict,
    body: Optional[bytes],
) -> dict:
    """Replace request body bytes (None clears body)."""
    draft = dict(draft)
    if body is None:
        draft["request_body"] = None
    else:
        draft["request_body"] = bytes(body)
    draft["edit_mode"] = draft.get("edit_mode") or "structured"
    return draft


def apply_cookie(draft: dict, name: str, value: str) -> dict:
    """
    Purpose:
        Set/replace a cookie in both the Cookie header and request_cookies map.
    Input:
        name  — cookie name (exact match on Cookie header pairs).
        value — cookie value (stored as-is; no quoting magic).
    """
    draft = dict(draft)
    name = name.strip()
    if not name:
        raise ValueError("cookie name must be non-empty")
    cookies = _merged_cookies(draft)
    cookies[name] = value
    draft["request_cookies"] = cookies
    draft["request_headers"] = _set_header(
        dict(draft.get("request_headers") or {}),
        "Cookie",
        _cookies_to_header(cookies),
    )
    draft["edit_mode"] = draft.get("edit_mode") or "structured"
    return draft


def remove_cookie(draft: dict, name: str) -> dict:
    """Remove a cookie from Cookie header + request_cookies map."""
    draft = dict(draft)
    name = name.strip()
    cookies = _merged_cookies(draft)
    cookies.pop(name, None)
    draft["request_cookies"] = cookies
    headers = dict(draft.get("request_headers") or {})
    if cookies:
        draft["request_headers"] = _set_header(
            headers, "Cookie", _cookies_to_header(cookies)
        )
    else:
        draft["request_headers"] = {
            k: v for k, v in headers.items() if k.lower() != "cookie"
        }
    draft["edit_mode"] = draft.get("edit_mode") or "structured"
    return draft


def remove_query_param(draft: dict, key: str) -> dict:
    """Drop a query parameter by key (all occurrences of that key)."""
    draft = dict(draft)
    parsed = urlparse(draft["url"])
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != key]
    new_query = urlencode(pairs, doseq=True)
    new_url = urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            new_query,
            parsed.fragment,
        )
    )
    draft["url"] = new_url
    draft["query"] = new_query
    draft["path"] = parsed.path or "/"
    draft["edit_mode"] = draft.get("edit_mode") or "structured"
    return draft


def apply_path(draft: dict, path: str) -> dict:
    """
    Purpose:
        Override path only; keep scheme/host/query; rebuild absolute URL.
    """
    draft = dict(draft)
    if not path.startswith("/"):
        path = "/" + path
    parsed = urlparse(draft["url"])
    new_url = urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )
    draft["url"] = new_url
    draft["path"] = path
    draft["query"] = parsed.query or ""
    draft["edit_mode"] = draft.get("edit_mode") or "structured"
    return draft


def apply_host(
    draft: dict,
    host: str,
    *,
    sync_host_header: bool = True,
) -> dict:
    """
    Purpose:
        Override host in the absolute URL. By default also update Host header.
    Input:
        host             — hostname or host:port authority.
        sync_host_header — when True (default), set Host header to match.
    """
    draft = dict(draft)
    host = host.strip()
    if not host:
        raise ValueError("host must be non-empty")
    parsed = urlparse(draft["url"])
    new_url = urlunparse(
        (
            parsed.scheme,
            host,
            parsed.path or "/",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )
    draft["url"] = new_url
    # host column stores hostname only (no port) when possible — match raw_http.
    hostname = host.split("@")[-1]
    if hostname.startswith("["):
        host_only = hostname
    else:
        host_only = hostname.rsplit(":", 1)[0] if ":" in hostname else hostname
    draft["host"] = host_only
    if sync_host_header:
        draft["request_headers"] = _set_header(
            dict(draft.get("request_headers") or {}),
            "Host",
            host,
        )
    draft["edit_mode"] = draft.get("edit_mode") or "structured"
    return draft


def apply_json_set(draft: dict, key: str, value: str) -> dict:
    """
    Purpose:
        If body is a JSON object, set a top-level key to a string value.
    Raises:
        ValueError when body is missing, not valid JSON, or not a JSON object.
    """
    draft = dict(draft)
    key = key.strip()
    if not key:
        raise ValueError("json-set key must be non-empty")
    body = draft.get("request_body")
    if body is None:
        raise ValueError("request body is empty; cannot --json-set")
    if isinstance(body, str):
        body_bytes = body.encode("utf-8", errors="replace")
    else:
        body_bytes = bytes(body)
    try:
        parsed = json.loads(body_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"request body is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(
            "request body JSON is not an object; --json-set requires a top-level object"
        )
    parsed[key] = value
    draft["request_body"] = json.dumps(parsed, separators=(",", ":")).encode("utf-8")
    draft["edit_mode"] = draft.get("edit_mode") or "structured"
    return draft


def apply_raw_message(
    draft: dict,
    raw: bytes,
    *,
    default_scheme: Optional[str] = None,
) -> dict:
    """
    Purpose:
        Replace draft request fields from a full raw HTTP message.
        Preserves lineage fields (parent_flow_id, endpoint_id, …).
    Input:
        draft          — existing draft (provides default URL / scheme).
        raw            — raw HTTP request bytes.
        default_scheme — optional scheme override.
    Output:
        Updated draft with edit_mode='raw'.
    Raises:
        ValueError on parse failure.
    """
    parent_url = draft.get("url") or ""
    scheme = default_scheme
    if not scheme and parent_url:
        scheme = urlparse(parent_url).scheme or "https"
    parsed = parse_request(
        raw,
        default_scheme=scheme or "https",
        default_url=parent_url or None,
    )
    out = dict(draft)
    out["method"] = parsed["method"]
    out["url"] = parsed["url"]
    out["host"] = parsed["host"]
    out["path"] = parsed["path"]
    out["query"] = parsed["query"]
    out["request_headers"] = dict(parsed["request_headers"])
    out["request_body"] = parsed["request_body"]
    out["edit_mode"] = "raw"
    return out


def apply_structured_patches(
    draft: dict,
    *,
    method: Optional[str] = None,
    url: Optional[str] = None,
    headers: Optional[list[tuple[str, str]]] = None,
    remove_headers: Optional[list[str]] = None,
    query_params: Optional[list[tuple[str, str]]] = None,
    remove_query: Optional[list[str]] = None,
    cookies: Optional[list[tuple[str, str]]] = None,
    remove_cookies: Optional[list[str]] = None,
    path: Optional[str] = None,
    host: Optional[str] = None,
    sync_host_header: bool = True,
    json_sets: Optional[list[tuple[str, str]]] = None,
    body: Optional[bytes] = None,
    body_set: bool = False,
) -> dict:
    """
    Purpose:
        Apply a batch of structured patches in a stable order:
        method → url → path → host → remove headers → set headers →
        remove cookies → set cookies → remove query → set query →
        body → json-set.
    Input:
        body_set — True when body was explicitly provided (including empty).
        json_sets applied after body so they can refine an explicit body.
    Output:
        Updated draft.
    Raises:
        ValueError from apply_json_set / apply_host / apply_cookie on bad input.
    """
    d = draft
    if method is not None:
        d = apply_method(d, method)
    if url is not None:
        d = apply_url(d, url)
    if path is not None:
        d = apply_path(d, path)
    if host is not None:
        d = apply_host(d, host, sync_host_header=sync_host_header)
    if remove_headers:
        for name in remove_headers:
            d = remove_header(d, name)
    if headers:
        for name, value in headers:
            d = apply_header(d, name, value)
    if remove_cookies:
        for name in remove_cookies:
            d = remove_cookie(d, name)
    if cookies:
        for name, value in cookies:
            d = apply_cookie(d, name, value)
    if remove_query:
        for key in remove_query:
            d = remove_query_param(d, key)
    if query_params:
        for key, value in query_params:
            d = apply_query_param(d, key, value)
    if body_set:
        d = apply_body(d, body)
    if json_sets:
        for key, value in json_sets:
            d = apply_json_set(d, key, value)
    return d


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

def _as_dict(value: object) -> dict:
    """Parse JSON text or accept dict; empty on failure."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value) if value else {}
            return dict(parsed) if isinstance(parsed, dict) else {}
        except (ValueError, TypeError):
            return {}
    return {}


def _set_header(headers: dict[str, str], name: str, value: str) -> dict[str, str]:
    """Set header replacing any existing key with the same name (case-insensitive)."""
    lower = name.lower()
    out: dict[str, str] = {}
    replaced = False
    for k, v in headers.items():
        if k.lower() == lower:
            if not replaced:
                out[name] = value
                replaced = True
            # drop other casing duplicates
        else:
            out[k] = v
    if not replaced:
        out[name] = value
    return out


def _header_value(headers: dict[str, str], name: str) -> Optional[str]:
    lower = name.lower()
    for k, v in headers.items():
        if k.lower() == lower:
            return v
    return None


def _parse_cookie_header(header: str) -> dict[str, str]:
    """Parse Cookie header into name→value map (last wins on duplicates)."""
    out: dict[str, str] = {}
    if not header:
        return out
    for part in header.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
        else:
            out[part] = ""
    return out


def _merged_cookies(draft: dict) -> dict[str, str]:
    """Merge Cookie header + request_cookies (map wins on key clash)."""
    header_cookies = _parse_cookie_header(
        _header_value(draft.get("request_headers") or {}, "Cookie") or ""
    )
    map_cookies = dict(draft.get("request_cookies") or {})
    return {**header_cookies, **map_cookies}


def _cookies_to_header(cookies: dict[str, str]) -> str:
    """Serialize cookies map to a Cookie header value."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())
