"""
Module: talos.send.draft

Purpose:
    Build and mutate an in-memory request draft forked from an existing flow.
    Drafts are not DB rows — only send_once persists a new flow.

    Edit surfaces:
        • Structured patches (AI-friendly): method, url, header, query, body
        • Raw HTTP file (human-friendly): full message replace via raw_http

    Encoding duality (Phase 1):
        • Structured query edits URL-encode values when setting params.
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
    body: Optional[bytes] = None,
    body_set: bool = False,
) -> dict:
    """
    Purpose:
        Apply a batch of structured patches in a stable order:
        method → url → remove headers → set headers → query → body.
    Input:
        body_set — True when body was explicitly provided (including empty).
    Output:
        Updated draft.
    """
    d = draft
    if method is not None:
        d = apply_method(d, method)
    if url is not None:
        d = apply_url(d, url)
    if remove_headers:
        for name in remove_headers:
            d = remove_header(d, name)
    if headers:
        for name, value in headers:
            d = apply_header(d, name, value)
    if query_params:
        for key, value in query_params:
            d = apply_query_param(d, key, value)
    if body_set:
        d = apply_body(d, body)
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
