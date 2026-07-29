"""
Module: talos.send.raw_http

Purpose:
    Parse and serialize raw HTTP/1.1 request messages for the Repeater
    draft surface (human edit in a file / AI paste).

    Format (request only)::

        METHOD path[?query] HTTP/1.1
        Header-Name: value
        …

        <optional body bytes>

Design:
    - Robust enough for normal HTTP/1.1 messages (CRLF or LF line endings).
    - No silent body re-encoding: body is raw bytes after the blank line.
    - Absolute URL is reconstructed from Host + request-target when scheme
      is known (caller supplies scheme from the parent flow).

Dependencies: re, typing
Data flow:
    draft / CLI → serialize_request → file
    file / --raw-file → parse_request → draft fields
Side effects: None (pure functions).
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse, urlunparse

# Header name: value (allow empty value; first colon separates).
_HEADER_RE = re.compile(rb"^([^:\s]+)\s*:\s*(.*)$")


def serialize_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: Optional[bytes] = None,
    *,
    http_version: str = "HTTP/1.1",
) -> bytes:
    """
    Purpose:
        Build a raw HTTP/1.1 request message from structured fields.
    Input:
        method       — HTTP method (e.g. GET, POST).
        url          — Absolute URL (scheme://host/path?query).
        headers      — Header map (case preserved as provided).
        body         — Optional request body bytes.
        http_version — Protocol token on the request line.
    Output:
        Raw request bytes suitable for writing to a file.
    Side effects: None.
    """
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        request_target = f"{path}?{parsed.query}"
    else:
        request_target = path

    lines: list[bytes] = [
        f"{method.upper()} {request_target} {http_version}\r\n".encode("ascii", errors="replace")
    ]

    # Ensure Host is present when we have a netloc (Burp-style draft).
    header_items = list(headers.items())
    has_host = any(k.lower() == "host" for k, _ in header_items)
    if not has_host and parsed.netloc:
        header_items.insert(0, ("Host", parsed.netloc))

    for name, value in header_items:
        # Skip Content-Length here only if caller already set it; we write as-is.
        lines.append(
            f"{name}: {value}\r\n".encode("utf-8", errors="replace")
        )

    lines.append(b"\r\n")
    if body:
        lines.append(body)
    return b"".join(lines)


def parse_request(
    raw: bytes,
    *,
    default_scheme: str = "https",
    default_url: Optional[str] = None,
) -> dict:
    """
    Purpose:
        Parse a raw HTTP/1.1 request message into structured draft fields.
    Input:
        raw            — Full request message bytes.
        default_scheme — Scheme used when building an absolute URL from Host.
        default_url    — Fallback absolute URL when Host / request-target are
                         incomplete (typically the parent flow URL).
    Output:
        dict with keys:
            method (str), url (str), host (str), path (str), query (str),
            request_headers (dict[str, str]), request_body (bytes|None),
            http_version (str)
    Raises:
        ValueError when the message cannot be parsed as a request.
    Side effects: None.
    """
    if not raw:
        raise ValueError("empty raw HTTP request")

    # Normalize lone LF to CRLF for splitting head/body; body stays binary.
    # Split headers from body on first blank line (CRLF or LF).
    head, body = _split_head_body(raw)
    head_text = head.decode("utf-8", errors="replace")
    lines = head_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    # Drop trailing empty lines from split artifacts.
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        raise ValueError("raw HTTP request has no request line")

    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2:
        raise ValueError(f"invalid request line: {request_line!r}")
    method = parts[0].upper()
    request_target = parts[1]
    http_version = parts[2] if len(parts) >= 3 else "HTTP/1.1"

    headers: dict[str, str] = {}
    # Preserve last occurrence on duplicate names (set/replace semantics).
    for line in lines[1:]:
        if not line.strip():
            continue
        # Use bytes regex on encoded line for robustness with non-ascii values.
        m = _HEADER_RE.match(line.encode("utf-8", errors="replace"))
        if not m:
            raise ValueError(f"invalid header line: {line!r}")
        name = m.group(1).decode("utf-8", errors="replace")
        value = m.group(2).decode("utf-8", errors="replace").strip()
        headers[name] = value

    # Reconstruct absolute URL.
    url, host, path, query = _resolve_url(
        request_target=request_target,
        headers=headers,
        default_scheme=default_scheme,
        default_url=default_url,
    )

    body_bytes: Optional[bytes] = body if body else None
    # Empty body after blank line → None for GET-like requests.
    if body_bytes == b"":
        body_bytes = None

    return {
        "method": method,
        "url": url,
        "host": host,
        "path": path,
        "query": query,
        "request_headers": headers,
        "request_body": body_bytes,
        "http_version": http_version,
    }


def _split_head_body(raw: bytes) -> tuple[bytes, bytes]:
    """
    Purpose:
        Split raw message into head (request-line + headers) and body.
    Input:
        raw — full message bytes.
    Output:
        (head_bytes, body_bytes). body may be empty.
    Side effects: None.
    """
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx], raw[idx + len(sep) :]
    # No blank line → entire message is head; no body.
    return raw, b""


def _resolve_url(
    *,
    request_target: str,
    headers: dict[str, str],
    default_scheme: str,
    default_url: Optional[str],
) -> tuple[str, str, str, str]:
    """
    Purpose:
        Build absolute URL + host/path/query from request-target + Host.
    Output:
        (url, host, path, query)
    Side effects: None.
    """
    # Absolute-form request target (proxy style).
    if request_target.startswith("http://") or request_target.startswith("https://"):
        parsed = urlparse(request_target)
        host = parsed.hostname or ""
        path = parsed.path or "/"
        query = parsed.query or ""
        return request_target, host, path, query

    # authority-form (CONNECT) — rare; treat path as given.
    host_header = _header_value(headers, "host")
    scheme = default_scheme or "https"
    fallback = urlparse(default_url) if default_url else None
    if fallback and fallback.scheme:
        scheme = fallback.scheme

    if request_target.startswith("/"):
        path_q = request_target
    elif request_target == "*":
        path_q = "/"
    else:
        # origin-form missing leading slash — tolerate.
        path_q = "/" + request_target

    if "?" in path_q:
        path, query = path_q.split("?", 1)
    else:
        path, query = path_q, ""

    if host_header:
        authority = host_header
    elif fallback and fallback.netloc:
        authority = fallback.netloc
    else:
        raise ValueError(
            "raw HTTP request has no Host header and no default URL to derive host"
        )

    # host column stores hostname only (no port) when possible — match replay.
    hostname = authority.split("@")[-1]
    if hostname.startswith("["):
        # IPv6 literal
        host_only = hostname
    else:
        host_only = hostname.rsplit(":", 1)[0] if ":" in hostname else hostname

    # urlunparse: (scheme, netloc, path, params, query, fragment)
    # Query must be the 5th component — putting it in params yields path;query.
    url = urlunparse((scheme, authority, path or "/", "", query, ""))
    return url, host_only, path or "/", query


def _header_value(headers: dict[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup."""
    lower = name.lower()
    for key, value in headers.items():
        if key.lower() == lower:
            return value
    return None
