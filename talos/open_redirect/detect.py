"""
Module: talos.open_redirect.detect

Purpose:
    Decide whether a probe response is an open redirect to the canary.

    Hits must be **new versus the captured baseline** Location / Refresh /
    meta refresh / JS location. Echoed payload text in the HTML body is
    not a finding unless it is a real redirect sink.

Dependencies: json, re, urllib.parse
Data flow: engine → analyze_open_redirect_response → verdict
Side effects: None.
"""

from __future__ import annotations

import json
import re
from typing import Optional
from urllib.parse import unquote, urlparse

from talos.open_redirect.models import CANARY_HOST, VERDICT_OPEN_REDIRECT, VERDICT_SECURE

_JS_RE = re.compile(
    r"""(?:window\.)?location(?:\.href|\.replace)?\s*=\s*['"]([^'"]+)['"]""",
    re.I,
)
_META_RE = re.compile(
    r"""<meta[^>]+http-equiv=['"]?refresh['"]?[^>]+content=['"]?\s*\d+\s*;\s*url=([^'"\s>]+)""",
    re.I,
)
_REFRESH_RE = re.compile(r"^\s*\d+\s*;\s*url=(.+)$", re.I)


def _decode_body(raw: object) -> str:
    """Purpose: Response body to searchable text."""
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def parse_headers(raw: object) -> dict[str, str]:
    """Purpose: Normalize stored/response headers to a lowercased map."""
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
    if not isinstance(data, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in data.items():
        if value is None:
            continue
        if isinstance(value, list):
            out[str(key).lower()] = str(value[0]) if value else ""
        else:
            out[str(key).lower()] = str(value)
    return out


def _header_get(headers: dict[str, str], name: str) -> str:
    """Purpose: Case-insensitive header lookup."""
    want = name.lower()
    for key, value in headers.items():
        if key.lower() == want:
            return value
    return ""


def host_matches_canary(url: str, canary_host: str) -> bool:
    """
    Purpose:
        True when ``url`` navigates to the canary host (or javascript:/data:).
    """
    text = unquote(unquote(url or "")).strip()
    if not text:
        return False
    lowered = text.lower()
    if lowered.startswith("javascript:") or lowered.startswith("data:"):
        return True
    host = (canary_host or CANARY_HOST).lower().rstrip(".")
    parsed = urlparse(text if "://" in text or text.startswith("//") else "//" + text.lstrip("/"))
    target = (parsed.hostname or "").lower().rstrip(".")
    if not target:
        # protocol-relative leftovers or host-only
        if lowered.startswith("//"):
            target = lowered[2:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        elif host in lowered:
            # last-ditch: encoded host still present after unquote
            return True
    if not target:
        return False
    return target == host or target.endswith("." + host)


def _redirect_targets(
    *,
    headers: dict[str, str],
    body: str,
) -> list[tuple[str, str]]:
    """
    Purpose:
        Collect (source, url) redirect sinks from headers + body.
    """
    out: list[tuple[str, str]] = []
    location = _header_get(headers, "location")
    if location:
        out.append(("location", location))
    refresh = _header_get(headers, "refresh")
    if refresh:
        match = _REFRESH_RE.match(refresh.strip())
        out.append(("refresh", match.group(1).strip() if match else refresh))
    content_loc = _header_get(headers, "content-location")
    if content_loc:
        out.append(("content-location", content_loc))
    for match in _META_RE.finditer(body or ""):
        out.append(("meta_refresh", match.group(1)))
    for match in _JS_RE.finditer(body or ""):
        out.append(("js_location", match.group(1)))
    return out


def analyze_open_redirect_response(
    *,
    baseline_headers: object,
    probe_headers: object,
    baseline_body: object = None,
    probe_body: object = None,
    canary_host: str = CANARY_HOST,
    payload_sent: str = "",
) -> tuple[str, str, str, str]:
    """
    Purpose:
        Classify one probe against the captured baseline.
    Output:
        (verdict, risk_hint, redirect_url, evidence)
    """
    base_h = parse_headers(baseline_headers)
    probe_h = parse_headers(probe_headers)
    base_body = _decode_body(baseline_body)
    probe_body_text = _decode_body(probe_body)

    base_targets = {
        (src, url)
        for src, url in _redirect_targets(headers=base_h, body=base_body)
        if host_matches_canary(url, canary_host)
    }
    probe_targets = [
        (src, url)
        for src, url in _redirect_targets(headers=probe_h, body=probe_body_text)
        if host_matches_canary(url, canary_host)
    ]
    new = [item for item in probe_targets if item not in base_targets]
    if not new:
        return VERDICT_SECURE, "", "", ""

    source, url = new[0]
    # javascript:/data: in Location is still an open redirect (often XSS).
    if url.lower().startswith("javascript:"):
        hint = "javascript"
    elif url.lower().startswith("data:"):
        hint = "data_uri"
    else:
        hint = source
    evidence = f"{source}: {url[:160]}"
    return VERDICT_OPEN_REDIRECT, hint, url[:500], evidence
