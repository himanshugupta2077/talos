"""
Module: talos.host_header.detect

Purpose:
    Decide whether a probe response used the attacker host in a URL-shaped
    sink (password-reset / cache / absolute URL generation).

    Hits must be **new versus the captured baseline**. Echo of the payload
    as plain text that is not a URL or a URL-bearing header is not a finding.
    A 400 / 421 / different virtual-host page without canary reflection is
    not a finding (that is BAC host-fuzz territory).

Dependencies: json, re, urllib.parse
Data flow: engine → analyze_host_header_response → verdict
Side effects: None.
"""

from __future__ import annotations

import json
import re
from typing import Optional
from urllib.parse import unquote, urlparse

from talos.host_header.models import CANARY_HOST, VERDICT_HOST_HEADER, VERDICT_SECURE

_JS_RE = re.compile(
    r"""(?:window\.)?location(?:\.href|\.replace)?\s*=\s*['"]([^'"]+)['"]""",
    re.I,
)
_META_RE = re.compile(
    r"""<meta[^>]+http-equiv=['"]?refresh['"]?[^>]+content=['"]?\s*\d+\s*;\s*url=([^'"\s>]+)""",
    re.I,
)
_ATTR_RE = re.compile(
    r"""(?:href|src|action|data-url|data-href|formaction|cite|poster)\s*=\s*['"]([^'"]+)['"]""",
    re.I,
)
_CANON_RE = re.compile(
    r"""<link[^>]+rel=['"](?:canonical|alternate)['"][^>]+href=['"]([^'"]+)['"]""",
    re.I,
)
_ABS_URL_RE = re.compile(r"""https?://[^\s"'<>\\]+""", re.I)
_JSON_URL_RE = re.compile(
    r"""['"](?:url|href|link|reset_url|resetUrl|redirect|next|location|host|domain)['"]\s*:\s*['"]([^'"]+)['"]""",
    re.I,
)
_REFRESH_RE = re.compile(r"^\s*\d+\s*;\s*url=(.+)$", re.I)
_COOKIE_DOMAIN_RE = re.compile(r"\bdomain=([^;]+)", re.I)

_CACHE_HEADERS = frozenset(
    {
        "x-cache",
        "x-cache-hits",
        "cf-cache-status",
        "age",
        "x-drupal-cache",
        "x-varnish",
        "x-cache-status",
        "x-proxy-cache",
    }
)

# Short needles (0, 127.0.0.1-ish) require an exact hostname match.
_EXACT_ONLY = frozenset({"0", "1", "::1", "[::1]"})


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
    return headers.get(name.lower(), "")


def host_matches_needle(url: str, needle: str) -> bool:
    """
    Purpose:
        True when ``url`` is a URL-shaped value whose host is ``needle``.
    """
    text = unquote(unquote(url or "")).strip()
    if not text or not needle:
        return False
    n = needle.lower().rstrip(".")
    lowered = text.lower()
    parsed = urlparse(
        text if "://" in text or text.startswith("//") else "//" + text.lstrip("/")
    )
    target = (parsed.hostname or "").lower().rstrip(".")
    if not target and lowered.startswith("["):
        target = lowered.split("]", 1)[0] + "]"
    if not target and lowered.startswith("//"):
        target = lowered[2:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if ":" in target and not target.startswith("["):
            target = target.rsplit(":", 1)[0]
    if not target:
        return False
    if n in _EXACT_ONLY or len(n) <= 3:
        return target == n or target == n.strip("[]")
    return (
        target == n
        or target.endswith("." + n)
        or target.startswith(n + ".")
        or n in target
    )


def _needles(
    *,
    canary_host: str,
    payload_sent: str,
) -> list[str]:
    """Purpose: Hosts to look for in URL-shaped sinks."""
    out: list[str] = []
    seen: set[str] = set()
    for item in (canary_host, CANARY_HOST):
        token = (item or "").strip().lower().rstrip(".")
        if token and token not in seen:
            seen.add(token)
            out.append(token)
    blob = unquote(unquote(payload_sent or "")).lower()
    extras = (
        "localhost",
        "127.0.0.1",
        "[::1]",
        "::1",
        "2130706433",
        "xn--talos-hhi-9za.invalid",
        "talos-hhi%2einvalid",
    )
    for extra in extras:
        if extra in blob or extra.strip("[]") in blob:
            if extra not in seen:
                seen.add(extra)
                out.append(extra)
    if re.search(r"(?:^|[\s/:@])0(?:$|[\s/:])", blob) and "0" not in seen:
        out.append("0")
    return out


def _url_sinks(*, headers: dict[str, str], body: str) -> list[tuple[str, str]]:
    """
    Purpose:
        Collect (kind, value) URL-shaped sinks from headers + body.
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
    link = _header_get(headers, "link")
    if link:
        out.append(("link", link))
    acao = _header_get(headers, "access-control-allow-origin")
    if acao:
        out.append(("acao", acao))
    cookie = _header_get(headers, "set-cookie")
    if cookie:
        match = _COOKIE_DOMAIN_RE.search(cookie)
        if match:
            out.append(("set_cookie", match.group(1).strip()))
        out.append(("set_cookie", cookie))
    csp = _header_get(headers, "content-security-policy")
    if csp:
        out.append(("csp", csp))
    csp_ro = _header_get(headers, "content-security-policy-report-only")
    if csp_ro:
        out.append(("csp", csp_ro))
    www = _header_get(headers, "www-authenticate")
    if www:
        out.append(("www_authenticate", www))

    text = body or ""
    for match in _META_RE.finditer(text):
        out.append(("meta_refresh", match.group(1)))
    for match in _JS_RE.finditer(text):
        out.append(("js_location", match.group(1)))
    for match in _CANON_RE.finditer(text):
        out.append(("html_url", match.group(1)))
    for match in _ATTR_RE.finditer(text):
        out.append(("html_url", match.group(1)))
    for match in _JSON_URL_RE.finditer(text):
        out.append(("json_url", match.group(1)))
    for match in _ABS_URL_RE.finditer(text):
        out.append(("body_url", match.group(0)))
    return out


def _has_cache_signal(headers: dict[str, str]) -> bool:
    """Purpose: True when the response looks cache-keyed."""
    for name in _CACHE_HEADERS:
        if _header_get(headers, name).strip():
            return True
    vary = _header_get(headers, "vary").lower()
    return "host" in vary


def analyze_host_header_response(
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
        (verdict, risk_hint, reflected_url, evidence)
    """
    base_h = parse_headers(baseline_headers)
    probe_h = parse_headers(probe_headers)
    base_body = _decode_body(baseline_body)
    probe_text = _decode_body(probe_body)
    needles = _needles(canary_host=canary_host, payload_sent=payload_sent)

    def _hits(headers: dict[str, str], body: str) -> list[tuple[str, str, str]]:
        found: list[tuple[str, str, str]] = []
        for kind, value in _url_sinks(headers=headers, body=body):
            for needle in needles:
                if host_matches_needle(value, needle):
                    found.append((kind, value, needle))
                    break
        return found

    base_keys = {(kind, value) for kind, value, _needle in _hits(base_h, base_body)}
    probe_hits = _hits(probe_h, probe_text)
    new = [item for item in probe_hits if (item[0], item[1]) not in base_keys]
    if not new:
        return VERDICT_SECURE, "", "", ""

    kind, value, _needle = new[0]
    hint = kind
    if _has_cache_signal(probe_h) and kind in {"html_url", "body_url", "json_url"}:
        hint = "cache"
    evidence = f"{kind}: {value[:160]}"
    return VERDICT_HOST_HEADER, hint, value[:500], evidence
