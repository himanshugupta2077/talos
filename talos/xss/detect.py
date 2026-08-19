"""
Module: talos.xss.detect

Purpose:
    Decide whether a probe response reflected an XSS or HTML-injection
    payload in a dangerous way.

    Confirmation requires the **TalosXss canary** in the HTTP response
    (body, and a short list of reflection-prone headers). Hits must be
    **new versus the captured baseline** so a page that already contains
    ``<script>`` does not become a finding.

    Encoding:
        raw          — canary + sink/tag appear unescaped
        html_entity  — tags present only as &lt; / &#x3c; (not a finding)
        url          — tags present only as %3c (not a finding)
        unicode      — tags present only as \\u003c (not a finding)

    Verdicts:
        XSS    — JS execution sink intact next to the canary
                 (script, event handler, javascript:, alert(canary))
        HTMLI  — HTML markup intact next to the canary, no JS sink
        SECURE — canary missing, encoded-only, or plain-text echo

Dependencies: html, re, urllib.parse
Data flow: engine → analyze_xss_response → verdict
Side effects: None.
"""

from __future__ import annotations

import html
import re
from typing import Optional
from urllib.parse import unquote

from talos.xss.models import (
    CANARY,
    CONTEXT_COMMENT,
    CONTEXT_GENERIC,
    CONTEXT_HTML_ATTR,
    CONTEXT_HTML_BODY,
    CONTEXT_JSON,
    CONTEXT_SCRIPT,
    CONTEXT_STYLE,
    CONTEXT_URL,
    VERDICT_HTMLI,
    VERDICT_SECURE,
    VERDICT_XSS,
)

# Markup / attribute JS sinks that must appear *unencoded* near the canary.
_XSS_TAG_SINK_RE = re.compile(
    r"<script[\s/>]|</script>"
    r"|\bon(?:error|load|focus|mouseover|click|pointerover|toggle|start|"
    r"animationend|pointerenter|begin)\s*="
    r"|javascript\s*:"
    r"|<svg[\s/>]|<math[\s/>]"
    r"|srcdoc\s*="
    r"|expression\s*\(",
    re.I,
)

# JS-context breakout: alert(canary) without requiring HTML tags.
_XSS_ALERT_RE = re.compile(
    r"alert\s*\(\s*['\"]?" + re.escape(CANARY),
    re.I,
)

# Markup that is HTML injection even without a JS sink.
_HTMLI_TAG_RE = re.compile(
    r"<(?:h[1-6]|b|i|u|em|strong|div|span|p|a|img|form|style|table|tr|td|"
    r"marquee|textarea|iframe|svg|font|center|hr|br|input|button|label|"
    r"pre|details|video|audio|object|embed|template|noscript|math)[\s/>]",
    re.I,
)

_ENCODED_LT = re.compile(
    r"&lt;|&#0*60;|&#x0*3c;|%3c|%253c|\\u003c|\\x3c",
    re.I,
)

_HEADER_KEYS = frozenset(
    {
        "location",
        "refresh",
        "content-disposition",
        "content-type",
        "set-cookie",
        "x-redirect",
        "access-control-allow-origin",
    }
)

_WINDOW = 160


def _decode_body(raw: object) -> str:
    """Purpose: Response body to searchable text. Output: str."""
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def _headers_blob(headers: object) -> str:
    """Purpose: Flatten selected response headers into searchable text."""
    if headers is None:
        return ""
    data = headers
    if isinstance(headers, (bytes, bytearray)):
        headers = headers.decode("utf-8", errors="replace")
    if isinstance(headers, str):
        text = headers.strip()
        if not text:
            return ""
        if text[:1] in "{[":
            try:
                import json

                data = json.loads(text)
            except (ValueError, TypeError):
                return text
        else:
            return text
    if isinstance(data, dict):
        parts: list[str] = []
        for key, value in data.items():
            if str(key).lower() not in _HEADER_KEYS:
                continue
            if value is None:
                continue
            if isinstance(value, list):
                parts.append(f"{key}: {value[0] if value else ''}")
            else:
                parts.append(f"{key}: {value}")
        return "\n".join(parts)
    return ""


def _content_type(headers: object, explicit: str = "") -> str:
    """Purpose: Lowercased Content-Type (no parameters)."""
    if explicit:
        return explicit.split(";", 1)[0].strip().lower()
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == "content-type":
                raw = value[0] if isinstance(value, list) else value
                return str(raw or "").split(";", 1)[0].strip().lower()
    blob = _headers_blob(headers)
    match = re.search(r"(?im)^content-type:\s*([^\r\n;]+)", blob)
    if match:
        return match.group(1).strip().lower()
    return ""


def _find_windows(text: str, needle: str, radius: int = _WINDOW) -> list[str]:
    """Purpose: ±radius slices around every case-insensitive needle hit."""
    if not text or not needle:
        return []
    lower = text.lower()
    key = needle.lower()
    out: list[str] = []
    start = 0
    while True:
        idx = lower.find(key, start)
        if idx < 0:
            break
        lo = max(0, idx - radius)
        hi = min(len(text), idx + len(needle) + radius)
        out.append(text[lo:hi])
        start = idx + 1
    return out


def _classify_context(window: str, content_type: str) -> str:
    """Purpose: Heuristic reflection context from the canary window."""
    ctype = content_type or ""
    if "javascript" in ctype or ctype.endswith("/ecmascript"):
        return CONTEXT_SCRIPT
    if "json" in ctype:
        return CONTEXT_JSON
    lowered = window.lower()
    script_open = lowered.rfind("<script")
    script_close = lowered.rfind("</script")
    if script_open >= 0 and script_open > script_close:
        return CONTEXT_SCRIPT
    if "<!--" in lowered and "-->" not in lowered[lowered.find("<!--") :]:
        return CONTEXT_COMMENT
    style_open = lowered.rfind("<style")
    style_close = lowered.rfind("</style")
    if style_open >= 0 and style_open > style_close:
        return CONTEXT_STYLE
    if re.search(r"""=\s*['"][^'"]*$""", window):
        return CONTEXT_HTML_ATTR
    if "javascript:" in lowered:
        return CONTEXT_URL
    if "html" in ctype or "xml" in ctype or "svg" in ctype or not ctype:
        return CONTEXT_HTML_BODY
    return CONTEXT_GENERIC


def _tag_encoding(window: str) -> str:
    """
    Purpose:
        How angle brackets / sinks appear next to the canary.
    Output:
        raw | html_entity | url | unicode
    """
    if _XSS_TAG_SINK_RE.search(window) or _HTMLI_TAG_RE.search(window):
        return "raw"
    if re.search(r"\\u003c|\\x3c", window, re.I):
        return "unicode"
    if re.search(r"%3c|%253c", window, re.I):
        return "url"
    if _ENCODED_LT.search(window):
        return "html_entity"
    return "raw"


def _window_is_xss(window: str) -> bool:
    """Purpose: Unencoded JS sink next to the canary."""
    if _XSS_TAG_SINK_RE.search(window):
        return True
    if _ENCODED_LT.search(window):
        # Tags were escaped; a leftover alert(canary) is not execution.
        return False
    return bool(_XSS_ALERT_RE.search(window))


def _window_is_htmli(window: str) -> bool:
    """Purpose: Unencoded HTML tag next to the canary (no JS required)."""
    return bool(_HTMLI_TAG_RE.search(window))


def collect_canary_hits(text: str, canary: str = CANARY) -> list[str]:
    """
    Purpose:
        Return canary windows in ``text`` (raw, then html/url unescaped).
    Output:
        Window strings (may be empty).
    """
    blob = text or ""
    hits = _find_windows(blob, canary)
    if hits:
        return hits
    unescaped = html.unescape(blob)
    if unescaped != blob:
        hits = _find_windows(unescaped, canary)
        if hits:
            return hits
    decoded = unquote(unquote(blob))
    if decoded != blob:
        return _find_windows(decoded, canary)
    return []


def analyze_xss_response(
    *,
    baseline_body: object,
    probe_body: object,
    payload_sent: str = "",
    content_type: str = "",
    probe_headers: object = None,
    baseline_headers: object = None,
    risk_class: str = "",
) -> tuple[str, str, Optional[str], Optional[str], str]:
    """
    Purpose:
        Classify one probe against the captured baseline.
    Output:
        (verdict, risk_hint, context_hint, encoding_hint, evidence)
    """
    del payload_sent  # reserved; canary is the confirmation token
    base_text = _decode_body(baseline_body) + "\n" + _headers_blob(baseline_headers)
    probe_text = _decode_body(probe_body) + "\n" + _headers_blob(probe_headers)
    ctype = _content_type(probe_headers, content_type)

    probe_hits = collect_canary_hits(probe_text)
    if not probe_hits:
        return VERDICT_SECURE, "", None, None, ""

    base_hits = collect_canary_hits(base_text)
    if base_hits and not any(
        _window_is_xss(w) or _window_is_htmli(w) for w in probe_hits
    ):
        return VERDICT_SECURE, "", None, None, ""
    if base_hits:
        # Canary already on the page — only fire if a *new* sink appeared.
        base_has_xss = any(_window_is_xss(w) for w in base_hits)
        base_has_html = any(_window_is_htmli(w) for w in base_hits)
        probe_xss = [w for w in probe_hits if _window_is_xss(w)]
        probe_html = [w for w in probe_hits if _window_is_htmli(w)]
        if base_has_xss or (not probe_xss and not probe_html):
            return VERDICT_SECURE, "", None, None, ""
        if base_has_html and not probe_xss:
            return VERDICT_SECURE, "", None, None, ""

    best_xss: Optional[str] = None
    best_html: Optional[str] = None
    encoding = "raw"
    context = CONTEXT_GENERIC
    for window in probe_hits:
        enc = _tag_encoding(window)
        ctx = _classify_context(window, ctype)
        if _window_is_xss(window):
            best_xss = window
            encoding = enc
            context = ctx
            break
        if _window_is_htmli(window) and best_html is None:
            best_html = window
            encoding = enc
            context = ctx

    if best_xss is not None:
        snippet = re.sub(r"\s+", " ", best_xss).strip()[:160]
        return VERDICT_XSS, "xss_sink", context, encoding, snippet

    if best_html is not None:
        snippet = re.sub(r"\s+", " ", best_html).strip()[:160]
        return VERDICT_HTMLI, "html_tag", context, encoding, snippet

    # Canary reflected but tags encoded or stripped.
    sample = re.sub(r"\s+", " ", probe_hits[0]).strip()[:160]
    enc = _tag_encoding(probe_hits[0])
    if enc != "raw":
        return VERDICT_SECURE, "encoded", _classify_context(probe_hits[0], ctype), enc, ""
    # JS-breakout payloads may reflect the canary inside alert() without tags.
    if _window_is_xss(probe_hits[0]):
        return (
            VERDICT_XSS,
            "xss_sink",
            _classify_context(probe_hits[0], ctype),
            "raw",
            sample,
        )
    if risk_class == "htmli":
        return VERDICT_SECURE, "reflected_plain", _classify_context(probe_hits[0], ctype), "raw", ""
    return VERDICT_SECURE, "reflected_plain", _classify_context(probe_hits[0], ctype), "raw", ""
