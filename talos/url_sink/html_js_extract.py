"""
Module: talos.url_sink.html_js_extract

Purpose:
    Extract URL-sink inventory candidates from HTML responses:
        1. Hidden ``<input>`` name/value pairs
        2. JS / bootstrap config islands (``__NEXT_DATA__``, ``window.__CONFIG__``,
           common ``apiUrl`` / ``baseUrl`` leaves)

    Read-only inventory enrichment — does not fetch external scripts.
    Gated by name category **or** value score ≥ threshold so static CDN
    strings do not flood the parameter table.

Dependencies: json, re (stdlib); talos.url_sink.{features, decode, name_classify}
Data flow: HTML text → list[HtmlJsParamCandidate]
Side effects: None.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from talos.url_sink.decode import MAX_JSON_DEPTH, walk_unwrapped_leaves
from talos.url_sink.features import NETWORK_RESOURCE_SCORE_THRESHOLD, compose_url_features
from talos.url_sink.value_classify import classify_value

# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------

_MAX_HIDDEN_INPUTS: int = 80
_MAX_JS_LEAVES: int = 80
_MAX_HTML_SCAN_CHARS: int = 2_000_000
_MAX_BOOTSTRAP_PAYLOAD: int = 500_000
_MAX_BOOTSTRAP_ISLANDS: int = 20

# Hidden input: type=hidden (quoted or unquoted) with name + optional value.
# Attr order is free: type may appear before or after name/value.
_HIDDEN_INPUT_RE = re.compile(
    r"""<input\b(?P<attrs>[^>]*?\btype\s*=\s*(?:['"]hidden['"]|hidden\b)[^>]*?)>""",
    re.IGNORECASE | re.DOTALL,
)
# name='…' | name="…" | name=bare
_ATTR_NAME = re.compile(
    r"""\bname\s*=\s*(?:['"]([^'"]+)['"]|([^\s>]+))""",
    re.IGNORECASE,
)
_ATTR_VALUE = re.compile(
    r"""\bvalue\s*=\s*(?:['"]([^'"]*)['"]|([^\s>]*))""",
    re.IGNORECASE,
)

# Name categories strong enough that an empty sample still inventorizes a
# potential sink name (redirect_url="" on a login page). Weak tokens like
# next/to/key with junk values are excluded from HTML/JS inventory.
_STRONG_EMPTY_NAME_CATEGORIES: frozenset[str] = frozenset({
    "redirect",
    "oauth",
    "webhook",
    "remote_fetch",
    "remote_asset",
    "import_metadata",
})

# Script tags (inline only — skip src=).
_SCRIPT_TAG = re.compile(
    r"<script(?P<attrs>[^>]*)>(?P<body>.*?)</script\s*>",
    re.IGNORECASE | re.DOTALL,
)
_ATTR_SRC = re.compile(r"""\bsrc\s*=""", re.IGNORECASE)
_ATTR_TYPE = re.compile(
    r"""\btype\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_ATTR_ID = re.compile(
    r"""\bid\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

_JSON_SCRIPT_TYPES = frozenset({
    "application/json",
    "application/ld+json",
    "text/json",
})
_BOOTSTRAP_ID_HINTS = frozenset({
    "__next_data__",
    "__nuxt_data__",
    "__nuxt__",
    "__app_data__",
    "__config__",
    "app-config",
    "runtime-config",
})

# window.__CONFIG__ = {…}; / window["__INITIAL_STATE__"] = {…};
# window.__NEXT_DATA__ = {…} must be matched as a full token first — a leading
# ``__?`` would consume the underscores and leave NEXT_DATA__ unmatched.
# Allow trailing underscores on well-known bootstrap names (__CONFIG__).
_WINDOW_BOOTSTRAP = re.compile(
    r"""window(?:\[["']|\.)("""
    r"""__NEXT_DATA__|__NUXT_DATA__|__NUXT__|"""
    r"""__?(?:CONFIG|INITIAL_STATE|INITIAL_DATA|PRELOADED_STATE|"""
    r"""APP_CONFIG|ENV|RUNTIME_CONFIG)_*"""
    r""")["']?\]?\s*=\s*""",
    re.IGNORECASE,
)

# Common JS assignment patterns: apiUrl: "https://…", base_url = '…'
_JS_URL_ASSIGN_RE = re.compile(
    r"""(?P<name>\b(?:apiUrl|api_url|baseUrl|base_url|baseURI|baseUri|"""
    r"""callbackUrl|callback_url|redirectUri|redirect_uri|redirectUrl|"""
    r"""redirect_url|webhookUrl|webhook_url|cdnUrl|cdn_url|assetUrl|"""
    r"""asset_url|publicUrl|public_url|origin|endpoint)\b)\s*[:=]\s*"""
    r"""['"](?P<value>[^'"]{4,500})['"]""",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class HtmlJsParamCandidate:
    """
    Purpose:
        One inventory candidate from HTML/JS response analysis.
    Fields:
        name         — parameter name (hidden input name or dotted JS path).
        sample_value — observed value.
        source       — ``html_hidden`` | ``js_config``.
        evidence     — machine-readable tokens for url_features merge.
        score        — composed score (for gate / tests).
    Side effects: None.
    """

    name: str
    sample_value: str
    source: str
    evidence: tuple[str, ...]
    score: int = 0


def extract_html_js_params(
    html_text: str | None,
    *,
    score_threshold: int = NETWORK_RESOURCE_SCORE_THRESHOLD,
    max_hidden: int = _MAX_HIDDEN_INPUTS,
    max_js_leaves: int = _MAX_JS_LEAVES,
) -> list[HtmlJsParamCandidate]:
    """
    Purpose:
        Build gated inventory candidates from an HTML response body.
    Input:
        html_text        — response body text (HTML or HTML shell with JS).
        score_threshold  — value/name gate (default network-resource threshold).
        max_hidden / max_js_leaves — safety caps.
    Output:
        Deduped list of HtmlJsParamCandidate (name key wins first sighting).
        Empty when HTML has nothing gate-passing.
    Side effects: None.
    Risk control:
        Require (name category **or** score ≥ threshold). Cap counts/sizes.
        Do not fetch external ``src`` scripts.
    """
    if not html_text or not html_text.strip():
        return []
    text = html_text if len(html_text) <= _MAX_HTML_SCAN_CHARS else html_text[:_MAX_HTML_SCAN_CHARS]

    candidates: list[HtmlJsParamCandidate] = []
    seen_names: set[str] = set()

    # 1) Hidden form fields
    hidden_count = 0
    for m in _HIDDEN_INPUT_RE.finditer(text):
        if hidden_count >= max_hidden:
            break
        attrs = m.group("attrs") or ""
        name = _attr_capture(_ATTR_NAME, attrs)
        if not name:
            continue
        value = _attr_capture(_ATTR_VALUE, attrs) or ""
        hidden_count += 1
        _maybe_add(
            candidates,
            seen_names,
            name=name,
            value=value,
            source="html_hidden",
            extra_evidence=("html_hidden",),
            score_threshold=score_threshold,
        )

    # 2) Bootstrap JSON islands + window assignments
    js_count = 0
    for island_name, payload in _iter_bootstrap_payloads(text):
        if js_count >= max_js_leaves:
            break
        parsed = _try_parse_jsonish(payload)
        if parsed is None:
            continue
        prefix = f"js.{island_name}" if island_name else "js.config"
        leaves = walk_unwrapped_leaves(
            parsed,
            prefix=prefix,
            max_depth=MAX_JSON_DEPTH,
            max_leaves=max_js_leaves - js_count,
        )
        for leaf_name, leaf_val in leaves:
            if js_count >= max_js_leaves:
                break
            if _maybe_add(
                candidates,
                seen_names,
                name=leaf_name,
                value=leaf_val,
                source="js_config",
                extra_evidence=("js_config", f"js_island:{island_name or 'config'}"),
                score_threshold=score_threshold,
            ):
                js_count += 1

    # 3) Common JS key assignments outside JSON (apiUrl: "…")
    if js_count < max_js_leaves:
        for m in _JS_URL_ASSIGN_RE.finditer(text):
            if js_count >= max_js_leaves:
                break
            name = m.group("name")
            value = m.group("value")
            if _maybe_add(
                candidates,
                seen_names,
                name=name,
                value=value,
                source="js_config",
                extra_evidence=("js_config", "js_assign"),
                score_threshold=score_threshold,
            ):
                js_count += 1

    return candidates


def passes_inventory_gate(
    name: str,
    value: str,
    *,
    score_threshold: int = NETWORK_RESOURCE_SCORE_THRESHOLD,
) -> tuple[bool, int, list[str]]:
    """
    Purpose:
        Gate HTML/JS inventory candidates to avoid flooding parameters with
        weak catalog name hits (``next=1``, ``key=abc``) while still accepting:
            - value-first network resources (score ≥ threshold)
            - name categories with URL/host/IP/path-shaped values
            - empty samples only for strong sink categories (redirect/oauth/…)
    Input:
        name / value / score_threshold
    Output:
        (pass, score, evidence_tokens)
    Side effects: None.
    """
    features = compose_url_features(name=name, value=value)
    score = int(features.get("score") or 0)
    categories = list(features.get("name_categories") or [])
    evidence = list(features.get("evidence") or [])
    vf = classify_value(value)
    value_stripped = (value or "").strip()

    # Value-first: absolute URL / strong network resource.
    if score >= score_threshold:
        return True, score, evidence
    if vf.possible_url_value and vf.score >= score_threshold:
        return True, max(score, vf.score), evidence

    if not categories:
        return False, score, evidence

    # Name category + network-shaped value (hostname, IP, path, URL).
    if value_stripped and (
        vf.possible_url_value
        or vf.possible_hostname
        or vf.possible_domain
        or vf.possible_ip
        or vf.possible_path
        or vf.possible_unc
        or vf.score >= 40
    ):
        return True, score, evidence

    # Empty sample: only strong sink categories (discover name as potential sink).
    if not value_stripped:
        if any(c in _STRONG_EMPTY_NAME_CATEGORIES for c in categories):
            return True, score, evidence
        return False, score, evidence

    # Name category + non-empty junk (next=1, key=abc) — reject.
    return False, score, evidence


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _attr_capture(pattern: re.Pattern[str], attrs: str) -> str:
    """Return first capture group (quoted or bare) from an attribute match."""
    m = pattern.search(attrs)
    if not m:
        return ""
    for g in m.groups():
        if g is not None and g != "":
            return g.strip()
    # value="" is a valid empty quoted value — group may be "".
    if m.lastindex:
        return (m.group(1) if m.group(1) is not None else m.group(2) or "").strip()
    return ""


def _maybe_add(
    candidates: list[HtmlJsParamCandidate],
    seen_names: set[str],
    *,
    name: str,
    value: str,
    source: str,
    extra_evidence: tuple[str, ...],
    score_threshold: int,
) -> bool:
    """Gate + de-dupe; append when accepted. Returns True if added."""
    if not name or name in seen_names:
        return False
    ok, score, base_ev = passes_inventory_gate(
        name, value or "", score_threshold=score_threshold,
    )
    if not ok:
        return False
    evidence = list(dict.fromkeys(list(extra_evidence) + base_ev))
    seen_names.add(name)
    candidates.append(HtmlJsParamCandidate(
        name=name,
        sample_value=value or "",
        source=source,
        evidence=tuple(evidence),
        score=score,
    ))
    return True


def _iter_bootstrap_payloads(html_text: str) -> list[tuple[str, str]]:
    """Collect (island_name, payload_text) from script JSON + window bootstrap."""
    out: list[tuple[str, str]] = []
    bootstrap_count = 0

    for m in _SCRIPT_TAG.finditer(html_text):
        if bootstrap_count >= _MAX_BOOTSTRAP_ISLANDS:
            break
        attrs = m.group("attrs") or ""
        body = (m.group("body") or "").strip()
        if _ATTR_SRC.search(attrs) or not body:
            continue
        type_m = _ATTR_TYPE.search(attrs)
        type_val = (type_m.group(1) if type_m else "").strip().lower()
        id_m = _ATTR_ID.search(attrs)
        id_val = (id_m.group(1) if id_m else "").strip()
        id_lower = id_val.lower()

        is_json_type = type_val in _JSON_SCRIPT_TYPES
        is_bootstrap_id = id_lower in _BOOTSTRAP_ID_HINTS or any(
            hint in id_lower for hint in ("__next", "__nuxt", "config", "bootstrap")
        )
        if not (is_json_type or is_bootstrap_id):
            # Still try if body looks like JSON object
            if not (body.startswith("{") or body.startswith("[")):
                continue
        payload = body[:_MAX_BOOTSTRAP_PAYLOAD]
        name = id_val or type_val or "script_json"
        out.append((name, payload))
        bootstrap_count += 1

    if bootstrap_count < _MAX_BOOTSTRAP_ISLANDS:
        for wm in _WINDOW_BOOTSTRAP.finditer(html_text):
            if bootstrap_count >= _MAX_BOOTSTRAP_ISLANDS:
                break
            start = wm.end()
            payload = _extract_balanced_jsonish(html_text, start)
            if not payload or len(payload.strip()) < 4:
                continue
            name = wm.group(1) or "window_bootstrap"
            out.append((name, payload[:_MAX_BOOTSTRAP_PAYLOAD]))
            bootstrap_count += 1

    return out


def _try_parse_jsonish(payload: str) -> Any | None:
    text = payload.strip()
    if not text:
        return None
    # Strip trailing JS semicolon / commas common in assignments.
    if text.endswith(";"):
        text = text[:-1].rstrip()
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError, TypeError):
        pass
    # Some NEXT_DATA payloads are already pure JSON; others fail — give up.
    return None


def _extract_balanced_jsonish(text: str, start: int) -> str:
    """
    Extract a balanced {...} or [...] region starting at first brace/bracket
    at or after ``start``. Mirrors passive HTML extractor philosophy.
    """
    i = start
    n = len(text)
    while i < n and text[i] in " \t\r\n":
        i += 1
    if i >= n or text[i] not in "{[":
        return ""
    open_ch = text[i]
    close_ch = "}" if open_ch == "{" else "]"
    depth = 0
    in_str = False
    escape = False
    quote = ""
    for j in range(i, min(n, i + _MAX_BOOTSTRAP_PAYLOAD)):
        ch = text[j]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                in_str = False
            continue
        if ch in ('"', "'"):
            in_str = True
            quote = ch
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return text[i : j + 1]
    return ""
