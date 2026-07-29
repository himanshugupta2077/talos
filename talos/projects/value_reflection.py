"""
Module: talos.projects.value_reflection

Purpose:
    Cross-flow / stored reflection intelligence:
      - Pure helpers: eligibility, body matching, reason formatting, profile merge
      - Config: CrossFlowConfig + process-level cache (never YAML-merge per flow)
      - DB CRUD: value_index, cross_flow_reflections, parameters.cross_flow_*
      - Unified ingest: on_flow_committed (proxy worker + replay/IV)

Dependencies: hashlib, math, re, json, sqlite3, threading, dataclasses, pathlib
Data flow:
    FlowWorker / insert_replayed_flow → on_flow_committed → value_index +
    cross_flow_reflections → (later) IV synthesize / candidates merge.
Side effects:
    Pure section: none.
    DB section: writes value_index / cross_flow_reflections / parameters flags.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_INDEX_VALUE_LEN = 256
MIN_VALUE_LEN_DEFAULT = 6

# Canary pattern used by IV multiprobe (TL + hex).
_CANARY_RE = re.compile(r"^TL[0-9a-fA-F]{8,}$")
_SHORT_INT_RE = re.compile(r"^-?\d{1,5}$")
_PURE_REPEAT_RE = re.compile(r"^(.)\1+$")
_PURE_DIGIT_RE = re.compile(r"^\d+$")
# Soft-skip shapes (JWT / UUID) for post-match confidence haircut.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_BOOLEANISH = frozenset({"true", "false", "yes", "no", "null", "undefined"})

# Soft-skip semantic types: index only under rare-on-host Rule D.
_SOFT_SKIP_SEMANTIC = frozenset({"jwt", "uuid"})

# §1.3 secret / PII param-name denylist (exact names after normalize).
_SECRET_EXACT_NAMES = frozenset({
    "password",
    "passwd",
    "pass",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "cookie",
    "set_cookie",
    "session",
    "sessionid",
    "session_id",
    "csrf",
    "csrf_token",
    "xsrf",
    "ssn",
    "social_security",
    "credit_card",
    "card_number",
    "cvv",
    "cvc",
    "pin",
    "private_key",
    "client_secret",
})

# Substring tokens: name contains any of these (after normalize).
_SECRET_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "ssn",
    "creditcard",
    "credit_card",
    "private_key",
    "client_secret",
)

# Extra exact names for header/cookie locations (defense in depth).
_SECRET_HEADER_COOKIE_EXACT = frozenset({
    "authorization",
    "proxy-authorization",
    "proxy_authorization",
    "cookie",
    "set-cookie",
    "set_cookie",
    "x-api-key",
    "x_api_key",
    "x-auth-token",
    "x_auth_token",
    "x-access-token",
    "x_access_token",
    "x-amz-security-token",
    "x_amz_security_token",
    "x-csrf-token",
    "x_csrf_token",
})

# Uncertainty severity for merge (lower is better / less uncertain).
_UNCERTAINTY_RANK = {"none": 0, "low": 1, "high": 2}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IndexEligibility:
    """
    Outcome of is_indexable_value.

    indexable  — whether the value should be written to value_index
    rule       — accept rule letter (A/B/C/D) or reject reason tag
    is_canary  — True when matched multiprobe canary pattern
    entropy    — Shannon entropy bits/char (0.0 if empty)
    """

    indexable: bool
    rule: str
    is_canary: bool = False
    entropy: float = 0.0


@dataclass(frozen=True)
class BodyMatch:
    """
    Outcome of find_value_in_body.

    found       — True when value (or encoded/transform form) is in body
    encoding    — raw | html_encoded | url_encoded | ''
    transforms  — optional transform tags (trim, lowercase, uppercase)
    """

    found: bool
    encoding: str = ""
    transforms: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Entropy & hashing
# ---------------------------------------------------------------------------

def shannon_entropy(value: str) -> float:
    """
    Purpose:
        Shannon entropy (bits per character) over the observed alphabet.
    Input:
        value — candidate string
    Output:
        Entropy in [0, log2(alphabet)]; 0.0 for empty.
    Side effects: None.
    """
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    ent = 0.0
    for count in counts.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent


def value_hash(value: str) -> str:
    """
    Purpose:
        Stable 32-char hex digest of the exact match string (sha256 truncated).
    Input:
        value — exact string used for matching (value_norm)
    Output:
        First 32 hex chars of sha256(value).
    Side effects: None.
    """
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Secret denylist
# ---------------------------------------------------------------------------

def _normalize_param_name(name: str) -> str:
    """Lowercase, strip, map hyphens to underscores for denylist compare."""
    return (name or "").strip().lower().replace("-", "_")


def is_secret_param_name(name: str, location: str = "") -> bool:
    """
    Purpose:
        True when param name matches the §1.3 secret/PII denylist.
        Applied to all locations; header/cookie get extra exact names.
    Input:
        name     — parameter name as observed
        location — path | query | body | header | cookie (case-insensitive)
    Output:
        True → never index this parameter's values.
    Side effects: None.
    """
    if not name or not str(name).strip():
        return False

    loc = (location or "").strip().lower()
    raw = str(name).strip().lower()
    norm = _normalize_param_name(name)

    if norm in _SECRET_EXACT_NAMES:
        return True
    if raw in _SECRET_EXACT_NAMES:
        return True

    for token in _SECRET_SUBSTRINGS:
        if token in norm or token in raw:
            return True

    if loc in ("header", "cookie"):
        # Header names often use hyphens; check both forms.
        if raw in _SECRET_HEADER_COOKIE_EXACT or norm in _SECRET_HEADER_COOKIE_EXACT:
            return True
        # Also match exact list with original hyphen form after lower only.
        if raw.replace("_", "-") in {
            "proxy-authorization",
            "set-cookie",
            "x-api-key",
            "x-auth-token",
            "x-access-token",
            "x-amz-security-token",
            "x-csrf-token",
        }:
            return True

    return False


# ---------------------------------------------------------------------------
# Index eligibility
# ---------------------------------------------------------------------------

def is_indexable_value(
    value: str,
    param_name: str = "",
    location: str = "",
    *,
    prior_source_count: int = 0,
    semantic_type: str | None = None,
    min_value_len: int = MIN_VALUE_LEN_DEFAULT,
) -> IndexEligibility:
    """
    Purpose:
        Decide whether a request parameter value is distinctive enough to
        enter the cross-flow value_index (design §1.2).

    Input:
        value              — raw parameter value string
        param_name         — parameter name (denylist)
        location           — path|query|body|header|cookie
        prior_source_count — how many distinct source_param_uuid already
                             index this value_hash on the host (Rule D)
        semantic_type      — optional passive semantic_type (jwt/uuid soft skip)
        min_value_len      — config floor (default 6); hard rejects still apply

    Output:
        IndexEligibility with indexable flag, rule/reason tag, canary bit.

    Side effects: None.
    """
    if value is None:
        return IndexEligibility(False, "empty", entropy=0.0)

    text = str(value)
    ent = shannon_entropy(text)

    # --- Hard rejects ---
    if not text or not text.strip():
        return IndexEligibility(False, "empty", entropy=ent)

    if len(text) > MAX_INDEX_VALUE_LEN:
        return IndexEligibility(False, "too_long", entropy=ent)

    if is_secret_param_name(param_name, location):
        return IndexEligibility(False, "secret_name", entropy=ent)

    lowered = text.strip().lower()
    if lowered in _BOOLEANISH:
        return IndexEligibility(False, "booleanish", entropy=ent)

    if _SHORT_INT_RE.match(text.strip()):
        return IndexEligibility(False, "short_integer", entropy=ent)

    if len(text) >= 4 and _PURE_REPEAT_RE.match(text):
        return IndexEligibility(False, "pure_repeat", entropy=ent)

    # --- Accept rules (first match wins for reporting; any accept indexes) ---

    # A. Canary (exempt from min_value_len floor)
    if _CANARY_RE.match(text):
        return IndexEligibility(True, "A_canary", is_canary=True, entropy=ent)

    # Config floor for non-canary Rules B/C/D (operator-tunable FP control).
    floor = max(1, int(min_value_len))
    if len(text) < floor:
        return IndexEligibility(False, "too_short", entropy=ent)

    # Soft skip fixed-format secrets: only rare-on-host (Rule D) may index.
    soft_skip = (semantic_type or "").strip().lower() in _SOFT_SKIP_SEMANTIC

    # B. Length-strong: len >= 8 and H >= 2.0 (also subject to min_value_len)
    if not soft_skip and len(text) >= 8 and ent >= 2.0:
        return IndexEligibility(True, "B_length_strong", entropy=ent)

    # C. Medium operator token: 6–7 chars, H >= 2.0, not pure digits
    if (
        not soft_skip
        and 6 <= len(text) <= 7
        and ent >= 2.0
        and not _PURE_DIGIT_RE.match(text)
    ):
        return IndexEligibility(True, "C_medium_token", entropy=ent)

    # D. Rare-on-host: len already >= floor, H >= 1.5, < 2 existing source params
    # prior_source_count is existing rows for this hash; < 2 means rare.
    # Keep a hard floor of 6 for Rule D even if min_value_len is lowered.
    if len(text) >= max(6, floor) and ent >= 1.5 and prior_source_count < 2:
        return IndexEligibility(True, "D_rare_on_host", entropy=ent)

    if soft_skip:
        return IndexEligibility(False, "soft_skip_semantic", entropy=ent)

    if ent < 1.5:
        return IndexEligibility(False, "low_entropy", entropy=ent)

    return IndexEligibility(False, "not_distinctive", entropy=ent)


# ---------------------------------------------------------------------------
# Body matching
# ---------------------------------------------------------------------------

def _html_encode(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def find_value_in_body(value: str, body: str) -> BodyMatch:
    """
    Purpose:
        Detect value in body as raw / html-encoded / url-encoded, plus light
        transforms (trim / case), matching multiprobe ``_find_encoded_forms``.
    Input:
        value — full value_match string
        body  — response body text (already decoded / capped by caller)
    Output:
        BodyMatch(found, encoding, transforms).
    Side effects: None.
    """
    if not value or not body:
        return BodyMatch(False)

    if value in body:
        return BodyMatch(True, "raw", ())

    html = _html_encode(value)
    if html != value and html in body:
        return BodyMatch(True, "html_encoded", ())

    url = quote(value, safe="")
    if url and url != value and url in body:
        return BodyMatch(True, "url_encoded", ())

    stripped = value.strip()
    if stripped and stripped != value and stripped in body:
        return BodyMatch(True, "raw", ("trim",))

    lower = value.lower()
    if lower != value and lower in body:
        return BodyMatch(True, "raw", ("lowercase",))

    upper = value.upper()
    if upper != value and upper in body:
        return BodyMatch(True, "raw", ("uppercase",))

    if stripped:
        if stripped.lower() in body and stripped.lower() != stripped:
            return BodyMatch(True, "raw", ("trim", "lowercase"))
        if stripped.upper() in body and stripped.upper() != stripped:
            return BodyMatch(True, "raw", ("trim", "uppercase"))
        html_s = _html_encode(stripped)
        if html_s != stripped and html_s in body:
            return BodyMatch(True, "html_encoded", ("trim",))

    return BodyMatch(False)


def infer_sink_context(content_type: str) -> str:
    """
    Purpose:
        Map Content-Type to a coarse sink context class (P0).
    Input:
        content_type — response Content-Type header value
    Output:
        html | json | xml | javascript | other
    Side effects: None.
    """
    ct = (content_type or "").lower()
    if "html" in ct:
        return "html"
    if "json" in ct:
        return "json"
    if "xml" in ct:
        return "xml"
    if "javascript" in ct or ct.strip() in ("application/js", "text/js"):
        return "javascript"
    if ct.strip():
        return "other"
    return "other"


def is_soft_skip_value_shape(value: str) -> bool:
    """
    Purpose:
        Detect JWT/UUID-shaped values for post-match confidence haircut
        (soft-skip semantic types that only index under Rule D).
    Side effects: None.
    """
    if not value:
        return False
    text = str(value).strip()
    if _UUID_RE.match(text):
        return True
    # JWT-like: three segments, header typically base64url JSON (eyJ…).
    parts = text.split(".")
    if len(parts) == 3 and text.startswith("eyJ") and all(parts):
        return True
    return False


def match_confidence(
    *,
    is_canary: bool,
    value_len: int,
    encoding: str,
    transforms: tuple[str, ...] | list[str],
    sink_context: str,
    unrelated_sink_count: int = 1,
    soft_skip_semantic: bool = False,
) -> int:
    """
    Purpose:
        Score a cross-flow match (design §5 confidence table). Pure helper
        for later insert path; unit-tested here.
    Output:
        Integer confidence 40–95.
    Side effects: None.
    """
    ctx = (sink_context or "other").lower()
    enc = (encoding or "raw").lower()
    has_tx = bool(transforms)

    if is_canary and enc == "raw" and ctx in ("html", "javascript", "js"):
        conf = 95
    elif is_canary and enc == "raw":
        conf = 90
    elif value_len >= 12 and enc == "raw" and ctx in ("html", "javascript", "js"):
        conf = 85
    elif 6 <= value_len <= 11 and enc == "raw" and ctx in ("html", "javascript", "js"):
        conf = 80
    elif enc in ("html_encoded", "url_encoded") and not has_tx:
        conf = 75
    elif has_tx:
        conf = 65
    elif ctx == "json":
        conf = 70
    elif enc == "raw":
        conf = 75
    else:
        conf = 70

    # Soft-skip shapes (JWT/UUID) index only under rare-on-host; lower confidence.
    if soft_skip_semantic and not is_canary:
        conf = max(40, conf - 10)

    if unrelated_sink_count >= 3:
        conf = max(40, conf - 10)

    return max(40, min(95, conf))


# ---------------------------------------------------------------------------
# Operator-facing reason string
# ---------------------------------------------------------------------------

def format_cross_flow_reason(link: dict[str, Any]) -> str:
    """
    Purpose:
        Build the canonical stored-reflection reason string for XSS candidates
        and CLI/CP surfaces (Appendix B).
    Input:
        link — cross_flow_reflections row or sink dict with source/sink fields
    Output:
        e.g. ``value from username@POST /register reflected on GET /profile (html, raw)``
    Side effects: None.
    """
    name = link.get("source_param_name") or "param"
    if link.get("source_method") and link.get("source_path"):
        src = f"{name}@{link['source_method']} {link['source_path']}"
    else:
        loc = link.get("source_location") or "unknown"
        src = f"{name}@{loc}"

    method = (link.get("sink_method") or "").strip()
    path = (link.get("sink_path") or "").strip()
    sink = f"{method} {path}".strip() or "unknown"
    ctx = link.get("sink_context") or link.get("context") or "other"
    enc = link.get("encoding") or "raw"
    return f"value from {src} reflected on {sink} ({ctx}, {enc})"


# ---------------------------------------------------------------------------
# Profile merge (pure)
# ---------------------------------------------------------------------------

def _snapshot_same_request(refl: dict[str, Any]) -> dict[str, Any]:
    """Copy top-level probe reflection fields into a same_request block."""
    return {
        "state": refl.get("state") or "unknown",
        "confidence": int(refl.get("confidence") or 0),
        "uncertainty": refl.get("uncertainty") or "high",
        "evidence_flow_ids": list(refl.get("evidence_flow_ids") or [])[:20],
        "contexts": list(refl.get("contexts") or []),
        "encoding": refl.get("encoding") or "",
    }


def _uncertainty_min(a: str, b: str) -> str:
    """Return the less severe (more certain) of two uncertainty labels."""
    ra = _UNCERTAINTY_RANK.get((a or "high").lower(), 2)
    rb = _UNCERTAINTY_RANK.get((b or "high").lower(), 2)
    winner = a if ra <= rb else b
    return winner if winner in _UNCERTAINTY_RANK else "high"


def _uncertainty_at_least(label: str, floor: str) -> str:
    """Raise uncertainty to at least ``floor`` severity."""
    rl = _UNCERTAINTY_RANK.get((label or "high").lower(), 2)
    rf = _UNCERTAINTY_RANK.get((floor or "high").lower(), 2)
    if rf >= rl:
        return floor if floor in _UNCERTAINTY_RANK else "high"
    return label if label in _UNCERTAINTY_RANK else "high"


def _build_cross_flow_block(links: list[dict[str, Any]]) -> dict[str, Any]:
    if not links:
        return {
            "state": "not_reflected",
            "confidence": 0,
            "uncertainty": "high",
            "link_count": 0,
            "sinks": [],
            "evidence_flow_ids": [],
            "contexts": [],
            "encoding": "",
        }

    sinks: list[dict[str, Any]] = []
    evidence: list[str] = []
    contexts: list[str] = []
    encodings: list[str] = []
    confidences: list[int] = []

    for link in links:
        conf = int(link.get("confidence") or 70)
        confidences.append(conf)
        ctx = link.get("sink_context") or link.get("context") or "other"
        if ctx == "javascript":
            ctx = "js"
        if ctx and ctx not in contexts:
            contexts.append(ctx)
        enc = link.get("encoding") or "raw"
        if enc:
            encodings.append(enc)
        for fid in (
            link.get("source_flow_id"),
            link.get("first_source_flow_id"),
            link.get("sink_flow_id"),
        ):
            if fid and fid not in evidence:
                evidence.append(str(fid))
        reason = link.get("reason") or format_cross_flow_reason(link)
        sinks.append({
            "sink_method": link.get("sink_method") or "",
            "sink_path": link.get("sink_path") or "",
            "sink_endpoint_id": link.get("sink_endpoint_id"),
            "sink_flow_id": link.get("sink_flow_id"),
            "context": link.get("sink_context") or link.get("context") or "other",
            "encoding": enc,
            "confidence": conf,
            "detection_mode": link.get("detection_mode") or "passive",
            "reason": reason,
        })

    # Prefer highest confidence among links as cross_flow confidence.
    best = max(confidences) if confidences else 70
    encoding = ""
    if encodings:
        encoding = max(set(encodings), key=encodings.count)

    return {
        "state": "reflected",
        "confidence": best,
        "uncertainty": "low",
        "link_count": len(links),
        "sinks": sinks,
        "evidence_flow_ids": evidence[:20],
        "contexts": contexts,
        "encoding": encoding,
    }


def merge_cross_flow_reflection(
    profile: dict[str, Any],
    links: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Purpose:
        Merge cross-flow reflection links into a param profile's
        ``observed.reflection`` tree (design §3.5 / §6.1 pure rules).

        Mutates and returns ``profile``. Nested ``same_request`` is preserved
        (snapshotted from top-level when missing). Top-level ``state`` becomes
        ``reflected`` when either mode is reflected; when only cross_flow is
        reflected, top-level confidence comes from stored links only.

    Input:
        profile — IV param profile document (dict)
        links   — list of cross_flow_reflections-shaped dicts

    Output:
        The same profile dict with reflection modes merged.

    Side effects: Mutates profile in place.
    """
    observed = profile.setdefault("observed", {})
    refl = observed.setdefault("reflection", {})
    if not isinstance(refl, dict):
        refl = {}
        observed["reflection"] = refl

    # 1. Ensure same_request exists (snapshot current top-level probe fields).
    if "same_request" not in refl or not isinstance(refl.get("same_request"), dict):
        refl["same_request"] = _snapshot_same_request(refl)
    same = refl["same_request"]

    # 2. cross_flow block from links.
    cross = _build_cross_flow_block(list(links or []))
    refl["cross_flow"] = cross

    same_state = str(same.get("state") or "unknown").lower()
    cross_state = str(cross.get("state") or "unknown").lower()
    same_conf = int(same.get("confidence") or 0)
    cross_conf = int(cross.get("confidence") or 0)
    same_unc = str(same.get("uncertainty") or "high")
    cross_unc = str(cross.get("uncertainty") or "high")

    # 3. Recompute top-level per merge table.
    modes: list[str] = []
    if same_state in ("reflected", "not_reflected", "conflicting"):
        modes.append("same_request")
    if cross_state in ("reflected", "not_reflected", "conflicting"):
        modes.append("cross_flow")

    if same_state == "reflected":
        top_state = "reflected"
        top_conf = max(same_conf, cross_conf if cross_state == "reflected" else same_conf)
        top_unc = _uncertainty_min(same_unc, cross_unc if cross_state == "reflected" else same_unc)
    elif cross_state == "reflected":
        # Critical: do not dilute with multiprobe "not reflected" confidence.
        top_state = "reflected"
        top_conf = cross_conf
        if same_state == "conflicting":
            top_unc = "high"
        else:
            top_unc = _uncertainty_at_least(cross_unc, "low")
        if "same_request" not in modes and same_state in (
            "not_reflected", "unknown", "conflicting",
        ):
            # Always surface both modes when probes and links were considered.
            if same_state != "unknown" and "same_request" not in modes:
                modes.insert(0, "same_request")
            elif same_state == "unknown" and same.get("evidence_flow_ids"):
                modes.insert(0, "same_request")
        # Design table: not_reflected + reflected → modes include both.
        if same_state == "not_reflected" and "same_request" not in modes:
            modes.insert(0, "same_request")
        if same_state == "conflicting" and "same_request" not in modes:
            modes.insert(0, "same_request")
    elif same_state == "not_reflected" and cross_state == "not_reflected":
        top_state = "not_reflected"
        top_conf = max(same_conf, cross_conf)
        top_unc = _uncertainty_min(same_unc, cross_unc)
    elif same_state == "conflicting":
        top_state = "conflicting"
        top_conf = same_conf
        top_unc = "high"
    else:
        top_state = "unknown"
        top_conf = 0
        top_unc = "high"
        modes = [m for m in modes if m]  # may be empty

    # Prefer same-request encoding when both reflected; else cross_flow.
    if same_state == "reflected" and same.get("encoding"):
        top_encoding = same.get("encoding") or ""
    elif cross_state == "reflected":
        top_encoding = cross.get("encoding") or ""
    else:
        top_encoding = same.get("encoding") or cross.get("encoding") or ""

    # Union contexts (map javascript → js for consistency with synthesize).
    ctx_set: list[str] = []
    for c in list(same.get("contexts") or []) + list(cross.get("contexts") or []):
        if c == "javascript":
            c = "js"
        if c and c not in ctx_set:
            ctx_set.append(c)

    # 4. Union evidence_flow_ids (cap 20).
    evidence: list[str] = []
    for fid in list(same.get("evidence_flow_ids") or []) + list(
        cross.get("evidence_flow_ids") or []
    ):
        if fid and fid not in evidence:
            evidence.append(str(fid))
    evidence = evidence[:20]

    # 5. modes already collected; ensure cross_flow present when links considered.
    if links is not None and "cross_flow" not in modes and cross_state in (
        "reflected", "not_reflected",
    ):
        modes.append("cross_flow")

    refl["state"] = top_state
    refl["confidence"] = max(0, min(100, top_conf))
    refl["uncertainty"] = top_unc if top_unc in _UNCERTAINTY_RANK else "high"
    refl["evidence_flow_ids"] = evidence
    refl["contexts"] = ctx_set
    refl["encoding"] = top_encoding or ""
    refl["modes"] = modes

    return profile


# =========================================================================== #
# Config (hot-path safe — never ConfigurationManager.load per flow)           #
# =========================================================================== #


@dataclass(frozen=True)
class CrossFlowConfig:
    """
    Frozen knobs for cross-flow indexing/scanning.
    Defaults match BUILTIN_DEFAULTS['parameter_intel']['cross_flow'].
    """

    enabled: bool = False
    feed_iv: bool = True
    active_sink_probe: bool = False
    value_index_ttl_hours: int = 72
    value_index_max_per_host: int = 50_000
    value_index_max_sources_per_value: int = 8
    min_value_len: int = 6
    scan_hot_set_k: int = 2000
    scan_time_budget_ms: int = 20
    max_body_scan_bytes: int = 2_000_000
    canary_ttl_hours: int = 24


# Process-level cache: populated once by worker/scheduler; hot path never reloads YAML.
_process_cross_flow_cfg: CrossFlowConfig | None = None
_process_cfg_lock = threading.Lock()
_process_cfg_loaded: bool = False


def set_process_cross_flow_config(cfg: CrossFlowConfig) -> None:
    """
    Purpose:
        Install a pre-resolved CrossFlowConfig for this process (worker init,
        scheduler start, or tests). Subsequent get_process_cross_flow_config()
        returns this without YAML I/O.
    Side effects: Updates process-level module globals.
    """
    global _process_cross_flow_cfg, _process_cfg_loaded
    with _process_cfg_lock:
        _process_cross_flow_cfg = cfg
        _process_cfg_loaded = True


def get_process_cross_flow_config() -> CrossFlowConfig:
    """
    Purpose:
        Return the process-cached CrossFlowConfig, or defaults if never set.
        Does **not** call ConfigurationManager.
    Side effects: None (read of module globals).
    """
    cfg = _process_cross_flow_cfg
    if cfg is not None:
        return cfg
    return CrossFlowConfig()


def ensure_process_cross_flow_config(
    project_data_dir: Path | None = None,
    *,
    project: Any = None,
) -> CrossFlowConfig:
    """
    Purpose:
        Return process-cached config; load from layered config **once** if
        never installed (scheduler/replay path without FlowWorker).
    Side effects:
        At most one ConfigurationManager load per process.
    """
    global _process_cross_flow_cfg, _process_cfg_loaded
    if _process_cfg_loaded and _process_cross_flow_cfg is not None:
        return _process_cross_flow_cfg
    with _process_cfg_lock:
        if _process_cfg_loaded and _process_cross_flow_cfg is not None:
            return _process_cross_flow_cfg
        cfg = load_cross_flow_config_for_project(
            project_data_dir, project=project
        )
        _process_cross_flow_cfg = cfg
        _process_cfg_loaded = True
        return cfg


def reset_process_cross_flow_config() -> None:
    """
    Purpose:
        Clear process cache (tests only).
    Side effects: Resets module globals.
    """
    global _process_cross_flow_cfg, _process_cfg_loaded
    with _process_cfg_lock:
        _process_cross_flow_cfg = None
        _process_cfg_loaded = False


def cross_flow_config_from_effective(effective: Any) -> CrossFlowConfig:
    """
    Purpose:
        Map EffectiveConfig.parameter_intel.cross_flow → CrossFlowConfig.
    Input:
        effective — EffectiveConfig (or object with .parameter_intel.cross_flow
                    or .get('parameter_intel.cross_flow.*')).
    Output:
        CrossFlowConfig snapshot.
    Side effects: None.
    """
    try:
        cf = effective.parameter_intel.cross_flow
        return CrossFlowConfig(
            enabled=bool(cf.enabled),
            feed_iv=bool(cf.feed_iv),
            active_sink_probe=bool(cf.active_sink_probe),
            value_index_ttl_hours=int(cf.value_index_ttl_hours),
            value_index_max_per_host=int(cf.value_index_max_per_host),
            value_index_max_sources_per_value=int(cf.value_index_max_sources_per_value),
            min_value_len=int(cf.min_value_len),
            scan_hot_set_k=int(cf.scan_hot_set_k),
            scan_time_budget_ms=int(cf.scan_time_budget_ms),
            max_body_scan_bytes=int(cf.max_body_scan_bytes),
            canary_ttl_hours=int(cf.canary_ttl_hours),
        )
    except Exception:
        pass
    # Fallback: raw tree
    try:
        raw = getattr(effective, "raw", None) or {}
        cf_raw = ((raw.get("parameter_intel") or {}).get("cross_flow") or {})
        if isinstance(cf_raw, dict) and cf_raw:
            return CrossFlowConfig(
                enabled=bool(cf_raw.get("enabled", False)),
                feed_iv=bool(cf_raw.get("feed_iv", True)),
                active_sink_probe=bool(cf_raw.get("active_sink_probe", False)),
                value_index_ttl_hours=int(cf_raw.get("value_index_ttl_hours", 72)),
                value_index_max_per_host=int(
                    cf_raw.get("value_index_max_per_host", 50_000)
                ),
                value_index_max_sources_per_value=int(
                    cf_raw.get("value_index_max_sources_per_value", 8)
                ),
                min_value_len=int(cf_raw.get("min_value_len", 6)),
                scan_hot_set_k=int(cf_raw.get("scan_hot_set_k", 2000)),
                scan_time_budget_ms=int(cf_raw.get("scan_time_budget_ms", 20)),
                max_body_scan_bytes=int(cf_raw.get("max_body_scan_bytes", 2_000_000)),
                canary_ttl_hours=int(cf_raw.get("canary_ttl_hours", 24)),
            )
    except Exception:
        pass
    return CrossFlowConfig()


def load_cross_flow_config_for_project(
    project_data_dir: Path | None = None,
    *,
    project: Any = None,
) -> CrossFlowConfig:
    """
    Purpose:
        One-shot load of CrossFlowConfig via ConfigurationManager (session start).
        Not for the per-flow hot path.
    Input:
        project_data_dir — project data directory (contains project.yaml).
        project          — optional Project-like object (data_dir + constraints).
    Output:
        CrossFlowConfig; defaults on load failure.
    Side effects: May read YAML from disk once.
    """
    try:
        from talos.configuration.manager import ConfigurationManager
        from talos.config import TalosConfig

        mgr = ConfigurationManager(TalosConfig.from_env().data_dir)
        if project is not None:
            effective = mgr.load_for_project(project)
        elif project_data_dir is not None:
            # ConfigurationManager.load accepts project_data_dir (project.yaml
            # + legacy). load_effective_config does not — do not call it here.
            effective = mgr.load(project_data_dir=Path(project_data_dir))
        else:
            return CrossFlowConfig()
        return cross_flow_config_from_effective(effective)
    except Exception:
        logger.debug(
            "cross_flow config load failed — using defaults",
            exc_info=True,
        )
        return CrossFlowConfig()


# =========================================================================== #
# Flow field normalization (proxy vs replay dict shapes)                      #
# =========================================================================== #


def normalize_flow_fields(flow: dict[str, Any]) -> dict[str, Any]:
    """
    Purpose:
        Normalize proxy vs replay flow dict shapes into a single view.
    Input:
        flow — proxy worker dict (flow_id / request_start) or replay dict
               (id / captured_at), or mixed.
    Output:
        Normalized dict with flow_id, captured_at, role_id, bodies, etc.
    Side effects: None.
    """
    flow_meta = flow.get("flow_meta") or {}
    if isinstance(flow_meta, str):
        try:
            flow_meta = json.loads(flow_meta) if flow_meta else {}
        except (ValueError, TypeError):
            flow_meta = {}
    if not isinstance(flow_meta, dict):
        flow_meta = {}

    resp_headers = flow.get("response_headers") or {}
    if isinstance(resp_headers, str):
        try:
            resp_headers = json.loads(resp_headers) if resp_headers else {}
        except (ValueError, TypeError):
            resp_headers = {}
    if not isinstance(resp_headers, dict):
        resp_headers = {}

    req_headers = flow.get("request_headers") or {}
    if isinstance(req_headers, str):
        try:
            req_headers = json.loads(req_headers) if req_headers else {}
        except (ValueError, TypeError):
            req_headers = {}
    if not isinstance(req_headers, dict):
        req_headers = {}

    content_type = (
        flow.get("content_type")
        or _header_value(resp_headers, "content-type")
        or ""
    )

    return {
        "flow_id": flow.get("flow_id") or flow.get("id") or "",
        "captured_at": flow.get("captured_at") or flow.get("request_start") or "",
        "role_id": flow.get("role_id") or None,
        "module_id": flow.get("module_id") or None,
        "response_body": flow.get("response_body"),
        "response_headers": resp_headers,
        "request_body": flow.get("request_body"),
        "request_headers": req_headers,
        "request_cookies": flow.get("request_cookies") or {},
        "content_type": content_type,
        "endpoint_id": flow.get("endpoint_id"),
        "host": flow.get("host") or "",
        "method": flow.get("method") or "",
        "path": flow.get("path") or "",
        "query": flow.get("query") or "",
        "url": flow.get("url") or "",
        "flow_meta": flow_meta,
        "project_id": flow.get("project_id") or "",
        "source": flow.get("source") or "",
        "replay_reason": flow.get("replay_reason") or "",
        "_raw": flow,
    }


def _header_value(headers: dict, name: str) -> str:
    if not headers:
        return ""
    target = name.lower()
    for key, val in headers.items():
        if str(key).lower() == target:
            if isinstance(val, (list, tuple)):
                return str(val[0]) if val else ""
            return str(val) if val is not None else ""
    return ""


# =========================================================================== #
# Canary / multiprobe meta extraction                                         #
# =========================================================================== #


def extract_canary_from_meta(
    multiprobe_meta: dict[str, Any] | None = None,
    flow_meta: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """
    Purpose:
        Resolve multiprobe canary + param identity from flow_meta / multiprobe plan.
    Output:
        Dict with keys: canary, param_name, location, param_uuid, host, endpoint_id
        or None when no canary found.
    Side effects: None.
    """
    meta = dict(flow_meta or {})
    if multiprobe_meta:
        meta = {**meta, **multiprobe_meta}
        if "multiprobe" not in meta and multiprobe_meta.get("canary"):
            meta["multiprobe"] = multiprobe_meta

    multiprobe = meta.get("multiprobe")
    canary = ""
    if isinstance(multiprobe, dict):
        canary = str(multiprobe.get("canary") or "")
    if not canary:
        # Identifier probes may put the canary in payload directly.
        payload = meta.get("payload")
        if isinstance(payload, str) and _CANARY_RE.match(payload):
            canary = payload
        elif isinstance(payload, str) and payload.startswith("TL"):
            # Multiprobe payload: canary is left token before separator.
            try:
                from talos.input_validation.multiprobe import parse_multiprobe_payload
                plan = parse_multiprobe_payload(payload)
                if plan is not None and plan.canary:
                    canary = plan.canary
            except Exception:
                pass

    if not canary or not _CANARY_RE.match(canary):
        return None

    mutation = meta.get("mutation") if isinstance(meta.get("mutation"), dict) else {}
    location = (
        meta.get("location")
        or mutation.get("location")
        or "body"
    )
    param_name = (
        meta.get("parameter_name")
        or meta.get("param_name")
        or meta.get("name")
        or ""
    )
    param_uuid = meta.get("parameter_uuid") or meta.get("param_uuid") or ""
    host = meta.get("host") or mutation.get("host") or ""
    endpoint_id = meta.get("endpoint_id") or mutation.get("endpoint_id")

    return {
        "canary": canary,
        "param_name": str(param_name or "unknown"),
        "location": str(location or "body"),
        "param_uuid": str(param_uuid or ""),
        "host": str(host or ""),
        "endpoint_id": endpoint_id,
    }


# =========================================================================== #
# DB helpers                                                                  #
# =========================================================================== #


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _expires_at(hours: int, now: datetime | None = None) -> str:
    base = now or datetime.now(timezone.utc)
    return (base + timedelta(hours=max(1, hours))).isoformat()


def parse_iso_timestamp(value: str | None) -> datetime | None:
    """
    Purpose:
        Parse ISO-8601 timestamps from mixed writers (``Z`` vs ``+00:00``).
        Returns timezone-aware UTC datetime, or None when unparseable.
    Side effects: None.
    """
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    # fromisoformat does not accept trailing Z in older Python; normalize.
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def iso_ts_le(a: str | None, b: str | None) -> bool:
    """
    Purpose:
        True when timestamp *a* is earlier than or equal to *b*.
        Equal instants with mixed ``Z`` / ``+00:00`` compare equal.
        Unparseable pairs fall back to normalized lexical compare.
    Side effects: None.
    """
    da, db = parse_iso_timestamp(a), parse_iso_timestamp(b)
    if da is not None and db is not None:
        return da <= db
    na = (str(a or "").strip().replace("Z", "+00:00").replace("z", "+00:00"))
    nb = (str(b or "").strip().replace("Z", "+00:00").replace("z", "+00:00"))
    return na <= nb


def iso_ts_max(a: str | None, b: str | None) -> str:
    """
    Purpose:
        Return the later of two ISO timestamps (preserving the winning string).
        Falls back to non-empty preference, then *b*.
    Side effects: None.
    """
    da, db = parse_iso_timestamp(a), parse_iso_timestamp(b)
    if da is not None and db is not None:
        return str(a) if da >= db else str(b)
    if da is not None and db is None:
        return str(a)
    if db is not None and da is None:
        return str(b)
    # Lexical fallback after Z normalize.
    na = (str(a or "").strip().replace("Z", "+00:00").replace("z", "+00:00"))
    nb = (str(b or "").strip().replace("Z", "+00:00").replace("z", "+00:00"))
    if not na:
        return str(b or "")
    if not nb:
        return str(a or "")
    return str(a) if na >= nb else str(b)


def resolve_canonical_host(
    conn: sqlite3.Connection,
    endpoint_id: str | None,
    normalized: dict[str, Any] | None = None,
) -> str:
    """
    Purpose:
        Prefer endpoints.host (canonical origin). Never invent from bare hostname
        when an endpoint row exists.
    Output:
        Canonical host string, or "" when unresolved.
    """
    if endpoint_id:
        row = conn.execute(
            "SELECT host FROM endpoints WHERE id = ?",
            (endpoint_id,),
        ).fetchone()
        if row is not None:
            host = row[0] if not isinstance(row, sqlite3.Row) else row["host"]
            if host:
                return str(host)
    # Prefer skip when endpoint missing to avoid host key skew.
    return ""


def resolve_param_id(
    conn: sqlite3.Connection,
    endpoint_id: str | None,
    name: str,
    location: str,
) -> str | None:
    """Resolve parameters.id for (endpoint_id, name, location)."""
    if not endpoint_id or not name:
        return None
    row = conn.execute(
        """
        SELECT id FROM parameters
        WHERE endpoint_id = ? AND name = ? AND location = ?
        """,
        (endpoint_id, name, location),
    ).fetchone()
    if row is None:
        return None
    return str(row[0] if not isinstance(row, sqlite3.Row) else row["id"])


def _endpoint_method_path(
    conn: sqlite3.Connection,
    endpoint_id: str | None,
) -> tuple[str, str]:
    if not endpoint_id:
        return "", ""
    row = conn.execute(
        "SELECT method, normalized_path FROM endpoints WHERE id = ?",
        (endpoint_id,),
    ).fetchone()
    if row is None:
        return "", ""
    if isinstance(row, sqlite3.Row):
        return str(row["method"] or ""), str(row["normalized_path"] or "")
    return str(row[0] or ""), str(row[1] or "")


def _count_sources_for_hash(
    conn: sqlite3.Connection,
    host: str,
    vhash: str,
) -> int:
    row = conn.execute(
        """
        SELECT COUNT(DISTINCT source_param_uuid)
        FROM value_index
        WHERE host = ? AND value_hash = ?
        """,
        (host, vhash),
    ).fetchone()
    return int(row[0] if row else 0)


def _make_param_uuid(host: str, location: str, name: str) -> str:
    raw = f"{host}|{location}|{name}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def upsert_value_index(
    conn: sqlite3.Connection,
    *,
    project_id: str,
    host: str,
    value: str,
    source_flow_id: str,
    captured_at: str,
    source_param_uuid: str,
    source_param_name: str,
    source_location: str,
    source_endpoint_id: str | None = None,
    source_param_id: str | None = None,
    source_method: str = "",
    source_path: str = "",
    source_role_id: str | None = None,
    is_canary: bool = False,
    cfg: CrossFlowConfig | None = None,
) -> bool:
    """
    Purpose:
        Upsert one (host, value_hash, source_param_uuid) into value_index.
        On update: ``last_seen_at = max(old, new)``; ``source_flow_id`` is
        replaced only when the new observation is at least as recent as the
        previous ``last_seen_at`` (most-recent observing flow).
    Output:
        True when a row was inserted or updated.
    Side effects: Writes value_index.
    """
    cfg = cfg or CrossFlowConfig()
    if not value or not host or not source_param_uuid or not source_flow_id:
        return False

    vhash = value_hash(value)
    now = captured_at or _utcnow_iso()
    ttl = cfg.canary_ttl_hours if is_canary else cfg.value_index_ttl_hours
    expires = _expires_at(ttl)

    existing = conn.execute(
        """
        SELECT id, hit_count, first_source_flow_id, first_seen_at, is_canary,
               last_seen_at, source_flow_id
        FROM value_index
        WHERE host = ? AND value_hash = ? AND source_param_uuid = ?
        """,
        (host, vhash, source_param_uuid),
    ).fetchone()

    if existing is not None:
        if isinstance(existing, sqlite3.Row):
            eid = existing["id"]
            hit = existing["hit_count"]
            old_canary = existing["is_canary"]
            old_last = str(existing["last_seen_at"] or "")
            old_source_flow = str(existing["source_flow_id"] or "")
        else:
            eid = existing[0]
            hit = existing[1]
            old_canary = existing[4]
            old_last = str(existing[5] or "")
            old_source_flow = str(existing[6] or "")

        # last_seen_at never goes backwards under out-of-order / clock skew.
        new_last = iso_ts_max(old_last, now) if old_last else now
        # source_flow_id tracks the most recent observing flow only.
        if not old_last or iso_ts_le(old_last, now):
            new_source_flow = source_flow_id
        else:
            new_source_flow = old_source_flow or source_flow_id

        conn.execute(
            """
            UPDATE value_index SET
                source_flow_id = ?,
                last_seen_at = ?,
                hit_count = ?,
                is_canary = ?,
                expires_at = ?,
                source_param_id = COALESCE(?, source_param_id),
                source_endpoint_id = COALESCE(?, source_endpoint_id),
                source_role_id = COALESCE(?, source_role_id)
            WHERE id = ?
            """,
            (
                new_source_flow,
                new_last,
                int(hit or 0) + 1,
                1 if (is_canary or int(old_canary or 0)) else 0,
                expires,
                source_param_id,
                source_endpoint_id,
                source_role_id,
                eid,
            ),
        )
        return True

    # Soft gate: too many distinct sources for this value → skip NEW triples.
    source_count = _count_sources_for_hash(conn, host, vhash)
    if source_count >= cfg.value_index_max_sources_per_value:
        return False

    conn.execute(
        """
        INSERT INTO value_index (
            id, project_id, host, value_hash, value_match, value_len,
            source_flow_id, first_source_flow_id,
            source_endpoint_id, source_param_id, source_param_uuid,
            source_param_name, source_location, source_method, source_path,
            source_role_id, first_seen_at, last_seen_at, hit_count,
            is_canary, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            project_id,
            host,
            vhash,
            value,  # full value_match, never truncated
            len(value),
            source_flow_id,
            source_flow_id,
            source_endpoint_id,
            source_param_id,
            source_param_uuid,
            source_param_name,
            source_location,
            source_method or "",
            source_path or "",
            source_role_id,
            now,
            now,
            1 if is_canary else 0,
            expires,
        ),
    )
    return True


def load_hot_set(
    conn: sqlite3.Connection,
    host: str,
    *,
    k: int = 2000,
) -> list[dict[str, Any]]:
    """
    Purpose:
        Load up to K value_index rows for host, canaries first, then recent.
        Skips expired rows.
    """
    now = _utcnow_iso()
    cur = conn.execute(
        """
        SELECT *
        FROM value_index
        WHERE host = ?
          AND (expires_at IS NULL OR expires_at >= ?)
        ORDER BY is_canary DESC, last_seen_at DESC
        LIMIT ?
        """,
        (host, now, max(1, k)),
    )
    rows = cur.fetchall()
    out: list[dict[str, Any]] = []
    keys: list[str] | None = None
    if cur.description:
        keys = [d[0] for d in cur.description]
    for row in rows:
        if isinstance(row, sqlite3.Row):
            out.append(dict(row))
        elif keys is not None:
            out.append(dict(zip(keys, row)))
    return out


def insert_or_bump_cross_flow_reflection(
    conn: sqlite3.Connection,
    *,
    project_id: str,
    host: str,
    index_row: dict[str, Any],
    sink_flow_id: str,
    sink_endpoint_id: str | None,
    sink_method: str,
    sink_path: str,
    sink_content_type: str,
    sink_context: str,
    sink_role_id: str | None,
    encoding: str,
    transforms: list[str] | tuple[str, ...],
    confidence: int,
    detection_mode: str = "passive",
    sink_captured_at: str = "",
) -> bool:
    """
    Purpose:
        Insert or bump a source→sink reflection link.
        UNIQUE (source_param_uuid, sink_flow_id, value_hash, encoding).
    Output:
        True **only on INSERT** (new unique edge). UPDATE bumps
        ``observation_count`` but returns False so callers can treat
        ``parameters.cross_flow_reflection_count`` as distinct-edge count.
    """
    source_flow_id = str(index_row.get("source_flow_id") or "")
    first_source = str(
        index_row.get("first_source_flow_id") or source_flow_id
    )
    if not source_flow_id or not sink_flow_id:
        return False
    if source_flow_id == sink_flow_id or first_source == sink_flow_id:
        return False  # same-flow exclusion

    param_uuid = str(index_row.get("source_param_uuid") or "")
    vhash = str(index_row.get("value_hash") or "")
    enc = encoding or "raw"
    now = sink_captured_at or _utcnow_iso()
    tx_json = json.dumps(list(transforms or []))

    existing = conn.execute(
        """
        SELECT id, observation_count, first_seen_at, last_seen_at
        FROM cross_flow_reflections
        WHERE source_param_uuid = ?
          AND sink_flow_id = ?
          AND value_hash = ?
          AND encoding = ?
        """,
        (param_uuid, sink_flow_id, vhash, enc),
    ).fetchone()

    if existing is not None:
        if isinstance(existing, sqlite3.Row):
            eid = existing["id"]
            obs = existing["observation_count"]
            old_last = str(existing["last_seen_at"] or "")
        else:
            eid = existing[0]
            obs = existing[1]
            old_last = str(existing[3] or "")
        new_last = iso_ts_max(old_last, now) if old_last else now
        conn.execute(
            """
            UPDATE cross_flow_reflections SET
                source_flow_id = ?,
                last_seen_at = ?,
                observation_count = ?,
                confidence = MAX(confidence, ?),
                transforms = ?
            WHERE id = ?
            """,
            (
                source_flow_id,
                new_last,
                int(obs or 0) + 1,
                int(confidence),
                tx_json,
                eid,
            ),
        )
        return False  # existing edge; do not re-bump parameter count

    conn.execute(
        """
        INSERT INTO cross_flow_reflections (
            id, project_id, host,
            source_flow_id, first_source_flow_id,
            source_endpoint_id, source_param_id, source_param_uuid,
            source_param_name, source_location, source_method, source_path,
            source_role_id,
            sink_flow_id, sink_endpoint_id, sink_method, sink_path,
            sink_content_type, sink_context, sink_role_id,
            encoding, transforms,
            value_hash, value_len, match_kind, confidence, detection_mode,
            first_seen_at, last_seen_at, observation_count
        ) VALUES (
            ?, ?, ?,
            ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?,
            ?,
            ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, 1
        )
        """,
        (
            str(uuid.uuid4()),
            project_id,
            host,
            source_flow_id,
            first_source,
            index_row.get("source_endpoint_id"),
            index_row.get("source_param_id"),
            param_uuid,
            index_row.get("source_param_name") or "",
            index_row.get("source_location") or "",
            index_row.get("source_method") or "",
            index_row.get("source_path") or "",
            index_row.get("source_role_id"),
            sink_flow_id,
            sink_endpoint_id,
            sink_method or "",
            sink_path or "",
            sink_content_type or "",
            sink_context or "other",
            sink_role_id,
            enc,
            tx_json,
            vhash,
            int(index_row.get("value_len") or 0),
            "exact",
            int(confidence),
            detection_mode,
            now,
            now,
        ),
    )
    return True


def _count_distinct_sinks_for_source(
    conn: sqlite3.Connection,
    *,
    host: str,
    source_param_uuid: str,
    value_hash: str,
) -> int:
    """
    Purpose:
        Count distinct sink endpoints already linked for this source value
        (feeds unrelated_sink_count confidence haircut).
    Side effects: None (read-only).
    """
    if not host or not source_param_uuid or not value_hash:
        return 0
    row = conn.execute(
        """
        SELECT COUNT(DISTINCT sink_endpoint_id)
        FROM cross_flow_reflections
        WHERE host = ?
          AND source_param_uuid = ?
          AND value_hash = ?
          AND sink_endpoint_id IS NOT NULL
          AND sink_endpoint_id != ''
        """,
        (host, source_param_uuid, value_hash),
    ).fetchone()
    return int(row[0] if row else 0)


def bump_parameter_cross_flow_flags(
    conn: sqlite3.Connection,
    index_row: dict[str, Any],
    sink_endpoint_id: str | None,
) -> None:
    """
    Purpose:
        Set parameters.cross_flow_reflected / count / sink_endpoints on a
        **new** unique reflection edge (caller must only invoke on INSERT).
        ``cross_flow_reflection_count`` is distinct-edge count, not
        re-observation count (see link ``observation_count`` for that).
        Resolves parameters.id when source_param_id missing (canary path).
    """
    param_id = index_row.get("source_param_id")
    if not param_id:
        param_id = resolve_param_id(
            conn,
            index_row.get("source_endpoint_id"),
            str(index_row.get("source_param_name") or ""),
            str(index_row.get("source_location") or ""),
        )
    if not param_id:
        return

    row = conn.execute(
        """
        SELECT cross_flow_reflection_count, cross_flow_sink_endpoints
        FROM parameters WHERE id = ?
        """,
        (param_id,),
    ).fetchone()
    if row is None:
        return

    if isinstance(row, sqlite3.Row):
        count = int(row["cross_flow_reflection_count"] or 0)
        sinks_raw = row["cross_flow_sink_endpoints"] or "[]"
    else:
        count = int(row[0] or 0)
        sinks_raw = row[1] or "[]"

    try:
        sinks = json.loads(sinks_raw) if sinks_raw else []
    except (ValueError, TypeError):
        sinks = []
    if not isinstance(sinks, list):
        sinks = []
    if sink_endpoint_id and sink_endpoint_id not in sinks:
        sinks.append(sink_endpoint_id)
        # Cap list size for storage hygiene.
        sinks = sinks[-50:]

    conn.execute(
        """
        UPDATE parameters SET
            cross_flow_reflected = 1,
            cross_flow_reflection_count = ?,
            cross_flow_sink_endpoints = ?
        WHERE id = ?
        """,
        (count + 1, json.dumps(sinks), param_id),
    )


def prune_value_index_if_needed(
    conn: sqlite3.Connection,
    host: str,
    *,
    max_per_host: int = 50_000,
) -> int:
    """
    Purpose:
        Prune value_index for host when over cap.
        Order: expired → non-canary oldest last_seen_at. Never prune unexpired canaries.
    Output:
        Number of rows deleted.
    """
    row = conn.execute(
        "SELECT COUNT(*) FROM value_index WHERE host = ?",
        (host,),
    ).fetchone()
    count = int(row[0] if row else 0)
    if count <= max_per_host:
        return 0

    excess = count - max_per_host
    now = _utcnow_iso()
    deleted = 0

    # 1. Expired rows first.
    cur = conn.execute(
        """
        DELETE FROM value_index
        WHERE id IN (
            SELECT id FROM value_index
            WHERE host = ? AND expires_at IS NOT NULL AND expires_at < ?
            ORDER BY expires_at ASC
            LIMIT ?
        )
        """,
        (host, now, excess),
    )
    deleted += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
    remaining = excess - deleted
    if remaining <= 0:
        return deleted

    # 2. Non-canary, oldest last_seen_at.
    cur = conn.execute(
        """
        DELETE FROM value_index
        WHERE id IN (
            SELECT id FROM value_index
            WHERE host = ? AND is_canary = 0
            ORDER BY last_seen_at ASC
            LIMIT ?
        )
        """,
        (host, remaining),
    )
    deleted += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
    return deleted


def list_cross_flow_reflections(
    db_path: Path,
    *,
    param_uuid: str | None = None,
    host: str | None = None,
    source_endpoint_id: str | None = None,
    sink_endpoint_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """
    Purpose:
        List cross_flow_reflections rows (read-only). No full secret values.
    """
    if not db_path.exists():
        return []
    clauses: list[str] = []
    args: list[Any] = []
    if param_uuid:
        clauses.append("source_param_uuid = ?")
        args.append(param_uuid)
    if host:
        clauses.append("host = ?")
        args.append(host)
    if source_endpoint_id:
        clauses.append("source_endpoint_id = ?")
        args.append(source_endpoint_id)
    if sink_endpoint_id:
        clauses.append("sink_endpoint_id = ?")
        args.append(sink_endpoint_id)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    args.append(max(1, min(int(limit), 10_000)))

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"""
            SELECT * FROM cross_flow_reflections
            {where}
            ORDER BY last_seen_at DESC
            LIMIT ?
            """,
            args,
        ).fetchall()
    return [dict(r) for r in rows]


def batch_list_cross_flow_reflections(
    db_path: Path,
    param_uuids: list[str],
    *,
    limit_per_param: int = 50,
) -> dict[str, list[dict[str, Any]]]:
    """
    Purpose:
        Batch-load links for many param_uuids (avoids N+1 in list_candidates).
    Output:
        Mapping param_uuid → list of link dicts (capped per param).
    """
    result: dict[str, list[dict[str, Any]]] = {u: [] for u in param_uuids if u}
    if not result or not db_path.exists():
        return result

    uuids = list(result.keys())
    # Chunk IN clauses for SQLite variable limits.
    chunk_size = 400
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        for i in range(0, len(uuids), chunk_size):
            chunk = uuids[i : i + chunk_size]
            placeholders = ",".join("?" * len(chunk))
            rows = conn.execute(
                f"""
                SELECT * FROM cross_flow_reflections
                WHERE source_param_uuid IN ({placeholders})
                ORDER BY last_seen_at DESC
                """,
                chunk,
            ).fetchall()
            for row in rows:
                d = dict(row)
                key = d.get("source_param_uuid") or ""
                if key not in result:
                    continue
                if len(result[key]) >= limit_per_param:
                    continue
                result[key].append(d)
    return result


# =========================================================================== #
# Body decode / scan filters                                                  #
# =========================================================================== #

_BINARY_CT_PREFIXES = (
    "image/",
    "audio/",
    "video/",
    "font/",
    "application/octet-stream",
    "application/pdf",
    "application/zip",
    "application/gzip",
    "application/x-gzip",
    "application/x-tar",
    "application/x-protobuf",
    "application/grpc",
)


def _is_binary_content_type(content_type: str) -> bool:
    ct = (content_type or "").lower().split(";")[0].strip()
    if not ct:
        return False
    for prefix in _BINARY_CT_PREFIXES:
        if ct.startswith(prefix) or ct == prefix:
            return True
    return False


def _decode_body_limited(
    body: Any,
    max_bytes: int,
) -> str:
    if body is None:
        return ""
    if isinstance(body, str):
        return body[:max_bytes]
    if isinstance(body, (bytes, bytearray, memoryview)):
        raw = bytes(body[:max_bytes])
        return raw.decode("utf-8", errors="replace")
    return str(body)[:max_bytes]


def should_scan_body(
    normalized: dict[str, Any],
    cfg: CrossFlowConfig,
) -> bool:
    """
    Purpose:
        Decide whether to run sink scan on this response.
        Skips empty / binary CT. Large bodies still scanned when TL canary prefix
        appears in the first 64 KiB.
    """
    body = normalized.get("response_body")
    if body is None:
        return False
    if isinstance(body, (bytes, bytearray)) and len(body) == 0:
        return False
    if isinstance(body, str) and not body:
        return False

    ct = str(normalized.get("content_type") or "")
    if _is_binary_content_type(ct):
        # Still scan if canary marker likely present.
        prefix = _decode_body_limited(body, 65_536)
        if "TL" not in prefix:
            return False
    return True


# =========================================================================== #
# Unified ingest: on_flow_committed                                           #
# =========================================================================== #


def on_flow_committed(
    conn: sqlite3.Connection,
    *,
    db_path: Path | None = None,  # noqa: ARG001 — reserved for future cache keys
    flow: dict[str, Any],
    endpoint_id: str | None,
    params: list[Any] | None = None,
    multiprobe_meta: dict[str, Any] | None = None,
    cfg: CrossFlowConfig | None = None,
) -> None:
    """
    Purpose:
        Index distinctive request values and sink-scan the response body for
        previously indexed values. Non-fatal by contract: callers wrap in
        try/except and never roll back the flow.

    Input:
        conn            — open SQLite connection (caller commits).
        flow            — proxy or replay flow dict.
        endpoint_id     — resolved endpoint id (preferred host key).
        params          — optional list of ExtractedParam (or duck-typed).
        multiprobe_meta — optional multiprobe plan / IV meta overlay.
        cfg             — pre-resolved CrossFlowConfig; never load YAML here.

    Side effects:
        Writes value_index / cross_flow_reflections / parameters.cross_flow_*.
    """
    # Prefer injected cfg; fall back to process cache / defaults — never YAML.
    resolved = cfg if cfg is not None else get_process_cross_flow_config()
    if not resolved.enabled:
        return

    n = normalize_flow_fields(flow)
    flow_id = str(n.get("flow_id") or "")
    captured_at = str(n.get("captured_at") or "")
    if not flow_id or not captured_at:
        return

    ep_id = endpoint_id or n.get("endpoint_id")
    host = resolve_canonical_host(conn, ep_id, n)
    if not host:
        return

    project_id = str(n.get("project_id") or "")
    role_id = n.get("role_id")
    ep_method, ep_path = _endpoint_method_path(conn, ep_id)
    source_method = ep_method or str(n.get("method") or "")
    source_path = ep_path or str(n.get("path") or "")

    # Ensure row_factory for hot-set dict conversion if not set.
    # (Do not force globally — load_hot_set handles both.)

    # --- A. Index sources ---
    sources: list[dict[str, Any]] = []

    if params:
        for p in params:
            name = getattr(p, "name", None) or (p.get("name") if isinstance(p, dict) else None)
            location = getattr(p, "location", None) or (
                p.get("location") if isinstance(p, dict) else None
            )
            value = getattr(p, "sample_value", None)
            if value is None and isinstance(p, dict):
                value = p.get("sample_value") or p.get("value")
            semantic = getattr(p, "semantic_type", None)
            if semantic is None and isinstance(p, dict):
                semantic = p.get("semantic_type")
            if not name or value is None:
                continue
            sources.append({
                "name": str(name),
                "location": str(location or "query"),
                "value": str(value),
                "semantic_type": semantic,
                "param_id": resolve_param_id(conn, ep_id, str(name), str(location or "query")),
                "param_uuid": _make_param_uuid(host, str(location or "query"), str(name)),
            })

    canary_info = extract_canary_from_meta(
        multiprobe_meta,
        n.get("flow_meta") if isinstance(n.get("flow_meta"), dict) else None,
    )
    if canary_info:
        cname = canary_info["param_name"]
        cloc = canary_info["location"]
        cuuid = canary_info.get("param_uuid") or _make_param_uuid(host, cloc, cname)
        c_param_id = resolve_param_id(conn, ep_id, cname, cloc)
        # Avoid double-indexing if already in sources with same value.
        already = any(
            s["value"] == canary_info["canary"] and s.get("param_uuid") == cuuid
            for s in sources
        )
        if not already:
            sources.append({
                "name": cname,
                "location": cloc,
                "value": canary_info["canary"],
                "semantic_type": None,
                "param_id": c_param_id,
                "param_uuid": cuuid,
                "is_canary": True,
            })

    for s in sources:
        value = s["value"]
        vhash = value_hash(value)
        prior = _count_sources_for_hash(conn, host, vhash)
        # For existing triple, prior includes this param — Rule D uses prior
        # for *new* eligibility; is_indexable_value handles it.
        eligibility = is_indexable_value(
            value,
            s["name"],
            s["location"],
            prior_source_count=prior,
            semantic_type=s.get("semantic_type"),
            min_value_len=resolved.min_value_len,
        )
        # Force canary accept when meta says so.
        is_canary = bool(s.get("is_canary") or eligibility.is_canary)
        if not eligibility.indexable and not is_canary:
            continue
        if is_canary and not eligibility.indexable:
            # Canary hard-accept even if denylist somehow tripped (shouldn't).
            if is_secret_param_name(s["name"], s["location"]):
                continue

        upsert_value_index(
            conn,
            project_id=project_id,
            host=host,
            value=value,
            source_flow_id=flow_id,
            captured_at=captured_at,
            source_param_uuid=s["param_uuid"],
            source_param_name=s["name"],
            source_location=s["location"],
            source_endpoint_id=str(ep_id) if ep_id else None,
            source_param_id=s.get("param_id"),
            source_method=source_method,
            source_path=source_path,
            source_role_id=str(role_id) if role_id else None,
            is_canary=is_canary,
            cfg=resolved,
        )

    # --- B. Sink scan ---
    if not should_scan_body(n, resolved):
        prune_value_index_if_needed(
            conn, host, max_per_host=resolved.value_index_max_per_host
        )
        return

    body_text = _decode_body_limited(
        n.get("response_body"),
        resolved.max_body_scan_bytes,
    )
    if not body_text:
        prune_value_index_if_needed(
            conn, host, max_per_host=resolved.value_index_max_per_host
        )
        return

    sink_context = infer_sink_context(str(n.get("content_type") or ""))
    sink_method = source_method  # sink is this flow's endpoint
    sink_path = source_path
    sink_ct = str(n.get("content_type") or "")

    hot = load_hot_set(conn, host, k=resolved.scan_hot_set_k)
    deadline = time.monotonic() + (resolved.scan_time_budget_ms / 1000.0)

    for row in hot:
        if time.monotonic() > deadline:
            logger.debug(
                "cross_flow scan aborted on budget — host=%s flow_id=%s",
                host,
                flow_id,
            )
            break

        row_first = str(row.get("first_source_flow_id") or "")
        row_source = str(row.get("source_flow_id") or "")
        if row_first == flow_id or row_source == flow_id:
            continue  # same-flow exclusion

        first_seen = str(row.get("first_seen_at") or "")
        # Source must predate or equal sink (parsed compare: Z vs +00:00 safe).
        if first_seen and not iso_ts_le(first_seen, captured_at):
            continue

        match_val = str(row.get("value_match") or "")
        if not match_val:
            continue

        found = find_value_in_body(match_val, body_text)
        if not found.found:
            continue

        row_param_uuid = str(row.get("source_param_uuid") or "")
        row_vhash = str(row.get("value_hash") or value_hash(match_val))
        existing_sinks = _count_distinct_sinks_for_source(
            conn,
            host=host,
            source_param_uuid=row_param_uuid,
            value_hash=row_vhash,
        )
        # Include the current sink when not already counted.
        sink_ep = str(ep_id) if ep_id else ""
        if sink_ep:
            # Cheap membership check via recount after hypothetical insert is
            # avoided; approximate with existing + 1 when this ep is new.
            already = conn.execute(
                """
                SELECT 1 FROM cross_flow_reflections
                WHERE host = ? AND source_param_uuid = ? AND value_hash = ?
                  AND sink_endpoint_id = ?
                LIMIT 1
                """,
                (host, row_param_uuid, row_vhash, sink_ep),
            ).fetchone()
            sink_count = existing_sinks if already else existing_sinks + 1
        else:
            sink_count = max(1, existing_sinks)

        conf = match_confidence(
            is_canary=bool(int(row.get("is_canary") or 0)),
            value_len=int(row.get("value_len") or len(match_val)),
            encoding=found.encoding,
            transforms=found.transforms,
            sink_context=sink_context,
            unrelated_sink_count=max(1, sink_count),
            soft_skip_semantic=is_soft_skip_value_shape(match_val),
        )
        is_new_edge = insert_or_bump_cross_flow_reflection(
            conn,
            project_id=project_id,
            host=host,
            index_row=row,
            sink_flow_id=flow_id,
            sink_endpoint_id=str(ep_id) if ep_id else None,
            sink_method=sink_method,
            sink_path=sink_path,
            sink_content_type=sink_ct,
            sink_context=sink_context,
            sink_role_id=str(role_id) if role_id else None,
            encoding=found.encoding or "raw",
            transforms=found.transforms,
            confidence=conf,
            detection_mode="passive",
            sink_captured_at=captured_at,
        )
        if is_new_edge:
            bump_parameter_cross_flow_flags(
                conn, row, str(ep_id) if ep_id else None
            )

    prune_value_index_if_needed(
        conn, host, max_per_host=resolved.value_index_max_per_host
    )


def redact_value_for_display(
    value_match: str | None,
    value_len: int = 0,
    *,
    include_values: bool = False,
) -> str:
    """
    Purpose:
        Operator-safe display of indexed values (CLI / CP).
        Full value only when include_values=True.
    """
    if include_values and value_match:
        return value_match
    if not value_match:
        return f"(len={value_len})"
    prefix = value_match[:4]
    length = value_len or len(value_match)
    return f"{prefix}… (len={length})"
