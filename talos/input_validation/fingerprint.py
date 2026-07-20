"""
Module: talos.input_validation.fingerprint

Purpose:
    Response fingerprint engine for Input Validation (Module 1 — Evidence
    Foundations).  Turns a flow dict (or synthetic response fields) into a
    stable ResponseFingerprint so later IV stages can compare probes, classify
    validation outcomes, and attach evidence without re-parsing raw bodies.

    Pure computation only: no DB, no HTTP, no scheduler side effects.

What is fingerprinted
    - HTTP status
    - Content-Type class (not the full media type string)
    - Body length (raw decoded character length)
    - Normalized body hash (volatile tokens stripped best-effort)
    - Selected response-header hash
    - JSON schema sketch (keys + types, depth-limited)
    - Redirect Location summary when present
    - Error signature (status ≥ 400 and/or common error JSON keys)
    - Timing sample: duration_ms when available (raw; mean/stddev later)

Limitations (documented for consumers)
    - SPA / client-rendered HTML often has high body noise; body_hash may
      still change when the server only swaps bootstrap tokens.
    - A/B and CDN headers (cf-ray, x-amz-*, server) are excluded from the
      header hash, but unknown experiment headers may still pollute it.
    - Body normalization is best-effort regex stripping (dates, UUIDs,
      long hex tokens, common CSRF/request-id field names). It will not
      catch every application-specific nonce.
    - Fingerprints are characterization signals, not cryptographic proofs.
    - duration_ms is optional; missing timing is not an error.

Dependencies: dataclasses, hashlib, json, re (stdlib only)
Data flow:
    flow dict (from flows table / probe export) → fingerprint_from_flow()
        → ResponseFingerprint
    baseline + probe fingerprints → compare_fingerprints() → delta dict
    (outcomes.classify_outcome consumes fingerprints + deltas)

Side effects: None.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Max depth for JSON schema sketch (keys + types tree).
_JSON_SCHEMA_MAX_DEPTH = 4

# Max keys recorded per object level (keeps fingerprints small).
_JSON_SCHEMA_MAX_KEYS = 40

# Response headers included in header_hash (lower-case). Order is fixed.
_FINGERPRINT_HEADER_NAMES: tuple[str, ...] = (
    "content-type",
    "location",
    "content-disposition",
    "www-authenticate",
    "x-content-type-options",
    "content-security-policy",
    "x-frame-options",
    "cache-control",
)

# Headers deliberately ignored as volatile / CDN / experiment noise.
_VOLATILE_HEADER_NAMES: frozenset[str] = frozenset({
    "date",
    "expires",
    "last-modified",
    "etag",
    "age",
    "set-cookie",
    "cf-ray",
    "cf-cache-status",
    "x-request-id",
    "x-correlation-id",
    "x-amzn-requestid",
    "x-amz-cf-id",
    "x-amz-request-id",
    "server-timing",
    "report-to",
    "nel",
})

# JSON object keys whose string values are replaced before body hashing.
_VOLATILE_JSON_KEY_RE = re.compile(
    r"^(csrf|xsrf|token|nonce|request[_-]?id|correlation[_-]?id|"
    r"trace[_-]?id|session[_-]?id|timestamp|created[_-]?at|updated[_-]?at|"
    r"expires[_-]?at|iat|exp|jti|rid|sid)$",
    re.IGNORECASE,
)

# Body volatility patterns (applied after optional JSON re-serialize).
_RE_ISO_DATETIME = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)
_RE_DATE_ONLY = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_RE_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_RE_LONG_HEX = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_RE_UNIX_TS_MS = re.compile(r"\b1[6-9]\d{11}\b")  # ms epoch ~2010–2033
_RE_UNIX_TS_S = re.compile(r"\b1[6-9]\d{8}\b")    # s epoch ~2010–2033

# Common error object keys used for error_signature heuristics.
_ERROR_JSON_KEYS: frozenset[str] = frozenset({
    "error",
    "errors",
    "message",
    "detail",
    "details",
    "code",
    "error_code",
    "errorCode",
    "status",
    "title",
    "type",
    "exception",
    "fault",
})


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ResponseFingerprint:
    """
    Purpose:
        Immutable, comparable summary of one HTTP response for IV evidence.

    Fields:
        status_code     — response status, or None if missing.
        content_type    — coarse class: empty|json|html|xml|text|binary|other.
        body_length     — character length of decoded body (before hash norm).
        body_hash       — sha256 hex of normalized body (16 chars truncated).
        header_hash     — sha256 hex of selected headers (16 chars truncated).
        json_schema     — depth-limited keys+types sketch, or None if not JSON.
        redirect        — normalized Location summary, or None.
        error_signature — short error class label, or None when not an error.
        duration_ms     — single timing sample in milliseconds, or None.
        extras          — optional non-hashed metadata (extensible; not in eq
                          for identity — stored for later synthesizers).

    Side effects: None (dataclass only).
    """

    status_code: int | None
    content_type: str
    body_length: int
    body_hash: str
    header_hash: str
    json_schema: dict | None
    redirect: str | None
    error_signature: str | None
    duration_ms: float | None
    extras: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Purpose: Serialize for profile storage / JSON export.
        Output: plain dict suitable for json.dumps.
        Side effects: None.
        """
        return asdict(self)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fingerprint_from_flow(flow: dict) -> ResponseFingerprint:
    """
    Purpose:
        Build a ResponseFingerprint from a flow-like dict (flows table row,
        probe export record, or synthetic test fixture).

    Input:
        flow — mapping that may include any of:
            status_code, content_type, response_body / body,
            response_headers (JSON str or dict),
            duration_ms, captured_at, response_end,
            redirect / location (optional overrides).

    Output:
        ResponseFingerprint (always; missing fields become None / empty).

    Side effects: None.
    """
    status = _coerce_status(flow.get("status_code"))
    raw_ct = flow.get("content_type") or ""
    if not raw_ct:
        # Fall back to response header when content_type column is empty.
        headers_probe = _parse_headers(flow.get("response_headers"))
        raw_ct = _header_get(headers_probe, "content-type") or ""

    body_text = _extract_body_text(flow)
    headers = _parse_headers(flow.get("response_headers"))
    ct_class = classify_content_type(raw_ct)

    normalized_body = normalize_body_for_hash(body_text, ct_class)
    body_hash = _short_hash(normalized_body)
    header_hash = _short_hash(_canonical_header_blob(headers))

    json_schema = None
    if ct_class == "json" or _looks_like_json(body_text):
        json_schema = sketch_json_schema(body_text)

    redirect = _redirect_summary(status, headers, flow)
    error_sig = _error_signature(status, body_text, ct_class, json_schema)
    duration_ms = _extract_duration_ms(flow)

    extras: dict[str, Any] = {}
    if raw_ct:
        extras["raw_content_type"] = str(raw_ct).split(";")[0].strip().lower()
    flow_id = flow.get("id") or flow.get("flow_id")
    if flow_id:
        extras["flow_id"] = str(flow_id)

    return ResponseFingerprint(
        status_code=status,
        content_type=ct_class,
        body_length=len(body_text),
        body_hash=body_hash,
        header_hash=header_hash,
        json_schema=json_schema,
        redirect=redirect,
        error_signature=error_sig,
        duration_ms=duration_ms,
        extras=extras,
    )


def compare_fingerprints(
    a: ResponseFingerprint,
    b: ResponseFingerprint,
) -> dict[str, Any]:
    """
    Purpose:
        Differential summary between a baseline fingerprint and a probe
        fingerprint.  Empty ``changed`` list means fingerprints match on
        all compared fields (timing excluded from equality signal).

    Input:
        a — baseline ResponseFingerprint.
        b — probe ResponseFingerprint.

    Output:
        dict:
            identical (bool) — True when no structural/status/body/header delta.
            changed (list[str]) — field names that differ.
            status (dict|None) — {from, to} when status differs.
            content_type (dict|None)
            body_length (dict|None) — {from, to, delta}
            body_hash_changed (bool)
            header_hash_changed (bool)
            json_schema_changed (bool)
            redirect (dict|None)
            error_signature (dict|None)
            duration_ms (dict|None) — informational only; does not set identical.

    Side effects: None.
    """
    changed: list[str] = []

    status_delta = None
    if a.status_code != b.status_code:
        changed.append("status_code")
        status_delta = {"from": a.status_code, "to": b.status_code}

    ct_delta = None
    if a.content_type != b.content_type:
        changed.append("content_type")
        ct_delta = {"from": a.content_type, "to": b.content_type}

    length_delta = None
    if a.body_length != b.body_length:
        changed.append("body_length")
        length_delta = {
            "from": a.body_length,
            "to": b.body_length,
            "delta": b.body_length - a.body_length,
        }

    body_hash_changed = a.body_hash != b.body_hash
    if body_hash_changed:
        changed.append("body_hash")

    header_hash_changed = a.header_hash != b.header_hash
    if header_hash_changed:
        changed.append("header_hash")

    json_changed = a.json_schema != b.json_schema
    if json_changed:
        changed.append("json_schema")

    redirect_delta = None
    if a.redirect != b.redirect:
        changed.append("redirect")
        redirect_delta = {"from": a.redirect, "to": b.redirect}

    error_delta = None
    if a.error_signature != b.error_signature:
        changed.append("error_signature")
        error_delta = {"from": a.error_signature, "to": b.error_signature}

    duration_delta = None
    if a.duration_ms != b.duration_ms:
        duration_delta = {"from": a.duration_ms, "to": b.duration_ms}

    return {
        "identical": len(changed) == 0,
        "changed": changed,
        "status": status_delta,
        "content_type": ct_delta,
        "body_length": length_delta,
        "body_hash_changed": body_hash_changed,
        "header_hash_changed": header_hash_changed,
        "json_schema_changed": json_changed,
        "redirect": redirect_delta,
        "error_signature": error_delta,
        "duration_ms": duration_delta,
    }


def classify_content_type(content_type: str | None) -> str:
    """
    Purpose:
        Map a Content-Type header value to a stable coarse class used in
        fingerprints and outcome reasoning.

    Input: raw Content-Type string (may include parameters).
    Output: empty | json | html | xml | text | binary | other
    Side effects: None.
    """
    if not content_type or not str(content_type).strip():
        return "empty"
    ct = str(content_type).split(";")[0].strip().lower()
    if not ct:
        return "empty"
    if "json" in ct or ct.endswith("+json"):
        return "json"
    if "html" in ct:
        return "html"
    if "xml" in ct or ct.endswith("+xml"):
        return "xml"
    if ct.startswith("text/"):
        return "text"
    if (
        ct.startswith("image/")
        or ct.startswith("audio/")
        or ct.startswith("video/")
        or ct in ("application/octet-stream", "application/pdf", "application/zip")
    ):
        return "binary"
    return "other"


def normalize_body_for_hash(body: str, content_type_class: str = "") -> str:
    """
    Purpose:
        Best-effort strip of volatile tokens so identical application state
        yields a stable body_hash across requests.

    Input:
        body — decoded response body text.
        content_type_class — optional class from classify_content_type.

    Output: normalized string (may be empty).
    Side effects: None.
    """
    if not body:
        return ""

    text = body
    if content_type_class == "json" or _looks_like_json(body):
        scrubbed = _scrub_json_volatile_values(body)
        if scrubbed is not None:
            text = scrubbed

    text = _RE_ISO_DATETIME.sub("<TS>", text)
    text = _RE_UUID.sub("<UUID>", text)
    text = _RE_LONG_HEX.sub("<HEX>", text)
    text = _RE_UNIX_TS_MS.sub("<TS>", text)
    text = _RE_UNIX_TS_S.sub("<TS>", text)
    # Date-only after ISO so we do not double-replace fragments oddly.
    text = _RE_DATE_ONLY.sub("<DATE>", text)
    # Collapse runs of whitespace that often come from pretty-print noise.
    text = re.sub(r"[ \t]+", " ", text)
    return text


def sketch_json_schema(body: str, max_depth: int = _JSON_SCHEMA_MAX_DEPTH) -> dict | None:
    """
    Purpose:
        Build a depth-limited keys+types tree for a JSON body.

    Input:
        body — response body expected to be JSON.
        max_depth — maximum nesting depth (default 4).

    Output:
        dict sketch, or None when body is not parseable JSON.

    Side effects: None.
    """
    try:
        data = json.loads(body)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return _schema_node(data, depth=0, max_depth=max_depth)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _short_hash(material: str) -> str:
    """
    Purpose: Stable truncated sha256 for fingerprint fields.
    Output: 16-char lowercase hex (enough for IV evidence uniqueness).
    Side effects: None.
    """
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:16]


def _coerce_status(value: object) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_body_text(flow: dict) -> str:
    """
    Purpose:
        Prefer decoded `body` (IV probe export) then `response_body` / text aliases.
    Output: unicode string (lossy replace for bytes); empty when absent.
    Side effects: None.
    """
    if "body" in flow and flow["body"] is not None:
        return _to_text(flow["body"])
    for key in ("response_body", "response_body_text"):
        if key in flow and flow[key] is not None:
            return _to_text(flow[key])
    return ""


def _to_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    return str(value)


def _parse_headers(raw: object) -> dict[str, str]:
    """
    Purpose: Normalize response_headers JSON string or dict to str→str map.
    Side effects: None.
    """
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(k): _header_value_to_str(v) for k, v in raw.items()}
    if isinstance(raw, str):
        if not raw.strip():
            return {}
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
        if isinstance(parsed, dict):
            return {str(k): _header_value_to_str(v) for k, v in parsed.items()}
    return {}


def _header_value_to_str(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value) if value is not None else ""


def _header_get(headers: dict[str, str], name: str) -> str | None:
    target = name.lower()
    for key, val in headers.items():
        if key.lower() == target:
            return val
    return None


def _canonical_header_blob(headers: dict[str, str]) -> str:
    """
    Purpose:
        Canonical string of selected non-volatile headers for hashing.
        Only known fingerprint headers are included; order is fixed.
    Side effects: None.
    """
    parts: list[str] = []
    lower_map = {k.lower(): v for k, v in headers.items()}
    for name in _FINGERPRINT_HEADER_NAMES:
        if name in _VOLATILE_HEADER_NAMES:
            continue
        if name not in lower_map:
            continue
        value = lower_map[name].strip()
        if name == "location":
            value = _normalize_location(value) or value
        if name == "content-type":
            value = value.split(";")[0].strip().lower()
        parts.append(f"{name}:{value}")
    return "\n".join(parts)


def _normalize_location(location: str) -> str | None:
    """
    Purpose:
        Summarize a Location header: scheme+host+path, drop volatile query
        tokens when possible. Absolute and relative URLs supported.
    Side effects: None.
    """
    if not location or not location.strip():
        return None
    loc = location.strip()
    try:
        parsed = urlparse(loc)
    except ValueError:
        return loc[:200]
    path = parsed.path or "/"
    # Keep path only for relative; include netloc for absolute.
    if parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}{path}"
    return path


def _redirect_summary(
    status: int | None,
    headers: dict[str, str],
    flow: dict,
) -> str | None:
    location = flow.get("redirect") or flow.get("location")
    if location:
        return _normalize_location(str(location))
    loc_header = _header_get(headers, "location")
    if loc_header:
        return _normalize_location(loc_header)
    if status is not None and 300 <= status < 400:
        return f"status_only:{status}"
    return None


def _looks_like_json(body: str) -> bool:
    s = body.lstrip()
    return bool(s) and s[0] in "{["


def _scrub_json_volatile_values(body: str) -> str | None:
    """
    Purpose:
        Parse JSON, replace volatile field values with placeholders, re-dump
        with sorted keys for stable hashing.
    Output: canonical JSON string, or None on parse failure.
    Side effects: None.
    """
    try:
        data = json.loads(body)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    scrubbed = _scrub_json_node(data, parent_key=None)
    try:
        return json.dumps(scrubbed, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return None


def _scrub_json_node(node: Any, parent_key: str | None) -> Any:
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, val in node.items():
            k = str(key)
            if isinstance(val, str) and _VOLATILE_JSON_KEY_RE.match(k):
                out[k] = "<VOLATILE>"
            else:
                out[k] = _scrub_json_node(val, parent_key=k)
        return out
    if isinstance(node, list):
        # Cap list contribution to keep hash work bounded.
        return [_scrub_json_node(item, parent_key=parent_key) for item in node[:50]]
    return node


def _schema_node(node: Any, depth: int, max_depth: int) -> dict[str, Any]:
    if depth >= max_depth:
        return {"type": _json_type_name(node), "truncated": True}

    tname = _json_type_name(node)
    if tname == "object":
        assert isinstance(node, dict)
        keys = sorted(str(k) for k in node.keys())
        truncated = len(keys) > _JSON_SCHEMA_MAX_KEYS
        keys = keys[:_JSON_SCHEMA_MAX_KEYS]
        # Map sorted string keys back to original dict keys (may be non-str).
        props: dict[str, Any] = {}
        for k in keys:
            raw_key: Any = k
            for candidate in node:
                if str(candidate) == k:
                    raw_key = candidate
                    break
            props[k] = _schema_node(node[raw_key], depth + 1, max_depth)
        result: dict[str, Any] = {"type": "object", "keys": keys, "props": props}
        if truncated:
            result["keys_truncated"] = True
        return result
    if tname == "array":
        assert isinstance(node, list)
        if not node:
            return {"type": "array", "length": 0, "item": None}
        # Union of first few item types for stability without full content.
        sample = node[:5]
        item_schemas = [_schema_node(item, depth + 1, max_depth) for item in sample]
        # Collapse identical item schemas.
        unique = []
        for sch in item_schemas:
            if sch not in unique:
                unique.append(sch)
        return {
            "type": "array",
            "length_bucket": _length_bucket(len(node)),
            "item": unique[0] if len(unique) == 1 else {"anyOf": unique},
        }
    return {"type": tname}


def _json_type_name(node: Any) -> str:
    if node is None:
        return "null"
    if isinstance(node, bool):
        return "boolean"
    if isinstance(node, int) and not isinstance(node, bool):
        return "integer"
    if isinstance(node, float):
        return "number"
    if isinstance(node, str):
        return "string"
    if isinstance(node, list):
        return "array"
    if isinstance(node, dict):
        return "object"
    return "unknown"


def _length_bucket(n: int) -> str:
    if n == 0:
        return "0"
    if n == 1:
        return "1"
    if n < 10:
        return "2-9"
    if n < 100:
        return "10-99"
    return "100+"


def _error_signature(
    status: int | None,
    body: str,
    ct_class: str,
    json_schema: dict | None,
) -> str | None:
    """
    Purpose:
        Heuristic error class for the response.  None when the response does
        not look like an error (2xx/3xx without error-shaped JSON).
    Side effects: None.
    """
    parts: list[str] = []
    if status is not None and status >= 400:
        parts.append(f"status:{status}")
    elif status is not None and 300 <= status < 400:
        # Redirects are not errors for fingerprint error_signature.
        pass

    error_keys: list[str] = []
    if json_schema and json_schema.get("type") == "object":
        keys = json_schema.get("keys") or []
        error_keys = sorted(k for k in keys if k.lower() in {e.lower() for e in _ERROR_JSON_KEYS} or k in _ERROR_JSON_KEYS)
    elif ct_class == "json" or _looks_like_json(body):
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                error_keys = sorted(
                    str(k) for k in data
                    if str(k).lower() in {e.lower() for e in _ERROR_JSON_KEYS}
                    or str(k) in _ERROR_JSON_KEYS
                )
        except (TypeError, ValueError, json.JSONDecodeError):
            pass

    if error_keys:
        parts.append("keys:" + ",".join(error_keys[:6]))

    # HTML error page hint
    if status is not None and status >= 400 and ct_class == "html":
        lower = body[:2000].lower()
        if "not found" in lower or "404" in lower:
            parts.append("html:not_found")
        elif "forbidden" in lower or "403" in lower:
            parts.append("html:forbidden")
        elif "unauthorized" in lower or "401" in lower:
            parts.append("html:unauthorized")
        elif "error" in lower:
            parts.append("html:error")

    if not parts:
        return None
    return "|".join(parts)


def _extract_duration_ms(flow: dict) -> float | None:
    """
    Purpose:
        Prefer explicit duration_ms; else derive from captured_at → response_end
        ISO timestamps when both present.
    Side effects: None.
    """
    if flow.get("duration_ms") is not None:
        try:
            return float(flow["duration_ms"])
        except (TypeError, ValueError):
            pass

    start = flow.get("captured_at") or flow.get("request_start")
    end = flow.get("response_end")
    if not start or not end:
        return None
    try:
        from datetime import datetime

        def _parse(ts: str) -> datetime:
            # Accept trailing Z.
            cleaned = str(ts).replace("Z", "+00:00")
            return datetime.fromisoformat(cleaned)

        delta = _parse(str(end)) - _parse(str(start))
        ms = delta.total_seconds() * 1000.0
        if ms < 0:
            return None
        return ms
    except (TypeError, ValueError, OSError):
        return None
