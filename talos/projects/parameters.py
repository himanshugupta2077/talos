"""
Module: talos.projects.parameters

Purpose:
    Extract every observable input surface from a captured flow and maintain a
    deduplicated, semantically-typed parameter inventory per endpoint.

    This module is the Parameter Intelligence layer inside Endpoint Intelligence.
    It analyses:
        - Path parameters  (dynamic segments resolved from the normalized path)
        - Query parameters
        - Body parameters  (JSON nested, URL-encoded form, multipart fields,
                           XML element names, GraphQL variables)
        - Security-relevant request headers (+ URL-ish allowlist; value-first
          for custom headers whose values look like network resources)
        - Request cookies
        - Structure discovery (Phase 2): base64/URL-encoded JSON unwrap, JWT
          URL claims as virtual params
        - Response inventory (Phase 2): HTML hidden fields + JS config URL keys

    For each parameter it infers a semantic type identifying security-relevant
    values: UUID, JWT, email, ObjectID, URL, IP, hash, timestamp, filename,
    boolean, integer, float, and string.

    Passive reflection intelligence is also collected: when a parameter value
    appears in the response body, the reflection location and encoding are noted.

    URL Sink Discovery:
        Phase 1 — each extracted parameter carries composed ``url_features``
        Phase 2 — encoded/JWT/header/HTML/JS surfaces expand the inventory

Dependencies: dataclasses, json, re, sqlite3, urllib.parse, uuid, xml.etree.ElementTree,
              talos.url_sink
Data flow:
    FlowWorker -> extract_flow_params() [+ extract_response_url_sink_params]
              -> upsert_endpoint_params() -> parameters table
Side effects: None in extraction layer; DB write in upsert layer.
"""

import json
import re
import sqlite3
import uuid
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote
from xml.etree import ElementTree

from talos.url_sink.decode import try_unwrap_json, walk_unwrapped_leaves
from talos.url_sink.features import (
    NETWORK_RESOURCE_SCORE_THRESHOLD,
    compose_url_features,
)
from talos.url_sink.html_js_extract import extract_html_js_params
from talos.url_sink.jwt_claims import extract_url_claim_params
from talos.url_sink.name_classify import classify_name
from talos.url_sink.value_classify import UrlValueFeatures, classify_value


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_EXAMPLE_VALUES: int = 5

# Cap nested leaves expanded from one encoded blob on the request path.
_MAX_STRUCTURE_LEAVES_PER_PARAM: int = 50

# Security-relevant + URL-ish request headers (PR-4 expanded allowlist).
# These are direct attack surface for BAC, SSRF, injection, header smuggling, etc.
_SECURITY_HEADERS: frozenset[str] = frozenset({
    "authorization",
    "x-api-key",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-server",
    "x-original-url",
    "x-rewrite-url",
    "x-http-method-override",
    "origin",
    "referer",
    "host",
    "content-location",
    "link",
    "destination",
    "x-tenant",
    "x-user",
    "x-user-id",
    "x-role",
    "x-request-id",
    "csrf-token",
    "x-csrf-token",
    "x-device",
    "x-client-id",
    "x-real-ip",
    "x-custom-ip-authorization",
    "x-forwarded-proto",
    "x-amz-security-token",
    "x-auth-token",
    "x-access-token",
    "proxy-authorization",
})

# Headers never captured via value-first discovery (noise / transport / body CT).
_HEADER_VALUE_FIRST_SKIP: frozenset[str] = frozenset({
    "accept",
    "accept-encoding",
    "accept-language",
    "accept-charset",
    "cache-control",
    "connection",
    "content-length",
    "content-type",
    "cookie",
    "date",
    "expect",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "keep-alive",
    "pragma",
    "range",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "user-agent",
    "via",
    "warning",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "sec-gpc",
    "dnt",
    "upgrade-insecure-requests",
    "priority",
})

# ---------------------------------------------------------------------------
# Semantic type patterns (most-specific first)
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_OBJECTID_RE = re.compile(r"^[0-9a-f]{24}$")
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_HASH_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.IGNORECASE)
_UNIX_TS_RE = re.compile(r"^\d{10}$")
_ISO_DATE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:[Z+-].*)?)?$"
)
_FILENAME_RE = re.compile(r"^[\w\-. ]+\.(?:[a-zA-Z]{1,6})$")
_BOOL_VALUES: frozenset[str] = frozenset({"true", "false", "1", "0", "yes", "no"})
_INT_RE = re.compile(r"^-?(?:0|[1-9]\d*)$")
_FLOAT_RE = re.compile(r"^-?(?:0|[1-9]\d*)?\.\d+$")
_BOUNDARY_RE = re.compile(r"boundary=([^\s;]+)", re.IGNORECASE)

# Hostname pattern: optional port, at least two dot-separated labels,
# no spaces.  Used to prevent misclassifying domains as filenames.
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,}"
    r"[a-zA-Z]{2,}(?::\d{1,5})?$"
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ExtractedParam:
    """
    Purpose:
        Carry one observed parameter: name, location, scalar type, semantic
        type, sample value, URL sink features, and the capture-context
        role/module for tracking.
    Fields:
        name          - Parameter name as supplied by the client (or virtual
                        path such as jwt.jku / config.oauth.metadata.url /
                        js.__NEXT_DATA__.apiUrl).
        location      - 'path' | 'query' | 'body' | 'header' | 'cookie' |
                        'response' (HTML/JS response inventory, Phase 2)
        param_type    - 'int' | 'float' | 'bool' | 'string' | 'unknown'
        semantic_type - UUID, JWT, email, objectid, url, ip, hash, timestamp,
                        filename, boolean, integer, float, array, string, unknown
        sample_value  - Raw string value (may be empty).
        role_id       - Role UUID at capture time.
        module_id     - Module UUID at capture time.
        url_features  - JSON string of passive URL sink features (may be "{}").
    Side effects: None.
    """

    name: str
    location: str
    param_type: str
    semantic_type: str
    sample_value: str
    role_id: str = ""
    module_id: str = ""
    url_features: str = "{}"


@dataclass
class ReflectionObservation:
    """
    Purpose:
        Record a passive reflection detection: parameter value seen in response.
    Fields:
        param_name          - Name of the reflected parameter.
        location            - Parameter location.
        reflection_location - 'html' | 'json' | 'xml' | 'javascript' | 'other'
        encoding            - 'raw' | 'html_encoded' | 'url_encoded' | 'other'
    Side effects: None.
    """

    param_name: str
    location: str
    reflection_location: str
    encoding: str


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_flow_params(
    query: str,
    request_body: bytes | None,
    request_headers: dict,
    request_cookies: dict | None = None,
    path: str = "",
    normalized_path: str = "",
    role_id: str = "",
    module_id: str = "",
) -> list[ExtractedParam]:
    """
    Purpose:
        Extract all observable parameters from one captured flow across every
        request input surface: path, query, body (all content types),
        security-relevant + value-first headers, and cookies.

        Phase 2 structure discovery also expands:
            - base64 / URL-encoded JSON nested leaves (full dotted paths)
            - JWT URL-shaped claims as virtual ``jwt.<claim>`` params
    Input:
        query           - Cleaned query string (no leading '?').
        request_body    - Raw request body bytes, or None.
        request_headers - Captured request headers dict (case-insensitive keys).
        request_cookies - Pre-parsed cookies dict, or None.
        path            - Original raw request path.
        normalized_path - Normalized path pattern (e.g. /users/{id}/orders/{oid}).
        role_id         - Active role UUID at capture time.
        module_id       - Active module UUID at capture time.
    Output:
        List of ExtractedParam. May be empty. Deduped by (name, location).
    Side effects: None.
    """
    cookies = request_cookies or {}
    params: list[ExtractedParam] = []
    params.extend(_stamp(
        _extract_path_params(path, normalized_path), role_id, module_id
    ))
    params.extend(_stamp(_extract_query_params(query), role_id, module_id))
    ct = _header_value(request_headers, "content-type")
    params.extend(_stamp(
        _extract_body_params(request_body, ct), role_id, module_id
    ))
    params.extend(_stamp(_extract_header_params(request_headers), role_id, module_id))
    params.extend(_stamp(
        _extract_cookie_params(cookies, request_headers), role_id, module_id
    ))
    # Structure discovery: encoded JSON leaves + JWT claims (request surfaces).
    # Gated by url_sink.passive.enabled (process-cached; default true).
    try:
        from talos.url_sink.config import get_process_url_sink_config

        if get_process_url_sink_config().passive_enabled:
            params = _expand_structure_discovery(params)
    except Exception:
        params = _expand_structure_discovery(params)
    params = _stamp(params, role_id, module_id)
    return _dedupe_params(params)


def extract_response_url_sink_params(
    response_body: bytes | None,
    response_headers: dict | None = None,
    *,
    role_id: str = "",
    module_id: str = "",
    score_threshold: int = NETWORK_RESOURCE_SCORE_THRESHOLD,
) -> list[ExtractedParam]:
    """
    Purpose:
        Phase 2 response inventory: hidden form fields and JS/bootstrap config
        URL keys from HTML responses, gated by name category or value score.
    Input:
        response_body    - Raw response body bytes (HTML / HTML shell).
        response_headers - Response headers (used for content-type gate).
        role_id / module_id — capture context.
        score_threshold  - Inventory gate (default possible_network_resource).
    Output:
        ExtractedParam list with location=``response``. May be empty.
    Side effects: None.
    Risk control:
        Only HTML-ish content-types (or missing CT with ``<`` body marker).
        De-dupe by name; score/name gate inside html_js_extract.
    """
    if not response_body:
        return []
    headers = response_headers or {}
    ct = _header_value(headers, "content-type").lower()
    body_text = response_body.decode("utf-8", errors="replace")
    if not _is_html_ish_response(ct, body_text):
        return []

    candidates = extract_html_js_params(
        body_text,
        score_threshold=score_threshold,
    )
    results: list[ExtractedParam] = []
    for cand in candidates:
        results.append(_make_param(
            cand.name,
            "response",
            cand.sample_value,
            extra_evidence=list(cand.evidence),
        ))
    return _stamp(results, role_id, module_id)


def detect_reflections(
    params: list[ExtractedParam],
    response_body: bytes | None,
    response_headers: dict,
) -> list[ReflectionObservation]:
    """
    Purpose:
        Passively detect whether any extracted parameter value appears in the
        response (raw, HTML-encoded, or URL-encoded).  Only non-trivial values
        (length >= 4) are checked to suppress noise from tokens like '0', '1'.
    Input:
        params           - Parameters extracted from the same flow.
        response_body    - Raw response body bytes.
        response_headers - Response headers dict.
    Output:
        List of ReflectionObservation. May be empty.
    Side effects: None.
    """
    if not params or not response_body:
        return []

    body_text = response_body.decode("utf-8", errors="replace")
    resp_ct = _header_value(response_headers, "content-type").lower()
    observations: list[ReflectionObservation] = []

    for param in params:
        # Response-derived inventory (HTML/JS) is extracted *from* this body —
        # treating those values as "reflected" is always a false positive.
        if param.location == "response":
            continue
        value = param.sample_value
        if not value or len(value) < 4:
            continue

        if value in body_text:
            observations.append(ReflectionObservation(
                param_name=param.name,
                location=param.location,
                reflection_location=_reflection_loc(resp_ct),
                encoding="raw",
            ))
            continue

        html_enc = _html_encode(value)
        if html_enc != value and html_enc in body_text:
            observations.append(ReflectionObservation(
                param_name=param.name,
                location=param.location,
                reflection_location=_reflection_loc(resp_ct),
                encoding="html_encoded",
            ))
            continue

        url_enc = quote(value, safe="")
        if url_enc != value and url_enc in body_text:
            observations.append(ReflectionObservation(
                param_name=param.name,
                location=param.location,
                reflection_location=_reflection_loc(resp_ct),
                encoding="url_encoded",
            ))

    return observations


def upsert_endpoint_params(
    conn: sqlite3.Connection,
    endpoint_id: str,
    params: list[ExtractedParam],
    reflections: list[ReflectionObservation] | None = None,
) -> None:
    """
    Purpose:
        Persist a batch of parameter observations for one endpoint.
        Inserts on first observation; updates on subsequent flows with type
        upgrades, example accumulation, role/module tracking, reflection
        intelligence, and url_features merge.
    Input:
        conn        - Open SQLite connection; caller manages the transaction.
        endpoint_id - UUID of the resolved endpoint.
        params      - Parameters extracted from one flow.
        reflections - Optional reflection observations from the same flow.
    Side effects:
        - Inserts or updates rows in the parameters table.
        - Never deletes existing rows.
        - Temporarily sets conn.row_factory = sqlite3.Row for named column
          access, then restores the previous factory (callers need not
          configure Row themselves).
    """
    refl_map: dict[tuple[str, str], ReflectionObservation] = {}
    if reflections:
        for obs in reflections:
            refl_map[(obs.param_name, obs.location)] = obs

    # Named column access regardless of caller's row_factory (local single-user
    # callers sometimes use default tuple rows).
    previous_factory = conn.row_factory
    conn.row_factory = sqlite3.Row
    try:
        _upsert_endpoint_params_rows(conn, endpoint_id, params, refl_map)
    finally:
        conn.row_factory = previous_factory


def _upsert_endpoint_params_rows(
    conn: sqlite3.Connection,
    endpoint_id: str,
    params: list[ExtractedParam],
    refl_map: dict[tuple[str, str], ReflectionObservation],
) -> None:
    """Inner upsert loop requiring conn.row_factory = sqlite3.Row."""
    for param in params:
        row = conn.execute(
            """
            SELECT id, param_type, semantic_type, example_values,
                   appears_in_roles, appears_in_modules,
                   is_reflected, reflection_count, reflection_locations,
                   reflection_encoding, seen_count, url_features
            FROM parameters
            WHERE endpoint_id = ? AND name = ? AND location = ?
            """,
            (endpoint_id, param.name, param.location),
        ).fetchone()

        obs = refl_map.get((param.name, param.location))
        features_json = _resolve_url_features_json(param)

        if row is None:
            initial_examples = (
                json.dumps([param.sample_value]) if param.sample_value else "[]"
            )
            roles = json.dumps([param.role_id]) if param.role_id else "[]"
            modules = json.dumps([param.module_id]) if param.module_id else "[]"
            is_reflected = 1 if obs else 0
            refl_count = 1 if obs else 0
            refl_locs = json.dumps([obs.reflection_location]) if obs else "[]"
            refl_encs = json.dumps([obs.encoding]) if obs else "[]"
            conn.execute(
                """
                INSERT INTO parameters (
                    id, endpoint_id, name, location,
                    param_type, semantic_type, example_values,
                    appears_in_roles, appears_in_modules,
                    is_reflected, reflection_count,
                    reflection_locations, reflection_encoding,
                    seen_count, url_features
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    endpoint_id,
                    param.name,
                    param.location,
                    param.param_type,
                    param.semantic_type,
                    initial_examples,
                    roles,
                    modules,
                    is_reflected,
                    refl_count,
                    refl_locs,
                    refl_encs,
                    1,
                    features_json,
                ),
            )
            continue

        # Upgrade scalar type only from 'unknown' -> known; never downgrade.
        updated_type: str = row["param_type"]
        if updated_type == "unknown" and param.param_type != "unknown":
            updated_type = param.param_type

        updated_semantic: str = row["semantic_type"]
        if updated_semantic == "unknown" and param.semantic_type != "unknown":
            updated_semantic = param.semantic_type
        # Prefer stronger semantic types when a URL-shaped value upgrades string.
        if (
            param.semantic_type == "url"
            and updated_semantic in ("unknown", "string", "filename")
        ):
            updated_semantic = "url"
        if (
            param.semantic_type == "ip"
            and updated_semantic in ("unknown", "string")
        ):
            updated_semantic = "ip"

        # Accumulate example values.
        try:
            examples: list = json.loads(row["example_values"])
        except (json.JSONDecodeError, TypeError):
            examples = []
        if not isinstance(examples, list):
            examples = []
        if param.sample_value and param.sample_value not in examples:
            examples.append(param.sample_value)
            if len(examples) > _MAX_EXAMPLE_VALUES:
                examples = examples[-_MAX_EXAMPLE_VALUES:]

        updated_roles = _merge_json_list(row["appears_in_roles"], param.role_id)
        updated_modules = _merge_json_list(row["appears_in_modules"], param.module_id)

        # Reflection updates.
        updated_is_reflected = row["is_reflected"]
        updated_refl_count = row["reflection_count"] or 0
        updated_refl_locs = row["reflection_locations"]
        updated_refl_encs = row["reflection_encoding"]

        if obs:
            updated_is_reflected = 1
            updated_refl_count += 1
            updated_refl_locs = _merge_json_list(
                row["reflection_locations"], obs.reflection_location
            )
            updated_refl_encs = _merge_json_list(
                row["reflection_encoding"], obs.encoding
            )

        # Prefer higher-score url_features when a stronger observation arrives.
        updated_url_features = _merge_url_features(
            row["url_features"] if "url_features" in row.keys() else None,
            features_json,
        )

        conn.execute(
            """
            UPDATE parameters SET
                param_type           = ?,
                semantic_type        = ?,
                example_values       = ?,
                appears_in_roles     = ?,
                appears_in_modules   = ?,
                is_reflected         = ?,
                reflection_count     = ?,
                reflection_locations = ?,
                reflection_encoding  = ?,
                seen_count           = seen_count + 1,
                url_features         = ?
            WHERE id = ?
            """,
            (
                updated_type,
                updated_semantic,
                json.dumps(examples),
                updated_roles,
                updated_modules,
                updated_is_reflected,
                updated_refl_count,
                updated_refl_locs,
                updated_refl_encs,
                updated_url_features,
                row["id"],
            ),
        )


# ---------------------------------------------------------------------------
# Private extraction helpers
# ---------------------------------------------------------------------------


def _stamp(
    params: list[ExtractedParam],
    role_id: str,
    module_id: str,
) -> list[ExtractedParam]:
    """Re-attach role/module context to a batch of parameters."""
    if not (role_id or module_id):
        return params
    return [
        ExtractedParam(
            name=p.name,
            location=p.location,
            param_type=p.param_type,
            semantic_type=p.semantic_type,
            sample_value=p.sample_value,
            role_id=role_id,
            module_id=module_id,
            url_features=p.url_features,
        )
        for p in params
    ]


def _make_param(
    name: str,
    location: str,
    sample_value: str,
    *,
    param_type: str | None = None,
    semantic_type: str | None = None,
    extra_evidence: list[str] | tuple[str, ...] | None = None,
) -> ExtractedParam:
    """
    Purpose:
        Build an ExtractedParam with scalar type, semantic type, and composed
        url_features derived from name + sample value.
    Input:
        name / location / sample_value — identity fields.
        param_type / semantic_type — optional overrides (e.g. array, filename).
        extra_evidence — optional tokens merged into url_features.evidence
                         (e.g. decode:base64, jwt_claim, html_hidden).
    Output:
        ExtractedParam with url_features JSON populated.
    Side effects: None.
    """
    value = sample_value if sample_value is not None else ""
    ptype = param_type if param_type is not None else _scalar_type(value)
    # Classify once; share between semantic_type and url_features.
    vf = classify_value(value)
    nf = classify_name(name)
    stype = (
        semantic_type
        if semantic_type is not None
        else _semantic_type(name, value, value_features=vf)
    )
    features = compose_url_features(
        name=name, value=value, value_features=vf, name_features=nf,
    )
    if extra_evidence:
        features = dict(features)
        merged = list(features.get("evidence") or [])
        merged.extend(extra_evidence)
        features["evidence"] = list(dict.fromkeys(merged))
    return ExtractedParam(
        name=name,
        location=location,
        param_type=ptype,
        semantic_type=stype,
        sample_value=value,
        url_features=json.dumps(features, separators=(",", ":")),
    )


def _resolve_url_features_json(param: ExtractedParam) -> str:
    """
    Purpose:
        Ensure url_features JSON is present for upsert (recompute if empty).
    Input:
        param — extracted parameter.
    Output:
        Compact JSON string.
    Side effects: None.
    """
    raw = (param.url_features or "").strip()
    if raw and raw != "{}":
        return raw
    features = compose_url_features(name=param.name, value=param.sample_value)
    return json.dumps(features, separators=(",", ":"))


def _merge_url_features(existing_json: str | None, new_json: str) -> str:
    """
    Purpose:
        Keep the stronger url_features document (higher score wins; ties prefer
        the observation with more evidence / name categories).
    Input:
        existing_json — prior row value (may be None / invalid).
        new_json      — features from the current flow.
    Output:
        JSON string to store.
    Side effects: None.
    """
    try:
        new_doc = json.loads(new_json) if new_json else {}
    except (json.JSONDecodeError, TypeError):
        new_doc = {}
    if not isinstance(new_doc, dict):
        new_doc = {}

    try:
        old_doc = json.loads(existing_json) if existing_json else {}
    except (json.JSONDecodeError, TypeError):
        old_doc = {}
    if not isinstance(old_doc, dict) or not old_doc:
        return json.dumps(new_doc, separators=(",", ":")) if new_doc else (new_json or "{}")

    old_score = int(old_doc.get("score") or 0)
    new_score = int(new_doc.get("score") or 0)
    if new_score > old_score:
        return json.dumps(new_doc, separators=(",", ":"))
    if new_score < old_score:
        return json.dumps(old_doc, separators=(",", ":"))

    # Equal score: prefer more evidence / categories; else prefer new (fresh).
    old_ev = len(old_doc.get("evidence") or [])
    new_ev = len(new_doc.get("evidence") or [])
    if new_ev >= old_ev and new_doc:
        # Merge name categories from both when scores equal.
        cats = list(dict.fromkeys(
            list(old_doc.get("name_categories") or [])
            + list(new_doc.get("name_categories") or [])
        ))
        if cats:
            new_doc = dict(new_doc)
            new_doc["name_categories"] = cats
            if not new_doc.get("name_category") and old_doc.get("name_category"):
                new_doc["name_category"] = old_doc["name_category"]
        return json.dumps(new_doc, separators=(",", ":"))
    return json.dumps(old_doc, separators=(",", ":"))


def _extract_path_params(raw_path: str, normalized_path: str) -> list[ExtractedParam]:
    """
    Purpose:
        Extract dynamic path segments by comparing the raw path to the
        normalized path pattern.  Segments enclosed in {braces} correspond
        to the raw value at the same position in the URL.
    Input:
        raw_path        - Original request path.
        normalized_path - Normalized pattern (e.g. /users/{id}/orders/{order_id}).
    Output:
        List of ExtractedParam with location='path'.
    Side effects: None.
    """
    if not raw_path or not normalized_path:
        return []
    raw_segs = raw_path.lstrip("/").split("/")
    norm_segs = normalized_path.lstrip("/").split("/")
    if len(raw_segs) != len(norm_segs):
        return []
    results: list[ExtractedParam] = []
    for raw_seg, norm_seg in zip(raw_segs, norm_segs):
        if norm_seg.startswith("{") and norm_seg.endswith("}"):
            name = norm_seg[1:-1] or "id"
            results.append(_make_param(name, "path", raw_seg))
    return results


def _extract_query_params(query: str) -> list[ExtractedParam]:
    """
    Purpose:
        Parse a cleaned query string into ExtractedParam items.
    Input:
        query - Cleaned query string (no leading '?').
    Side effects: None.
    """
    if not query:
        return []
    results: list[ExtractedParam] = []
    for name, value in parse_qsl(query, keep_blank_values=True):
        if not name:
            continue
        results.append(_make_param(name, "query", value))
    return results


def _extract_body_params(body: bytes | None, content_type: str) -> list[ExtractedParam]:
    """
    Purpose:
        Dispatch body extraction to the appropriate parser based on Content-Type.
        Handles: JSON, form-urlencoded, multipart/form-data, XML/SOAP, GraphQL.
    """
    if not body:
        return []
    ct = content_type.lower().split(";")[0].strip()
    if ct == "application/json":
        return _extract_json_params(body)
    if ct == "application/x-www-form-urlencoded":
        return _extract_form_params(body)
    if ct == "multipart/form-data":
        return _extract_multipart_params(body, content_type)
    if ct in ("application/xml", "text/xml", "application/soap+xml"):
        return _extract_xml_params(body)
    if ct == "application/graphql":
        return _extract_graphql_params(body)
    return []


def _extract_header_params(headers: dict) -> list[ExtractedParam]:
    """
    Purpose:
        Extract security-relevant / URL-ish request headers as parameters.

        Capture rules (Phase 2):
            1. Allowlist: headers in ``_SECURITY_HEADERS`` (expanded URL-ish set).
            2. Value-first: any other header whose value classifies as a network
               resource (score ≥ threshold) — custom URL headers without names
               on the allowlist still surface.

        The 'cookie' header is never duplicated here — handled separately.
        Routine transport headers (Accept, User-Agent, Content-Length, …) are
        skipped via ``_HEADER_VALUE_FIRST_SKIP``.
    """
    results: list[ExtractedParam] = []
    seen: set[str] = set()
    for key, raw_value in headers.items():
        norm_key = str(key).lower()
        if norm_key == "cookie" or norm_key in seen:
            continue
        value = _coerce_header(raw_value)
        allowlisted = norm_key in _SECURITY_HEADERS
        if not allowlisted:
            if norm_key in _HEADER_VALUE_FIRST_SKIP:
                continue
            # Value-first: only when the value looks like a network resource.
            vf = classify_value(value)
            if not (
                vf.possible_network_resource
                or vf.score >= NETWORK_RESOURCE_SCORE_THRESHOLD
                or vf.possible_url_value
            ):
                continue
            extra = ["header_value_first"]
        else:
            extra = None
        seen.add(norm_key)
        results.append(_make_param(
            norm_key, "header", value, extra_evidence=extra,
        ))
    return results


def _extract_cookie_params(
    cookies: dict,
    headers: dict,
) -> list[ExtractedParam]:
    """
    Purpose:
        Extract cookies as individual parameters.
        Uses the pre-parsed cookies dict first; falls back to parsing the
        raw Cookie header when the dict is empty.
    """
    jar: dict[str, str] = {}
    if isinstance(cookies, dict) and cookies:
        for k, v in cookies.items():
            if isinstance(k, str) and k:
                jar[k] = str(v) if v is not None else ""
    else:
        raw = _header_value(headers, "cookie")
        for part in raw.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                k = k.strip()
                if k:
                    jar[k] = v.strip()

    return [
        _make_param(name, "cookie", value)
        for name, value in jar.items()
    ]


def _extract_json_params(body: bytes) -> list[ExtractedParam]:
    """
    Purpose:
        Recursively extract parameters from a JSON body.
        Uses dotted path names for nested keys (e.g. "address.city").
        Arrays are recorded as a single entry; the first dict element
        is also walked to capture the schema.
    """
    try:
        parsed = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return []
    results: list[ExtractedParam] = []
    _walk_json(parsed, prefix="", results=results, depth=0)
    return results


def _walk_json(
    node: object,
    prefix: str,
    results: list[ExtractedParam],
    depth: int,
) -> None:
    """Recursive JSON walker. Capped at depth 6 to prevent abuse."""
    if depth > 6:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            if not isinstance(key, str) or not key:
                continue
            full = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                _walk_json(value, full, results, depth + 1)
            elif isinstance(value, list):
                results.append(_make_param(
                    full, "body", "",
                    param_type="unknown", semantic_type="array",
                ))
                if value and isinstance(value[0], dict):
                    _walk_json(value[0], full + "[]", results, depth + 1)
            elif value is None:
                results.append(_make_param(
                    full, "body", "",
                    param_type="unknown", semantic_type="unknown",
                ))
            else:
                sample = str(value)
                results.append(_make_param(full, "body", sample))
    elif isinstance(node, list):
        results.append(_make_param(
            "[]", "body", "",
            param_type="unknown", semantic_type="array",
        ))
        if node and isinstance(node[0], dict):
            _walk_json(node[0], "[]", results, depth + 1)


def _extract_form_params(body: bytes) -> list[ExtractedParam]:
    """Extract URL-encoded form parameters."""
    try:
        pairs = parse_qsl(
            body.decode("utf-8", errors="replace"), keep_blank_values=True
        )
    except Exception:
        return []
    return [
        _make_param(name, "body", value)
        for name, value in pairs
        if name
    ]


def _extract_multipart_params(body: bytes, content_type: str) -> list[ExtractedParam]:
    """
    Purpose:
        Extract field names from a multipart/form-data body.
        File upload parts are recorded with semantic_type='filename' and
        an empty sample value.
    """
    m = _BOUNDARY_RE.search(content_type)
    if not m:
        return []
    boundary = m.group(1).encode("latin-1", errors="replace")
    delimiter = b"--" + boundary
    results: list[ExtractedParam] = []
    try:
        parts = body.split(delimiter)
    except Exception:
        return []

    for part in parts:
        if not part or part.startswith(b"--"):
            continue
        if b"\r\n\r\n" in part:
            head_raw, part_body = part.split(b"\r\n\r\n", 1)
        elif b"\n\n" in part:
            head_raw, part_body = part.split(b"\n\n", 1)
        else:
            continue
        head_text = head_raw.decode("utf-8", errors="replace")
        name_m = re.search(r'name="([^"]+)"', head_text)
        if not name_m:
            continue
        name = name_m.group(1)
        if 'filename="' in head_text:
            results.append(_make_param(
                name, "body", "",
                param_type="string", semantic_type="filename",
            ))
            continue
        value = part_body.rstrip(b"\r\n").decode("utf-8", errors="replace")
        results.append(_make_param(name, "body", value))
    return results


def _extract_xml_params(body: bytes) -> list[ExtractedParam]:
    """Extract leaf element names and text from an XML/SOAP request body."""
    try:
        root = ElementTree.fromstring(body.decode("utf-8", errors="replace"))
    except Exception:
        return []
    results: list[ExtractedParam] = []
    _walk_xml(root, results, depth=0)
    return results


def _walk_xml(
    element: ElementTree.Element,
    results: list[ExtractedParam],
    depth: int,
) -> None:
    """Recursive XML walker. Capped at depth 8."""
    if depth > 8:
        return
    tag = element.tag
    if "}" in tag:
        tag = tag.split("}", 1)[1]
    text = (element.text or "").strip()
    if not list(element):
        results.append(_make_param(tag, "body", text))
    else:
        for child in element:
            _walk_xml(child, results, depth + 1)


def _extract_graphql_params(body: bytes) -> list[ExtractedParam]:
    """
    Purpose:
        Extract variables from a GraphQL JSON request body.
        Only the 'variables' dict is treated as parameter-level intelligence.
    """
    try:
        parsed = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return []
    if not isinstance(parsed, dict):
        return []

    results: list[ExtractedParam] = []
    op = parsed.get("operationName")
    if op and isinstance(op, str):
        results.append(_make_param(
            "operationName", "body", op,
            param_type="string", semantic_type="string",
        ))
    variables = parsed.get("variables")
    if isinstance(variables, dict):
        _walk_json(variables, prefix="variables", results=results, depth=0)
    return results


# ---------------------------------------------------------------------------
# Type inference
# ---------------------------------------------------------------------------


def _scalar_type(value: str) -> str:
    """
    Classify a scalar string into 'int' | 'float' | 'bool' | 'string' | 'unknown'.
    """
    if not value:
        return "unknown"
    if _INT_RE.match(value):
        return "int"
    if _FLOAT_RE.match(value):
        return "float"
    if value.lower() in _BOOL_VALUES:
        return "bool"
    return "string"


def _semantic_type(
    name: str,
    value: str,
    *,
    value_features: UrlValueFeatures | None = None,
) -> str:
    """
    Classify a parameter by its security-relevant semantic type using
    both value patterns and name heuristics.

    URL Sink Discovery: strong URL-shaped values (any scheme, protocol-relative)
    map to semantic_type=url even without a name hint. Hostnames that score as
    network resources stay string (not filename). IPs remain ip.

    Input:
        name / value — parameter identity.
        value_features — optional precomputed classify_value result (avoids
                         double work when called from _make_param).
    Returns one of: uuid | jwt | email | objectid | url | ip | hash |
                    timestamp | filename | boolean | integer | float |
                    array | string | unknown
    """
    if not value:
        return _name_hint(name)

    # Strip common auth prefixes before pattern matching so 'Bearer <jwt>'
    # is still classified as jwt rather than string.
    # Basic auth is opaque base64 credentials — never a JWT.
    low_value = value.lower()
    if low_value.startswith("basic "):
        return "string"
    check_value = value
    if low_value.startswith("bearer "):
        check_value = value[7:].strip()
    elif low_value.startswith("token "):
        check_value = value[6:].strip()
    elif value.lower().startswith("basic "):
        check_value = value[6:].strip()

    if _UUID_RE.match(check_value):
        return "uuid"
    if _JWT_RE.match(check_value) and len(check_value) > 50:
        return "jwt"
    if _EMAIL_RE.match(check_value):
        return "email"
    if _OBJECTID_RE.match(check_value):
        return "objectid"
    if _IPV4_RE.match(check_value):
        return "ip"

    # Value-first URL detection via url_sink classifier (broader than https?://).
    # Recompute only when the stripped check_value differs from raw value
    # (auth prefixes) or when no precomputed features were supplied.
    if value_features is not None and check_value == value:
        vf = value_features
    else:
        vf = classify_value(check_value)
    if vf.possible_ip and not vf.possible_url_value:
        return "ip"
    if vf.possible_url_value or (
        vf.possible_protocol and vf.score >= 85
    ):
        return "url"
    # Legacy thin http(s) check kept as belt-and-suspenders.
    if _URL_RE.match(check_value):
        return "url"

    if len(check_value) in (32, 40, 64) and _HASH_RE.match(check_value):
        return "hash"
    if _UNIX_TS_RE.match(check_value):
        return "timestamp"
    if _ISO_DATE_RE.match(check_value):
        return "timestamp"
    # Hostname / domain from url_sink first (excludes file-extension collisions
    # like report.pdf; keeps real multi-label hosts like cdn.example.com).
    if vf.possible_hostname or vf.possible_domain:
        return "string"
    # File basenames (report.pdf, photo.png) — after hostname so multi-label
    # domains are not swallowed by the broad _FILENAME_RE (ends with .com etc.).
    if (
        _FILENAME_RE.match(check_value)
        and "." in check_value
        and not vf.possible_url_value
        and not vf.possible_ip
    ):
        return "filename"
    if _HOSTNAME_RE.match(check_value):
        return "string"
    # Only treat 'true'/'false'/'yes'/'no' as boolean — not '1'/'0' which are
    # more often integers in API contexts.
    if check_value.lower() in {"true", "false", "yes", "no"}:
        return "boolean"
    if _INT_RE.match(check_value):
        return "integer"
    if _FLOAT_RE.match(check_value):
        return "float"

    return _name_hint(name) or "string"


def _name_hint(name: str) -> str:
    """
    Infer semantic type from parameter name conventions.
    Returns empty string when no clear match.
    """
    low = name.lower().replace("-", "_").replace(".", "_")
    if any(t in low for t in ("uuid", "user_id", "item_id", "object_id")):
        return "uuid"
    # Specific id-like suffixes only — avoid matching random words ending in 'id'.
    if low.endswith("_id") or low.startswith("id_"):
        return "uuid"
    if any(t in low for t in ("jwt", "access_token", "id_token", "refresh_token")):
        return "jwt"
    # Auth header names alone do not imply JWT (Basic/API-key schemes exist).
    # Value-shape detection above already maps compact JWTs → jwt.
    if low in ("x_auth_token", "x_access_token", "x_api_key", "x_amz_security_token"):
        return "jwt"
    if "email" in low or "mail" in low:
        return "email"
    if any(t in low for t in ("ip_address", "ip_addr", "remote_addr", "x_forwarded_for",
                               "x_real_ip", "x_custom_ip")):
        return "ip"
    # Broader URL-ish name hints (catalog leaf tokens).
    if any(t in low for t in (
        "url", "uri", "redirect", "callback", "webhook", "return_url",
        "return_uri", "return_to", "goto", "next", "continue", "avatar",
        "image_url", "img_url", "media_url", "base_url", "api_url",
        "endpoint", "fetch", "href", "src",
    )):
        return "url"
    if any(t in low for t in ("hash", "checksum", "digest", "hmac", "signature")):
        return "hash"
    if any(t in low for t in ("timestamp", "created_at", "updated_at", "expires_at",
                               "date", "_time", "time_")):
        return "timestamp"
    if any(t in low for t in ("filename", "attachment")):
        return "filename"
    return ""


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _merge_json_list(existing_json: str, new_val: str) -> str:
    """Append new_val to a JSON list string, deduplicating."""
    try:
        existing: list = json.loads(existing_json)
    except (json.JSONDecodeError, TypeError):
        existing = []
    if not isinstance(existing, list):
        existing = []
    if new_val and new_val not in existing:
        existing.append(new_val)
    return json.dumps(existing)


def _reflection_loc(resp_ct: str) -> str:
    """Classify reflection location from response content-type."""
    if "html" in resp_ct:
        return "html"
    if "json" in resp_ct:
        return "json"
    if "xml" in resp_ct:
        return "xml"
    if "javascript" in resp_ct or "ecmascript" in resp_ct:
        return "javascript"
    return "other"


def _html_encode(value: str) -> str:
    """Apply basic HTML entity encoding."""
    return (
        value.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#x27;")
    )


def _header_value(headers: dict, name: str) -> str:
    """Extract a header value by case-insensitive name."""
    for key, value in headers.items():
        if str(key).lower() == name:
            return _coerce_header(value)
    return ""


def _coerce_header(raw: object) -> str:
    """Coerce a header value (list or scalar) to a plain string."""
    if isinstance(raw, list):
        return str(raw[0]) if raw else ""
    return str(raw) if raw is not None else ""


# ---------------------------------------------------------------------------
# Phase 2 structure discovery helpers
# ---------------------------------------------------------------------------


def _expand_structure_discovery(
    params: list[ExtractedParam],
) -> list[ExtractedParam]:
    """
    Purpose:
        From already-extracted request params, emit additional inventory rows for:
            - Nested leaves inside base64 / URL-encoded JSON scalar values
            - URL-shaped JWT claims (``jwt.jku``, ``jwt.iss``, …)
    Input:
        params — primary extract list (path/query/body/header/cookie).
    Output:
        Original params plus expansions (caller dedupes). Low-score outer
        encoded-JSON wrappers are dropped when leaves were emitted so inventory
        is not flooded with opaque base64 parents (QA-USD-17).
    Side effects: None.
    Risk control:
        Per-value leaf cap; one nested re-unwrap pass on newly emitted leaves
        (base64-in-base64); skip virtual jwt.* re-decode of claims.
    """
    if not params:
        return params
    extra: list[ExtractedParam] = []
    # Outer names that produced encoded-JSON leaves (eligible for parent drop).
    encoded_parents: set[str] = set()
    for param in params:
        value = param.sample_value or ""
        if not value:
            continue
        # Encoded JSON structure walk (query/body/header/cookie/path values).
        if not param.name.startswith("jwt."):
            leaves = _expand_encoded_json_param(param)
            if leaves:
                encoded_parents.add(param.name)
                extra.extend(leaves)
        # JWT claims from any JWT-shaped sample.
        extra.extend(_expand_jwt_param(param))

    # Second pass: nested encoded blobs that surfaced as leaves in pass 1
    # (e.g. outer base64 JSON containing an inner base64 JSON string).
    if extra:
        nested: list[ExtractedParam] = []
        for param in extra:
            if param.name.startswith("jwt."):
                continue
            if not (param.sample_value or ""):
                continue
            nested.extend(_expand_encoded_json_param(param))
        if nested:
            extra = list(extra) + nested

    if not extra:
        return params

    # Drop low-score structure wrappers that only exist as opaque containers
    # after successful leaf expansion (parent score 0 / non-NRS noise).
    keep_parents: list[ExtractedParam] = []
    for param in params:
        if param.name not in encoded_parents:
            keep_parents.append(param)
            continue
        if _structure_parent_worth_keeping(param):
            keep_parents.append(param)
    return list(keep_parents) + extra


def _structure_parent_worth_keeping(param: ExtractedParam) -> bool:
    """
    Purpose:
        Keep an outer encoded-JSON field only when the **value itself** looks
        like a network resource. Name-category-only hits (e.g. bare ``config``
        / ``cfg`` over opaque base64) are inventory noise once leaves exist.
    Side effects: None.
    """
    try:
        feat = json.loads(param.url_features or "{}")
    except (json.JSONDecodeError, TypeError):
        feat = {}
    if not isinstance(feat, dict):
        feat = {}
    if feat.get("possible_network_resource") is True:
        return True
    try:
        score = int(feat.get("score") or 0)
    except (TypeError, ValueError):
        score = 0
    if score >= NETWORK_RESOURCE_SCORE_THRESHOLD:
        return True
    # Value-shaped flags without full NRS (hostname/IP/path) still keep parent.
    if any(
        feat.get(k) is True
        for k in (
            "possible_url_value",
            "possible_hostname",
            "possible_ip",
            "possible_domain",
            "possible_unc",
        )
    ):
        return True
    return False


def _expand_encoded_json_param(param: ExtractedParam) -> list[ExtractedParam]:
    """
    Purpose:
        If ``param.sample_value`` is base64/URL-encoded JSON, walk nested leaves
        with full dotted paths under the outer parameter name.
    Output:
        Zero or more ExtractedParam with location inherited from parent.
    Side effects: None.
    """
    unwrap = try_unwrap_json(param.sample_value)
    if unwrap.parsed is None:
        return []
    leaves = walk_unwrapped_leaves(
        unwrap.parsed,
        prefix=param.name,
        max_leaves=_MAX_STRUCTURE_LEAVES_PER_PARAM,
    )
    if not leaves:
        return []
    decode_ev = list(unwrap.evidence)
    results: list[ExtractedParam] = []
    for leaf_name, leaf_val in leaves:
        if leaf_name == param.name:
            continue
        results.append(_make_param(
            leaf_name,
            param.location,
            leaf_val,
            extra_evidence=decode_ev + [f"parent:{param.name}"],
        ))
    return results


def _expand_jwt_param(param: ExtractedParam) -> list[ExtractedParam]:
    """
    Purpose:
        Emit virtual ``jwt.<claim>`` params for URL-shaped claims in a JWT value.
    Output:
        Zero or more ExtractedParam (location = parent location).
    Side effects: None.
    """
    # Avoid re-expanding already-virtual claim params.
    if param.name.startswith("jwt."):
        return []
    claims = extract_url_claim_params(
        param.sample_value,
        parent_name=param.name,
        parent_location=param.location,
    )
    results: list[ExtractedParam] = []
    for claim in claims:
        results.append(_make_param(
            claim.name,
            param.location,
            claim.sample_value,
            extra_evidence=list(claim.evidence),
        ))
    return results


def _dedupe_params(params: list[ExtractedParam]) -> list[ExtractedParam]:
    """
    Purpose:
        Keep first sighting of each (name, location); prefer richer url_features
        score when a later duplicate is stronger.
    Side effects: None.
    """
    best: dict[tuple[str, str], ExtractedParam] = {}
    order: list[tuple[str, str]] = []
    for p in params:
        key = (p.name, p.location)
        if key not in best:
            best[key] = p
            order.append(key)
            continue
        # Prefer higher url_features score on collision.
        try:
            old_score = int(json.loads(best[key].url_features or "{}").get("score") or 0)
        except (json.JSONDecodeError, TypeError, ValueError):
            old_score = 0
        try:
            new_score = int(json.loads(p.url_features or "{}").get("score") or 0)
        except (json.JSONDecodeError, TypeError, ValueError):
            new_score = 0
        if new_score > old_score:
            best[key] = p
    return [best[k] for k in order]


def _is_html_ish_response(content_type: str, body_text: str) -> bool:
    """
    Purpose:
        Gate response inventory to HTML (or HTML shells with missing CT).
    Side effects: None.
    """
    ct = (content_type or "").lower()
    if "html" in ct or "xhtml" in ct:
        return True
    if ct and not any(t in ct for t in ("text/", "application/xhtml", "application/xml")):
        # Explicit non-HTML JSON/image/etc. — skip (avoid scanning APIs as HTML).
        if any(t in ct for t in ("json", "javascript", "image/", "octet-stream", "pdf")):
            return False
    # Missing or generic CT: look for a light HTML marker.
    sample = body_text.lstrip()[:2000].lower()
    return (
        "<html" in sample
        or "<!doctype html" in sample
        or "<input" in sample
        or "__next_data__" in sample
        or "window.__" in sample
    )
