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
        - Security-relevant request headers
        - Request cookies

    For each parameter it infers a semantic type identifying security-relevant
    values: UUID, JWT, email, ObjectID, URL, IP, hash, timestamp, filename,
    boolean, integer, float, and string.

    Passive reflection intelligence is also collected: when a parameter value
    appears in the response body, the reflection location and encoding are noted.

Dependencies: dataclasses, json, re, sqlite3, urllib.parse, uuid, xml.etree.ElementTree
Data flow:
    FlowWorker -> extract_flow_params() -> upsert_endpoint_params() -> parameters table
Side effects: None in extraction layer; DB write in upsert layer.
"""

import json
import re
import sqlite3
import uuid
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote
from xml.etree import ElementTree


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_EXAMPLE_VALUES: int = 5

# Security-relevant request headers.  These are direct attack surface for
# BAC, SSRF, injection, header smuggling, etc.
_SECURITY_HEADERS: frozenset[str] = frozenset({
    "authorization",
    "x-api-key",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-original-url",
    "x-http-method-override",
    "origin",
    "referer",
    "host",
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
        type, sample value, and the capture-context role/module for tracking.
    Fields:
        name          - Parameter name as supplied by the client.
        location      - 'path' | 'query' | 'body' | 'header' | 'cookie'
        param_type    - 'int' | 'float' | 'bool' | 'string' | 'unknown'
        semantic_type - UUID, JWT, email, objectid, url, ip, hash, timestamp,
                        filename, boolean, integer, float, array, string, unknown
        sample_value  - Raw string value (may be empty).
        role_id       - Role UUID at capture time.
        module_id     - Module UUID at capture time.
    Side effects: None.
    """

    name: str
    location: str
    param_type: str
    semantic_type: str
    sample_value: str
    role_id: str = ""
    module_id: str = ""


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
        input surface: path, query, body (all content types), security-relevant
        headers, and cookies.
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
        List of ExtractedParam. May be empty.
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
    return params


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
        upgrades, example accumulation, role/module tracking, and reflection
        intelligence.
    Input:
        conn        - Open SQLite connection; caller manages the transaction.
        endpoint_id - UUID of the resolved endpoint.
        params      - Parameters extracted from one flow.
        reflections - Optional reflection observations from the same flow.
    Side effects:
        - Inserts or updates rows in the parameters table.
        - Never deletes existing rows.
    """
    refl_map: dict[tuple[str, str], ReflectionObservation] = {}
    if reflections:
        for obs in reflections:
            refl_map[(obs.param_name, obs.location)] = obs

    for param in params:
        row = conn.execute(
            """
            SELECT id, param_type, semantic_type, example_values,
                   appears_in_roles, appears_in_modules,
                   is_reflected, reflection_count, reflection_locations,
                   reflection_encoding, seen_count
            FROM parameters
            WHERE endpoint_id = ? AND name = ? AND location = ?
            """,
            (endpoint_id, param.name, param.location),
        ).fetchone()

        obs = refl_map.get((param.name, param.location))

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
                    seen_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                seen_count           = seen_count + 1
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
        )
        for p in params
    ]


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
            results.append(ExtractedParam(
                name=name,
                location="path",
                param_type=_scalar_type(raw_seg),
                semantic_type=_semantic_type(name, raw_seg),
                sample_value=raw_seg,
            ))
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
        results.append(ExtractedParam(
            name=name,
            location="query",
            param_type=_scalar_type(value),
            semantic_type=_semantic_type(name, value),
            sample_value=value,
        ))
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
        Extract security-relevant request headers as parameters.
        Only headers in _SECURITY_HEADERS are captured; routine headers
        (Accept, User-Agent, Content-Length) are excluded.
        The 'cookie' header is never duplicated here — handled separately.
    """
    results: list[ExtractedParam] = []
    for key, raw_value in headers.items():
        norm_key = str(key).lower()
        if norm_key not in _SECURITY_HEADERS:
            continue
        value = _coerce_header(raw_value)
        results.append(ExtractedParam(
            name=norm_key,
            location="header",
            param_type=_scalar_type(value),
            semantic_type=_semantic_type(norm_key, value),
            sample_value=value,
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
        ExtractedParam(
            name=name,
            location="cookie",
            param_type=_scalar_type(value),
            semantic_type=_semantic_type(name, value),
            sample_value=value,
        )
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
                results.append(ExtractedParam(
                    name=full, location="body",
                    param_type="unknown", semantic_type="array",
                    sample_value="",
                ))
                if value and isinstance(value[0], dict):
                    _walk_json(value[0], full + "[]", results, depth + 1)
            elif value is None:
                results.append(ExtractedParam(
                    name=full, location="body",
                    param_type="unknown", semantic_type="unknown",
                    sample_value="",
                ))
            else:
                sample = str(value)
                results.append(ExtractedParam(
                    name=full, location="body",
                    param_type=_scalar_type(sample),
                    semantic_type=_semantic_type(full, sample),
                    sample_value=sample,
                ))
    elif isinstance(node, list):
        results.append(ExtractedParam(
            name="[]", location="body",
            param_type="unknown", semantic_type="array",
            sample_value="",
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
        ExtractedParam(
            name=name, location="body",
            param_type=_scalar_type(value),
            semantic_type=_semantic_type(name, value),
            sample_value=value,
        )
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
            results.append(ExtractedParam(
                name=name, location="body",
                param_type="string", semantic_type="filename",
                sample_value="",
            ))
            continue
        value = part_body.rstrip(b"\r\n").decode("utf-8", errors="replace")
        results.append(ExtractedParam(
            name=name, location="body",
            param_type=_scalar_type(value),
            semantic_type=_semantic_type(name, value),
            sample_value=value,
        ))
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
        results.append(ExtractedParam(
            name=tag, location="body",
            param_type=_scalar_type(text),
            semantic_type=_semantic_type(tag, text),
            sample_value=text,
        ))
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
        results.append(ExtractedParam(
            name="operationName", location="body",
            param_type="string", semantic_type="string",
            sample_value=op,
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


def _semantic_type(name: str, value: str) -> str:
    """
    Classify a parameter by its security-relevant semantic type using
    both value patterns and name heuristics.
    Returns one of: uuid | jwt | email | objectid | url | ip | hash |
                    timestamp | filename | boolean | integer | float |
                    array | string | unknown
    """
    if not value:
        return _name_hint(name)

    # Strip common auth prefixes before pattern matching so 'Bearer <jwt>'
    # is still classified as jwt rather than string.
    check_value = value
    if value.lower().startswith("bearer "):
        check_value = value[7:].strip()
    elif value.lower().startswith("token "):
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
    if _URL_RE.match(check_value):
        return "url"
    if len(check_value) in (32, 40, 64) and _HASH_RE.match(check_value):
        return "hash"
    if _UNIX_TS_RE.match(check_value):
        return "timestamp"
    if _ISO_DATE_RE.match(check_value):
        return "timestamp"
    # Hostname check before filename: no spaces, at least two labels separated by dots.
    if _HOSTNAME_RE.match(check_value):
        return "string"
    if _FILENAME_RE.match(check_value) and "." in check_value:
        return "filename"
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
    # 'authorization' header always carries an auth credential.
    if low in ("authorization", "proxy_authorization", "x_auth_token", "x_access_token",
               "x_api_key", "x_amz_security_token"):
        return "jwt"
    if "email" in low or "mail" in low:
        return "email"
    if any(t in low for t in ("ip_address", "ip_addr", "remote_addr", "x_forwarded_for",
                               "x_real_ip", "x_custom_ip")):
        return "ip"
    if any(t in low for t in ("url", "redirect", "callback", "next", "return_url")):
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
