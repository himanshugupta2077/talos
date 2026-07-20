"""
Module: talos.input_validation.surface

Purpose:
    Module 9 — Surface completeness: make every input location first-class for
    IV injection and profiling (path, query, body JSON/form/multipart/XML/
    GraphQL, header, cookie).

    Pure helpers only — no HTTP, no SQLite.  Callers (phases.prepare_iv_probe,
    engine skip policy, synthesizer capabilities) consume these functions.

Scope (Module 9):
    - Path segment rewrite via normalized ``{name}`` placeholders
    - Hardened header/cookie injection (multi-cookie, case, hop-by-hop policy)
    - Multipart field values and filenames
    - GraphQL variables (variables.* paths) and XML leaf text
    - Default skip list for dangerous auth artifacts
    - Uniform surface-kind labels for profiles / planner

Dependencies: json, re, urllib.parse, xml.etree.ElementTree
Data flow:
    engine skip check → is_auth_artifact / should_skip_param
    prepare_iv_probe → inject_value / inject_* helpers
    synthesize → surface_kind_for_param → capabilities
Side effects: None.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse
from xml.etree import ElementTree


# ---------------------------------------------------------------------------
# Location / surface vocabulary (uniform profile keys)
# ---------------------------------------------------------------------------

LOCATION_PATH = "path"
LOCATION_QUERY = "query"
LOCATION_BODY = "body"
LOCATION_HEADER = "header"
LOCATION_COOKIE = "cookie"

KNOWN_LOCATIONS: frozenset[str] = frozenset({
    LOCATION_PATH,
    LOCATION_QUERY,
    LOCATION_BODY,
    LOCATION_HEADER,
    LOCATION_COOKIE,
})

# Finer body/surface kinds (stored as observed.surface.kind when useful).
SURFACE_PATH = "path"
SURFACE_QUERY = "query"
SURFACE_HEADER = "header"
SURFACE_COOKIE = "cookie"
SURFACE_JSON_BODY = "json_body"
SURFACE_FORM_BODY = "form_body"
SURFACE_MULTIPART_FIELD = "multipart_field"
SURFACE_MULTIPART_FILENAME = "multipart_filename"
SURFACE_GRAPHQL_VARIABLE = "graphql_variable"
SURFACE_XML_LEAF = "xml_leaf"
SURFACE_BODY_UNKNOWN = "body_unknown"

KNOWN_SURFACE_KINDS: frozenset[str] = frozenset({
    SURFACE_PATH,
    SURFACE_QUERY,
    SURFACE_HEADER,
    SURFACE_COOKIE,
    SURFACE_JSON_BODY,
    SURFACE_FORM_BODY,
    SURFACE_MULTIPART_FIELD,
    SURFACE_MULTIPART_FILENAME,
    SURFACE_GRAPHQL_VARIABLE,
    SURFACE_XML_LEAF,
    SURFACE_BODY_UNKNOWN,
})

# Cache phase name for auth-skip / surface policy records.
PHASE_SURFACE = "surface"

# Skip reason tokens (status / cache result).
SKIP_AUTH_ARTIFACT = "auth_artifact"
SKIP_HOP_BY_HOP_HEADER = "hop_by_hop_header"
SKIP_UNSUPPORTED_SURFACE = "unsupported_surface"

# Hop-by-hop headers that must not be mutated (RFC 7230).
HOP_BY_HOP_HEADERS: frozenset[str] = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
})

# Default auth-like header names (lowercase) — skipped unless include_auth_artifacts.
DEFAULT_AUTH_HEADERS: frozenset[str] = frozenset({
    "authorization",
    "proxy-authorization",
    "x-auth-token",
    "x-access-token",
    "x-amz-security-token",
    "x-api-key",  # often secret; treat as auth artifact by default
})

# Cookie name patterns (exact lowercase match) for session / credential cookies.
DEFAULT_AUTH_COOKIE_NAMES: frozenset[str] = frozenset({
    "session",
    "sessionid",
    "sess",
    "sid",
    "phpsessid",
    "jsessionid",
    "aspsessionid",
    "asp.net_sessionid",
    "connect.sid",
    "auth",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "jwt",
    "bearer",
    "csrf",
    "csrftoken",
    "csrf_token",
    "xsrf-token",
    "xsrftoken",
    "_csrf",
    "remember_me",
    "remember-me",
    "auth_token",
    "oauth_token",
})

# Substring markers for cookie/header names (case-insensitive).
_AUTH_NAME_MARKERS: tuple[str, ...] = (
    "session",
    "auth",
    "token",
    "jwt",
    "csrf",
    "xsrf",
    "credential",
    "password",
    "passwd",
    "secret",
    "bearer",
)

_BOUNDARY_RE = re.compile(r"boundary=([^\s;]+)", re.IGNORECASE)
_FILENAME_ATTR_RE = re.compile(
    r'(filename=")([^"]*)(")',
    re.IGNORECASE,
)
_NAME_ATTR_RE = re.compile(
    r'name="([^"]+)"',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Skip policy
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SkipDecision:
    """
    Purpose:
        Result of auth/hop-by-hop surface skip evaluation.
    Fields:
        skip   — True when the parameter must not be probed.
        reason — stable token (auth_artifact | hop_by_hop_header | …).
        detail — human-readable explanation for status / logs.
    """

    skip: bool
    reason: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "skip": self.skip,
            "reason": self.reason,
            "detail": self.detail,
        }


def is_hop_by_hop_header(name: str) -> bool:
    """
    Purpose: True when header name is hop-by-hop (must not be IV-mutated).
    Side effects: None.
    """
    return (name or "").strip().lower() in HOP_BY_HOP_HEADERS


def is_auth_artifact(
    *,
    location: str,
    name: str,
    semantic_type: str = "",
    configured_cookies: list[str] | tuple[str, ...] | None = None,
    configured_headers: list[str] | tuple[str, ...] | None = None,
) -> bool:
    """
    Purpose:
        Detect session / credential surfaces that IV must not mutate by default.
    Input:
        location            — path|query|body|header|cookie.
        name                — parameter name.
        semantic_type       — passive semantic (jwt triggers skip on header/cookie).
        configured_cookies  — names from talos auth set --cookie.
        configured_headers  — names from talos auth set --header.
    Output:
        True when this parameter is an auth artifact.
    Side effects: None.
    """
    loc = (location or "").strip().lower()
    n = (name or "").strip()
    n_low = n.lower()
    st = (semantic_type or "").strip().lower()

    cfg_cookies = {c.strip().lower() for c in (configured_cookies or []) if c}
    cfg_headers = {h.strip().lower() for h in (configured_headers or []) if h}

    if loc == LOCATION_HEADER:
        if n_low in DEFAULT_AUTH_HEADERS or n_low in cfg_headers:
            return True
        if st == "jwt":
            return True
        if any(m in n_low for m in ("auth", "token", "jwt", "session", "secret")):
            # Keep Host/Origin-style security headers probeable (not auth).
            if n_low in ("authorization", "proxy-authorization") or n_low.startswith("x-auth"):
                return True
            if n_low in DEFAULT_AUTH_HEADERS:
                return True
        return False

    if loc == LOCATION_COOKIE:
        if n_low in DEFAULT_AUTH_COOKIE_NAMES or n_low in cfg_cookies:
            return True
        if st == "jwt":
            return True
        # Prefix patterns: __Host-session, __Secure-auth_token
        bare = n_low
        for prefix in ("__host-", "__secure-"):
            if bare.startswith(prefix):
                bare = bare[len(prefix):]
        if bare in DEFAULT_AUTH_COOKIE_NAMES or bare in cfg_cookies:
            return True
        if any(m in n_low for m in _AUTH_NAME_MARKERS):
            return True
        return False

    # Path / query / body: only skip when explicitly configured as auth artifact
    # name (rare) or semantic is jwt on a param literally named like a token.
    if n_low in cfg_cookies or n_low in cfg_headers:
        return True
    return False


def should_skip_param(
    *,
    location: str,
    name: str,
    semantic_type: str = "",
    include_auth_artifacts: bool = False,
    configured_cookies: list[str] | tuple[str, ...] | None = None,
    configured_headers: list[str] | tuple[str, ...] | None = None,
) -> SkipDecision:
    """
    Purpose:
        Unified skip gate for scheduling: hop-by-hop headers always skipped;
        auth artifacts skipped unless include_auth_artifacts is True.
    Output:
        SkipDecision.
    Side effects: None.
    """
    loc = (location or "").strip().lower()
    n = (name or "").strip()

    if loc == LOCATION_HEADER and is_hop_by_hop_header(n):
        return SkipDecision(
            skip=True,
            reason=SKIP_HOP_BY_HOP_HEADER,
            detail=(
                f"Header '{n}' is hop-by-hop and is not mutated by Input Validation "
                f"(RFC 7230)."
            ),
        )

    if not include_auth_artifacts and is_auth_artifact(
        location=loc,
        name=n,
        semantic_type=semantic_type,
        configured_cookies=configured_cookies,
        configured_headers=configured_headers,
    ):
        return SkipDecision(
            skip=True,
            reason=SKIP_AUTH_ARTIFACT,
            detail=(
                f"Parameter {loc}/{n} looks like an auth artifact and is skipped by "
                f"default. Re-run with --include-auth-artifacts or "
                f"'talos input-validation config --include-auth-artifacts' to probe."
            ),
        )

    return SkipDecision(skip=False)


# ---------------------------------------------------------------------------
# Surface kind detection
# ---------------------------------------------------------------------------

def content_type_of(headers: dict, *, lower: bool = True) -> str:
    """
    Purpose:
        Content-Type value from a headers dict.
        lower=True (default) lowercases the full value for media-type checks.
        lower=False preserves original casing (required for multipart boundary).
    Side effects: None.
    """
    for k, v in (headers or {}).items():
        if str(k).lower() == "content-type":
            raw = v if isinstance(v, str) else (v[0] if v else "")
            raw = raw if isinstance(raw, str) else str(raw or "")
            return raw.lower() if lower else raw
    return ""


def detect_surface_kind(
    *,
    location: str,
    param_name: str = "",
    content_type: str = "",
    semantic_type: str = "",
    body: bytes | None = None,
) -> str:
    """
    Purpose:
        Classify the concrete injection surface for uniform profile handling.
    Output:
        One of KNOWN_SURFACE_KINDS.
    Side effects: None.
    """
    loc = (location or "").strip().lower()
    if loc == LOCATION_PATH:
        return SURFACE_PATH
    if loc == LOCATION_QUERY:
        return SURFACE_QUERY
    if loc == LOCATION_HEADER:
        return SURFACE_HEADER
    if loc == LOCATION_COOKIE:
        return SURFACE_COOKIE
    if loc != LOCATION_BODY:
        return SURFACE_BODY_UNKNOWN

    ct = (content_type or "").lower()
    st = (semantic_type or "").strip().lower()
    name = param_name or ""

    if st == "filename" or name.endswith(":filename"):
        return SURFACE_MULTIPART_FILENAME

    if "multipart/form-data" in ct:
        return SURFACE_MULTIPART_FIELD if st != "filename" else SURFACE_MULTIPART_FILENAME

    if name == "operationName" or name.startswith("variables.") or name == "variables":
        return SURFACE_GRAPHQL_VARIABLE

    if "graphql" in ct:
        return SURFACE_GRAPHQL_VARIABLE

    if body and _looks_like_graphql_json(body) and (
        name.startswith("variables") or name == "operationName" or "query" in name
    ):
        return SURFACE_GRAPHQL_VARIABLE

    if "xml" in ct or "soap" in ct:
        return SURFACE_XML_LEAF

    if "json" in ct:
        return SURFACE_JSON_BODY

    if "x-www-form-urlencoded" in ct or ("form" in ct and "multipart" not in ct):
        return SURFACE_FORM_BODY

    # Body without CT: sniff.
    if body:
        text = body[:200].lstrip()
        if text.startswith(b"{") or text.startswith(b"["):
            if _looks_like_graphql_json(body):
                return SURFACE_GRAPHQL_VARIABLE if name.startswith("variables") else SURFACE_JSON_BODY
            return SURFACE_JSON_BODY
        if text.startswith(b"<"):
            return SURFACE_XML_LEAF

    return SURFACE_BODY_UNKNOWN


def _looks_like_graphql_json(body: bytes) -> bool:
    try:
        parsed = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return False
    return isinstance(parsed, dict) and ("query" in parsed or "variables" in parsed)


# ---------------------------------------------------------------------------
# Path injection
# ---------------------------------------------------------------------------

def inject_path_param(
    url: str,
    name: str,
    value: str,
    *,
    normalized_path: str = "",
    raw_path: str = "",
) -> str:
    """
    Purpose:
        Replace the path segment that corresponds to parameter ``name``.

        Mapping uses the endpoint's normalized path (e.g. ``/users/{id}``):
        the brace name must match ``name``.  When ``normalized_path`` is empty,
        falls back to replacing a single segment equal to the current value
        only if exactly one ``{…}``-style placeholder can be inferred — otherwise
        returns url unchanged.

    Input:
        url              — full request URL.
        name             — path parameter name (from parameters table).
        value            — probe payload for the segment.
        normalized_path  — e.g. /api/users/{id}/orders/{oid}.
        raw_path         — optional override for path (defaults to urlparse path).

    Output:
        New URL string with the matching segment replaced (percent-encoded).

    Side effects: None.
    """
    parsed = urlparse(url)
    path = raw_path if raw_path else (parsed.path or "/")
    norm = (normalized_path or "").strip()
    if not name:
        return url

    encoded = quote(str(value), safe="")

    if norm:
        raw_segs = path.lstrip("/").split("/") if path not in ("", "/") else []
        norm_segs = norm.lstrip("/").split("/") if norm not in ("", "/") else []
        # Allow trailing slash differences.
        if path.endswith("/") and raw_segs and raw_segs[-1] == "":
            raw_segs = raw_segs[:-1]
        if norm.endswith("/") and norm_segs and norm_segs[-1] == "":
            norm_segs = norm_segs[:-1]
        if len(raw_segs) == len(norm_segs) and raw_segs:
            new_segs: list[str] = []
            replaced = False
            for raw_seg, norm_seg in zip(raw_segs, norm_segs):
                if (
                    norm_seg.startswith("{")
                    and norm_seg.endswith("}")
                    and norm_seg[1:-1] == name
                ):
                    new_segs.append(encoded)
                    replaced = True
                else:
                    new_segs.append(raw_seg)
            if replaced:
                new_path = "/" + "/".join(new_segs)
                if path.endswith("/") and not new_path.endswith("/"):
                    new_path += "/"
                return urlunparse(parsed._replace(path=new_path))
        return url

    # Fallback without normalized path: single-segment path with brace-less name.
    # If the path is /x/{name}/y as literal braces (rare), replace that token.
    brace = "{" + name + "}"
    if brace in path:
        new_path = path.replace(brace, encoded)
        return urlunparse(parsed._replace(path=new_path))

    return url


# ---------------------------------------------------------------------------
# Header / cookie injection (hardened)
# ---------------------------------------------------------------------------

def inject_header_param(headers: dict, name: str, value: str) -> dict:
    """
    Purpose:
        Replace or add a header value (case-insensitive key match).
        Preserves original key casing when replacing; adds ``name`` if absent.
        Hop-by-hop headers are left unchanged (policy).
    Side effects: None.
    """
    if is_hop_by_hop_header(name):
        return dict(headers or {})

    result: dict = {}
    found = False
    target = (name or "").lower()
    for k, v in (headers or {}).items():
        if str(k).lower() == target:
            result[k] = value
            found = True
        else:
            result[k] = v
    if not found and name:
        result[name] = value
    return result


def inject_cookie_param(headers: dict, name: str, value: str) -> dict:
    """
    Purpose:
        Replace a specific cookie value in the Cookie header, preserving other
        cookies and original Cookie header key casing.  If the named cookie is
        absent, appends it.  If no Cookie header exists, creates one.
        Cookie names are matched case-sensitively (RFC 6265).
    Side effects: None.
    """
    result = dict(headers or {})
    cookie_key = None
    raw_cookie = ""
    for k, v in result.items():
        if str(k).lower() == "cookie":
            cookie_key = k
            if isinstance(v, list):
                # Multi-valued Cookie headers: join with "; ".
                raw_cookie = "; ".join(str(x) for x in v if x is not None)
            else:
                raw_cookie = v if isinstance(v, str) else (str(v) if v else "")
            break

    parts: list[str] = []
    found = False
    if raw_cookie:
        for part in raw_cookie.split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                k, _, _v = part.partition("=")
                if k.strip() == name:
                    parts.append(f"{k.strip()}={value}")
                    found = True
                else:
                    parts.append(part)
            else:
                parts.append(part)
    if not found and name:
        parts.append(f"{name}={value}")

    new_cookie = "; ".join(parts)
    if cookie_key is not None:
        result[cookie_key] = new_cookie
    else:
        result["Cookie"] = new_cookie
    return result


# ---------------------------------------------------------------------------
# Query / form / JSON (shared)
# ---------------------------------------------------------------------------

def inject_query_param(url: str, name: str, value: str) -> str:
    """Replace or append a query parameter. Side effects: None."""
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    found = False
    new_pairs: list[tuple[str, str]] = []
    for k, v in pairs:
        if k == name:
            new_pairs.append((k, value))
            found = True
        else:
            new_pairs.append((k, v))
    if not found:
        new_pairs.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(new_pairs)))


def inject_form_param(body: bytes | None, name: str, value: str) -> bytes:
    """Replace or append a URL-encoded form field. Side effects: None."""
    text = (body or b"").decode("utf-8", errors="replace")
    pairs = parse_qsl(text, keep_blank_values=True)
    found = False
    new_pairs: list[tuple[str, str]] = []
    for k, v in pairs:
        if k == name:
            new_pairs.append((k, value))
            found = True
        else:
            new_pairs.append((k, v))
    if not found:
        new_pairs.append((name, value))
    return urlencode(new_pairs).encode("utf-8")


def _set_nested(obj: object, parts: list[str], value: Any) -> None:
    """Walk/create dict path and set the leaf. Side effects: mutates obj."""
    if not isinstance(obj, dict) or not parts:
        return
    head, *tail = parts
    if not tail:
        obj[head] = value  # type: ignore[index]
        return
    child = obj.get(head) if head in obj else None  # type: ignore[index]
    if not isinstance(child, dict):
        obj[head] = {}  # type: ignore[index]
    _set_nested(obj[head], tail, value)  # type: ignore[index]


def inject_json_param(body: bytes | None, name: str, value: str) -> bytes:
    """
    Purpose:
        Set a dotted JSON path (e.g. address.city or variables.id) to value.
        Creates intermediate objects when missing.
    Side effects: None.
    """
    if not body:
        root: Any = {}
    else:
        try:
            root = json.loads(body.decode("utf-8", errors="replace"))
        except Exception:
            return body or b"{}"
        if not isinstance(root, dict):
            root = {}
    parts = [p for p in name.split(".") if p]
    if not parts:
        return body or b"{}"
    _set_nested(root, parts, value)
    return json.dumps(root, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Multipart
# ---------------------------------------------------------------------------

def inject_multipart_param(
    body: bytes | None,
    content_type: str,
    name: str,
    value: str,
    *,
    target: str = "value",
) -> bytes:
    """
    Purpose:
        Replace a multipart field value or filename for ``name``.

        target='value'    — replace part body (text fields).
        target='filename' — replace filename="…" attribute (file uploads).

    Input:
        body, content_type — original request body and Content-Type (boundary).
        name               — multipart field name.
        value              — probe string.
        target             — value | filename.

    Output:
        Mutated body bytes, or original body if boundary/name not found.

    Side effects: None.
    """
    if not body:
        return b""
    m = _BOUNDARY_RE.search(content_type or "")
    if not m:
        return body
    boundary = m.group(1).strip().strip('"')
    delimiter = b"--" + boundary.encode("latin-1", errors="replace")
    try:
        parts = body.split(delimiter)
    except Exception:
        return body

    out_parts: list[bytes] = []
    changed = False
    for part in parts:
        if not part or part.startswith(b"--"):
            out_parts.append(part)
            continue
        # Preserve leading CRLF from split.
        prefix = b""
        work = part
        if work.startswith(b"\r\n"):
            prefix = b"\r\n"
            work = work[2:]
        elif work.startswith(b"\n"):
            prefix = b"\n"
            work = work[1:]

        if b"\r\n\r\n" in work:
            head_raw, part_body = work.split(b"\r\n\r\n", 1)
            sep = b"\r\n\r\n"
        elif b"\n\n" in work:
            head_raw, part_body = work.split(b"\n\n", 1)
            sep = b"\n\n"
        else:
            out_parts.append(part)
            continue

        head_text = head_raw.decode("utf-8", errors="replace")
        name_m = _NAME_ATTR_RE.search(head_text)
        if not name_m or name_m.group(1) != name:
            out_parts.append(part)
            continue

        if target == "filename":
            new_head, nsub = _FILENAME_ATTR_RE.subn(
                lambda mo: f"{mo.group(1)}{value}{mo.group(3)}",
                head_text,
                count=1,
            )
            if nsub == 0:
                # No filename attr — add one after name=.
                new_head = re.sub(
                    r'(name="[^"]+")',
                    rf'\1; filename="{value}"',
                    head_text,
                    count=1,
                )
            head_raw = new_head.encode("utf-8", errors="replace")
            changed = True
            out_parts.append(prefix + head_raw + sep + part_body)
            continue

        # Field value: replace body; preserve trailing CRLF before next delimiter.
        trailing = b""
        core = part_body
        if core.endswith(b"\r\n"):
            trailing = b"\r\n"
            core = core[:-2]
        elif core.endswith(b"\n"):
            trailing = b"\n"
            core = core[:-1]
        if core.endswith(b"--"):
            out_parts.append(part)
            continue
        new_body = value.encode("utf-8", errors="replace") + trailing
        changed = True
        out_parts.append(prefix + head_raw + sep + new_body)

    if not changed:
        return body
    return delimiter.join(out_parts)


def inject_multipart_filename(
    body: bytes | None,
    content_type: str,
    name: str,
    value: str,
) -> bytes:
    """Replace multipart filename for field ``name``. Side effects: None."""
    return inject_multipart_param(
        body, content_type, name, value, target="filename"
    )


# ---------------------------------------------------------------------------
# GraphQL
# ---------------------------------------------------------------------------

def inject_graphql_param(body: bytes | None, name: str, value: str) -> bytes:
    """
    Purpose:
        Inject into GraphQL JSON request bodies.

        - operationName → top-level operationName
        - variables.foo / variables.foo.bar → nested under variables
        - bare names → variables.<name> when a variables object exists,
          else top-level JSON path (same as inject_json_param)

    Side effects: None.
    """
    if not body:
        root: dict[str, Any] = {"query": "", "variables": {}}
    else:
        try:
            parsed = json.loads(body.decode("utf-8", errors="replace"))
        except Exception:
            return body or b"{}"
        if not isinstance(parsed, dict):
            return body or b"{}"
        root = parsed

    if name == "operationName":
        root["operationName"] = value
        return json.dumps(root, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    path = name
    if path.startswith("variables."):
        path = path  # already fully qualified for inject_json
        return inject_json_param(
            json.dumps(root).encode("utf-8"),
            path,
            value,
        )

    # Bare variable name under variables.
    variables = root.get("variables")
    if not isinstance(variables, dict):
        root["variables"] = {}
        variables = root["variables"]
    parts = [p for p in path.split(".") if p]
    if parts and parts[0] == "variables":
        parts = parts[1:]
    if not parts:
        return json.dumps(root, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    _set_nested(variables, parts, value)
    root["variables"] = variables
    return json.dumps(root, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# XML
# ---------------------------------------------------------------------------

def inject_xml_param(body: bytes | None, name: str, value: str) -> bytes:
    """
    Purpose:
        Replace text of the first leaf element whose local tag equals ``name``
        (namespace URI stripped).  Non-leaf matches are ignored.
    Side effects: None.
    """
    if not body:
        return b""
    try:
        text = body.decode("utf-8", errors="replace")
        root = ElementTree.fromstring(text)
    except Exception:
        return body

    target = name
    if "}" in target:
        target = target.split("}", 1)[1]

    def _local(tag: str) -> str:
        return tag.split("}", 1)[1] if "}" in tag else tag

    def _walk(el: ElementTree.Element) -> bool:
        if _local(el.tag) == target and len(list(el)) == 0:
            el.text = value
            return True
        for child in el:
            if _walk(child):
                return True
        return False

    if not _walk(root):
        return body

    # Preserve XML declaration if present.
    out = ElementTree.tostring(root, encoding="utf-8")
    if text.lstrip().startswith("<?xml"):
        decl_end = text.find("?>")
        if decl_end != -1:
            decl = text[: decl_end + 2].encode("utf-8")
            return decl + b"\n" + out
    return out


# ---------------------------------------------------------------------------
# Unified inject
# ---------------------------------------------------------------------------

def inject_value(
    location: str,
    name: str,
    value: str,
    url: str,
    headers: dict,
    body: bytes | None,
    *,
    normalized_path: str = "",
    semantic_type: str = "",
    surface_kind: str = "",
) -> tuple[str, dict, bytes | None]:
    """
    Purpose:
        Inject probe ``value`` into the correct request location / body type.

    Input:
        location         — path|query|body|header|cookie.
        name             — parameter name (path brace name, header key, …).
        value            — probe payload.
        url/headers/body — base request parts.
        normalized_path  — required for reliable path injection.
        semantic_type    — passive type (filename → multipart filename).
        surface_kind     — optional precomputed kind; else detected.

    Output:
        (new_url, new_headers, new_body).

    Side effects: None.
    """
    loc = (location or "").strip().lower()
    ct_raw = content_type_of(headers, lower=False)
    ct = ct_raw.lower()
    kind = surface_kind or detect_surface_kind(
        location=loc,
        param_name=name,
        content_type=ct,
        semantic_type=semantic_type,
        body=body,
    )

    if loc == LOCATION_QUERY:
        return inject_query_param(url, name, value), headers, body

    if loc == LOCATION_PATH:
        return (
            inject_path_param(
                url, name, value, normalized_path=normalized_path
            ),
            headers,
            body,
        )

    if loc == LOCATION_HEADER:
        return url, inject_header_param(headers, name, value), body

    if loc == LOCATION_COOKIE:
        return url, inject_cookie_param(headers, name, value), body

    if loc == LOCATION_BODY:
        # Multipart boundary is case-sensitive — always pass raw Content-Type.
        if kind == SURFACE_MULTIPART_FILENAME or (
            kind == SURFACE_MULTIPART_FIELD and semantic_type == "filename"
        ):
            return url, headers, inject_multipart_filename(
                body, ct_raw, name, value
            )
        if kind in (SURFACE_MULTIPART_FIELD, SURFACE_MULTIPART_FILENAME) or "multipart/form-data" in ct:
            if semantic_type == "filename" or kind == SURFACE_MULTIPART_FILENAME:
                return url, headers, inject_multipart_filename(
                    body, ct_raw, name, value
                )
            return url, headers, inject_multipart_param(
                body, ct_raw, name, value, target="value"
            )
        if kind == SURFACE_GRAPHQL_VARIABLE or "graphql" in ct or (
            body and _looks_like_graphql_json(body) and (
                name.startswith("variables") or name == "operationName"
            )
        ):
            return url, headers, inject_graphql_param(body, name, value)
        if kind == SURFACE_XML_LEAF or "xml" in ct or "soap" in ct:
            return url, headers, inject_xml_param(body, name, value)
        if "json" in ct or kind == SURFACE_JSON_BODY:
            return url, headers, inject_json_param(body, name, value)
        if "x-www-form-urlencoded" in ct or kind == SURFACE_FORM_BODY:
            return url, headers, inject_form_param(body, name, value)
        # Unknown body: try JSON then form.
        if body and body.lstrip().startswith(b"{"):
            return url, headers, inject_json_param(body, name, value)
        if body and b"=" in body[:200]:
            return url, headers, inject_form_param(body, name, value)
        return url, headers, body

    return url, headers, body


def surface_meta(
    *,
    location: str,
    param_name: str = "",
    content_type: str = "",
    semantic_type: str = "",
    body: bytes | None = None,
    skip: SkipDecision | None = None,
) -> dict[str, Any]:
    """
    Purpose:
        Build a small surface descriptor for profile.observed.surface / cache.
    Side effects: None.
    """
    kind = detect_surface_kind(
        location=location,
        param_name=param_name,
        content_type=content_type,
        semantic_type=semantic_type,
        body=body,
    )
    meta: dict[str, Any] = {
        "location": (location or "").strip().lower(),
        "kind": kind,
    }
    if skip and skip.skip:
        meta["skipped"] = True
        meta["skip_reason"] = skip.reason
        meta["skip_detail"] = skip.detail
    return meta
