"""
Module: talos.input_validation.phases

Purpose:
    Two responsibilities only:

    1. Request preparation — mutate a base flow dict by injecting a probe
       payload into the target parameter.  Returns a mutations dict that
       replay_with_mutation() uses to create the actual replay flow.

    2. Pure analysis — derive transformation and reflection conclusions from
       a set of already-completed replay flows.  Zero outbound HTTP requests.

    Probe lists (used by the scheduling engine to generate per-probe jobs):
        IV_IDENTIFIER_PROBES  — 9 identifier values that survive URL/HTML
                                encoding and detect reflection.
        IV_TEST_CHARS         — 30 characters for character acceptance testing.
        IV_TEST_LENGTHS       — 10 byte lengths for length behaviour testing.
        IV_TYPE_PROBES        — (name, value) pairs for type characterisation.
        IV_VALIDATION_PROBES  — (name, value) pairs for validation behaviour.

    Phase map (HTTP requests generated per phase):
        baseline        — 1  (original request, no mutation)
        identifier      — 9  (one per IV_IDENTIFIER_PROBES entry)
        characters      — 30 (one per IV_TEST_CHARS entry)
        length          — 10 (one per IV_TEST_LENGTHS entry)
        types           — 12 (one per IV_TYPE_PROBES entry)
        validation      — 8  (one per IV_VALIDATION_PROBES entry)
        transformations — 0  (pure analysis of existing flows)
        reflection      — 0  (pure analysis of existing flows)

Dependencies: json, urllib.parse
Data flow:
    engine.py → probe lists → scheduler_jobs (one job per probe)
    scheduler._execute_iv_job → prepare_iv_probe() → mutations dict
                               → replay_with_mutation() → replay flow
    scheduler._execute_iv_job → analyze_transformations() / analyze_reflection()
                               → iv_param_cache / iv_reflection_cache
Side effects:
    None — this module is pure computation.  All HTTP is handled by callers.
"""

import json
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse


# ---------------------------------------------------------------------------
# Probe lists
# ---------------------------------------------------------------------------

# Nine identifier probes that span numeric, alphabetic, and mixed forms.
IV_IDENTIFIER_PROBES: list[str] = [
    "123456",
    "987654",
    "135790",
    "abcdef",
    "ABCDEF",
    "AbCdEf",
    "abc123",
    "ABC123",
    "a1b2c3",
]

# Thirty characters covering injection-relevant classes.
IV_TEST_CHARS: list[str] = [
    "a", "1", "_", "-", ".", " ", ",", ":", ";",
    "'", '"', "`", "<", ">", "(", ")", "[", "]",
    "{", "}", "/", "\\", "%", "+", "=", "#", "@", "&", "?",
]

# Ten lengths for truncation and limit detection.
IV_TEST_LENGTHS: list[int] = [1, 4, 8, 16, 32, 64, 128, 256, 512, 1024]

# Type probes: (payload_class_label, value_string).
IV_TYPE_PROBES: list[tuple[str, str]] = [
    ("integer",   "42"),
    ("float",     "3.14"),
    ("boolean",   "true"),
    ("uuid",      "550e8400-e29b-41d4-a716-446655440000"),
    ("email",     "probe@talos.test"),
    ("url",       "https://talos.test/probe"),
    ("timestamp", "1700000000"),
    ("iso_date",  "2024-01-15"),
    ("hash_md5",  "d41d8cd98f00b204e9800998ecf8427e"),
    ("string",    "testvalue"),
    ("empty",     ""),
    ("null_str",  "null"),
]

# Validation probes: (payload_class_label, value_string).
IV_VALIDATION_PROBES: list[tuple[str, str]] = [
    ("empty",          ""),
    ("whitespace",     "   "),
    ("null_byte",      "\x00"),
    ("very_long",      "A" * 10000),
    ("special_chars",  "'; DROP TABLE--"),
    ("html_injection", "<script>x</script>"),
    ("negative_int",   "-999999"),
    ("float",          "9.9999999"),
]


# ---------------------------------------------------------------------------
# Injection helpers (pure functions — no I/O)
# ---------------------------------------------------------------------------

def _get_flow_parts(flow: dict) -> tuple[str, str, dict, bytes | None]:
    """
    Purpose:
        Extract (method, url, headers_dict, body_bytes) from a flow dict.
    Side effects: None.
    """
    method: str = flow["method"]
    url: str = flow["url"]
    raw_headers = flow.get("request_headers", "{}")
    headers: dict = (
        json.loads(raw_headers) if isinstance(raw_headers, str) else dict(raw_headers)
    )
    body: bytes | None = flow.get("request_body")
    return method, url, headers, body


def _inject_query_param(url: str, name: str, value: str) -> str:
    """Replace the value of a query parameter in a URL."""
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs = [(k, value if k == name else v) for k, v in pairs]
    new_query = urlencode(new_pairs)
    return urlunparse(parsed._replace(query=new_query))


def _inject_json_param(body: bytes | None, name: str, value: str) -> bytes:
    """
    Purpose:
        Replace a value in a JSON body.
        Handles dotted path keys (e.g. 'address.city').
        Array notation (e.g. 'items[]') is unsupported — body returned unchanged.
    Side effects: None.
    """
    if not body:
        return b"{}"
    try:
        parsed = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return body or b""
    parts = name.split(".")
    _set_nested(parsed, parts, value)
    return json.dumps(parsed).encode("utf-8")


def _set_nested(obj: object, parts: list[str], value: str) -> None:
    """Walk obj following parts, replacing the final key with value."""
    if not isinstance(obj, dict) or not parts:
        return
    head, *tail = parts
    if not tail:
        if head in obj:
            obj[head] = value  # type: ignore[index]
    else:
        if head in obj and isinstance(obj[head], dict):  # type: ignore[index]
            _set_nested(obj[head], tail, value)  # type: ignore[index]


def _inject_form_param(body: bytes | None, name: str, value: str) -> bytes:
    """Replace a value in a URL-encoded form body."""
    if not body:
        return b""
    text = body.decode("utf-8", errors="replace")
    pairs = parse_qsl(text, keep_blank_values=True)
    new_pairs = [(k, value if k == name else v) for k, v in pairs]
    return urlencode(new_pairs).encode("utf-8")


def _inject_header_param(headers: dict, name: str, value: str) -> dict:
    """Replace a header value (case-insensitive key match)."""
    result = {}
    for k, v in headers.items():
        result[k] = value if k.lower() == name.lower() else v
    return result


def _inject_cookie_param(headers: dict, name: str, value: str) -> dict:
    """Replace a specific cookie value in the Cookie header."""
    result = dict(headers)
    raw_cookie = ""
    for k, v in headers.items():
        if k.lower() == "cookie":
            raw_cookie = v if isinstance(v, str) else (v[0] if v else "")
            break
    if not raw_cookie:
        return result
    parts = []
    for part in raw_cookie.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            parts.append(f"{k.strip()}={value}" if k.strip() == name else part)
        else:
            parts.append(part)
    new_cookie = "; ".join(parts)
    for k in result:
        if k.lower() == "cookie":
            result[k] = new_cookie
            break
    return result


def _get_content_type(headers: dict) -> str:
    for k, v in headers.items():
        if k.lower() == "content-type":
            return (v if isinstance(v, str) else (v[0] if v else "")).lower()
    return ""


def _inject_value(
    location: str,
    name: str,
    value: str,
    url: str,
    headers: dict,
    body: bytes | None,
) -> tuple[str, dict, bytes | None]:
    """
    Purpose:
        Inject probe value into the correct request location.
    Output:
        (new_url, new_headers, new_body) tuple.
    Side effects: None.
    """
    if location == "query":
        return _inject_query_param(url, name, value), headers, body

    if location == "body":
        ct = _get_content_type(headers)
        if "json" in ct:
            return url, headers, _inject_json_param(body, name, value)
        if "x-www-form-urlencoded" in ct:
            return url, headers, _inject_form_param(body, name, value)
        return url, headers, body

    if location == "header":
        return url, _inject_header_param(headers, name, value), body

    if location == "cookie":
        return url, _inject_cookie_param(headers, name, value), body

    # path: best-effort not implemented — return unchanged.
    return url, headers, body


# ---------------------------------------------------------------------------
# Request preparation — called by scheduler._execute_iv_job
# ---------------------------------------------------------------------------

def prepare_iv_probe(
    analysis: str,
    flow: dict,
    param_name: str,
    location: str,
    payload: str | None,
) -> dict:
    """
    Purpose:
        Build a mutations dict for one IV probe by injecting payload into the
        specified parameter location.  The dict is passed directly to
        replay_with_mutation() — no HTTP is sent here.

        For the 'baseline' analysis (payload=None) the mutations dict is empty,
        meaning the original request is replayed unchanged.

    Input:
        analysis   — analysis name (baseline|identifier|characters|…).
        flow       — base flow dict (original captured request).
        param_name — parameter name to inject into.
        location   — path|query|body|header|cookie.
        payload    — exact string to inject; None for baseline.
    Output:
        dict with any subset of {url, request_headers, request_body} that
        differ from the original.  Empty dict means no mutation (baseline).
    Side effects: None.
    """
    if payload is None or analysis == "baseline":
        return {}

    method, url, headers, body = _get_flow_parts(flow)
    new_url, new_headers, new_body = _inject_value(
        location, param_name, payload, url, headers, body
    )

    mutations: dict = {}
    if new_url != url:
        mutations["url"] = new_url
    if new_headers != headers:
        mutations["request_headers"] = new_headers
    if new_body != body:
        mutations["request_body"] = new_body

    return mutations


# ---------------------------------------------------------------------------
# Pure analysis — zero HTTP requests
# ---------------------------------------------------------------------------

def analyze_transformations(probe_flow_records: list[dict]) -> dict:
    """
    Purpose:
        Derive transformation conclusions from the replay flows generated for
        a parameter during identifier and character phases.
        Detects trim, lowercase, uppercase, and similar normalisation.

        This function consumes already-stored replay flow response data; it
        never sends any HTTP request.

    Input:
        probe_flow_records — list of dicts, each with:
            payload      (str)  — injected payload string.
            payload_class (str) — class label (identifier, character, …).
            status_code  (int)  — HTTP response status.
            body         (str)  — decoded response body.
    Output:
        dict: {
            transformations: list[str],   — detected transform names
            evidence: list[dict],
        }
    Side effects: None.
    """
    transformations: set[str] = set()
    evidence: list[dict] = []

    for rec in probe_flow_records:
        probe = rec.get("payload") or ""
        resp_body = rec.get("body") or ""
        if not probe or not resp_body:
            continue

        detected: list[str] = []
        reflected_as = ""

        if probe in resp_body:
            reflected_as = probe
        elif probe.strip() in resp_body:
            reflected_as = probe.strip()
            detected.append("trim")
        elif probe.strip().lower() in resp_body:
            reflected_as = probe.strip().lower()
            detected.extend(["trim", "lowercase"])
        elif probe.strip().upper() in resp_body:
            reflected_as = probe.strip().upper()
            detected.extend(["trim", "uppercase"])
        elif probe.lower() in resp_body:
            reflected_as = probe.lower()
            detected.append("lowercase")
        elif probe.upper() in resp_body:
            reflected_as = probe.upper()
            detected.append("uppercase")

        if detected:
            transformations.update(detected)
            evidence.append({
                "payload": probe,
                "reflected_as": reflected_as,
                "transforms": detected,
            })

    return {
        "transformations": sorted(transformations),
        "evidence": evidence,
    }


def analyze_reflection(
    probe_flow_records: list[dict],
    param_name: str,
    endpoint_id: str,
) -> dict:
    """
    Purpose:
        Determine reflection characteristics for a specific endpoint+parameter
        by analysing the set of replay flows already generated for it.
        Zero HTTP requests — consumes only stored response body data.

    Input:
        probe_flow_records — list of dicts with keys:
            payload       (str)  — injected payload string.
            status_code   (int)  — HTTP response status.
            body          (str)  — decoded response body.
            content_type  (str)  — response Content-Type.
            flow_id       (str)  — UUID of the replay flow (optional).
        param_name         — parameter name (stored in result for context).
        endpoint_id        — endpoint UUID (stored in result for context).
    Output:
        dict: {
            reflected          (bool),
            reflection_count   (int),
            reflection_location (str),  — html|json|xml|javascript|other|''
            encoding           (str),   — raw|html_encoded|url_encoded|''
            reflected_payloads (list),  — payloads that were reflected
            evidence_flow_ids  (list),  — flow UUIDs where reflection found
            param_name         (str),
            endpoint_id        (str),
        }
    Side effects: None.
    """
    reflected_payloads: list[str] = []
    evidence_flow_ids: list[str] = []
    total_count = 0
    location = ""
    encoding = ""

    def _html_enc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    for rec in probe_flow_records:
        payload = rec.get("payload") or ""
        resp_body = rec.get("body") or ""
        ct = (rec.get("content_type") or "").lower()
        flow_id = rec.get("flow_id") or ""
        if not payload or not resp_body:
            continue

        found_enc = ""
        found = False

        if payload in resp_body:
            found = True
            found_enc = "raw"
        elif _html_enc(payload) in resp_body:
            found = True
            found_enc = "html_encoded"
        elif quote(payload, safe="") in resp_body:
            found = True
            found_enc = "url_encoded"

        if found:
            reflected_payloads.append(payload)
            if flow_id:
                evidence_flow_ids.append(flow_id)
            total_count += resp_body.count(payload)
            if not location:
                location = (
                    "html" if "html" in ct
                    else "json" if "json" in ct
                    else "xml" if "xml" in ct
                    else "javascript" if "javascript" in ct
                    else "other"
                )
            if not encoding:
                encoding = found_enc

    return {
        "reflected": bool(reflected_payloads),
        "reflection_count": total_count,
        "reflection_location": location,
        "encoding": encoding,
        "reflected_payloads": reflected_payloads,
        "evidence_flow_ids": evidence_flow_ids,
        "param_name": param_name,
        "endpoint_id": endpoint_id,
    }


# ---------------------------------------------------------------------------
# Legacy flow lookup helpers (used by scheduler until full migration)
# ---------------------------------------------------------------------------

def find_best_flow_for_param(
    db_path,
    host: str,
    location: str,
    param_name: str,
) -> "dict | None":
    """
    Purpose:
        Find the best qualifying replay flow for a parameter identified by
        (host, location, param_name).  Selects the most recent proxy_capture
        flow with status_code=200 from ANY endpoint on that host that carries
        this parameter.
    Input:
        db_path    — project database path.
        host       — hostname the parameter was observed on.
        location   — parameter location (query, body, header, cookie, path).
        param_name — parameter name.
    Output:
        Flow dict ready for HTTP replay, or None if no qualifying flow exists.
    Side effects: Read-only DB access.
    """
    import sqlite3
    from pathlib import Path as _Path
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        flow_row = conn.execute(
            """
            SELECT f.id, f.method, f.url, f.host, f.path, f.query,
                   f.request_headers, f.request_cookies,
                   f.request_body, f.request_body_truncated,
                   f.status_code, f.response_body, f.response_headers, f.content_type,
                   f.endpoint_id, f.role_id, f.module_id, f.source
            FROM flows f
            JOIN endpoints e ON e.id = f.endpoint_id
            JOIN parameters p ON p.endpoint_id = e.id
            WHERE e.host = ? AND p.location = ? AND p.name = ?
              AND f.status_code = 200
              AND f.source = 'proxy_capture'
            ORDER BY f.captured_at DESC
            LIMIT 1
            """,
            (host, location, param_name),
        ).fetchone()
    return dict(flow_row) if flow_row else None


def find_best_flow_for_endpoint(
    db_path,
    endpoint_id: str,
) -> "dict | None":
    """
    Purpose:
        Find the best qualifying flow for a specific endpoint_id.
        Used for reflection and transformation analysis jobs (per-endpoint).
    Output:
        Flow dict, or None.
    Side effects: Read-only DB access.
    """
    import sqlite3
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT id, method, url, host, path, query,
                   request_headers, request_cookies,
                   request_body, request_body_truncated,
                   status_code, response_body, response_headers, content_type,
                   endpoint_id, role_id, module_id, source
            FROM flows
            WHERE endpoint_id = ? AND status_code = 200
              AND source = 'proxy_capture'
            ORDER BY captured_at DESC
            LIMIT 1
            """,
            (endpoint_id,),
        ).fetchone()
    return dict(row) if row else None
