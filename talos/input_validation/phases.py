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
        IV_IDENTIFIER_PROBES  — legacy weak fixed tokens (exhaustive strategy
                                only; default path uses multiprobe canaries).
        IV_TEST_CHARS         — legacy 30-char list (exhaustive escape hatch;
                                Module 6 prefers taxonomy.char_probes_for_strategy).
        IV_TEST_LENGTHS       — legacy 10 fixed lengths (exhaustive / matrix mode;
                                Module 6 prefers length_search binary/log seeds).
        IV_TYPE_PROBES        — full type matrix (exhaustive / legacy).
                                Module 7 prefers type_intel.select_type_probes
                                (passive-first pruning under standard).
        prepare_iv_probe      — Module 8 structural inject (dup/JSON null/array)
                                via payload_type / injection_mode; Module 9
                                path/header/cookie/multipart/GraphQL/XML inject.
        IV_VALIDATION_PROBES  — full legacy validation list.  Module 7 splits
                                core (empty/null/length/numeric) vs edge
                                (SQLi/XSS-shaped: deep/exhaustive only) via
                                type_intel.validation_probes_for_strategy.

    Phase map (HTTP requests; M4 multiprobe + M6 taxonomy/length + M7 types):
        baseline        — 1  (original request, no mutation)
        multiprobe      — 1  (canary + taxonomy samples; see multiprobe.py)
        identifier      — strategy-dependent canaries (legacy list: exhaustive)
        characters      — class representatives (standard) or drill-down (deep);
                          full extended list under exhaustive; skipped under
                          standard/quick when multiprobe is on
        length          — logarithmic seed (≤5 standard) + binary refine;
                          full IV_TEST_LENGTHS under exhaustive
        types           — pruned type_confirm (standard ~2–4) or full 12 matrix
        validation      — semantic_rules + core validation (no exploit strings
                          by default); edge SQLi/XSS shapes on deep+ only
        transformations — 0  (pure analysis of existing flows)
        reflection      — 0  (pure analysis of existing flows)

Dependencies: json, urllib.parse; surface (Module 9 injectors)
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
from urllib.parse import quote

from talos.input_validation.surface import inject_value as surface_inject_value


# ---------------------------------------------------------------------------
# Probe lists
# ---------------------------------------------------------------------------

# Legacy weak identifier probes (Module 4: used only under probe_strategy=
# exhaustive).  Default/standard path uses high-entropy canaries via
# multiprobe.identifier_probes_for_strategy / multiprobe jobs instead.
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

# Legacy thirty characters covering injection-relevant classes.
# Module 6: prefer taxonomy.EXHAUSTIVE_TEST_CHARS / char_probes_for_strategy;
# this list remains the stable exhaustive matrix core (no structure chars).
IV_TEST_CHARS: list[str] = [
    "a", "1", "_", "-", ".", " ", ",", ":", ";",
    "'", '"', "`", "<", ">", "(", ")", "[", "]",
    "{", "}", "/", "\\", "%", "+", "=", "#", "@", "&", "?",
]

# Legacy ten lengths for truncation and limit detection (exhaustive matrix).
# Module 6 standard path uses length_search.seed_lengths() instead (≤5).
IV_TEST_LENGTHS: list[int] = [1, 4, 8, 16, 32, 64, 128, 256, 512, 1024]

# Type probes: (payload_class_label, value_string).
# Module 7: type_intel.select_type_probes prunes this matrix under standard;
# exhaustive / ACTION_TYPES still uses the full list.
IV_TYPE_PROBES: list[tuple[str, str]] = [
    ("integer",   "42"),
    ("float",     "3.14"),
    ("boolean",   "true"),
    ("boolean_false", "false"),
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
# Module 7 core (always when validation on): empty, whitespace, null_byte,
# very_long, negative_int, float.  Edge exploit-shaped strings (special_chars,
# html_injection) are deep/exhaustive only — not required for default validation.
IV_VALIDATION_PROBES: list[tuple[str, str]] = [
    ("empty",          ""),
    ("whitespace",     "   "),
    ("null_byte",      "\x00"),
    ("very_long",      "A" * 10000),
    ("special_chars",  "'; DROP TABLE--"),  # edge: deep+ only
    ("html_injection", "<script>x</script>"),  # edge: deep+ only
    ("negative_int",   "-999999"),
    ("float",          "9.9999999"),
]

# Core-only subset labels (Module 7 default validation path).
IV_VALIDATION_CORE_LABELS: frozenset[str] = frozenset({
    "empty", "whitespace", "null_byte", "very_long", "negative_int", "float",
})

# Edge exploit-shaped labels (deep/exhaustive only).
IV_VALIDATION_EDGE_LABELS: frozenset[str] = frozenset({
    "special_chars", "html_injection",
})


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


def _inject_value(
    location: str,
    name: str,
    value: str,
    url: str,
    headers: dict,
    body: bytes | None,
    *,
    normalized_path: str = "",
    semantic_type: str = "",
    payload_type: str = "",
) -> tuple[str, dict, bytes | None]:
    """
    Purpose:
        Inject probe value into the correct request location (Module 9:
        path, header, cookie, multipart, GraphQL, XML, JSON, form).
    Output:
        (new_url, new_headers, new_body) tuple.
    Side effects: None.
    """
    return surface_inject_value(
        location,
        name,
        value,
        url,
        headers,
        body,
        normalized_path=normalized_path,
        semantic_type=semantic_type,
        payload_type=payload_type,
    )


# ---------------------------------------------------------------------------
# Request preparation — called by scheduler._execute_iv_job
# ---------------------------------------------------------------------------

def prepare_iv_probe(
    analysis: str,
    flow: dict,
    param_name: str,
    location: str,
    payload: str | None,
    *,
    payload_type: str | None = None,
    injection_mode: str | None = None,
    normalized_path: str | None = None,
    semantic_type: str | None = None,
) -> dict:
    """
    Purpose:
        Build a mutations dict for one IV probe by injecting payload into the
        specified parameter location.  The dict is passed directly to
        replay_with_mutation() — no HTTP is sent here.

        For the 'baseline' analysis (payload=None) the mutations dict is empty,
        meaning the original request is replayed unchanged.

        Module 8: when ``injection_mode`` or a ``parser:`` / ``norm:``
        ``payload_type`` is set, structural injections (duplicate query keys,
        JSON null/omit/dup-key, array styles) are applied via parser_intel.

        Module 9: path segments (via normalized_path), multipart field/filename,
        GraphQL variables, XML leaves, hardened header/cookie inject.

    Input:
        analysis         — analysis name (baseline|identifier|characters|…).
        flow             — base flow dict (original captured request).
        param_name       — parameter name to inject into.
        location         — path|query|body|header|cookie.
        payload          — exact string to inject; None for baseline.
        payload_type     — optional probe label (norm:trim, parser:dup_query, …).
        injection_mode   — optional explicit mode (dup_query, json_null, …).
        normalized_path  — endpoint pattern for path params (optional; flow may
                           already carry normalized_path).
        semantic_type    — passive semantic (filename → multipart filename).
    Output:
        dict with any subset of {url, request_headers, request_body} that
        differ from the original.  Empty dict means no mutation (baseline).
    Side effects: None.
    """
    if payload is None or analysis == "baseline":
        return {}

    method, url, headers, body = _get_flow_parts(flow)
    norm_path = (
        normalized_path
        if normalized_path is not None
        else str(flow.get("normalized_path") or "")
    )
    sem = (
        semantic_type
        if semantic_type is not None
        else str(flow.get("semantic_type") or "")
    )

    # Module 8 structural / typed injection.
    mode = injection_mode
    if not mode and payload_type:
        from talos.input_validation.parser_intel import (
            injection_mode_for_payload_type,
            is_parser_payload_type,
        )
        if is_parser_payload_type(payload_type):
            mode = injection_mode_for_payload_type(payload_type)

    ptype = payload_type or ""
    if mode and mode != "value":
        from talos.input_validation.parser_intel import apply_parser_injection
        new_url, new_headers, new_body = apply_parser_injection(
            injection_mode=mode,
            location=location,
            name=param_name,
            payload=payload or "",
            url=url,
            headers=headers,
            body=body,
            normalized_path=norm_path,
            semantic_type=sem,
            payload_type=ptype,
        )
    elif mode == "value" or (
        payload_type and str(payload_type).startswith("norm:")
    ):
        # Normalization probes use surface-aware value inject.
        new_url, new_headers, new_body = _inject_value(
            location,
            param_name,
            payload or "",
            url,
            headers,
            body,
            normalized_path=norm_path,
            semantic_type=sem,
            payload_type=ptype,
        )
    else:
        new_url, new_headers, new_body = _inject_value(
            location,
            param_name,
            payload,
            url,
            headers,
            body,
            normalized_path=norm_path,
            semantic_type=sem,
            payload_type=ptype,
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
                   f.endpoint_id, f.role_id, f.module_id, f.source,
                   e.normalized_path AS normalized_path,
                   p.semantic_type AS semantic_type
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
            SELECT f.id, f.method, f.url, f.host, f.path, f.query,
                   f.request_headers, f.request_cookies,
                   f.request_body, f.request_body_truncated,
                   f.status_code, f.response_body, f.response_headers, f.content_type,
                   f.endpoint_id, f.role_id, f.module_id, f.source,
                   e.normalized_path AS normalized_path
            FROM flows f
            LEFT JOIN endpoints e ON e.id = f.endpoint_id
            WHERE f.endpoint_id = ? AND f.status_code = 200
              AND f.source = 'proxy_capture'
            ORDER BY f.captured_at DESC
            LIMIT 1
            """,
            (endpoint_id,),
        ).fetchone()
    return dict(row) if row else None
