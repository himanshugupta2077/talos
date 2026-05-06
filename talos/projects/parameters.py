"""
Module: talos.projects.parameters

Purpose:
    Extract observable parameters from a captured flow and maintain a
    deduplicated, type-aware parameter inventory per endpoint.

    Only query parameters and request body parameters are extracted.
    Headers and cookies are out of scope for this stage.

Dependencies: dataclasses, json, re, sqlite3, urllib.parse, uuid
Data flow:
    FlowWorker → extract_flow_params() → upsert_endpoint_params() → parameters table
Side effects: None in extraction layer; DB write in upsert layer.
"""

import json
import re
import sqlite3
import uuid
from dataclasses import dataclass
from urllib.parse import parse_qsl


# Maximum number of sampled values stored per parameter.
# Prevents unbounded growth while preserving observational diversity.
_MAX_EXAMPLE_VALUES: int = 5

# Matches a bare integer (positive or negative, no decimals, no leading zeros
# except for "0" itself).
_INT_RE = re.compile(r"^-?(?:0|[1-9]\d*)$")

# Values that unambiguously signal a boolean parameter.
_BOOL_VALUES: frozenset[str] = frozenset({"true", "false", "1", "0", "yes", "no"})


@dataclass(frozen=True, slots=True)
class ExtractedParam:
    """
    Purpose:
        Carry one observed parameter name, location, inferred type, and a sample
        value from a single flow before database persistence.
    Fields:
        name         — Parameter name as supplied by the client.
        location     — Structural origin: 'query' or 'body'.
        param_type   — Inferred scalar type: 'int' | 'bool' | 'string' | 'unknown'.
        sample_value — Raw string value observed in this flow (may be empty).
    Side effects: None.
    """

    name: str
    location: str
    param_type: str
    sample_value: str


def extract_flow_params(
    query: str,
    request_body: bytes | None,
    request_headers: dict,
) -> list[ExtractedParam]:
    """
    Purpose:
        Extract all observable parameters from one captured flow.
    Input:
        query           — Cleaned query string (no tracking/cache-bust params,
                          already sorted). Derived from NormalizedFlowURL.
        request_body    — Raw request body bytes, or None when absent or not stored.
        request_headers — Captured request headers dict (case-insensitive keys).
    Output:
        List of ExtractedParam items. May be empty. No duplicates within a single
        call — later keys shadow earlier ones only within the same location.
    Side effects: None.
    """
    params: list[ExtractedParam] = []
    params.extend(_extract_query_params(query))
    content_type = _get_request_content_type(request_headers)
    params.extend(_extract_body_params(request_body, content_type))
    return params


def upsert_endpoint_params(
    conn: sqlite3.Connection,
    endpoint_id: str,
    params: list[ExtractedParam],
) -> None:
    """
    Purpose:
        Persist a batch of parameter observations for one endpoint.
        Inserts new (endpoint_id, name, location) rows on first observation;
        updates param_type and example_values on subsequent flows.
    Input:
        conn        — Open SQLite connection, caller manages the transaction.
        endpoint_id — UUID of the resolved endpoint these params belong to.
        params      — Parameters extracted from one flow (may be empty).
    Output: None.
    Side effects:
        - Inserts or updates rows in the parameters table.
        - Never deletes existing parameter rows.
    Type update rule:
        'unknown' → known type (int/bool/string) when new evidence arrives.
        A known type is never downgraded — conflicts are silently ignored.
    """
    for param in params:
        row = conn.execute(
            """
            SELECT id, param_type, example_values
            FROM parameters
            WHERE endpoint_id = ? AND name = ? AND location = ?
            """,
            (endpoint_id, param.name, param.location),
        ).fetchone()

        if row is None:
            # First observation of this (endpoint, name, location) triple.
            initial_examples = (
                json.dumps([param.sample_value]) if param.sample_value else "[]"
            )
            conn.execute(
                """
                INSERT INTO parameters
                    (id, endpoint_id, name, location, param_type, example_values)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    endpoint_id,
                    param.name,
                    param.location,
                    param.param_type,
                    initial_examples,
                ),
            )
            continue

        # Upgrade type only from 'unknown' → a known type; never downgrade.
        updated_type: str = row["param_type"]
        if updated_type == "unknown" and param.param_type != "unknown":
            updated_type = param.param_type

        # Merge sample value into the stored list, capped at _MAX_EXAMPLE_VALUES.
        try:
            examples: list = json.loads(row["example_values"])
        except (json.JSONDecodeError, TypeError):
            examples = []

        if not isinstance(examples, list):
            examples = []

        if param.sample_value and param.sample_value not in examples:
            examples.append(param.sample_value)
            # Trim to cap: keep the most recent observations.
            if len(examples) > _MAX_EXAMPLE_VALUES:
                examples = examples[-_MAX_EXAMPLE_VALUES:]

        conn.execute(
            "UPDATE parameters SET param_type = ?, example_values = ? WHERE id = ?",
            (updated_type, json.dumps(examples), row["id"]),
        )


# ------------------------------------------------------------------ #
# Private extraction helpers                                           #
# ------------------------------------------------------------------ #


def _extract_query_params(query: str) -> list[ExtractedParam]:
    """
    Purpose:
        Parse a cleaned query string into ExtractedParam items.
    Input:
        query — cleaned query string (no leading '?').
    Output:
        List of ExtractedParam with location='query'.
    Side effects: None.
    """
    if not query:
        return []

    results: list[ExtractedParam] = []
    for name, value in parse_qsl(query, keep_blank_values=True):
        if not name:
            continue
        results.append(
            ExtractedParam(
                name=name,
                location="query",
                param_type=_infer_type(value),
                sample_value=value,
            )
        )
    return results


def _extract_body_params(
    body: bytes | None,
    content_type: str,
) -> list[ExtractedParam]:
    """
    Purpose:
        Extract parameters from a request body based on its content type.
        Handles JSON objects and URL-encoded form data.
        On malformed or unrecognised body formats: returns an empty list.
    Input:
        body         — Raw request body bytes, or None.
        content_type — Full Content-Type header value.
    Output:
        List of ExtractedParam with location='body'.
    Side effects: None.
    """
    if not body:
        return []

    # Strip charset / boundary directives before comparing.
    ct = content_type.lower().split(";")[0].strip()

    if ct == "application/json":
        return _extract_json_params(body)
    if ct == "application/x-www-form-urlencoded":
        return _extract_form_params(body)
    return []


def _extract_json_params(body: bytes) -> list[ExtractedParam]:
    """
    Purpose:
        Extract top-level key/value pairs from a JSON request body.
        Only processes JSON objects (dicts); arrays and primitives are skipped
        because their keys have no stable semantic meaning.
    Input:
        body — Raw request body bytes.
    Output:
        List of ExtractedParam. Empty on parse failure, non-dict body, or empty object.
    Side effects: None.
    """
    try:
        parsed = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return []

    if not isinstance(parsed, dict):
        return []

    results: list[ExtractedParam] = []
    for name, value in parsed.items():
        if not isinstance(name, str) or not name:
            continue
        # Nested objects/arrays are recorded as 'unknown' — not introspected here.
        if isinstance(value, (dict, list)):
            sample = ""
            inferred = "unknown"
        elif value is None:
            sample = ""
            inferred = "unknown"
        else:
            sample = str(value)
            inferred = _infer_type(sample)

        results.append(
            ExtractedParam(
                name=name,
                location="body",
                param_type=inferred,
                sample_value=sample,
            )
        )
    return results


def _extract_form_params(body: bytes) -> list[ExtractedParam]:
    """
    Purpose:
        Extract parameters from a URL-encoded form body.
    Input:
        body — Raw request body bytes.
    Output:
        List of ExtractedParam with location='body'.
    Side effects: None.
    """
    try:
        pairs = parse_qsl(
            body.decode("utf-8", errors="replace"), keep_blank_values=True
        )
    except Exception:
        return []

    results: list[ExtractedParam] = []
    for name, value in pairs:
        if not name:
            continue
        results.append(
            ExtractedParam(
                name=name,
                location="body",
                param_type=_infer_type(value),
                sample_value=value,
            )
        )
    return results


def _infer_type(value: str) -> str:
    """
    Purpose:
        Classify a scalar string value into one of four minimal types.
    Input:
        value — Raw string value from a parameter.
    Output:
        'int' | 'bool' | 'string' | 'unknown'
        'unknown' is returned only for empty strings (no evidence to classify).
    Rules:
        - Empty string → 'unknown'
        - Matches _INT_RE → 'int'  (checked before bool to avoid classifying '0'/'1' as bool)
        - Lowercase in _BOOL_VALUES → 'bool'
        - Anything else → 'string'
    Side effects: None.
    """
    if not value:
        return "unknown"
    if _INT_RE.match(value):
        return "int"
    if value.lower() in _BOOL_VALUES:
        return "bool"
    return "string"


def _get_request_content_type(headers: dict) -> str:
    """
    Purpose:
        Extract the Content-Type value from a request headers dict.
    Input:
        headers — Captured request headers dict (keys may be any case).
    Output:
        Content-Type value as a string, or empty string when absent.
    Side effects: None.
    """
    for key, value in headers.items():
        if str(key).lower() != "content-type":
            continue
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)
    return ""
