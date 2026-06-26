"""
Module: talos.projects.bac.decision_filter

Purpose:
    Load and evaluate the per-project BAC-decision-filter.yaml configuration file.
    Determines whether an HTTP replay response represents:
        POSSIBLE_BAC — authorization enforcement failed (attacker got through).
        SECURE       — authorization enforcement succeeded (access was denied).
        UNKNOWN      — response matched no configured pattern.

    Evaluation order (first match wins):
        1. failed_detection  → POSSIBLE_BAC
        2. passed_detection  → SECURE
        3. No match          → UNKNOWN

    Returns None from load_filter() when no filter file is present, so the engine
    can fall back to hardcoded heuristics.

    Responsibility boundary:
        This module answers only: "Does this HTTP response look like authorization
        was enforced or bypassed?"  It does NOT evaluate session validity,
        infrastructure health, or cross-response comparisons.

Dependencies: re, logging, pathlib, yaml (pyyaml)
Data flow:
    engine._send_and_store → load_filter(project_data_dir)
        → evaluate_response(filter, response_data) → verdict string
Side effects: None (load_filter performs one read-only file access).
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)

# Filename resolved relative to the project's data directory.
FILTER_FILENAME = "BAC-decision-filter.yaml"

VERDICT_POSSIBLE_BAC = "POSSIBLE_BAC"
VERDICT_SECURE = "SECURE"
VERDICT_UNKNOWN = "UNKNOWN"

_VALID_LOCATIONS = frozenset({"status", "header", "body", "response", "response_length"})

_VALID_OPERATORS = frozenset({
    "equals", "not_equals",
    "contains", "not_contains",
    "regex", "regex_not",
})

# Operators that compare numeric values (status / response_length).
_NUMERIC_OPERATORS = frozenset({"equals", "not_equals"})


# ------------------------------------------------------------------ #
# Data models                                                          #
# ------------------------------------------------------------------ #

@dataclass
class FilterRule:
    """
    Purpose:
        One atomic match condition targeting a specific part of the HTTP response.

    Fields:
        location  — Which part of the response to inspect.
                    One of: status | header | body | response | response_length
        operator  — Comparison operator.
                    One of: equals | not_equals | contains | not_contains |
                            regex | regex_not
        value     — Expected value (str for text locations; int for numeric locations).
        field     — Header field name; required when location == 'header' and a
                    specific header is targeted.  When absent with location='header',
                    all response header values are searched.
    """

    location: str
    operator: str
    value: object  # str for text; int for status/response_length
    field: Optional[str] = None


@dataclass
class FilterGroup:
    """
    Purpose:
        A named set of rules combined by a single logical operator.
        Represents one authorization outcome pattern (e.g. "401 + Unauthorized body").

    Fields:
        operator — 'AND' | 'OR' — how rules within this group are combined.
        rules    — Ordered list of FilterRule objects.
    """

    operator: str  # AND | OR
    rules: list[FilterRule] = field(default_factory=list)


@dataclass
class DetectionSection:
    """
    Purpose:
        One complete detection section (passed_detection or failed_detection).
        Contains one or more groups; groups are combined by group_operator.

    Fields:
        group_operator — 'AND' | 'OR' — how groups within this section are combined.
                         OR is the standard setting (any group can match).
        groups         — Ordered list of FilterGroup objects.
    """

    group_operator: str  # AND | OR
    groups: list[FilterGroup] = field(default_factory=list)


@dataclass
class BacDecisionFilter:
    """
    Purpose:
        The complete parsed and validated BAC-decision-filter.yaml.

    Fields:
        version          — Config schema version (currently 1).
        passed_detection — Patterns that prove authorization was enforced.
                           Matching → SECURE.  May be None if section is absent.
        failed_detection — Patterns that prove authorization was bypassed.
                           Matching → POSSIBLE_BAC.  May be None if section is absent.
    """

    version: int
    passed_detection: Optional[DetectionSection]
    failed_detection: Optional[DetectionSection]


@dataclass
class ResponseData:
    """
    Purpose:
        Normalized HTTP response data passed to the filter evaluator.
        Constructed from the raw replayed flow dict in the engine.

    Fields:
        status_code      — Integer HTTP status code; None if response never arrived.
        headers          — Response headers dict with lowercased keys.
        body_bytes       — Raw response body; None if absent.
        body_text        — Response body decoded as UTF-8 (best-effort; '' on failure).
        full_response    — Headers formatted as 'key: value' lines + blank line + body.
                           Used for 'response' location rules.
        response_length  — Byte length of the response body.
    """

    status_code: Optional[int]
    headers: dict[str, str]
    body_bytes: Optional[bytes]
    body_text: str
    full_response: str
    response_length: int


# ------------------------------------------------------------------ #
# Filter loading                                                       #
# ------------------------------------------------------------------ #

def load_filter(project_data_dir: Path) -> Optional[BacDecisionFilter]:
    """
    Purpose:
        Load and parse BAC-decision-filter.yaml from the project data directory.
        Returns None when the file is absent (engine falls back to heuristics).
        Logs a warning and returns None on any parse failure so the engine
        never crashes due to a malformed config file.

    Input:
        project_data_dir — Absolute path to the project's data directory
                           (the directory containing talos.db).
    Output:
        Parsed BacDecisionFilter, or None when the file is absent or unreadable.
    Side effects:
        Reads one file from disk.  May emit WARNING log entries.
    """
    filter_path = project_data_dir / FILTER_FILENAME
    if not filter_path.exists():
        return None

    try:
        import yaml  # pyyaml — imported lazily to avoid hard dep if filter unused
        raw = yaml.safe_load(filter_path.read_text(encoding="utf-8"))
    except ImportError:
        _log.warning(
            "pyyaml is not installed.  BAC decision filter cannot be loaded.  "
            "Install it with: pip install pyyaml"
        )
        return None
    except Exception as exc:
        _log.warning("Failed to read BAC decision filter at %s: %s", filter_path, exc)
        return None

    if not isinstance(raw, dict):
        _log.warning(
            "BAC decision filter at %s has invalid structure (expected a YAML mapping)",
            filter_path,
        )
        return None

    try:
        return _parse_filter(raw)
    except Exception as exc:
        _log.warning("Failed to parse BAC decision filter at %s: %s", filter_path, exc)
        return None


def validate_filter_file(project_data_dir: Path) -> tuple[bool, str]:
    """
    Purpose:
        Validate the BAC-decision-filter.yaml without running an attack.
        Used by the 'filter validate' CLI command.

    Input:
        project_data_dir — Absolute path to the project's data directory.
    Output:
        (ok, message) — ok is True when the filter loaded cleanly; message
        describes what was found or what went wrong.
    Side effects:
        Reads one file from disk.
    """
    filter_path = project_data_dir / FILTER_FILENAME
    if not filter_path.exists():
        return False, f"Filter file not found: {filter_path}"

    try:
        import yaml
        raw = yaml.safe_load(filter_path.read_text(encoding="utf-8"))
    except ImportError:
        return False, "pyyaml is not installed.  Run: pip install pyyaml"
    except Exception as exc:
        return False, f"Failed to read filter file: {exc}"

    if not isinstance(raw, dict):
        return False, "Filter file must be a YAML mapping at the top level."

    try:
        f = _parse_filter(raw)
    except Exception as exc:
        return False, f"Parse error: {exc}"

    parts = []
    if f.passed_detection:
        g = len(f.passed_detection.groups)
        r = sum(len(grp.rules) for grp in f.passed_detection.groups)
        parts.append(f"passed_detection: {g} group(s), {r} rule(s)")
    else:
        parts.append("passed_detection: (not configured)")

    if f.failed_detection:
        g = len(f.failed_detection.groups)
        r = sum(len(grp.rules) for grp in f.failed_detection.groups)
        parts.append(f"failed_detection: {g} group(s), {r} rule(s)")
    else:
        parts.append("failed_detection: (not configured)")

    return True, "Filter is valid.  " + "  |  ".join(parts)


# ------------------------------------------------------------------ #
# YAML parsing helpers                                                 #
# ------------------------------------------------------------------ #

def _parse_filter(raw: dict) -> BacDecisionFilter:
    """
    Purpose:
        Convert a raw dict (from yaml.safe_load) into a BacDecisionFilter.
    Input:
        raw — top-level YAML dict.
    Output:
        BacDecisionFilter.
    Raises:
        ValueError on missing required fields or unknown values.
    Side effects: None.
    """
    version = int(raw.get("version", 1))

    passed = (
        _parse_detection(raw["passed_detection"])
        if "passed_detection" in raw
        else None
    )
    failed = (
        _parse_detection(raw["failed_detection"])
        if "failed_detection" in raw
        else None
    )

    return BacDecisionFilter(
        version=version,
        passed_detection=passed,
        failed_detection=failed,
    )


def _parse_detection(raw: dict) -> DetectionSection:
    """
    Purpose: Parse one detection section (passed_detection or failed_detection).
    Raises: ValueError on invalid structure.
    """
    if not isinstance(raw, dict):
        raise ValueError("Detection section must be a YAML mapping.")

    group_op = str(raw.get("group_operator", "OR")).upper()
    if group_op not in ("AND", "OR"):
        raise ValueError(f"group_operator must be AND or OR; got '{group_op}'")

    raw_groups = raw.get("groups", [])
    if not isinstance(raw_groups, list):
        raise ValueError("'groups' must be a list.")

    groups = [_parse_group(i, g) for i, g in enumerate(raw_groups)]
    return DetectionSection(group_operator=group_op, groups=groups)


def _parse_group(index: int, raw: dict) -> FilterGroup:
    """
    Purpose: Parse one rule group.
    Raises: ValueError on invalid structure.
    """
    if not isinstance(raw, dict):
        raise ValueError(f"Group at index {index} must be a YAML mapping.")

    op = str(raw.get("operator", "AND")).upper()
    if op not in ("AND", "OR"):
        raise ValueError(f"Group operator at index {index} must be AND or OR; got '{op}'")

    raw_rules = raw.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ValueError(f"'rules' in group {index} must be a list.")

    rules = [_parse_rule(index, j, r) for j, r in enumerate(raw_rules)]
    return FilterGroup(operator=op, rules=rules)


def _parse_rule(group_index: int, rule_index: int, raw: dict) -> FilterRule:
    """
    Purpose: Parse one atomic rule.
    Raises: ValueError on missing/unknown fields or invalid operator for location.
    """
    if not isinstance(raw, dict):
        raise ValueError(
            f"Rule at group[{group_index}].rule[{rule_index}] must be a YAML mapping."
        )

    location = str(raw.get("location", "")).lower().strip()
    operator = str(raw.get("operator", "")).lower().strip()
    value = raw.get("value")
    field_name: Optional[str] = raw.get("field")

    if not location:
        raise ValueError(
            f"Rule at group[{group_index}].rule[{rule_index}] is missing 'location'."
        )
    if location not in _VALID_LOCATIONS:
        raise ValueError(
            f"Rule at group[{group_index}].rule[{rule_index}] has unknown location "
            f"'{location}'.  Valid values: {sorted(_VALID_LOCATIONS)}"
        )

    if not operator:
        raise ValueError(
            f"Rule at group[{group_index}].rule[{rule_index}] is missing 'operator'."
        )
    if operator not in _VALID_OPERATORS:
        raise ValueError(
            f"Rule at group[{group_index}].rule[{rule_index}] has unknown operator "
            f"'{operator}'.  Valid values: {sorted(_VALID_OPERATORS)}"
        )

    if value is None:
        raise ValueError(
            f"Rule at group[{group_index}].rule[{rule_index}] is missing 'value'."
        )

    # Coerce numeric locations to int.
    if location in ("status", "response_length"):
        try:
            value = int(value)
        except (TypeError, ValueError):
            raise ValueError(
                f"Rule at group[{group_index}].rule[{rule_index}] location='{location}' "
                f"requires an integer value; got {value!r}"
            )
        if operator not in _NUMERIC_OPERATORS:
            raise ValueError(
                f"Rule at group[{group_index}].rule[{rule_index}] location='{location}' "
                f"only supports operators: {sorted(_NUMERIC_OPERATORS)}; got '{operator}'"
            )

    return FilterRule(
        location=location,
        operator=operator,
        value=value,
        field=field_name,
    )


# ------------------------------------------------------------------ #
# Response data construction                                           #
# ------------------------------------------------------------------ #

def build_response_data(replayed: dict) -> ResponseData:
    """
    Purpose:
        Build a ResponseData from a replayed flow dict (as stored by the engine).
        Called immediately after the HTTP response is received.

    Input:
        replayed — flow dict containing status_code, response_headers (JSON str),
                   and response_body (bytes or None).
    Output:
        ResponseData ready for filter evaluation.
    Side effects: None (pure construction).
    """
    import json

    status_code: Optional[int] = replayed.get("status_code")

    raw_headers = replayed.get("response_headers", "{}")
    headers_raw: dict = (
        json.loads(raw_headers) if isinstance(raw_headers, str) else (raw_headers or {})
    )
    # Normalize to lowercase keys for case-insensitive header matching.
    headers_lower = {k.lower(): str(v) for k, v in headers_raw.items()}

    body_bytes: Optional[bytes] = replayed.get("response_body")
    body_text = ""
    if body_bytes:
        try:
            body_text = body_bytes.decode("utf-8", errors="replace")
        except Exception:
            body_text = ""

    # Build full_response: "header: value\r\n..." + "\r\n\r\n" + body text.
    # This mirrors what an HTTP client would see in raw form.
    header_block = "\r\n".join(f"{k}: {v}" for k, v in headers_raw.items())
    full_response = header_block + "\r\n\r\n" + body_text

    response_length = len(body_bytes) if body_bytes else 0

    return ResponseData(
        status_code=status_code,
        headers=headers_lower,
        body_bytes=body_bytes,
        body_text=body_text,
        full_response=full_response,
        response_length=response_length,
    )


# ------------------------------------------------------------------ #
# Evaluation engine                                                    #
# ------------------------------------------------------------------ #

def evaluate_response(
    bac_filter: BacDecisionFilter,
    response_data: ResponseData,
) -> str:
    """
    Purpose:
        Evaluate an HTTP response against the loaded BAC decision filter.

        Priority order:
            1. failed_detection matched  → POSSIBLE_BAC
            2. passed_detection matched  → SECURE
            3. Neither matched           → UNKNOWN

        failed_detection has higher priority because evidence that protected
        content was successfully returned is stronger than evidence of a denial.

    Input:
        bac_filter    — Parsed BacDecisionFilter (from load_filter).
        response_data — Normalized response data (from build_response_data).
    Output:
        'POSSIBLE_BAC' | 'SECURE' | 'UNKNOWN'
    Side effects: None.
    """
    if bac_filter.failed_detection is not None:
        if _evaluate_detection(bac_filter.failed_detection, response_data):
            return VERDICT_POSSIBLE_BAC

    if bac_filter.passed_detection is not None:
        if _evaluate_detection(bac_filter.passed_detection, response_data):
            return VERDICT_SECURE

    return VERDICT_UNKNOWN


def _evaluate_detection(
    section: DetectionSection,
    response_data: ResponseData,
) -> bool:
    """
    Purpose:
        Evaluate all groups in a detection section.
        group_operator OR  → any group must match (short-circuits on first match).
        group_operator AND → all groups must match.
    Input:
        section       — DetectionSection with group_operator and groups.
        response_data — Normalized response data.
    Output:
        True when the section matches, False otherwise.
    Side effects: None.
    """
    if not section.groups:
        return False

    if section.group_operator == "OR":
        return any(_evaluate_group(g, response_data) for g in section.groups)

    # AND — every group must match.
    return all(_evaluate_group(g, response_data) for g in section.groups)


def _evaluate_group(group: FilterGroup, response_data: ResponseData) -> bool:
    """
    Purpose:
        Evaluate all rules in a group.
        operator AND → all rules must match (short-circuits on first failure).
        operator OR  → any rule must match (short-circuits on first success).
    Input:
        group         — FilterGroup with operator and rules.
        response_data — Normalized response data.
    Output:
        True when the group matches, False otherwise.
    Side effects: None.
    """
    if not group.rules:
        return False

    if group.operator == "AND":
        return all(_evaluate_rule(r, response_data) for r in group.rules)

    # OR — any rule must match.
    return any(_evaluate_rule(r, response_data) for r in group.rules)


def _evaluate_rule(rule: FilterRule, response_data: ResponseData) -> bool:
    """
    Purpose:
        Evaluate one atomic rule against the response data.
        Returns True when the rule's condition is satisfied, False otherwise.
        Never raises — returns False on any unexpected condition to prevent
        a malformed rule from crashing the verdict pipeline.

    Input:
        rule          — FilterRule specifying location, operator, and value.
        response_data — Normalized response data.
    Output:
        True (match) or False (no match).
    Side effects: None.
    """
    try:
        location = rule.location

        if location == "status":
            return _match_numeric(
                response_data.status_code,
                rule.operator,
                int(rule.value),  # type: ignore[arg-type]
            )

        if location == "response_length":
            return _match_numeric(
                response_data.response_length,
                rule.operator,
                int(rule.value),  # type: ignore[arg-type]
            )

        if location == "header":
            return _match_header(
                response_data.headers,
                rule.field,
                rule.operator,
                str(rule.value),
            )

        if location == "body":
            return _match_text(response_data.body_text, rule.operator, str(rule.value))

        if location == "response":
            return _match_text(response_data.full_response, rule.operator, str(rule.value))

    except Exception as exc:  # noqa: BLE001
        _log.debug("Rule evaluation error (location=%s operator=%s): %s", rule.location, rule.operator, exc)

    return False


# ------------------------------------------------------------------ #
# Low-level match helpers                                              #
# ------------------------------------------------------------------ #

def _match_numeric(actual: Optional[int], operator: str, expected: int) -> bool:
    """
    Purpose:
        Apply a numeric comparison between actual and expected.
        Returns False when actual is None (response never arrived).
    Side effects: None.
    """
    if actual is None:
        return False
    if operator == "equals":
        return actual == expected
    if operator == "not_equals":
        return actual != expected
    return False


def _match_header(
    headers: dict[str, str],
    field_name: Optional[str],
    operator: str,
    value: str,
) -> bool:
    """
    Purpose:
        Match against a specific response header (when field_name is given)
        or against the concatenation of all header values (when field_name is None).

        Header keys are lowercase in headers dict; field_name comparison is
        case-insensitive.
    Side effects: None.
    """
    if field_name:
        # Match against a specific header field.
        target = headers.get(field_name.lower(), "")
        return _match_text(target, operator, value)

    # No field specified — search all header values combined.
    combined = " ".join(headers.values())
    return _match_text(combined, operator, value)


def _match_text(text: str, operator: str, value: str) -> bool:
    """
    Purpose:
        Apply a text comparison between text and value using the given operator.
    Side effects: None.
    """
    if operator == "equals":
        return text == value
    if operator == "not_equals":
        return text != value
    if operator == "contains":
        return value in text
    if operator == "not_contains":
        return value not in text
    if operator == "regex":
        return re.search(value, text) is not None
    if operator == "regex_not":
        return re.search(value, text) is None
    return False


# ------------------------------------------------------------------ #
# Sample filter YAML                                                   #
# ------------------------------------------------------------------ #

SAMPLE_FILTER_YAML = """\
# BAC-decision-filter.yaml
# Configure how Talos determines whether authorization was enforced.
#
# failed_detection  — patterns that mean authorization was BYPASSED → POSSIBLE_BAC
# passed_detection  — patterns that mean authorization was ENFORCED → SECURE
#
# Evaluation order: failed_detection is checked first (stronger evidence).
# If neither section matches → UNKNOWN.
#
# Supported locations : status | header | body | response | response_length
# Supported operators : equals | not_equals | contains | not_contains | regex | regex_not
#
# group_operator : OR  (any group can match)
#                  AND (all groups must match — rarely needed)
# operator       : AND (all rules in the group must match)
#                  OR  (any rule in the group must match)

version: 1

# -----------------------------------------------------------------------
# PASSED DETECTION
# Describe how this application signals that access was denied.
# -----------------------------------------------------------------------
passed_detection:

  group_operator: OR

  groups:

    # Standard 401 Unauthorized
    - operator: AND
      rules:
        - location: status
          operator: equals
          value: 401
        - location: body
          operator: contains
          value: Unauthorized

    # Standard 403 Forbidden
    - operator: AND
      rules:
        - location: status
          operator: equals
          value: 403
        - location: body
          operator: contains
          value: Access Denied

    # Redirect to login
    - operator: AND
      rules:
        - location: status
          operator: equals
          value: 302
        - location: header
          field: Location
          operator: contains
          value: /login

    # HTTP authentication challenge
    - operator: OR
      rules:
        - location: header
          field: WWW-Authenticate
          operator: contains
          value: Basic
        - location: header
          field: WWW-Authenticate
          operator: contains
          value: Bearer

# -----------------------------------------------------------------------
# FAILED DETECTION
# Describe what a successful access bypass looks like.
# -----------------------------------------------------------------------
failed_detection:

  group_operator: OR

  groups:

    # Dashboard page returned
    - operator: AND
      rules:
        - location: status
          operator: equals
          value: 200
        - location: body
          operator: contains
          value: Dashboard

    # User profile data returned
    - operator: AND
      rules:
        - location: status
          operator: equals
          value: 200
        - location: body
          operator: regex
          value: '"username"\\s*:'

    # Authenticated JSON with user id + email
    - operator: AND
      rules:
        - location: response
          operator: regex
          value: '"id"\\s*:\\s*\\d+'
        - location: response
          operator: regex
          value: '"email"\\s*:'
"""
