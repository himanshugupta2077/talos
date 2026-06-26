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

    Returns a DecisionResult that carries not just the verdict but also which
    section, group, and individual rules matched, enabling full explainability.

    Returns None from load_filter() when no filter file is present, so the engine
    can fall back to hardcoded heuristics.

    Responsibility boundary:
        This module answers only: "Does this HTTP response look like authorization
        was enforced or bypassed?"  It does NOT evaluate session validity,
        infrastructure health, or cross-response comparisons.

Dependencies: re, logging, pathlib, yaml (pyyaml)
Data flow:
    engine._send_and_store → load_filter(project_data_dir)
        → evaluate_response(filter, response_data) → DecisionResult
Side effects: None (load_filter performs one read-only file access).
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)

FILTER_FILENAME = "BAC-decision-filter.yaml"

VERDICT_POSSIBLE_BAC = "POSSIBLE_BAC"
VERDICT_SECURE = "SECURE"
VERDICT_UNKNOWN = "UNKNOWN"

_VALID_LOCATIONS = frozenset({"status", "header", "body", "response", "response_length"})

_VALID_OPERATORS = frozenset({
    "equals", "not_equals",
    "contains", "not_contains",
    "regex", "regex_not",
    "exists", "not_exists",
})

_NUMERIC_OPERATORS = frozenset({"equals", "not_equals"})
_EXISTENCE_OPERATORS = frozenset({"exists", "not_exists"})


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
                            regex | regex_not | exists | not_exists
        value     — Expected value (str for text; int for status/response_length).
                    None for exists/not_exists operators.
        field     — Header field name; used when location == 'header' to target
                    a specific header.  When absent, all header values are searched.
        rule_id   — Optional human-readable identifier.
                    Auto-generated as 'rule_<index>' if not supplied in YAML.
                    Appears in DecisionResult.matched_rules for explainability.
    """

    location: str
    operator: str
    value: object  # str | int | None
    field: Optional[str] = None
    rule_id: str = ""


@dataclass
class FilterGroup:
    """
    Purpose:
        A named set of rules combined by a single logical operator.
        Represents one authorization outcome pattern (e.g. "401 + Unauthorized body").

    Fields:
        operator  — 'AND' | 'OR' — how rules within this group are combined.
        rules     — Ordered list of FilterRule objects.
        group_id  — Optional human-readable identifier.
                    Auto-generated as 'group_<index>' if not supplied in YAML.
                    Appears in DecisionResult.matched_group_id for explainability.
    """

    operator: str  # AND | OR
    rules: list[FilterRule] = field(default_factory=list)
    group_id: str = ""


@dataclass
class DetectionSection:
    """
    Purpose:
        One complete detection section (passed_detection or failed_detection).
        Contains one or more groups combined by group_operator.

    Fields:
        group_operator — 'AND' | 'OR' — how groups are combined.  OR is standard.
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
        passed_detection — Patterns that prove authorization was enforced → SECURE.
        failed_detection — Patterns that prove authorization was bypassed → POSSIBLE_BAC.
    """

    version: int
    passed_detection: Optional[DetectionSection]
    failed_detection: Optional[DetectionSection]


@dataclass
class ResponseData:
    """
    Purpose:
        Normalized HTTP response data passed to the filter evaluator.

    Fields:
        status_code      — Integer HTTP status code; None if response never arrived.
        headers          — Response headers dict with lowercased keys.
        body_bytes       — Raw response body; None if absent.
        body_text        — Response body decoded as UTF-8 (best-effort; '' on failure).
        full_response    — Headers + blank line + body as a single string.
        response_length  — Byte length of the response body.
    """

    status_code: Optional[int]
    headers: dict[str, str]
    body_bytes: Optional[bytes]
    body_text: str
    full_response: str
    response_length: int


@dataclass
class DecisionResult:
    """
    Purpose:
        Rich result from evaluate_response().  Carries the verdict and all evidence
        used to reach it so the engine never loses the reasoning behind a decision.

    Fields:
        verdict          — 'POSSIBLE_BAC' | 'SECURE' | 'UNKNOWN'.
        matched_section  — 'failed_detection' | 'passed_detection' | None.
                           None when UNKNOWN or when a heuristic was used.
        matched_group_id — ID or auto-label of the group that matched.
                           None when no section matched.
        matched_rules    — Human-readable description of every rule that matched
                           within the winning group.  Empty list when no rules fired.

    Usage:
        decision = evaluate_response(bac_filter, response_data)
        bac_verdict = decision.verdict          # stored in DB verdict column
        explanation  = decision.matched_rules   # logged / displayed / reported
    """

    verdict: str
    matched_section: Optional[str]
    matched_group_id: Optional[str]
    matched_rules: list[str]


# ------------------------------------------------------------------ #
# Filter loading                                                       #
# ------------------------------------------------------------------ #

def load_filter(project_data_dir: Path) -> Optional[BacDecisionFilter]:
    """
    Purpose:
        Load and parse BAC-decision-filter.yaml from the project data directory.
        Returns None when the file is absent (engine falls back to heuristics).
        Logs a warning and returns None on any parse failure.

    Input:
        project_data_dir — Path to the directory containing talos.db.
    Output:
        Parsed BacDecisionFilter, or None.
    Side effects:
        Reads one file from disk.  May emit WARNING log entries.
    """
    filter_path = project_data_dir / FILTER_FILENAME
    if not filter_path.exists():
        return None

    try:
        import yaml
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
        project_data_dir — Path to the directory containing talos.db.
    Output:
        (ok, message) — ok True when file loads cleanly; message describes structure or error.
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
    for sname, section in (("passed_detection", f.passed_detection), ("failed_detection", f.failed_detection)):
        if section:
            ids = [g.group_id for g in section.groups]
            r = sum(len(g.rules) for g in section.groups)
            parts.append(f"{sname}: {len(section.groups)} group(s) [{', '.join(ids)}], {r} rule(s)")
        else:
            parts.append(f"{sname}: (not configured)")

    return True, "Filter is valid.  " + "  |  ".join(parts)


# ------------------------------------------------------------------ #
# YAML parsing helpers                                                 #
# ------------------------------------------------------------------ #

def _parse_filter(raw: dict) -> BacDecisionFilter:
    """
    Purpose: Convert yaml.safe_load output into a BacDecisionFilter.
    Raises: ValueError on structural errors.
    """
    version = int(raw.get("version", 1))
    passed = _parse_detection(raw["passed_detection"]) if "passed_detection" in raw else None
    failed = _parse_detection(raw["failed_detection"]) if "failed_detection" in raw else None
    return BacDecisionFilter(version=version, passed_detection=passed, failed_detection=failed)


def _parse_detection(raw: dict) -> DetectionSection:
    """Purpose: Parse one detection section. Raises ValueError on invalid structure."""
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
    Purpose:
        Parse one rule group.
        Optional 'id' field becomes group_id; defaults to 'group_<index>'.
    Raises: ValueError on invalid structure.
    """
    if not isinstance(raw, dict):
        raise ValueError(f"Group at index {index} must be a YAML mapping.")
    op = str(raw.get("operator", "AND")).upper()
    if op not in ("AND", "OR"):
        raise ValueError(f"Group operator at index {index} must be AND or OR; got '{op}'")
    group_id = str(raw.get("id", "")).strip() or f"group_{index}"
    raw_rules = raw.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ValueError(f"'rules' in group {index} must be a list.")
    rules = [_parse_rule(index, j, r) for j, r in enumerate(raw_rules)]
    return FilterGroup(operator=op, rules=rules, group_id=group_id)


def _parse_rule(group_index: int, rule_index: int, raw: dict) -> FilterRule:
    """
    Purpose:
        Parse one atomic rule.
        Optional 'id' field becomes rule_id; defaults to 'rule_<index>'.
        'value' is optional for exists/not_exists operators.
        'exists'/'not_exists' are restricted to location='header'.
    Raises: ValueError on structural or constraint violations.
    """
    if not isinstance(raw, dict):
        raise ValueError(f"Rule at group[{group_index}].rule[{rule_index}] must be a YAML mapping.")

    location = str(raw.get("location", "")).lower().strip()
    operator = str(raw.get("operator", "")).lower().strip()
    value = raw.get("value")
    field_name: Optional[str] = raw.get("field")
    rule_id = str(raw.get("id", "")).strip() or f"rule_{rule_index}"

    if not location:
        raise ValueError(f"Rule at group[{group_index}].rule[{rule_index}] is missing 'location'.")
    if location not in _VALID_LOCATIONS:
        raise ValueError(
            f"Rule at group[{group_index}].rule[{rule_index}] has unknown location "
            f"'{location}'.  Valid: {sorted(_VALID_LOCATIONS)}"
        )
    if not operator:
        raise ValueError(f"Rule at group[{group_index}].rule[{rule_index}] is missing 'operator'.")
    if operator not in _VALID_OPERATORS:
        raise ValueError(
            f"Rule at group[{group_index}].rule[{rule_index}] has unknown operator "
            f"'{operator}'.  Valid: {sorted(_VALID_OPERATORS)}"
        )

    # exists/not_exists only valid for header location.
    if operator in _EXISTENCE_OPERATORS and location != "header":
        raise ValueError(
            f"Rule at group[{group_index}].rule[{rule_index}]: "
            f"operator '{operator}' is only valid for location='header'; got location='{location}'."
        )

    # value required unless operator is exists/not_exists.
    if operator not in _EXISTENCE_OPERATORS and value is None:
        raise ValueError(f"Rule at group[{group_index}].rule[{rule_index}] is missing 'value'.")

    # Coerce numeric locations.
    if location in ("status", "response_length"):
        try:
            value = int(value)  # type: ignore[arg-type]
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

    return FilterRule(location=location, operator=operator, value=value, field=field_name, rule_id=rule_id)


# ------------------------------------------------------------------ #
# Response data construction                                           #
# ------------------------------------------------------------------ #

def build_response_data(replayed: dict) -> ResponseData:
    """
    Purpose:
        Build a ResponseData from a replayed flow dict (as stored by the engine).
    Input:
        replayed — flow dict with status_code, response_headers (JSON str), response_body (bytes|None).
    Output:
        ResponseData ready for filter evaluation.
    Side effects: None.
    """
    import json

    status_code: Optional[int] = replayed.get("status_code")
    raw_headers = replayed.get("response_headers", "{}")
    headers_raw: dict = json.loads(raw_headers) if isinstance(raw_headers, str) else (raw_headers or {})
    headers_lower = {k.lower(): str(v) for k, v in headers_raw.items()}

    body_bytes: Optional[bytes] = replayed.get("response_body")
    body_text = ""
    if body_bytes:
        try:
            body_text = body_bytes.decode("utf-8", errors="replace")
        except Exception:
            body_text = ""

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
) -> DecisionResult:
    """
    Purpose:
        Evaluate an HTTP response against the loaded BAC decision filter.
        Returns a rich DecisionResult preserving the evidence used to decide.

        Priority order (first match wins):
            1. failed_detection matched  → POSSIBLE_BAC
            2. passed_detection matched  → SECURE
            3. Neither matched           → UNKNOWN

    Input:
        bac_filter    — Parsed BacDecisionFilter.
        response_data — Normalized response data.
    Output:
        DecisionResult with verdict, matched_section, matched_group_id, matched_rules.
    Side effects: None.
    """
    if bac_filter.failed_detection is not None:
        match = _find_section_match(bac_filter.failed_detection, response_data)
        if match is not None:
            group, matched_rules = match
            return DecisionResult(
                verdict=VERDICT_POSSIBLE_BAC,
                matched_section="failed_detection",
                matched_group_id=group.group_id,
                matched_rules=matched_rules,
            )

    if bac_filter.passed_detection is not None:
        match = _find_section_match(bac_filter.passed_detection, response_data)
        if match is not None:
            group, matched_rules = match
            return DecisionResult(
                verdict=VERDICT_SECURE,
                matched_section="passed_detection",
                matched_group_id=group.group_id,
                matched_rules=matched_rules,
            )

    return DecisionResult(verdict=VERDICT_UNKNOWN, matched_section=None, matched_group_id=None, matched_rules=[])


def _find_section_match(
    section: DetectionSection,
    response_data: ResponseData,
) -> Optional[tuple[FilterGroup, list[str]]]:
    """
    Purpose:
        Search a detection section for a matching group and collect evidence.

        group_operator OR:  first matching group wins.
        group_operator AND: all groups must match; evidence combined, last group returned.

    Output:
        (FilterGroup, matched_rule_descriptions) when matched, else None.
    Side effects: None.
    """
    if not section.groups:
        return None

    if section.group_operator == "OR":
        for group in section.groups:
            matched = _collect_matched_rules(group, response_data)
            if _group_passes(group, matched):
                return (group, matched)
        return None

    # AND — every group must match.
    combined_rules: list[str] = []
    for group in section.groups:
        matched = _collect_matched_rules(group, response_data)
        if not _group_passes(group, matched):
            return None
        combined_rules.extend(matched)
    return (section.groups[-1], combined_rules)


def _group_passes(group: FilterGroup, matched_rules: list[str]) -> bool:
    """
    Purpose:
        Decide if a group's pass condition is met given which rules matched.
        AND: all rules must have matched.
        OR:  at least one rule must have matched.
    Side effects: None.
    """
    if group.operator == "AND":
        return len(matched_rules) == len(group.rules)
    return len(matched_rules) > 0


def _collect_matched_rules(group: FilterGroup, response_data: ResponseData) -> list[str]:
    """
    Purpose:
        Run every rule in the group and return human-readable descriptions of
        those that matched.  Runs all rules to collect complete evidence —
        pass/fail logic is handled separately by _group_passes().
    Output:
        List of description strings for every rule that matched.
    Side effects: None.
    """
    return [
        _format_rule_description(rule)
        for rule in group.rules
        if _evaluate_rule(rule, response_data)
    ]


def _format_rule_description(rule: FilterRule) -> str:
    """
    Purpose:
        Build a concise human-readable description of a matched rule.
        Includes the rule_id prefix for custom IDs; suppresses auto-generated 'rule_N'.

        Examples:
            '[access_denied] body contains "Access Denied"'
            'status == 403'
            'header[WWW-Authenticate] exists'
            'header[Location] contains "/login"'
    Side effects: None.
    """
    # Show custom IDs; hide auto-generated ones.
    prefix = f"[{rule.rule_id}] " if rule.rule_id and not rule.rule_id.startswith("rule_") else ""

    if rule.location == "status":
        op = "==" if rule.operator == "equals" else "!="
        return f"{prefix}status {op} {rule.value}"

    if rule.location == "response_length":
        op = "==" if rule.operator == "equals" else "!="
        return f"{prefix}response_length {op} {rule.value}"

    if rule.location == "header":
        fp = f"[{rule.field}]" if rule.field else ""
        if rule.operator in _EXISTENCE_OPERATORS:
            return f"{prefix}header{fp} {rule.operator}"
        return f"{prefix}header{fp} {_op_label(rule.operator)} {rule.value!r}"

    # body / response
    return f"{prefix}{rule.location} {_op_label(rule.operator)} {rule.value!r}"


def _op_label(op: str) -> str:
    """Map operator names to display labels."""
    return {"equals": "==", "not_equals": "!="}.get(op, op)


def _evaluate_rule(rule: FilterRule, response_data: ResponseData) -> bool:
    """
    Purpose:
        Evaluate one atomic rule against the response data.
        Never raises — returns False on any unexpected error.
    Output:
        True (match) or False (no match).
    Side effects: None.
    """
    try:
        loc = rule.location

        if loc == "status":
            return _match_numeric(response_data.status_code, rule.operator, int(rule.value))  # type: ignore[arg-type]

        if loc == "response_length":
            return _match_numeric(response_data.response_length, rule.operator, int(rule.value))  # type: ignore[arg-type]

        if loc == "header":
            return _match_header(
                response_data.headers,
                rule.field,
                rule.operator,
                None if rule.operator in _EXISTENCE_OPERATORS else str(rule.value),
            )

        if loc == "body":
            return _match_text(response_data.body_text, rule.operator, str(rule.value))

        if loc == "response":
            return _match_text(response_data.full_response, rule.operator, str(rule.value))

    except Exception as exc:  # noqa: BLE001
        _log.debug("Rule evaluation error (location=%s operator=%s): %s", rule.location, rule.operator, exc)

    return False


# ------------------------------------------------------------------ #
# Low-level match helpers                                              #
# ------------------------------------------------------------------ #

def _match_numeric(actual: Optional[int], operator: str, expected: int) -> bool:
    """Apply a numeric comparison. Returns False when actual is None."""
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
    value: Optional[str],
) -> bool:
    """
    Purpose:
        Match against a specific response header or all header values.

        exists     — True when the header field is present (any value).
        not_exists — True when the header field is absent.
        All other operators delegate to _match_text.

        Header keys in the dict are lowercased; field_name matching is case-insensitive.
    Side effects: None.
    """
    if operator == "exists":
        return (field_name.lower() in headers) if field_name else (len(headers) > 0)

    if operator == "not_exists":
        return (field_name.lower() not in headers) if field_name else (len(headers) == 0)

    target = headers.get(field_name.lower(), "") if field_name else " ".join(headers.values())
    return _match_text(target, operator, value or "")


def _match_text(text: str, operator: str, value: str) -> bool:
    """Apply a text comparison."""
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
#                       exists | not_exists  (header only — no value required)
#
# group_operator : OR  (any group can match — default)
#                  AND (all groups must match — rarely needed)
# operator       : AND (all rules in the group must match — default)
#                  OR  (any rule in the group must match)
#
# Optional identifiers for explainability in results:
#   groups:  - id: redirect_to_login     ← appears in matched_group_id
#   rules:   - id: status_is_302         ← appears in matched_rules output

version: 1

# -----------------------------------------------------------------------
# PASSED DETECTION — how this application signals that access was denied
# -----------------------------------------------------------------------
passed_detection:

  group_operator: OR

  groups:

    - id: unauthorized_401
      operator: AND
      rules:
        - id: status_401
          location: status
          operator: equals
          value: 401
        - id: body_unauthorized
          location: body
          operator: contains
          value: Unauthorized

    - id: forbidden_403
      operator: AND
      rules:
        - id: status_403
          location: status
          operator: equals
          value: 403
        - id: body_access_denied
          location: body
          operator: contains
          value: Access Denied

    - id: redirect_to_login
      operator: AND
      rules:
        - id: status_302
          location: status
          operator: equals
          value: 302
        - id: location_login
          location: header
          field: Location
          operator: contains
          value: /login

    - id: www_auth_challenge
      operator: OR
      rules:
        - id: www_auth_basic
          location: header
          field: WWW-Authenticate
          operator: contains
          value: Basic
        - id: www_auth_bearer
          location: header
          field: WWW-Authenticate
          operator: contains
          value: Bearer

    # Any WWW-Authenticate header present — no value needed
    - id: www_auth_exists
      operator: AND
      rules:
        - id: www_authenticate_present
          location: header
          field: WWW-Authenticate
          operator: exists

# -----------------------------------------------------------------------
# FAILED DETECTION — what a successful access bypass looks like
# -----------------------------------------------------------------------
failed_detection:

  group_operator: OR

  groups:

    - id: dashboard_returned
      operator: AND
      rules:
        - id: status_200
          location: status
          operator: equals
          value: 200
        - id: body_dashboard
          location: body
          operator: contains
          value: Dashboard

    - id: profile_data_returned
      operator: AND
      rules:
        - id: status_200_profile
          location: status
          operator: equals
          value: 200
        - id: username_json
          location: body
          operator: regex
          value: '"username"\\s*:'

    - id: authed_json_response
      operator: AND
      rules:
        - id: json_id_field
          location: response
          operator: regex
          value: '"id"\\s*:\\s*\\d+'
        - id: json_email_field
          location: response
          operator: regex
          value: '"email"\\s*:'
"""
