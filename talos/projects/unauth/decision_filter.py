"""
Module: talos.projects.unauth.decision_filter

Purpose:
    Load and evaluate the per-project unauth-decision-filter.yaml configuration.
    Determines whether an unauthenticated HTTP replay response represents:
        BYPASS  — authentication enforcement failed (attacker reached the resource).
        SECURE  — authentication enforcement succeeded (access was correctly denied).
        UNKNOWN — response matched no configured pattern.

    Evaluation order (first match wins):
        1. failed_detection  → BYPASS
        2. passed_detection  → SECURE
        3. No match          → UNKNOWN

    Default SECURE patterns (passed_detection):
        Status codes  : 401, 403, 407
        Headers       : WWW-Authenticate (present)
        Body keywords : Access Denied, Unauthorized, Forbidden,
                        Login required, Authentication required,
                        Invalid token, Session expired, Sign in

    Default BYPASS patterns (failed_detection):
        Status codes  : 2xx (200-299)
        Body keywords : Welcome

    Falls back to hardcoded heuristics when no filter file is present:
        SECURE  — status in {401, 403, 407} or status is 3xx.
        BYPASS  — status is 2xx.
        UNKNOWN — anything else (5xx, errors, etc.)

Dependencies: re, logging, pathlib, yaml (pyyaml)
Data flow:
    engine._send_and_store → load_filter(project_data_dir)
        → evaluate_response(filter, response_data) → UnauthDecisionResult
Side effects: None (load_filter performs one read-only file access).
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)

FILTER_FILENAME = "unauth-decision-filter.yaml"

VERDICT_BYPASS = "BYPASS"
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

# Default filter shipped when no project-level file exists.
# Users create one via: talos attack unauth filter init
_DEFAULT_YAML = """\
version: 1

# SECURE: authentication enforcement detected — request was blocked.
passed_detection:
  group_operator: OR
  groups:
    - group_id: status_401
      operator: AND
      rules:
        - location: status
          operator: equals
          value: 401
    - group_id: status_403
      operator: AND
      rules:
        - location: status
          operator: equals
          value: 403
    - group_id: status_407
      operator: AND
      rules:
        - location: status
          operator: equals
          value: 407
    - group_id: www_authenticate_header
      operator: AND
      rules:
        - location: header
          field: WWW-Authenticate
          operator: exists
    - group_id: proxy_error_page_burp
      operator: OR
      rules:
        - location: body
          operator: contains
          value: "<title>Burp Suite</title>"

    - group_id: body_auth_keywords
      operator: OR
      rules:
        - location: body
          operator: contains
          value: Access Denied
        - location: body
          operator: contains
          value: Unauthorized
        - location: body
          operator: contains
          value: Forbidden
        - location: body
          operator: contains
          value: Login required
        - location: body
          operator: contains
          value: Authentication required
        - location: body
          operator: contains
          value: Invalid token
        - location: body
          operator: contains
          value: Session expired
        - location: body
          operator: contains
          value: Sign in

# BYPASS: authentication enforcement absent — attacker reached the resource.
failed_detection:
  group_operator: OR
  groups:
    - group_id: status_2xx
      operator: AND
      rules:
        - location: status
          operator: regex
          value: "^2[0-9][0-9]$"
    - group_id: body_welcome
      operator: AND
      rules:
        - location: body
          operator: contains
          value: Welcome
"""


# ------------------------------------------------------------------ #
# Data models (shared structure with bac.decision_filter)             #
# ------------------------------------------------------------------ #

@dataclass
class FilterRule:
    """One atomic match condition targeting a specific part of the HTTP response."""
    location: str
    operator: str
    value: object  # str | int | None
    field: Optional[str] = None
    rule_id: str = ""


@dataclass
class FilterGroup:
    """A named set of rules combined by a single logical operator."""
    operator: str  # AND | OR
    rules: list[FilterRule] = field(default_factory=list)
    group_id: str = ""


@dataclass
class DetectionSection:
    """One complete detection section (passed_detection or failed_detection)."""
    group_operator: str  # AND | OR
    groups: list[FilterGroup] = field(default_factory=list)


@dataclass
class UnauthDecisionFilter:
    """The complete parsed and validated unauth-decision-filter.yaml."""
    version: int
    passed_detection: Optional[DetectionSection]
    failed_detection: Optional[DetectionSection]


@dataclass
class ResponseData:
    """Normalized HTTP response data passed to the filter evaluator."""
    status: Optional[int]
    headers: dict
    body: Optional[bytes]
    response_length: int


@dataclass
class UnauthDecisionResult:
    """
    Purpose:
        Result of evaluating a response against the decision filter.

    Fields:
        verdict         — BYPASS | SECURE | UNKNOWN.
        matched_section — 'passed_detection' | 'failed_detection' | None.
        matched_group_id — ID of the matching group; None when heuristic.
        matched_rules   — List of matched rule IDs for explainability.
    """
    verdict: str
    matched_section: Optional[str]
    matched_group_id: Optional[str]
    matched_rules: list[str] = field(default_factory=list)


# ------------------------------------------------------------------ #
# Filter loading                                                       #
# ------------------------------------------------------------------ #

def load_filter(project_data_dir: Path) -> Optional[UnauthDecisionFilter]:
    """
    Purpose:
        Load and parse unauth-decision-filter.yaml from the project data directory.
        Returns None if the file does not exist (engine falls back to heuristics).
    Input:
        project_data_dir — Path to the project's data directory (db_path.parent).
    Output:
        Parsed UnauthDecisionFilter, or None if the file is absent.
    Side effects:
        Reads one YAML file; logs warnings on parse errors.
    """
    filter_path = project_data_dir / FILTER_FILENAME
    if not filter_path.exists():
        return None

    try:
        import yaml  # pyyaml
    except ImportError:
        _log.warning(
            "pyyaml not installed — cannot load %s. Using heuristic verdict.",
            FILTER_FILENAME,
        )
        return None

    try:
        text = filter_path.read_text(encoding="utf-8")
        raw = yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001
        _log.warning("Failed to load %s: %s. Using heuristic verdict.", FILTER_FILENAME, exc)
        return None

    return _parse_filter(raw)


def _parse_filter(raw: dict) -> Optional[UnauthDecisionFilter]:
    """
    Purpose:
        Convert raw YAML dict into a UnauthDecisionFilter.
        Returns None on structural errors.
    Input:  raw — deserialized YAML dict.
    Output: UnauthDecisionFilter or None.
    Side effects: Logs validation warnings.
    """
    if not isinstance(raw, dict):
        _log.warning("unauth-decision-filter.yaml: root must be a mapping.")
        return None

    version = raw.get("version", 1)
    passed = _parse_section(raw.get("passed_detection"), "passed_detection")
    failed = _parse_section(raw.get("failed_detection"), "failed_detection")

    return UnauthDecisionFilter(
        version=version,
        passed_detection=passed,
        failed_detection=failed,
    )


def _parse_section(raw_section: object, section_name: str) -> Optional[DetectionSection]:
    """Parse one detection section (passed_detection or failed_detection)."""
    if raw_section is None:
        return None
    if not isinstance(raw_section, dict):
        _log.warning("unauth filter: section '%s' must be a mapping.", section_name)
        return None

    group_op = str(raw_section.get("group_operator", "OR")).upper()
    raw_groups = raw_section.get("groups", [])
    if not isinstance(raw_groups, list):
        return None

    groups: list[FilterGroup] = []
    for i, rg in enumerate(raw_groups):
        grp = _parse_group(rg, i)
        if grp is not None:
            groups.append(grp)

    return DetectionSection(group_operator=group_op, groups=groups)


def _parse_group(raw_group: object, idx: int) -> Optional[FilterGroup]:
    """Parse one filter group."""
    if not isinstance(raw_group, dict):
        return None

    operator = str(raw_group.get("operator", "AND")).upper()
    group_id = str(raw_group.get("group_id", f"group_{idx}"))
    raw_rules = raw_group.get("rules", [])
    if not isinstance(raw_rules, list):
        return None

    rules: list[FilterRule] = []
    for j, rr in enumerate(raw_rules):
        rule = _parse_rule(rr, j)
        if rule is not None:
            rules.append(rule)

    return FilterGroup(operator=operator, rules=rules, group_id=group_id)


def _parse_rule(raw_rule: object, idx: int) -> Optional[FilterRule]:
    """Parse one filter rule."""
    if not isinstance(raw_rule, dict):
        return None

    location = str(raw_rule.get("location", ""))
    operator = str(raw_rule.get("operator", ""))
    value = raw_rule.get("value")
    field_name = raw_rule.get("field")
    rule_id = str(raw_rule.get("rule_id", f"rule_{idx}"))

    if location not in _VALID_LOCATIONS:
        _log.warning("unauth filter rule_%d: unknown location '%s'.", idx, location)
        return None
    if operator not in _VALID_OPERATORS:
        _log.warning("unauth filter rule_%d: unknown operator '%s'.", idx, operator)
        return None

    return FilterRule(
        location=location,
        operator=operator,
        value=value,
        field=field_name,
        rule_id=rule_id,
    )


# ------------------------------------------------------------------ #
# Filter evaluation                                                    #
# ------------------------------------------------------------------ #

def evaluate_response(
    decision_filter: UnauthDecisionFilter,
    response_data: ResponseData,
) -> UnauthDecisionResult:
    """
    Purpose:
        Evaluate the HTTP response against the decision filter.
        Evaluation order: failed_detection first → BYPASS; then passed_detection → SECURE.
    Input:
        decision_filter — parsed UnauthDecisionFilter.
        response_data   — normalized response fields.
    Output:
        UnauthDecisionResult with verdict and explainability fields.
    Side effects: None.
    """
    if decision_filter.failed_detection:
        result = _evaluate_section(
            decision_filter.failed_detection, "failed_detection", response_data
        )
        if result is not None:
            return UnauthDecisionResult(
                verdict=VERDICT_BYPASS,
                matched_section="failed_detection",
                matched_group_id=result[0],
                matched_rules=result[1],
            )

    if decision_filter.passed_detection:
        result = _evaluate_section(
            decision_filter.passed_detection, "passed_detection", response_data
        )
        if result is not None:
            return UnauthDecisionResult(
                verdict=VERDICT_SECURE,
                matched_section="passed_detection",
                matched_group_id=result[0],
                matched_rules=result[1],
            )

    return UnauthDecisionResult(
        verdict=VERDICT_UNKNOWN,
        matched_section=None,
        matched_group_id=None,
        matched_rules=[],
    )


def _evaluate_section(
    section: DetectionSection,
    section_name: str,
    response_data: ResponseData,
) -> Optional[tuple[str, list[str]]]:
    """
    Evaluate all groups within a section using section.group_operator.
    Returns (matched_group_id, matched_rules) on first matching group (OR mode),
    or aggregated result for AND mode.  Returns None if no match.
    """
    if section.group_operator == "OR":
        for grp in section.groups:
            matched_rules = _evaluate_group(grp, response_data)
            if matched_rules is not None:
                return grp.group_id, matched_rules
        return None

    # AND mode: all groups must match.
    all_rules: list[str] = []
    for grp in section.groups:
        matched_rules = _evaluate_group(grp, response_data)
        if matched_rules is None:
            return None
        all_rules.extend(matched_rules)
    return (section.groups[0].group_id if section.groups else ""), all_rules


def _evaluate_group(
    group: FilterGroup,
    response_data: ResponseData,
) -> Optional[list[str]]:
    """
    Evaluate all rules within a group using group.operator.
    Returns list of matched rule IDs on match, or None on no match.
    """
    matched: list[str] = []

    if group.operator == "OR":
        for rule in group.rules:
            if _evaluate_rule(rule, response_data):
                matched.append(rule.rule_id)
                return matched  # first match wins
        return None

    # AND mode: all rules must match.
    for rule in group.rules:
        if not _evaluate_rule(rule, response_data):
            return None
        matched.append(rule.rule_id)
    return matched if matched else None


def _evaluate_rule(rule: FilterRule, response_data: ResponseData) -> bool:
    """Evaluate a single atomic rule against the response."""
    location = rule.location
    operator = rule.operator
    value = rule.value

    # Resolve the target value from the response.
    if location == "status":
        target = response_data.status
        if target is None:
            return operator in ("not_exists",)
    elif location == "header":
        if rule.field:
            field_lower = rule.field.lower()
            target = next(
                (v for k, v in response_data.headers.items() if k.lower() == field_lower),
                None,
            )
        else:
            target = " ".join(response_data.headers.values())
    elif location in ("body", "response"):
        target = response_data.body.decode("utf-8", errors="replace") if response_data.body else ""
    elif location == "response_length":
        target = response_data.response_length
    else:
        return False

    # Existence operators.
    if operator == "exists":
        return target is not None
    if operator == "not_exists":
        return target is None

    if target is None:
        return False

    # Numeric equality (status and response_length).
    if location in ("status", "response_length") and operator in _NUMERIC_OPERATORS:
        try:
            target_int = int(target)
            value_int = int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False
        if operator == "equals":
            return target_int == value_int
        if operator == "not_equals":
            return target_int != value_int

    # String operators.
    target_str = str(target)
    value_str = str(value) if value is not None else ""

    if operator == "equals":
        return target_str == value_str
    if operator == "not_equals":
        return target_str != value_str
    if operator == "contains":
        return value_str.lower() in target_str.lower()
    if operator == "not_contains":
        return value_str.lower() not in target_str.lower()
    if operator == "regex":
        try:
            return bool(re.search(value_str, target_str))
        except re.error:
            return False
    if operator == "regex_not":
        try:
            return not bool(re.search(value_str, target_str))
        except re.error:
            return False

    return False


# ------------------------------------------------------------------ #
# Heuristic fallback verdict                                           #
# ------------------------------------------------------------------ #

def heuristic_verdict(
    original_status: Optional[int],
    replay_status: Optional[int],
    replay_error: Optional[str],
) -> UnauthDecisionResult:
    """
    Purpose:
        Compute a verdict without a decision filter (hardcoded heuristics).
        Used when no unauth-decision-filter.yaml exists in the project.
    Input:
        original_status — HTTP status of the original (authenticated) flow.
        replay_status   — HTTP status of the unauthenticated replay.
        replay_error    — Non-None if a network error prevented a response.
    Output:
        UnauthDecisionResult with verdict BYPASS | SECURE | UNKNOWN.
    Side effects: None.
    """
    if replay_error or replay_status is None:
        return UnauthDecisionResult(VERDICT_UNKNOWN, None, None)

    if replay_status in (401, 403, 407) or 300 <= replay_status < 400:
        return UnauthDecisionResult(VERDICT_SECURE, None, "heuristic_4xx_3xx")

    if 200 <= replay_status < 300:
        return UnauthDecisionResult(VERDICT_BYPASS, None, "heuristic_2xx")

    return UnauthDecisionResult(VERDICT_UNKNOWN, None, None)


# ------------------------------------------------------------------ #
# Default filter initialisation                                        #
# ------------------------------------------------------------------ #

def write_default_filter(project_data_dir: Path) -> bool:
    """
    Purpose:
        Write the default unauth-decision-filter.yaml to the project data directory.
        No-op if the file already exists.
    Input:  project_data_dir — Path to the project's data directory.
    Output: True when written; False when the file already existed.
    Side effects: Creates one YAML file.
    """
    filter_path = project_data_dir / FILTER_FILENAME
    if filter_path.exists():
        return False
    filter_path.write_text(_DEFAULT_YAML, encoding="utf-8")
    return True
