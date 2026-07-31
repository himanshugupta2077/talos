"""
Module: talos.auth_session.decision_filter

Purpose:
    Load and evaluate the per-project ``auth-session-decision-filter.yaml``.
    Determines whether a mutated-token HTTP replay response represents:
        WEAK_VALIDATION — server accepted a broken token (failed_detection)
        SECURE          — server correctly rejected the token (passed_detection)
        UNKNOWN         — no section matched (engine falls through to heuristic)

    Evaluation order (first match wins — same shape as unauth/BAC):
        1. failed_detection  → WEAK_VALIDATION
        2. passed_detection  → SECURE
        3. No match          → UNKNOWN (caller applies heuristic fallback)

    Auth-session differs from unauth on fallback: when the filter file is
    absent, fails to load, or matches nothing, the engine always falls
    through to status+diff heuristic (never UNKNOWN-only on no match).

    Default SECURE patterns (passed_detection) reduce false WEAKs on soft-fail
    bodies (invalid token / unauthorized / signature error pages).

Dependencies: re, logging, pathlib, yaml (pyyaml)
Data flow:
    engine._send_and_store → load_filter(project_data_dir)
        → evaluate_response(filter, response_data) → AuthSessionDecisionResult
    CLI filter init|show|validate → write_default_filter / load_filter
Side effects: load_filter is read-only; write_default_filter creates one file.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from talos.auth_session.models import (
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
    VERDICT_WEAK_VALIDATION,
)

_log = logging.getLogger(__name__)

FILTER_FILENAME = "auth-session-decision-filter.yaml"

_VALID_LOCATIONS = frozenset({
    "status", "header", "body", "response", "response_length",
})
_VALID_OPERATORS = frozenset({
    "equals", "not_equals",
    "contains", "not_contains",
    "regex", "regex_not",
    "exists", "not_exists",
})
_NUMERIC_OPERATORS = frozenset({"equals", "not_equals"})

# Default filter shipped via: talos attack auth-session filter init
# Primary value: SECURE soft-fail body/status patterns (design Phase 4).
_DEFAULT_YAML = """\
version: 1

# SECURE: token validation detected — mutated credential was rejected.
# Tunable soft-fail bodies reduce false WEAK_VALIDATION when APIs return
# 2xx with an error envelope that is close in length to the baseline.
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
    # Soft-fail body phrases only — do NOT use bare tokens like "jwt" or
    # "signature" alone; authorized APIs often echo those words and would
    # force false SECURE on true WEAK_VALIDATION (2xx + SAME body).
    - group_id: body_auth_keywords
      operator: OR
      rules:
        - location: body
          operator: contains
          value: invalid token
        - location: body
          operator: contains
          value: invalid jwt
        - location: body
          operator: contains
          value: malformed token
        - location: body
          operator: contains
          value: malformed jwt
        - location: body
          operator: contains
          value: jwt expired
        - location: body
          operator: contains
          value: token expired
        - location: body
          operator: contains
          value: invalid signature
        - location: body
          operator: contains
          value: signature verification failed
        - location: body
          operator: contains
          value: signature invalid
        - location: body
          operator: contains
          value: unauthorized
        - location: body
          operator: contains
          value: access denied
        - location: body
          operator: contains
          value: forbidden
        - location: body
          operator: contains
          value: authentication required
        - location: body
          operator: contains
          value: login required
        - location: body
          operator: contains
          value: session expired
        - location: body
          operator: contains
          value: not authenticated
        - location: body
          operator: contains
          value: authentication failed

# WEAK_VALIDATION: optional explicit weak signals (heuristic also covers
# 2xx + structural SAME). Add groups here when soft-fail envelopes still
# prove access (e.g. body contains welcome/dashboard with broken JWT).
failed_detection:
  group_operator: OR
  groups: []
"""


# ------------------------------------------------------------------ #
# Data models                                                          #
# ------------------------------------------------------------------ #


@dataclass
class FilterRule:
    """One atomic match condition targeting a part of the HTTP response."""

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
class AuthSessionDecisionFilter:
    """Parsed and validated auth-session-decision-filter.yaml."""

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
class AuthSessionDecisionResult:
    """
    Purpose:
        Result of evaluating a response against the decision filter.
    Fields:
        verdict          — WEAK_VALIDATION | SECURE | UNKNOWN
        matched_section  — 'passed_detection' | 'failed_detection' | None
        matched_group_id — matching group id; None when no match
        matched_rules    — matched rule ids for explainability
    """

    verdict: str
    matched_section: Optional[str]
    matched_group_id: Optional[str]
    matched_rules: list[str] = field(default_factory=list)


# ------------------------------------------------------------------ #
# Filter loading                                                       #
# ------------------------------------------------------------------ #


def load_filter(project_data_dir: Path) -> Optional[AuthSessionDecisionFilter]:
    """
    Purpose:
        Load and parse auth-session-decision-filter.yaml from the project
        data directory. Returns None if absent or unparseable (engine then
        uses heuristic only). **Never raises** — callers (engine, CLI validate)
        rely on None for soft failure.
    Input:
        project_data_dir — project data dir (typically db_path.parent)
    Output:
        Parsed AuthSessionDecisionFilter, or None
    Side effects:
        One read-only file access; logs warnings on parse errors.
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
        _log.warning(
            "Failed to load %s: %s. Using heuristic verdict.",
            FILTER_FILENAME,
            exc,
        )
        return None

    try:
        return _parse_filter(raw)
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "Failed to parse %s: %s. Using heuristic verdict.",
            FILTER_FILENAME,
            exc,
        )
        return None


def _parse_filter(raw: object) -> Optional[AuthSessionDecisionFilter]:
    """Convert raw YAML into AuthSessionDecisionFilter; None on structural errors."""
    if not isinstance(raw, dict):
        _log.warning("%s: root must be a mapping.", FILTER_FILENAME)
        return None

    try:
        version = int(raw.get("version", 1) or 1)
    except (TypeError, ValueError):
        _log.warning("%s: invalid version field; defaulting to 1.", FILTER_FILENAME)
        version = 1

    passed = _parse_section(raw.get("passed_detection"), "passed_detection")
    failed = _parse_section(raw.get("failed_detection"), "failed_detection")

    return AuthSessionDecisionFilter(
        version=version,
        passed_detection=passed,
        failed_detection=failed,
    )


def _parse_section(
    raw_section: object, section_name: str
) -> Optional[DetectionSection]:
    if raw_section is None:
        return None
    if not isinstance(raw_section, dict):
        _log.warning(
            "auth-session filter: section '%s' must be a mapping.", section_name
        )
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
    if not isinstance(raw_rule, dict):
        return None

    location = str(raw_rule.get("location", ""))
    operator = str(raw_rule.get("operator", ""))
    value = raw_rule.get("value")
    field_name = raw_rule.get("field")
    rule_id = str(raw_rule.get("rule_id", f"rule_{idx}"))

    if location not in _VALID_LOCATIONS:
        _log.warning(
            "auth-session filter rule_%d: unknown location '%s'.", idx, location
        )
        return None
    if operator not in _VALID_OPERATORS:
        _log.warning(
            "auth-session filter rule_%d: unknown operator '%s'.", idx, operator
        )
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
    decision_filter: AuthSessionDecisionFilter,
    response_data: ResponseData,
) -> AuthSessionDecisionResult:
    """
    Purpose:
        Evaluate the HTTP response against the decision filter.
        Order: failed_detection → WEAK_VALIDATION; then passed_detection → SECURE.
        No match → UNKNOWN (caller falls through to heuristic).
    Side effects: None.
    """
    if decision_filter.failed_detection:
        result = _evaluate_section(
            decision_filter.failed_detection, "failed_detection", response_data
        )
        if result is not None:
            return AuthSessionDecisionResult(
                verdict=VERDICT_WEAK_VALIDATION,
                matched_section="failed_detection",
                matched_group_id=result[0],
                matched_rules=result[1],
            )

    if decision_filter.passed_detection:
        result = _evaluate_section(
            decision_filter.passed_detection, "passed_detection", response_data
        )
        if result is not None:
            return AuthSessionDecisionResult(
                verdict=VERDICT_SECURE,
                matched_section="passed_detection",
                matched_group_id=result[0],
                matched_rules=result[1],
            )

    return AuthSessionDecisionResult(
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
    Evaluate groups within a section. Returns (group_id, matched_rules) or None.
    Empty groups list never matches.
    """
    if not section.groups:
        return None

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
    """Returns list of matched rule ids on match, or None."""
    if not group.rules:
        return None

    matched: list[str] = []

    if group.operator == "OR":
        for rule in group.rules:
            if _evaluate_rule(rule, response_data):
                matched.append(rule.rule_id)
                return matched
        return None

    for rule in group.rules:
        if not _evaluate_rule(rule, response_data):
            return None
        matched.append(rule.rule_id)
    return matched if matched else None


def _evaluate_rule(rule: FilterRule, response_data: ResponseData) -> bool:
    location = rule.location
    operator = rule.operator
    value = rule.value

    if location == "status":
        target = response_data.status
        if target is None:
            return operator in ("not_exists",)
    elif location == "header":
        if rule.field:
            field_lower = rule.field.lower()
            target = next(
                (
                    v
                    for k, v in response_data.headers.items()
                    if k.lower() == field_lower
                ),
                None,
            )
        else:
            target = " ".join(str(v) for v in response_data.headers.values())
    elif location in ("body", "response"):
        target = (
            response_data.body.decode("utf-8", errors="replace")
            if response_data.body
            else ""
        )
    elif location == "response_length":
        target = response_data.response_length
    else:
        return False

    if operator == "exists":
        return target is not None
    if operator == "not_exists":
        return target is None

    if target is None:
        return False

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
# Default filter initialisation                                        #
# ------------------------------------------------------------------ #


def write_default_filter(project_data_dir: Path) -> bool:
    """
    Purpose:
        Write the default auth-session-decision-filter.yaml.
        No-op if the file already exists.
    Output: True when written; False when already present.
    Side effects: Creates one YAML file under project_data_dir.
    """
    filter_path = project_data_dir / FILTER_FILENAME
    if filter_path.exists():
        return False
    filter_path.write_text(_DEFAULT_YAML, encoding="utf-8")
    return True


def default_filter_yaml() -> str:
    """Return the shipped default YAML text (for tests / docs)."""
    return _DEFAULT_YAML
