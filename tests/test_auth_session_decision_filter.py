"""
Tests: auth-session Phase 4 decision filter (load / eval / score fallback).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from talos.auth_session.decision_filter import (
    FILTER_FILENAME,
    ResponseData,
    evaluate_response,
    load_filter,
    write_default_filter,
)
from talos.auth_session.models import (
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
    VERDICT_WEAK_VALIDATION,
)
from talos.auth_session.verdict import heuristic_verdict, score_verdict


def test_write_and_load_default_filter(tmp_path: Path) -> None:
    assert write_default_filter(tmp_path) is True
    assert (tmp_path / FILTER_FILENAME).exists()
    assert write_default_filter(tmp_path) is False  # no-op

    flt = load_filter(tmp_path)
    assert flt is not None
    assert flt.version == 1
    assert flt.passed_detection is not None
    assert len(flt.passed_detection.groups) >= 1
    # Default failed_detection is empty groups → no match from that section
    assert flt.failed_detection is not None


def test_load_filter_absent(tmp_path: Path) -> None:
    assert load_filter(tmp_path) is None


def test_passed_detection_status_401(tmp_path: Path) -> None:
    write_default_filter(tmp_path)
    flt = load_filter(tmp_path)
    assert flt is not None
    result = evaluate_response(
        flt,
        ResponseData(status=401, headers={}, body=b"", response_length=0),
    )
    assert result.verdict == VERDICT_SECURE
    assert result.matched_section == "passed_detection"
    assert result.matched_group_id == "status_401"


def test_passed_detection_body_invalid_token(tmp_path: Path) -> None:
    write_default_filter(tmp_path)
    flt = load_filter(tmp_path)
    assert flt is not None
    body = b'{"error":"Invalid token signature"}'
    result = evaluate_response(
        flt,
        ResponseData(
            status=200,
            headers={"content-type": "application/json"},
            body=body,
            response_length=len(body),
        ),
    )
    assert result.verdict == VERDICT_SECURE
    assert result.matched_section == "passed_detection"


def test_failed_detection_forces_weak(tmp_path: Path) -> None:
    yaml_text = """\
version: 1
passed_detection:
  group_operator: OR
  groups: []
failed_detection:
  group_operator: OR
  groups:
    - group_id: body_welcome
      operator: AND
      rules:
        - location: body
          operator: contains
          value: Welcome
"""
    (tmp_path / FILTER_FILENAME).write_text(yaml_text, encoding="utf-8")
    flt = load_filter(tmp_path)
    assert flt is not None
    body = b"Welcome admin dashboard"
    result = evaluate_response(
        flt,
        ResponseData(status=200, headers={}, body=body, response_length=len(body)),
    )
    assert result.verdict == VERDICT_WEAK_VALIDATION
    assert result.matched_section == "failed_detection"
    assert result.matched_group_id == "body_welcome"


def test_no_match_returns_unknown(tmp_path: Path) -> None:
    yaml_text = """\
version: 1
passed_detection:
  group_operator: OR
  groups: []
failed_detection:
  group_operator: OR
  groups: []
"""
    (tmp_path / FILTER_FILENAME).write_text(yaml_text, encoding="utf-8")
    flt = load_filter(tmp_path)
    assert flt is not None
    result = evaluate_response(
        flt,
        ResponseData(status=200, headers={}, body=b'{"ok":true}', response_length=10),
    )
    assert result.verdict == VERDICT_UNKNOWN
    assert result.matched_section is None


def test_score_verdict_filter_wins_over_heuristic() -> None:
    # 2xx SAME would be WEAK heuristically; filter SECURE wins.
    scored = score_verdict(
        replay_status=200,
        diff_verdict="SAME",
        filter_verdict=VERDICT_SECURE,
        filter_matched_section="passed_detection",
        filter_matched_group="body_auth_keywords",
        filter_matched_rules=["rule_0"],
    )
    assert scored.verdict == VERDICT_SECURE
    assert scored.source == "filter"
    assert scored.matched_section == "passed_detection"
    assert scored.matched_group == "body_auth_keywords"
    assert scored.matched_rules == "rule_0"


def test_score_verdict_heuristic_fallback_on_unknown_filter() -> None:
    scored = score_verdict(
        replay_status=200,
        diff_verdict="SAME",
        filter_verdict=VERDICT_UNKNOWN,
        filter_matched_section=None,
    )
    assert scored.verdict == VERDICT_WEAK_VALIDATION
    assert scored.source == "heuristic"
    assert scored.matched_section is None


def test_score_verdict_no_filter_uses_heuristic() -> None:
    scored = score_verdict(
        replay_status=401,
        diff_verdict="DIFFERENT",
        filter_verdict=None,
    )
    assert scored.verdict == VERDICT_SECURE
    assert scored.source == "heuristic"


def test_score_verdict_error_skips_filter() -> None:
    scored = score_verdict(
        replay_status=200,
        diff_verdict="SAME",
        replay_error="timeout",
        filter_verdict=VERDICT_SECURE,
        filter_matched_section="passed_detection",
    )
    assert scored.verdict == VERDICT_UNKNOWN
    assert scored.source == "error"


def test_heuristic_unchanged() -> None:
    assert (
        heuristic_verdict(replay_status=200, diff_verdict="SAME")
        == VERDICT_WEAK_VALIDATION
    )
    assert heuristic_verdict(replay_status=403, diff_verdict="DIFFERENT") == VERDICT_SECURE


def test_invalid_yaml_returns_none(tmp_path: Path) -> None:
    (tmp_path / FILTER_FILENAME).write_text("not: [valid: yaml: {", encoding="utf-8")
    assert load_filter(tmp_path) is None


def test_failed_detection_before_passed(tmp_path: Path) -> None:
    """failed_detection is evaluated first (design order)."""
    yaml_text = """\
version: 1
passed_detection:
  group_operator: OR
  groups:
    - group_id: status_200_secure
      operator: AND
      rules:
        - location: status
          operator: equals
          value: 200
failed_detection:
  group_operator: OR
  groups:
    - group_id: status_200_weak
      operator: AND
      rules:
        - location: status
          operator: equals
          value: 200
"""
    (tmp_path / FILTER_FILENAME).write_text(yaml_text, encoding="utf-8")
    flt = load_filter(tmp_path)
    assert flt is not None
    result = evaluate_response(
        flt,
        ResponseData(status=200, headers={}, body=b"x", response_length=1),
    )
    assert result.verdict == VERDICT_WEAK_VALIDATION
    assert result.matched_group_id == "status_200_weak"


def test_default_filter_does_not_match_bare_jwt_or_signature(tmp_path: Path) -> None:
    """
    Authorized APIs often echo 'jwt' / 'signature' in success JSON.
    Bare tokens must not force SECURE (would hide true WEAK_VALIDATION).
    """
    write_default_filter(tmp_path)
    flt = load_filter(tmp_path)
    assert flt is not None

    for body in (
        b'{"user":"admin","token_type":"jwt","role":"user"}',
        b'{"alg":"RS256","signature_verified":true}',
        b'{"ok":true,"typ":"JWT"}',
    ):
        result = evaluate_response(
            flt,
            ResponseData(
                status=200,
                headers={},
                body=body,
                response_length=len(body),
            ),
        )
        assert result.verdict == VERDICT_UNKNOWN, body
        assert result.matched_section is None


def test_default_filter_still_matches_soft_fail_phrases(tmp_path: Path) -> None:
    write_default_filter(tmp_path)
    flt = load_filter(tmp_path)
    assert flt is not None
    for phrase in (
        b'{"error":"Invalid token"}',
        b"signature verification failed",
        b"JWT expired please login",
        b"Authentication required",
    ):
        result = evaluate_response(
            flt,
            ResponseData(status=200, headers={}, body=phrase, response_length=len(phrase)),
        )
        assert result.verdict == VERDICT_SECURE, phrase
        assert result.matched_section == "passed_detection"


def test_load_filter_never_raises_on_bad_yaml_or_version(tmp_path: Path) -> None:
    (tmp_path / FILTER_FILENAME).write_text(
        "version: not-a-number\npassed_detection: {}\n", encoding="utf-8"
    )
    flt = load_filter(tmp_path)
    assert flt is not None  # version coerced to 1
    assert flt.version == 1

    (tmp_path / FILTER_FILENAME).write_text("version: [1]\n", encoding="utf-8")
    flt2 = load_filter(tmp_path)  # must not raise
    assert flt2 is not None
    assert flt2.version == 1

    (tmp_path / FILTER_FILENAME).write_text(
        "not: [valid: yaml: {", encoding="utf-8"
    )
    assert load_filter(tmp_path) is None
