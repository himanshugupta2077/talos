"""
Tests: auth-session Phase 3 heuristic verdict (KD7).

Pure function: status × diff → WEAK_VALIDATION | SECURE | UNKNOWN.
"""

from __future__ import annotations

import pytest

from talos.auth_session.models import (
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
    VERDICT_WEAK_VALIDATION,
)
from talos.auth_session.verdict import heuristic_verdict


@pytest.mark.parametrize(
    "status,diff,error,expected",
    [
        (None, None, "timeout", VERDICT_UNKNOWN),
        (None, None, None, VERDICT_UNKNOWN),
        (200, "SAME", "connection_error", VERDICT_UNKNOWN),
        (401, "DIFFERENT", None, VERDICT_SECURE),
        (403, "SAME", None, VERDICT_SECURE),
        (407, None, None, VERDICT_SECURE),
        (302, "DIFFERENT", None, VERDICT_SECURE),
        (301, "SAME", None, VERDICT_SECURE),
        (200, "SAME", None, VERDICT_WEAK_VALIDATION),
        (204, "SAME", None, VERDICT_WEAK_VALIDATION),
        (201, "SAME", None, VERDICT_WEAK_VALIDATION),
        (200, "DIFFERENT", None, VERDICT_UNKNOWN),
        (200, "ERROR", None, VERDICT_UNKNOWN),
        (200, None, None, VERDICT_UNKNOWN),
        (500, "SAME", None, VERDICT_UNKNOWN),
        (502, "DIFFERENT", None, VERDICT_UNKNOWN),
        (418, "SAME", None, VERDICT_UNKNOWN),
    ],
)
def test_heuristic_matrix(status, diff, error, expected) -> None:
    assert (
        heuristic_verdict(
            replay_status=status,
            diff_verdict=diff,
            replay_error=error,
        )
        == expected
    )
