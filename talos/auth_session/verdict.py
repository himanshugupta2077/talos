"""
Module: talos.auth_session.verdict

Purpose:
    Pure heuristic scoring for Authentication & Session Testing (Phase 3).

    Verdicts (KD7):
        WEAK_VALIDATION — server accepted a *mutated* token with the same
                          authorized resource fingerprint (2xx + diff SAME).
        SECURE          — clear reject (401/403/407) or redirect (3xx).
        UNKNOWN         — network error, 5xx, 2xx+DIFFERENT, or other.

    Phase 4 will evaluate ``auth-session-decision-filter.yaml`` *before*
    falling through to this heuristic when the filter is present but
    unmatched (design: always heuristic fallback — not unauth-style
    UNKNOWN-only when a filter file exists).

    compute_diff coarseness (document for operators):
        SAME is **not** full-body equality. ``talos.replay.diff.compute_diff``
        returns DIFFERENT only when status changes, body length delta exceeds
        max(500 bytes, 20% of original), or both bodies are JSON with
        different top-level key sets. Small drift (timestamps, request ids)
        can still yield SAME → possible false WEAK_VALIDATION; large soft-fail
        error bodies yield DIFFERENT → UNKNOWN (miss). Decision-filter
        patterns (Phase 4) tune this without code changes.

Dependencies: models (verdict constants)
Data flow: status + diff_verdict (+ optional replay_error) → verdict string
Side effects: None (pure function).
"""

from __future__ import annotations

from typing import Optional

from talos.auth_session.models import (
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
    VERDICT_WEAK_VALIDATION,
)


def heuristic_verdict(
    *,
    replay_status: Optional[int],
    diff_verdict: Optional[str],
    replay_error: Optional[str] = None,
) -> str:
    """
    Purpose:
        Map replay status + structural diff to WEAK_VALIDATION | SECURE | UNKNOWN.
    Input:
        replay_status — HTTP status from mutated replay, or None on transport error
        diff_verdict  — SAME | DIFFERENT | ERROR | None
        replay_error  — non-None when transport/protocol failed before a status
    Output:
        Verdict string constant.
    Side effects: None.
    """
    if replay_error:
        return VERDICT_UNKNOWN
    if replay_status is None:
        return VERDICT_UNKNOWN

    # Clear authentication / session rejection signals.
    if replay_status in (401, 403, 407):
        return VERDICT_SECURE
    if 300 <= replay_status < 400:
        return VERDICT_SECURE

    # Weak validation: authorized resource still served with broken token.
    if 200 <= replay_status < 300:
        if diff_verdict == "SAME":
            return VERDICT_WEAK_VALIDATION
        # 2xx + DIFFERENT / ERROR / None → inconclusive for v1 heuristic.
        return VERDICT_UNKNOWN

    # 5xx and any other status class.
    return VERDICT_UNKNOWN
