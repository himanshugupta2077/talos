"""
Module: talos.auth_session.verdict

Purpose:
    Scoring for Authentication & Session Testing (Phases 3–4).

    Verdicts (KD7):
        WEAK_VALIDATION — server accepted a *mutated* token with the same
                          authorized resource fingerprint (2xx + diff SAME),
                          or decision-filter failed_detection match.
        SECURE          — clear reject (401/403/407) or redirect (3xx),
                          or decision-filter passed_detection match.
        UNKNOWN         — network error, 5xx, 2xx+DIFFERENT, or other.

    Exact engine order (design Detection section):
        1. Replay error / missing status → UNKNOWN (never open filter)
        2. If auth-session-decision-filter.yaml exists and loads:
           failed_detection → WEAK_VALIDATION; passed_detection → SECURE
        3. Filter absent / load error / no match → **heuristic** (status + diff)
           (differs from unauth UNKNOWN-only when filter file exists but
           nothing matches)

    compute_diff coarseness (document for operators):
        SAME is **not** full-body equality. ``talos.replay.diff.compute_diff``
        returns DIFFERENT only when status changes, body length delta exceeds
        max(500 bytes, 20% of original), or both bodies are JSON with
        different top-level key sets. Small drift (timestamps, request ids)
        can still yield SAME → possible false WEAK_VALIDATION; large soft-fail
        error bodies yield DIFFERENT → UNKNOWN (miss). Decision-filter
        patterns tune this without code changes.

Dependencies: models; decision_filter (optional at call site)
Data flow: status + diff (+ filter result) → VerdictScore
Side effects: None (pure functions).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from talos.auth_session.models import (
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
    VERDICT_WEAK_VALIDATION,
)


@dataclass(frozen=True)
class VerdictScore:
    """
    Purpose:
        Combined scoring result for result row + outcome persistence.
    Fields:
        verdict          — WEAK_VALIDATION | SECURE | UNKNOWN
        matched_section  — filter section that won, or None for heuristic
        matched_group    — filter group id, or None
        matched_rules    — comma-joined rule ids (DB column shape), or None
        source           — 'filter' | 'heuristic' | 'error'
    """

    verdict: str
    matched_section: Optional[str] = None
    matched_group: Optional[str] = None
    matched_rules: Optional[str] = None
    source: str = "heuristic"


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


def score_verdict(
    *,
    replay_status: Optional[int],
    diff_verdict: Optional[str],
    replay_error: Optional[str] = None,
    filter_verdict: Optional[str] = None,
    filter_matched_section: Optional[str] = None,
    filter_matched_group: Optional[str] = None,
    filter_matched_rules: Optional[list[str]] = None,
) -> VerdictScore:
    """
    Purpose:
        Full Phase-4 scoring: error → filter match → heuristic fallback.
    Input:
        replay_status / diff_verdict / replay_error — from engine send
        filter_verdict — WEAK_VALIDATION | SECURE | UNKNOWN from evaluate_response,
                         or None when no filter was loaded
        filter_matched_* — explainability from evaluate_response
    Output:
        VerdictScore with DB-ready matched_* fields.
    Side effects: None.
    """
    # Step 1: transport / missing status — never open filter.
    if replay_error or replay_status is None:
        return VerdictScore(
            verdict=VERDICT_UNKNOWN,
            source="error",
        )

    # Step 2: filter match wins when present and not UNKNOWN.
    if filter_verdict is not None and filter_verdict != VERDICT_UNKNOWN:
        rules_str: Optional[str] = None
        if filter_matched_rules:
            rules_str = ",".join(filter_matched_rules)
        return VerdictScore(
            verdict=filter_verdict,
            matched_section=filter_matched_section,
            matched_group=filter_matched_group,
            matched_rules=rules_str,
            source="filter",
        )

    # Step 3: heuristic fallback (no file, load error, or no section matched).
    return VerdictScore(
        verdict=heuristic_verdict(
            replay_status=replay_status,
            diff_verdict=diff_verdict,
            replay_error=None,
        ),
        source="heuristic",
    )
