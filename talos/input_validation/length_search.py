"""
Module: talos.input_validation.length_search

Purpose:
    Module 6 — Binary / logarithmic length intelligence.

    Replaces the fixed 10-length matrix with a budget-aware search that:

        - Seeds logarithmic length points (standard: ≤ 5 first-wave probes)
        - Refines with binary midpoints when a bound gap remains
        - Distinguishes hard reject vs truncation when reflection is available
        - Produces observed.length fields: max_accepted, min_rejected,
          truncation_at, state, confidence, uncertainty

    Pure decision logic — no HTTP, no SQLite.  Engine expands planner
    ``length_binary`` actions via ``next_length_targets()``; synthesizer
    aggregates outcomes via ``synthesize_length_state()``.

Dependencies: outcomes vocabulary only
Data flow:
    planner length_binary → next_length_targets(observed) → probe lengths
    probe outcomes → synthesize_length_state() → profile.observed.length
Side effects: None.
"""

from __future__ import annotations

from typing import Any

from talos.input_validation.outcomes import (
    OUTCOME_ACCEPTED,
    OUTCOME_ENCODED,
    OUTCOME_MODIFIED,
    OUTCOME_NORMALIZED,
    OUTCOME_REJECTED,
    OUTCOME_TRUNCATED,
    OUTCOME_UNKNOWN,
)
from talos.input_validation.profile import (
    STATE_UNKNOWN,
    UNCERTAINTY_HIGH,
    UNCERTAINTY_LOW,
    UNCERTAINTY_NONE,
    empty_characteristic,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LENGTH_SEARCH_MIN = 1
LENGTH_SEARCH_MAX_STANDARD = 1024
LENGTH_SEARCH_MAX_DEEP = 4096
LENGTH_SEARCH_MAX_EXHAUSTIVE = 1024

# Fixed exhaustive matrix (legacy IV_TEST_LENGTHS).
EXHAUSTIVE_LENGTHS: tuple[int, ...] = (1, 4, 8, 16, 32, 64, 128, 256, 512, 1024)

# First-wave logarithmic seeds by tier (all < 10 for standard).
SEED_LENGTHS: dict[str, tuple[int, ...]] = {
    "quick": (1, 64, 1024),           # rarely used; quick usually skips length
    "standard": (1, 32, 128, 512, 1024),  # 5 probes
    "deep": (1, 16, 64, 256, 1024, 4096),
    "exhaustive": EXHAUSTIVE_LENGTHS,
}

# Cap total length probes per param (including refinements).
MAX_LENGTH_PROBES: dict[str, int] = {
    "quick": 3,
    "standard": 7,
    "deep": 10,
    "exhaustive": 10,
}

# Soft accept for length bound estimation.
_SOFT_ACCEPT: frozenset[str] = frozenset({
    OUTCOME_ACCEPTED,
    OUTCOME_MODIFIED,
    OUTCOME_ENCODED,
    OUTCOME_NORMALIZED,
})

# Outcomes that establish an upper bound (hard stop or truncation).
_BOUNDING: frozenset[str] = frozenset({
    OUTCOME_REJECTED,
    OUTCOME_TRUNCATED,
})


# ---------------------------------------------------------------------------
# Public API — next targets
# ---------------------------------------------------------------------------

def max_length_probes(strategy: str) -> int:
    """Hard cap of length HTTP probes for the tier. Side effects: None."""
    tier = (strategy or "standard").lower().strip()
    return MAX_LENGTH_PROBES.get(tier, MAX_LENGTH_PROBES["standard"])


def seed_lengths(strategy: str) -> tuple[int, ...]:
    """First-wave length points for the tier. Side effects: None."""
    tier = (strategy or "standard").lower().strip()
    return SEED_LENGTHS.get(tier, SEED_LENGTHS["standard"])


def next_length_targets(
    strategy: str,
    observed: dict[int, str],
    *,
    max_new: int | None = None,
    reflection_available: bool = False,
) -> list[int]:
    """
    Purpose:
        Decide the next length values to probe given outcomes already seen.

        Wave 1: logarithmic seeds not yet observed.
        Wave 2+: binary midpoints between max_accepted and min_bounding
                 when the gap is large and budget remains.

    Input:
        strategy             — quick|standard|deep|exhaustive.
        observed             — length → outcome label (accepted|rejected|…).
        max_new              — cap on how many new lengths to return this wave.
        reflection_available — reserved for future reflection-guided steps.

    Output:
        Sorted list of new lengths (empty when search is complete or budget 0).

    Side effects: None.
    """
    del reflection_available  # reserved; truncation uses outcomes only for now
    tier = (strategy or "standard").lower().strip()
    if max_new is not None and max_new <= 0:
        return []

    cap = max_length_probes(tier)
    already = set(int(k) for k in observed.keys())
    if len(already) >= cap:
        return []

    remaining_slots = cap - len(already)
    if max_new is not None:
        remaining_slots = min(remaining_slots, int(max_new))
    if remaining_slots <= 0:
        return []

    # Exhaustive: emit full matrix once (minus already probed).
    if tier == "exhaustive":
        targets = [n for n in EXHAUSTIVE_LENGTHS if n not in already]
        return targets[:remaining_slots]

    # Seed wave: any seed lengths not yet observed.
    seeds = [n for n in seed_lengths(tier) if n not in already]
    if seeds:
        return seeds[:remaining_slots]

    # Refinement: binary midpoints between accept bound and reject/trunc bound.
    max_acc, min_bound = _bounds(observed)
    if max_acc is None and min_bound is None:
        return []

    lo = max_acc if max_acc is not None else LENGTH_SEARCH_MIN
    hi_cap = (
        LENGTH_SEARCH_MAX_DEEP if tier == "deep" else LENGTH_SEARCH_MAX_STANDARD
    )
    hi = min_bound if min_bound is not None else hi_cap

    if hi <= lo + 1:
        # Bound is tight enough (adjacent integers).
        return []

    # Gap too large → probe midpoint (binary search step).
    mid = (lo + hi) // 2
    targets: list[int] = []
    if mid not in already and mid > lo and (min_bound is None or mid < min_bound):
        targets.append(mid)

    # Optional second midpoint for deep when budget allows.
    if tier == "deep" and remaining_slots >= 2 and min_bound is not None:
        mid2 = (mid + hi) // 2 if mid < hi else (lo + mid) // 2
        if mid2 not in already and mid2 != mid and lo < mid2 < hi:
            targets.append(mid2)

    return targets[:remaining_slots]


def length_search_complete(
    strategy: str,
    observed: dict[int, str],
    *,
    confidence: int = 0,
    uncertainty: str = UNCERTAINTY_HIGH,
) -> bool:
    """
    Purpose:
        True when no further length_binary probes are warranted.
    Side effects: None.
    """
    tier = (strategy or "standard").lower().strip()
    if not observed:
        return False
    if len(observed) >= max_length_probes(tier):
        return True
    # High confidence with low uncertainty → done.
    if int(confidence) >= 90 and (uncertainty or "").lower() in ("none", "low"):
        return True
    state = synthesize_length_state(observed, strategy=tier)
    if state.get("uncertainty") in (UNCERTAINTY_NONE, UNCERTAINTY_LOW):
        if state.get("state") in ("bounded", "all_rejected", "truncated", "open"):
            # open with low uncertainty only if we hit the tier max and accepted.
            return True
    # Tight bound: max_accepted and min_rejected adjacent or equal gap ≤ 1.
    max_acc, min_bound = _bounds(observed)
    if max_acc is not None and min_bound is not None and min_bound - max_acc <= 1:
        return True
    # Seeds done and no refine targets left.
    if not next_length_targets(tier, observed, max_new=1):
        return True
    return False


# ---------------------------------------------------------------------------
# Public API — synthesis
# ---------------------------------------------------------------------------

def synthesize_length_state(
    observed: dict[int, str],
    *,
    strategy: str = "standard",
    evidence_flow_ids: list[str] | None = None,
    reflected_prefix_lengths: dict[int, int] | None = None,
) -> dict[str, Any]:
    """
    Purpose:
        Aggregate length probe outcomes into an observed.length characteristic.

    Truncation vs hard reject:
        - outcome ``rejected`` → hard bound (min_rejected)
        - outcome ``truncated`` → truncation_at (server kept success class but
          shortened); also treated as an upper bound
        - when ``reflected_prefix_lengths`` maps sent_len → reflected_len and
          reflected_len < sent_len with soft-accept outcome → truncation_at

    Input:
        observed                 — length → outcome.
        strategy                 — tier (affects open-state confidence).
        evidence_flow_ids        — supporting flow UUIDs.
        reflected_prefix_lengths — optional sent_len → max reflected char count.

    Output:
        Characteristic dict with extras: max_accepted, min_rejected,
        truncation_at, lengths, method=binary|matrix.

    Side effects: None.
    """
    tier = (strategy or "standard").lower().strip()
    if not observed:
        return empty_characteristic(
            state=STATE_UNKNOWN,
            confidence=0,
            uncertainty=UNCERTAINTY_HIGH,
            extra={
                "max_accepted": 0,
                "min_rejected": None,
                "truncation_at": None,
                "lengths": {},
                "method": "binary",
                "known_test_lengths": list(seed_lengths(tier)),
            },
        )

    accepted: list[int] = []
    rejected: list[int] = []
    truncated: list[int] = []
    per_length: dict[str, str] = {}

    for length, outcome in sorted(observed.items(), key=lambda kv: int(kv[0])):
        n = int(length)
        oc = (outcome or OUTCOME_UNKNOWN).lower()
        per_length[str(n)] = oc
        if oc in _SOFT_ACCEPT:
            accepted.append(n)
        elif oc == OUTCOME_REJECTED:
            rejected.append(n)
        elif oc == OUTCOME_TRUNCATED:
            truncated.append(n)

    # Reflection-assisted truncation: partial echo of a longer payload.
    trunc_from_reflection: list[int] = []
    if reflected_prefix_lengths:
        for sent_len, refl_len in reflected_prefix_lengths.items():
            sent_i = int(sent_len)
            refl_i = int(refl_len)
            if refl_i > 0 and refl_i < sent_i:
                oc = (observed.get(sent_i) or "").lower()
                if oc in _SOFT_ACCEPT or oc == OUTCOME_TRUNCATED or not oc:
                    trunc_from_reflection.append(refl_i)
                    # Annotate the sent length as truncated when soft-accepted.
                    if str(sent_i) in per_length and per_length[str(sent_i)] in _SOFT_ACCEPT:
                        per_length[str(sent_i)] = OUTCOME_TRUNCATED
                    if sent_i not in truncated:
                        truncated.append(sent_i)

    max_accepted = max(accepted) if accepted else 0
    min_rejected = min(rejected) if rejected else None
    truncation_candidates = truncated + trunc_from_reflection
    truncation_at: int | None = min(truncation_candidates) if truncation_candidates else None

    # If truncated and no hard reject, max_accepted is just below truncation.
    if truncation_at is not None and accepted:
        # Values fully accepted without truncation evidence.
        fully = [
            n for n in accepted
            if per_length.get(str(n)) in _SOFT_ACCEPT
        ]
        if fully:
            max_accepted = max(fully)
        elif max_accepted >= truncation_at:
            max_accepted = max(0, truncation_at - 1) if truncation_at > 0 else 0

    n_samples = len(observed)
    conf = min(95, 40 + n_samples * 8)

    state = STATE_UNKNOWN
    if truncation_at is not None and not rejected:
        state = "truncated"
        conf = min(95, conf + 8)
    elif accepted and rejected and min_rejected is not None and min_rejected > max_accepted:
        state = "bounded"
        conf = min(95, conf + 10)
    elif accepted and truncated and truncation_at is not None:
        state = "truncated"
        conf = min(95, conf + 8)
    elif not accepted and rejected:
        state = "all_rejected"
        conf = min(90, conf)
    elif accepted and not rejected and not truncated:
        # Hit tier max without rejection → open-ended.
        tier_max = max(seed_lengths(tier)) if seed_lengths(tier) else LENGTH_SEARCH_MAX_STANDARD
        if max_accepted >= tier_max:
            state = "open"
            conf = min(90, conf)
        else:
            state = "open"
            conf = min(75, conf)
    elif truncated and not accepted:
        state = "truncated"
        conf = min(85, conf)

    if n_samples >= 5 and state in ("bounded", "truncated", "all_rejected"):
        uncertainty = UNCERTAINTY_NONE
    elif n_samples >= 3 or state in ("bounded", "truncated"):
        uncertainty = UNCERTAINTY_LOW
    else:
        uncertainty = UNCERTAINTY_HIGH

    method = "matrix" if tier == "exhaustive" else "binary"

    return empty_characteristic(
        state=state,
        confidence=conf,
        uncertainty=uncertainty,
        evidence_flow_ids=list(evidence_flow_ids or [])[:20],
        extra={
            "max_accepted": max_accepted,
            "min_rejected": min_rejected,
            "truncation_at": truncation_at,
            "lengths": per_length,
            "method": method,
            "known_test_lengths": list(seed_lengths(tier)),
        },
    )


def estimated_length_probe_count(
    strategy: str,
    observed: dict[int, str] | None = None,
) -> int:
    """
    Purpose:
        Planner estimate for the next length_binary wave size.
    Side effects: None.
    """
    obs = observed or {}
    targets = next_length_targets(strategy, obs)
    return len(targets)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _bounds(observed: dict[int, str]) -> tuple[int | None, int | None]:
    """
    Purpose:
        Return (max_accepted, min_bounding) where bounding is reject or truncate.
    Side effects: None.
    """
    accepted: list[int] = []
    bounding: list[int] = []
    for length, outcome in observed.items():
        n = int(length)
        oc = (outcome or "").lower()
        if oc in _SOFT_ACCEPT:
            accepted.append(n)
        elif oc in _BOUNDING:
            bounding.append(n)
    max_acc = max(accepted) if accepted else None
    min_bound = min(bounding) if bounding else None
    return max_acc, min_bound


def parse_length_outcomes(
    rows: list[dict[str, Any]],
) -> dict[int, str]:
    """
    Purpose:
        Build length → outcome map from probe summary dicts or probe rows.
        Accepts keys: length_value / payload length, outcome.
    Side effects: None.
    """
    out: dict[int, str] = {}
    for row in rows:
        lv = row.get("length_value")
        if lv is None:
            payload = row.get("payload")
            if isinstance(payload, str):
                lv = len(payload)
            else:
                continue
        try:
            n = int(lv)
        except (TypeError, ValueError):
            continue
        outcome = str(row.get("outcome") or OUTCOME_UNKNOWN)
        # Prefer more decisive outcomes if duplicate lengths appear.
        prev = out.get(n)
        if prev is None or _outcome_rank(outcome) >= _outcome_rank(prev):
            out[n] = outcome
    return out


def _outcome_rank(outcome: str) -> int:
    """Higher = more decisive for length bound. Side effects: None."""
    oc = (outcome or "").lower()
    if oc == OUTCOME_REJECTED:
        return 5
    if oc == OUTCOME_TRUNCATED:
        return 4
    if oc in _SOFT_ACCEPT:
        return 3
    if oc == OUTCOME_UNKNOWN:
        return 1
    return 2
