"""
Module: talos.passive.scoring

Purpose:
    Deterministic confidence scoring for Passive Source Intelligence.

    Converts RawMatch → (score 0–100, confidence_level) using additive
    weights.  Provider rules ship with base scores; generic / entropy
    paths start lower and require assignment / keyword boosts.

Score bands (constants.SCORE_*):
    90–100 CONFIRMED_PATTERN
    70–89  HIGH
    50–69  MEDIUM
    <50    OBSERVATION_ONLY

Dependencies: talos.passive.constants, detectors.base, models
Data flow: RawMatch → score_match() → (score, level)
Side effects: None.
"""

from __future__ import annotations

from talos.passive.constants import (
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_OBSERVATION_ONLY,
    DETECTOR_FAMILY_CONNECTION_STRING,
    DETECTOR_FAMILY_CONTEXTUAL,
    DETECTOR_FAMILY_ENTROPY,
    DETECTOR_FAMILY_GENERIC,
    DETECTOR_FAMILY_INFRA,
    DETECTOR_FAMILY_JWT,
    DETECTOR_FAMILY_PEM,
    DETECTOR_FAMILY_PROVIDER,
    SCORE_CONFIRMED_PATTERN_MIN,
    SCORE_HIGH_MIN,
    SCORE_MEDIUM_MIN,
)
from talos.passive.detectors.base import shannon_entropy
from talos.passive.models import RawMatch

# Additive weights (design doc examples)
_W_SENSITIVE_ASSIGNMENT = 30
_W_NEARBY_KEYWORD = 20
_W_HIGH_ENTROPY = 15
_W_AUTH_URI_CONTEXT = 30
_W_MINIFIED_BARE = -15
_W_ENCODED_BONUS = 5  # slight boost when recovered from encoding (real embed)


def level_from_score(score: int) -> str:
    """
    Purpose:
        Map additive score to confidence level label.
    Input:
        score — 0–100 (clamped)
    Output:
        One of CONFIDENCE_* constants
    Side effects: None.
    """
    s = max(0, min(100, int(score)))
    if s >= SCORE_CONFIRMED_PATTERN_MIN:
        return CONFIDENCE_CONFIRMED_PATTERN
    if s >= SCORE_HIGH_MIN:
        return CONFIDENCE_HIGH
    if s >= SCORE_MEDIUM_MIN:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_OBSERVATION_ONLY


def score_match(raw: RawMatch) -> tuple[int, str]:
    """
    Purpose:
        Compute confidence_score and confidence_level for a RawMatch.

    Input:
        raw — detector hit (metadata may include base_score / base_level)

    Output:
        (score, level) with score clamped to 0–100

    Side effects: None.
    """
    meta = raw.metadata or {}
    family = (raw.detector_family or "").lower()

    # Infrastructure / disclosure — trust base score/level; never boost to HIGH
    if family == DETECTOR_FAMILY_INFRA:
        base = int(meta.get("base_score") or 40)
        level_hint = str(meta.get("base_level") or CONFIDENCE_OBSERVATION_ONLY)
        score = max(0, min(100, base))
        if level_hint in {
            CONFIDENCE_CONFIRMED_PATTERN,
            CONFIDENCE_HIGH,
            CONFIDENCE_MEDIUM,
            CONFIDENCE_OBSERVATION_ONLY,
        }:
            # Cap infra at MEDIUM even if a future rule mis-sets base score
            if score >= SCORE_HIGH_MIN:
                score = SCORE_HIGH_MIN - 1
            if level_hint in (CONFIDENCE_CONFIRMED_PATTERN, CONFIDENCE_HIGH):
                level_hint = CONFIDENCE_MEDIUM if score >= SCORE_MEDIUM_MIN else CONFIDENCE_OBSERVATION_ONLY
            return score, level_hint
        return score, level_from_score(score)

    # Provider / PEM / JWT / connection_string: trust rule base with small tweaks
    if family in {
        DETECTOR_FAMILY_PROVIDER,
        DETECTOR_FAMILY_PEM,
        DETECTOR_FAMILY_JWT,
        DETECTOR_FAMILY_CONNECTION_STRING,
    }:
        base = int(meta.get("base_score") or 90)
        level_hint = str(meta.get("base_level") or "")
        score = base
        if raw.encoding_chain:
            score += _W_ENCODED_BONUS
        # Minified bare UUID-like without keyword context — mild penalty only
        # for bearer-style provider rules
        if raw.detector_id == "bearer_token_literal":
            ctx = f"{raw.context_before} {raw.context_after}".lower()
            if not any(
                k in ctx
                for k in ("authorization", "bearer", "token", "auth", "header")
            ):
                score += _W_MINIFIED_BARE
        score = max(0, min(100, score))
        if level_hint in {
            CONFIDENCE_CONFIRMED_PATTERN,
            CONFIDENCE_HIGH,
            CONFIDENCE_MEDIUM,
            CONFIDENCE_OBSERVATION_ONLY,
        } and abs(score - base) <= 5:
            # Keep rule's level when score barely moved
            return score, level_hint
        return score, level_from_score(score)

    # Contextual / generic assignment path
    if family in {
        DETECTOR_FAMILY_CONTEXTUAL,
        DETECTOR_FAMILY_GENERIC,
    }:
        score = int(meta.get("base_score") or 40)
        score += _W_SENSITIVE_ASSIGNMENT
        ent = raw.entropy if raw.entropy is not None else shannon_entropy(raw.raw_value)
        if ent >= 3.5:
            score += _W_HIGH_ENTROPY
        if ent >= 4.5:
            score += 10
        ctx = f"{raw.context_before} {raw.context_after}".lower()
        if any(
            k in ctx
            for k in ("authorization", "bearer", "basic ", "mongodb://", "postgres://")
        ):
            score += _W_AUTH_URI_CONTEXT
        if raw.encoding_chain:
            score += _W_ENCODED_BONUS
        # Short / weak values get pulled down (suppression also handles)
        if len(raw.raw_value or "") < 8:
            score -= 15
        score = max(0, min(100, score))
        return score, level_from_score(score)

    # Entropy stage
    if family == DETECTOR_FAMILY_ENTROPY:
        score = int(meta.get("base_score") or 35)
        if meta.get("has_assignment"):
            score += _W_SENSITIVE_ASSIGNMENT
        if meta.get("has_keyword"):
            score += _W_NEARBY_KEYWORD
        ent = raw.entropy if raw.entropy is not None else shannon_entropy(raw.raw_value)
        if ent >= 4.0:
            score += _W_HIGH_ENTROPY
        if raw.encoding_chain:
            score += _W_ENCODED_BONUS
        score = max(0, min(100, score))
        return score, level_from_score(score)

    # Default / unknown family
    base = int(meta.get("base_score") or 50)
    return max(0, min(100, base)), level_from_score(base)


def is_high_entropy(value: str, *, min_length: int = 16, min_entropy: float = 3.5) -> bool:
    """
    Purpose:
        Cheap gate for entropy detector candidates.
    Input:
        value / min_length / min_entropy thresholds
    Output:
        True when length and Shannon entropy clear thresholds
    Side effects: None.
    """
    if not value or len(value) < min_length:
        return False
    return shannon_entropy(value) >= min_entropy
