"""
Phase 6/7 tests: scoring bands and family-specific weights.
"""

from __future__ import annotations

from talos.passive.models import RawMatch
from talos.passive.scoring import is_high_entropy, level_from_score, score_match


def _raw(**kwargs) -> RawMatch:
    base = dict(
        detector_id="x",
        detector_family="provider",
        category="secret",
        secret_type="t",
        matched_key=None,
        raw_value="AKIAJFAKESECRET00001",
        match_start=0,
        match_end=20,
        metadata={},
    )
    base.update(kwargs)
    return RawMatch(**base)


def test_level_bands():
    assert level_from_score(100) == "CONFIRMED_PATTERN"
    assert level_from_score(90) == "CONFIRMED_PATTERN"
    assert level_from_score(89) == "HIGH"
    assert level_from_score(70) == "HIGH"
    assert level_from_score(69) == "MEDIUM"
    assert level_from_score(50) == "MEDIUM"
    assert level_from_score(49) == "OBSERVATION_ONLY"
    assert level_from_score(0) == "OBSERVATION_ONLY"


def test_provider_base_score():
    score, level = score_match(
        _raw(metadata={"base_score": 95, "base_level": "CONFIRMED_PATTERN"})
    )
    assert score == 95
    assert level == "CONFIRMED_PATTERN"


def test_contextual_assignment_boost():
    score, level = score_match(
        _raw(
            detector_id="contextual_assignment",
            detector_family="contextual",
            raw_value="A82k9mQx7vNp3wR5tY1uZ8bC4dE6fG0h",
            entropy=4.2,
            metadata={"base_score": 40, "has_assignment": True},
        )
    )
    assert score >= 70  # assignment + entropy
    assert level in ("HIGH", "CONFIRMED_PATTERN", "MEDIUM")


def test_entropy_family_needs_boosts():
    low = score_match(
        _raw(
            detector_id="high_entropy_secret",
            detector_family="entropy",
            raw_value="Xk9mQ2pL7vN4wR8tY1uZ0bC3dE5fG6hJ",
            entropy=4.5,
            metadata={"base_score": 35},
        )
    )
    high = score_match(
        _raw(
            detector_id="high_entropy_secret",
            detector_family="entropy",
            raw_value="Xk9mQ2pL7vN4wR8tY1uZ0bC3dE5fG6hJ",
            entropy=4.5,
            metadata={
                "base_score": 35,
                "has_assignment": True,
                "has_keyword": True,
            },
        )
    )
    assert high[0] > low[0]


def test_is_high_entropy():
    assert is_high_entropy("aaaaaaaaaaaaaaaa") is False  # repeated char
    assert is_high_entropy("Xk9mQ2pL7vN4wR8t") is True
    assert is_high_entropy("short") is False
