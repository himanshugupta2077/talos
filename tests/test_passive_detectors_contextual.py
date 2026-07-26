"""
Phase 6 tests: contextual assignment detector + suppression + scoring.
"""

from __future__ import annotations

from pathlib import Path

from talos.passive.detectors.contextual import ContextualDetector
from talos.passive.detectors.orchestrator import DetectorOrchestrator, scan_text
from talos.passive.scoring import level_from_score, score_match
from talos.passive.suppress import should_suppress
from talos.passive.models import RawMatch

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "passive"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_client_secret_assignment_detected():
    text = _read("contextual_secrets.js")
    hits = ContextualDetector().detect(text)
    values = {h.raw_value for h in hits}
    assert any("A82k9mQx" in v for v in values)
    keys = {h.matched_key for h in hits if h.matched_key}
    assert any(k and "clientSecret" in k or k and "client" in k.lower() for k in keys) or any(
        "A82k" in v for v in values
    )


def test_const_text_client_secret_phrase_not_assignment():
    # "const text = \"client secret\"" is a phrase value, not a sensitive key
    text = 'const text = "client secret";'
    hits = ContextualDetector().detect(text)
    # key is `text`, not sensitive — should not match
    assert hits == []


def test_password_password_suppressed():
    text = 'const password = "password";'
    dets = scan_text(text)
    # Either no detection or suppressed-only (default store_suppressed=False)
    assert not any(
        d.detector_id == "contextual_assignment" and not d.suppressed for d in dets
    )


def test_your_api_key_suppressed():
    text = 'const apiKey = "YOUR_API_KEY";'
    dets = scan_text(text)
    assert not any(
        d.detector_id == "contextual_assignment" and not d.suppressed for d in dets
    )


def test_process_env_suppressed():
    text = "const key = process.env.API_KEY;"
    # RHS is bare process.env.API_KEY — contextual may not even match assignment
    # value pattern depending on dots; if it does, suppress.
    dets = scan_text(text)
    for d in dets:
        if d.matched_key and "key" in (d.matched_key or "").lower():
            assert d.suppressed or d.detector_id != "contextual_assignment"


def test_good_password_detected():
    text = 'const goodPassword = "SuperSecret123!xyz";'
    dets = scan_text(text)
    good = [
        d
        for d in dets
        if d.detector_id == "contextual_assignment"
        and "SuperSecret" in (d.raw_value or d.redacted_value or "")
        or (d.redacted_value and d.matched_key and "Password" in (d.matched_key or ""))
    ]
    # raw_value is not on Detection after orchestrator unless store_raw —
    # check via fingerprint presence / non-suppressed contextual
    contextual = [
        d for d in dets if d.detector_id == "contextual_assignment" and not d.suppressed
    ]
    assert contextual, f"expected contextual hit, got {dets}"


def test_suppress_helpers():
    assert should_suppress("")[0] is True
    assert should_suppress("null")[0] is True
    assert should_suppress("YOUR_API_KEY")[0] is True
    assert should_suppress("${API_KEY}")[0] is True
    assert should_suppress("process.env.API_KEY")[0] is True
    assert should_suppress("AKIAIOSFODNN7EXAMPLE")[0] is True
    ok, _ = should_suppress(
        "A82k9mQx7vNp3wR5tY1uZ8bC4dE6fG0h",
        detector_family="contextual",
    )
    assert ok is False


def test_scoring_bands():
    assert level_from_score(95) == "CONFIRMED_PATTERN"
    assert level_from_score(75) == "HIGH"
    assert level_from_score(55) == "MEDIUM"
    assert level_from_score(20) == "OBSERVATION_ONLY"


def test_score_match_provider_uses_base():
    raw = RawMatch(
        detector_id="aws_access_key_id",
        detector_family="provider",
        category="secret",
        secret_type="aws_access_key",
        matched_key=None,
        raw_value="AKIAJFAKESECRET00001",
        match_start=0,
        match_end=20,
        metadata={"base_score": 95, "base_level": "CONFIRMED_PATTERN"},
    )
    score, level = score_match(raw)
    assert score == 95
    assert level == "CONFIRMED_PATTERN"


def test_orchestrator_fixture_corpus():
    text = _read("contextual_secrets.js")
    dets = DetectorOrchestrator().scan_text(text)
    # clientSecret high-entropy value kept; placeholders dropped
    kept = [d for d in dets if not d.suppressed]
    assert any(d.detector_id == "contextual_assignment" for d in kept)
    redacted_blob = " ".join(d.redacted_value for d in kept)
    assert "YOUR_API_KEY" not in redacted_blob
