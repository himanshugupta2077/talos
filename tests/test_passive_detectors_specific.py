"""
Phase 5 tests: YAML rules + specific/PEM detectors + orchestrator Stage 1.

Synthetic fixtures only — never live credentials.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from talos.passive.constants import (
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
    DETECTOR_FAMILY_PEM,
    DETECTOR_FAMILY_PROVIDER,
)
from talos.passive.detectors.orchestrator import DetectorOrchestrator, scan_text
from talos.passive.detectors.pem import PemDetector
from talos.passive.detectors.specific import SpecificPatternDetector
from talos.passive.rules_loader import get_rule_index, load_rule_packs

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "passive"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_load_default_rule_packs():
    index = load_rule_packs()
    assert index.load_errors == []
    ids = {r.id for r in index.rules}
    assert "aws_access_key_id" in ids
    assert "github_pat" in ids
    assert "stripe_secret_key" in ids
    assert "google_api_key" in ids
    assert index.generic is not None
    assert "password" in {k.lower() for k in index.generic.sensitive_keys}


def test_invalid_rule_pack_fails_closed(tmp_path: Path):
    bad = tmp_path / "broken.yaml"
    bad.write_text("rules:\n  - id: x\n    patterns: ['[unterminated'\n", encoding="utf-8")
    index = load_rule_packs(tmp_path, fail_closed=True)
    assert index.load_errors
    # Worker-safe: no exception


def test_aws_key_true_positive():
    text = _read("aws_key.js")
    hits = SpecificPatternDetector().detect(text)
    aws = [h for h in hits if h.detector_id == "aws_access_key_id"]
    assert len(aws) == 1
    assert aws[0].raw_value.startswith("AKIA")
    assert aws[0].detector_family == DETECTOR_FAMILY_PROVIDER
    assert aws[0].metadata.get("base_level") == CONFIDENCE_CONFIRMED_PATTERN


def test_github_pat_true_positive():
    text = _read("github_pat.js")
    hits = SpecificPatternDetector().detect(text)
    assert any(h.detector_id == "github_pat" for h in hits)


def _stripe_fixture_body() -> str:
    """
    Purpose:
        Build a Stripe-shaped secret body without storing a contiguous
        sk_live_/sk_test_ token in a repo fixture file (push protection).
    Side effects: None.
    """
    # Split construction so static scanners never see a full sk_* string in source.
    prefix = "sk_" + "live_"
    body = "TALOS" + "FAKE" + "KEY" + ("0" * 16)
    return (
        '{\n  "payment": {\n    "provider": "stripe",\n'
        f'    "secretKey": "{prefix}{body}"\n  }}\n}}\n'
    )


def test_stripe_and_google_true_positive():
    stripe = SpecificPatternDetector().detect(_stripe_fixture_body())
    assert any(h.detector_id == "stripe_secret_key" for h in stripe)
    google = SpecificPatternDetector().detect(_read("google_api.js"))
    assert any(h.detector_id == "google_api_key" for h in google)


def test_uuid_noise_no_aws():
    text = _read("noise_uuids.js")
    hits = SpecificPatternDetector().detect(text)
    assert not any(h.detector_id == "aws_access_key_id" for h in hits)
    assert not any(h.detector_id == "github_pat" for h in hits)


def test_public_aws_example_suppressed_by_orchestrator():
    text = 'const k = "AKIAIOSFODNN7EXAMPLE";'
    dets = scan_text(text)
    # Public docs token is suppressed — not persisted by default
    assert not any(d.detector_id == "aws_access_key_id" for d in dets)


def test_pem_detector():
    text = _read("pem_key.js")
    hits = PemDetector().detect(text)
    assert len(hits) >= 1
    assert hits[0].detector_family == DETECTOR_FAMILY_PEM
    assert "BEGIN PRIVATE KEY" in hits[0].raw_value


def test_orchestrator_persists_scored_detection_shape():
    text = _read("aws_key.js")
    dets = DetectorOrchestrator().scan_text(text, document_id="doc-1")
    aws = [d for d in dets if d.detector_id == "aws_access_key_id"]
    assert len(aws) == 1
    d = aws[0]
    assert d.document_id == "doc-1"
    assert d.confidence_level in (CONFIDENCE_CONFIRMED_PATTERN, CONFIDENCE_HIGH)
    assert d.confidence_score >= 70
    assert d.redacted_value
    assert d.value_fingerprint
    assert not d.suppressed
    assert "****" in d.redacted_value or d.redacted_value == "****"


def test_keyword_prefilter_skips_absent_rules():
    # No AKIA/ASIA → AWS rule should not run regex (still may match others)
    text = 'const x = "hello world without secrets";'
    hits = SpecificPatternDetector().detect(text)
    assert hits == []


def test_get_rule_index_cached():
    a = get_rule_index()
    b = get_rule_index()
    assert a is b
