"""
JWT compact form + database connection string detector tests.
"""

from __future__ import annotations

from pathlib import Path

from talos.passive.constants import (
    CATEGORY_SECRET,
    CONFIDENCE_HIGH,
    DETECTOR_FAMILY_CONNECTION_STRING,
    DETECTOR_FAMILY_JWT,
)
from talos.passive.detectors.connection_string import ConnectionStringDetector
from talos.passive.detectors.jwt import JwtDetector
from talos.passive.detectors.orchestrator import DetectorOrchestrator

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "passive"


def test_jwt_compact_detect():
    text = (FIXTURES / "jwt_and_conn.js").read_text(encoding="utf-8")
    hits = JwtDetector().detect(text)
    assert hits
    assert hits[0].detector_family == DETECTOR_FAMILY_JWT
    assert hits[0].secret_type == "jwt"
    assert hits[0].raw_value.startswith("eyJ")
    assert hits[0].category == CATEGORY_SECRET


def test_jwt_ignores_short_segments():
    assert JwtDetector().detect("eyJabc.def.ghi") == []
    assert JwtDetector().detect("not a jwt at all") == []


def test_connection_string_detect():
    text = (FIXTURES / "jwt_and_conn.js").read_text(encoding="utf-8")
    hits = ConnectionStringDetector().detect(text)
    assert hits
    assert hits[0].detector_family == DETECTOR_FAMILY_CONNECTION_STRING
    assert "postgres://" in hits[0].raw_value
    assert "s3cretPassw0rd" in hits[0].raw_value


def test_connection_string_requires_password():
    text = 'url = "postgres://user@localhost/db";'
    assert ConnectionStringDetector().detect(text) == []


def test_orchestrator_jwt_and_conn_high():
    text = (FIXTURES / "jwt_and_conn.js").read_text(encoding="utf-8")
    dets = DetectorOrchestrator().scan_text(text, document_id="d1")
    families = {d.detector_family for d in dets}
    assert DETECTOR_FAMILY_JWT in families or any(
        d.secret_type == "jwt" for d in dets
    )
    assert DETECTOR_FAMILY_CONNECTION_STRING in families or any(
        d.secret_type == "connection_string" for d in dets
    )
    secret_dets = [d for d in dets if d.category == CATEGORY_SECRET]
    assert any(
        d.confidence_level in (CONFIDENCE_HIGH, "CONFIRMED_PATTERN")
        for d in secret_dets
    )
