"""
Unit tests for talos.passive models, constants, and config defaults.

Phase 1 only — no DB, no worker.
"""

from __future__ import annotations

from dataclasses import fields

import pytest

import talos.passive as passive
from talos.passive.config import (
    AUTO_FINDING_THRESHOLDS,
    PassiveScanConfig,
    config_from_dict,
    default_config,
    merge_config,
)
from talos.passive.constants import (
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_OBSERVATION_ONLY,
    DEFAULT_MAX_DECODE_DEPTH,
    DEFAULT_MAX_DOCUMENT_SIZE,
    DEFAULT_QUEUE_MAXSIZE,
    FINDING_ELIGIBLE_LEVELS,
    SCANNER_VERSION,
    SourceKind,
)
from talos.passive.models import (
    DecodeResult,
    Detection,
    PassiveScanJob,
    RawMatch,
    SourceDocument,
    SourceOccurrence,
)


def test_package_import_exports() -> None:
    assert passive.SCANNER_VERSION == SCANNER_VERSION
    assert passive.SourceKind is SourceKind
    assert callable(passive.fingerprint_secret)
    assert callable(passive.redact_secret)
    assert callable(passive.default_config)
    assert callable(passive.is_source_candidate)
    assert callable(passive.classify_source)
    assert callable(passive.normalize_body)


def test_scanner_version_is_semver_like() -> None:
    # Bumped when detector behaviour changes (1.1.0 = Phases 5–7).
    parts = SCANNER_VERSION.split(".")
    assert len(parts) >= 2
    assert all(p.isdigit() for p in parts[:3] if p)


def test_source_kind_values() -> None:
    assert SourceKind.JAVASCRIPT.value == "javascript"
    assert SourceKind.HTML.value == "html"
    assert SourceKind.SOURCEMAP.value == "sourcemap"
    # str Enum interoperates with plain strings
    assert SourceKind.JSON == "json"


def test_passive_scan_job_construction() -> None:
    job = PassiveScanJob(
        project_id="proj-1",
        flow_id="flow-1",
        endpoint_id="ep-1",
        url="https://app.example/static/app.js",
        host="app.example",
        path="/static/app.js",
        content_type="application/javascript",
        truncated=False,
        role_id="role-1",
        module_id="mod-1",
        observed_at="2026-01-01T00:00:00Z",
    )
    assert job.flow_id == "flow-1"
    assert job.endpoint_id == "ep-1"
    # frozen
    with pytest.raises(Exception):
        job.flow_id = "other"  # type: ignore[misc]


def test_source_document_defaults() -> None:
    doc = SourceDocument(
        id="doc-1",
        project_id="proj-1",
        body_hash="a" * 64,
        source_kind=SourceKind.JAVASCRIPT,
        body_size=1024,
    )
    assert doc.scan_status == "pending"
    assert doc.truncated is False
    assert doc.scanner_version is None
    assert doc.text is None


def test_source_occurrence_construction() -> None:
    occ = SourceOccurrence(
        id="occ-1",
        document_id="doc-1",
        flow_id="flow-1",
        endpoint_id=None,
        url="https://app.example/a.js",
        host="app.example",
        path="/a.js",
        logical_source_name="app.<BUILD_HASH>.js",
        content_type="application/javascript",
        observed_at="2026-01-01T00:00:00Z",
        role_id="r",
        module_id="m",
    )
    assert occ.logical_source_name.startswith("app.")


def test_raw_match_and_detection() -> None:
    raw = RawMatch(
        detector_id="aws_access_key_id",
        detector_family="provider",
        category="secret",
        secret_type="aws_access_key",
        matched_key="AWS_ACCESS_KEY_ID",
        raw_value="AKIAIOSFODNN7EXAMPLE",
        match_start=10,
        match_end=30,
    )
    assert raw.encoding_chain == []
    assert raw.decode_depth == 0

    det = Detection(
        id="det-1",
        document_id="doc-1",
        occurrence_id="occ-1",
        detector_id=raw.detector_id,
        detector_family=raw.detector_family,
        category=raw.category,
        secret_type=raw.secret_type,
        matched_key=raw.matched_key,
        redacted_value=passive.redact_secret(raw.raw_value),
        value_fingerprint=passive.fingerprint_secret(
            raw.detector_family, raw.raw_value
        ),
        confidence_score=95,
        confidence_level=CONFIDENCE_CONFIRMED_PATTERN,
        raw_value=raw.raw_value,
    )
    assert det.redacted_value == "AKIA****MPLE"
    assert len(det.value_fingerprint) == 64
    assert det.suppressed is False


def test_decode_result_defaults() -> None:
    result = DecodeResult(original="YQ==", decoded="a", encoding_chain=["base64"], depth=1, success=True)
    assert result.success is True
    assert result.error is None


def test_default_config_matches_design() -> None:
    cfg = default_config()
    assert cfg.enabled is True
    assert cfg.auto_finding_threshold == CONFIDENCE_HIGH
    assert cfg.max_document_size == DEFAULT_MAX_DOCUMENT_SIZE
    assert cfg.max_decode_depth == DEFAULT_MAX_DECODE_DEPTH
    assert cfg.queue_maxsize == DEFAULT_QUEUE_MAXSIZE
    assert cfg.scan_html is True
    assert cfg.scan_javascript is True
    assert cfg.scan_wasm is False
    assert cfg.store_raw_secret_in_evidence is True
    assert cfg.store_suppressed_detections is False


def test_merge_config_overrides() -> None:
    base = default_config()
    merged = merge_config(base, {"enabled": False, "queue_maxsize": 10, "scan_wasm": True})
    assert merged.enabled is False
    assert merged.queue_maxsize == 10
    assert merged.scan_wasm is True
    # base unchanged
    assert base.enabled is True
    assert base.queue_maxsize == DEFAULT_QUEUE_MAXSIZE


def test_merge_config_ignores_unknown_keys() -> None:
    merged = merge_config(None, {"not_a_field": 1, "enabled": False})
    assert merged.enabled is False
    assert not hasattr(merged, "not_a_field")


def test_config_from_dict() -> None:
    cfg = config_from_dict({"max_decode_depth": 1, "auto_finding_threshold": "confirmed_pattern"})
    assert cfg.max_decode_depth == 1
    assert cfg.auto_finding_threshold == CONFIDENCE_CONFIRMED_PATTERN


def test_is_finding_eligible_high_threshold() -> None:
    cfg = default_config()
    assert cfg.is_finding_eligible(CONFIDENCE_CONFIRMED_PATTERN) is True
    assert cfg.is_finding_eligible(CONFIDENCE_HIGH) is True
    assert cfg.is_finding_eligible(CONFIDENCE_MEDIUM) is False
    assert cfg.is_finding_eligible(CONFIDENCE_OBSERVATION_ONLY) is False


def test_is_finding_eligible_off() -> None:
    cfg = merge_config(None, {"auto_finding_threshold": "OFF"})
    assert cfg.is_finding_eligible(CONFIDENCE_CONFIRMED_PATTERN) is False
    assert cfg.is_finding_eligible(CONFIDENCE_HIGH) is False


def test_is_finding_eligible_confirmed_only() -> None:
    cfg = merge_config(None, {"auto_finding_threshold": CONFIDENCE_CONFIRMED_PATTERN})
    assert cfg.is_finding_eligible(CONFIDENCE_CONFIRMED_PATTERN) is True
    assert cfg.is_finding_eligible(CONFIDENCE_HIGH) is False


def test_finding_eligible_levels_set() -> None:
    assert CONFIDENCE_CONFIRMED_PATTERN in FINDING_ELIGIBLE_LEVELS
    assert CONFIDENCE_HIGH in FINDING_ELIGIBLE_LEVELS
    assert CONFIDENCE_MEDIUM not in FINDING_ELIGIBLE_LEVELS


def test_config_to_dict_round_trip_keys() -> None:
    cfg = default_config()
    data = cfg.to_dict()
    names = {f.name for f in fields(PassiveScanConfig)}
    assert set(data.keys()) == names
    restored = config_from_dict(data)
    assert restored.to_dict() == data


def test_auto_finding_thresholds_include_off() -> None:
    assert "OFF" in AUTO_FINDING_THRESHOLDS
