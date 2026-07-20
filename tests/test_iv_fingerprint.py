"""
Unit tests for Input Validation Module 1 — Evidence Foundations.

Covers:
    - ResponseFingerprint stability after body normalization
    - Non-empty deltas for status/body changes
    - Outcome classifier (outcome + confidence + reasons)
    - Schema envelope constants
"""

from __future__ import annotations

import json

import pytest

from talos.input_validation.fingerprint import (
    ResponseFingerprint,
    classify_content_type,
    compare_fingerprints,
    fingerprint_from_flow,
    normalize_body_for_hash,
    sketch_json_schema,
)
from talos.input_validation.outcomes import (
    IV_ENGINE_VERSION,
    IV_PROFILE_SCHEMA_VERSION,
    OUTCOME_ACCEPTED,
    OUTCOME_ENCODED,
    OUTCOME_IGNORED,
    OUTCOME_MODIFIED,
    OUTCOME_NORMALIZED,
    OUTCOME_REJECTED,
    OUTCOME_TRUNCATED,
    OUTCOME_UNKNOWN,
    VALIDATION_OUTCOMES,
    classify_outcome,
    is_valid_outcome,
    profile_envelope,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flow(
    *,
    status: int = 200,
    content_type: str = "application/json",
    body: str | bytes = '{"ok":true}',
    headers: dict | None = None,
    **extra: object,
) -> dict:
    hdrs = headers if headers is not None else {"Content-Type": content_type}
    return {
        "status_code": status,
        "content_type": content_type,
        "response_body": body,
        "response_headers": json.dumps(hdrs),
        **extra,
    }


# ---------------------------------------------------------------------------
# Content-type classification
# ---------------------------------------------------------------------------

class TestClassifyContentType:
    def test_json_variants(self) -> None:
        assert classify_content_type("application/json") == "json"
        assert classify_content_type("application/vnd.api+json; charset=utf-8") == "json"

    def test_html_xml_text_binary_empty(self) -> None:
        assert classify_content_type("text/html; charset=utf-8") == "html"
        assert classify_content_type("application/xml") == "xml"
        assert classify_content_type("text/plain") == "text"
        assert classify_content_type("application/octet-stream") == "binary"
        assert classify_content_type("") == "empty"
        assert classify_content_type(None) == "empty"


# ---------------------------------------------------------------------------
# Normalization + hash stability
# ---------------------------------------------------------------------------

class TestNormalizationStability:
    def test_identical_bodies_same_hash(self) -> None:
        a = fingerprint_from_flow(_flow(body='{"id":1,"name":"x"}'))
        b = fingerprint_from_flow(_flow(body='{"id":1,"name":"x"}'))
        assert a.body_hash == b.body_hash
        assert a.header_hash == b.header_hash
        assert compare_fingerprints(a, b)["identical"] is True

    def test_volatile_uuid_and_timestamp_do_not_change_hash(self) -> None:
        body_a = json.dumps({
            "user": "alice",
            "request_id": "550e8400-e29b-41d4-a716-446655440000",
            "created_at": "2024-01-15T12:00:00Z",
            "csrf": "abc123def456",
        })
        body_b = json.dumps({
            "user": "alice",
            "request_id": "11111111-2222-3333-4444-555555555555",
            "created_at": "2025-06-01T08:30:00+00:00",
            "csrf": "zzzzdifferenttoken",
        })
        fa = fingerprint_from_flow(_flow(body=body_a))
        fb = fingerprint_from_flow(_flow(body=body_b))
        assert fa.body_hash == fb.body_hash

    def test_semantic_body_change_changes_hash(self) -> None:
        fa = fingerprint_from_flow(_flow(body='{"user":"alice"}'))
        fb = fingerprint_from_flow(_flow(body='{"user":"bob"}'))
        assert fa.body_hash != fb.body_hash

    def test_normalize_strips_iso_dates_in_text(self) -> None:
        a = normalize_body_for_hash("created 2024-01-15T12:00:00Z done")
        b = normalize_body_for_hash("created 2025-12-31T23:59:59Z done")
        assert a == b
        assert "<TS>" in a


# ---------------------------------------------------------------------------
# Fingerprint fields
# ---------------------------------------------------------------------------

class TestFingerprintFields:
    def test_json_schema_sketch(self) -> None:
        body = json.dumps({"id": 1, "name": "x", "tags": ["a"], "meta": {"n": 1}})
        fp = fingerprint_from_flow(_flow(body=body))
        assert fp.json_schema is not None
        assert fp.json_schema["type"] == "object"
        assert "id" in fp.json_schema["keys"]
        assert fp.json_schema["props"]["id"]["type"] == "integer"
        assert fp.json_schema["props"]["tags"]["type"] == "array"

    def test_sketch_none_on_non_json(self) -> None:
        assert sketch_json_schema("not json") is None

    def test_redirect_from_location_header(self) -> None:
        fp = fingerprint_from_flow(_flow(
            status=302,
            content_type="text/html",
            body="",
            headers={
                "Content-Type": "text/html",
                "Location": "https://app.test/login?next=1&ts=99",
            },
        ))
        assert fp.redirect == "https://app.test/login"
        assert fp.status_code == 302

    def test_error_signature_on_4xx_json(self) -> None:
        fp = fingerprint_from_flow(_flow(
            status=400,
            body=json.dumps({"error": "bad", "code": "INVALID"}),
        ))
        assert fp.error_signature is not None
        assert "status:400" in fp.error_signature
        assert "keys:" in fp.error_signature

    def test_no_error_signature_on_2xx(self) -> None:
        fp = fingerprint_from_flow(_flow(status=200, body='{"ok":true}'))
        assert fp.error_signature is None

    def test_duration_from_explicit_field(self) -> None:
        fp = fingerprint_from_flow(_flow(duration_ms=42.5))
        assert fp.duration_ms == pytest.approx(42.5)

    def test_duration_from_timestamps(self) -> None:
        fp = fingerprint_from_flow(_flow(
            captured_at="2024-01-01T00:00:00+00:00",
            response_end="2024-01-01T00:00:00.100+00:00",
        ))
        assert fp.duration_ms == pytest.approx(100.0)

    def test_body_as_bytes_and_probe_body_alias(self) -> None:
        fp_bytes = fingerprint_from_flow(_flow(body=b'{"ok":true}'))
        fp_alias = fingerprint_from_flow({
            "status_code": 200,
            "content_type": "application/json",
            "body": '{"ok":true}',
            "response_headers": "{}",
        })
        assert fp_bytes.body_hash == fp_alias.body_hash

    def test_volatile_headers_ignored_in_header_hash(self) -> None:
        a = fingerprint_from_flow(_flow(headers={
            "Content-Type": "application/json",
            "Date": "Mon, 01 Jan 2024 00:00:00 GMT",
            "X-Request-Id": "aaa",
        }))
        b = fingerprint_from_flow(_flow(headers={
            "Content-Type": "application/json",
            "Date": "Tue, 02 Feb 2025 12:00:00 GMT",
            "X-Request-Id": "bbb",
        }))
        assert a.header_hash == b.header_hash

    def test_content_type_header_change_affects_header_hash(self) -> None:
        a = fingerprint_from_flow(_flow(
            content_type="application/json",
            headers={"Content-Type": "application/json"},
        ))
        b = fingerprint_from_flow(_flow(
            content_type="text/html",
            headers={"Content-Type": "text/html"},
        ))
        assert a.header_hash != b.header_hash

    def test_to_dict_roundtrip_keys(self) -> None:
        fp = fingerprint_from_flow(_flow())
        d = fp.to_dict()
        assert d["status_code"] == 200
        assert d["content_type"] == "json"
        assert "body_hash" in d
        assert isinstance(d["extras"], dict)


# ---------------------------------------------------------------------------
# Differential compare
# ---------------------------------------------------------------------------

class TestCompareFingerprints:
    def test_status_delta(self) -> None:
        a = fingerprint_from_flow(_flow(status=200))
        b = fingerprint_from_flow(_flow(status=400, body='{"error":"x"}'))
        delta = compare_fingerprints(a, b)
        assert delta["identical"] is False
        assert "status_code" in delta["changed"]
        assert delta["status"] == {"from": 200, "to": 400}

    def test_body_delta_non_empty(self) -> None:
        a = fingerprint_from_flow(_flow(body='{"a":1}'))
        b = fingerprint_from_flow(_flow(body='{"a":2}'))
        delta = compare_fingerprints(a, b)
        assert delta["body_hash_changed"] is True
        assert "body_hash" in delta["changed"]

    def test_timing_not_in_identical_gate(self) -> None:
        a = fingerprint_from_flow(_flow(duration_ms=10))
        b = fingerprint_from_flow(_flow(duration_ms=999))
        delta = compare_fingerprints(a, b)
        assert delta["identical"] is True
        assert delta["duration_ms"] == {"from": 10.0, "to": 999.0}


# ---------------------------------------------------------------------------
# Outcome classifier
# ---------------------------------------------------------------------------

class TestClassifyOutcome:
    def test_accepted_identical(self) -> None:
        base = fingerprint_from_flow(_flow())
        probe = fingerprint_from_flow(_flow())
        result = classify_outcome(base, probe)
        assert result["outcome"] == OUTCOME_ACCEPTED
        assert 0 <= result["confidence"] <= 100
        assert result["reasons"]
        assert "delta" in result

    def test_rejected_on_4xx(self) -> None:
        base = fingerprint_from_flow(_flow(status=200, body='{"ok":true}'))
        probe = fingerprint_from_flow(_flow(
            status=400,
            body=json.dumps({"error": "invalid", "message": "bad input"}),
        ))
        result = classify_outcome(base, probe)
        assert result["outcome"] == OUTCOME_REJECTED
        assert result["confidence"] >= 60
        assert any("reject" in r.lower() or "400" in r for r in result["reasons"])

    def test_modified_same_status_different_body(self) -> None:
        base = fingerprint_from_flow(_flow(body='{"v":1}'))
        probe = fingerprint_from_flow(_flow(body='{"v":2,"extra":true}'))
        result = classify_outcome(base, probe)
        assert result["outcome"] == OUTCOME_MODIFIED
        assert result["confidence"] >= 60

    def test_encoded_with_reflection_hint(self) -> None:
        base = fingerprint_from_flow(_flow(body="<html>ok</html>", content_type="text/html"))
        probe = fingerprint_from_flow(_flow(
            body="<html>&lt;script&gt;</html>",
            content_type="text/html",
        ))
        result = classify_outcome(
            base,
            probe,
            reflection_hints={"reflected": True, "encoding": "html_encoded"},
        )
        assert result["outcome"] == OUTCOME_ENCODED

    def test_normalized_with_transform_hint(self) -> None:
        base = fingerprint_from_flow(_flow(body='{"q":"x"}'))
        probe = fingerprint_from_flow(_flow(body='{"q":"ABC"}'))
        result = classify_outcome(
            base,
            probe,
            reflection_hints={
                "reflected": True,
                "encoding": "raw",
                "transforms": ["uppercase"],
            },
        )
        assert result["outcome"] == OUTCOME_NORMALIZED

    def test_ignored_when_parameter_effect_false(self) -> None:
        base = fingerprint_from_flow(_flow())
        probe = fingerprint_from_flow(_flow())
        result = classify_outcome(
            base,
            probe,
            reflection_hints={"parameter_effect": False},
        )
        assert result["outcome"] == OUTCOME_IGNORED

    def test_truncated_large_body_drop(self) -> None:
        long_body = json.dumps({"data": "A" * 1000})
        short_body = json.dumps({"data": "A"})
        base = fingerprint_from_flow(_flow(body=long_body))
        probe = fingerprint_from_flow(_flow(body=short_body))
        result = classify_outcome(base, probe)
        assert result["outcome"] == OUTCOME_TRUNCATED

    def test_all_outcomes_in_vocabulary(self) -> None:
        assert is_valid_outcome(OUTCOME_ACCEPTED)
        assert is_valid_outcome(OUTCOME_UNKNOWN)
        assert not is_valid_outcome("exploited")
        assert len(VALIDATION_OUTCOMES) == 8


# ---------------------------------------------------------------------------
# Schema envelope
# ---------------------------------------------------------------------------

class TestProfileSchema:
    def test_schema_version_constant(self) -> None:
        assert IV_PROFILE_SCHEMA_VERSION == 1
        assert IV_ENGINE_VERSION

    def test_profile_envelope_shape(self) -> None:
        env = profile_envelope(updated_at="2024-01-01T00:00:00+00:00")
        assert env["schema_version"] == 1
        assert env["engine_version"] == IV_ENGINE_VERSION
        assert env["profile_version"] == 1
        assert env["updated_at"].startswith("2024")

    def test_profile_envelope_omits_updated_at_when_none(self) -> None:
        env = profile_envelope()
        assert "updated_at" not in env


# ---------------------------------------------------------------------------
# Frozen dataclass behaviour
# ---------------------------------------------------------------------------

class TestResponseFingerprintType:
    def test_frozen(self) -> None:
        fp = fingerprint_from_flow(_flow())
        assert isinstance(fp, ResponseFingerprint)
        with pytest.raises(Exception):
            fp.status_code = 500  # type: ignore[misc]
