"""
Smoke tests for talos.error_intel constants, models, and config (Phase 0).
"""

from __future__ import annotations

from talos.error_intel import (
    CATEGORY_STACK_TRACE,
    ERROR_CATEGORIES,
    ERROR_INTEL_VERSION,
    ERROR_SEVERITIES,
    ErrorCluster,
    ErrorIntelConfig,
    ErrorIntelJob,
    ErrorObservation,
    RawErrorMatch,
    SEVERITY_HIGH,
    config_from_dict,
    default_config,
    merge_config,
)


def test_version_and_closed_vocab() -> None:
    assert ERROR_INTEL_VERSION.startswith("0.4")
    assert CATEGORY_STACK_TRACE in ERROR_CATEGORIES
    assert SEVERITY_HIGH in ERROR_SEVERITIES
    assert len(ERROR_CATEGORIES) == 9


def test_job_frozen() -> None:
    job = ErrorIntelJob(
        project_id="p",
        flow_id="f",
        endpoint_id=None,
        url="https://ex/api",
        host="ex",
        path="/api",
        content_type="application/json",
        status_code=500,
        truncated=False,
        attack_type="proxy",
        parameter_uuid=None,
        parameter_name=None,
        payload_redacted=None,
        duration_ms=None,
        observed_at="2026-01-01T00:00:00Z",
    )
    assert job.flow_id == "f"
    assert job.attack_type == "proxy"


def test_raw_match_and_cluster() -> None:
    m = RawErrorMatch(
        detector_id="java_sql",
        family="stack_trace",
        exception_type="java.sql.SQLSyntaxErrorException",
        confidence="CONFIRMED_PATTERN",
    )
    assert m.exception_type is not None
    c = ErrorCluster(
        id="e1",
        project_id="p",
        fingerprint="abc",
        category=CATEGORY_STACK_TRACE,
        severity=SEVERITY_HIGH,
        exception_type=m.exception_type,
        has_stack_trace=True,
    )
    assert c.observation_count == 0
    obs = ErrorObservation(
        id="o1",
        error_id=c.id,
        flow_id="f",
        attack_type="iv",
        parameter_name="username",
    )
    assert obs.parameter_name == "username"


def test_config_merge() -> None:
    cfg = merge_config(
        default_config(),
        {
            "store_generic_http_errors": True,
            "max_body_scan": 1000,
            "error_header_names": ["X-Foo", "x-exception"],
            "unknown_key": "ignored",
        },
    )
    assert cfg.store_generic_http_errors is True
    assert cfg.max_body_scan == 1000
    assert "x-foo" in cfg.error_header_names
    assert "x-exception" in cfg.error_header_names
    d = cfg.to_dict()
    assert isinstance(d["error_header_names"], list)
    assert config_from_dict(d).max_body_scan == 1000
    assert isinstance(default_config(), ErrorIntelConfig)
