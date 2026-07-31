"""
Tests: URL Sink Discovery Phase 3 — IV canary probes + fingerprinting.

Covers (offline, no live network):
    - Eligibility / warrant from passive url_features
    - Probe selection by budget tier (standard vs deep+)
    - Fingerprint phrase + Location canary + soft timing
    - Synthesis → observed.url_sink + tested.url_sink:*
    - Planner schedules url_sink_probes when warranted
    - Planner skips when not warranted / already known
    - Engine expands jobs with iv_url_sink meta
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

import pytest

from talos.input_validation.config import IVAnalysesConfig, IVConfig, save_config
from talos.input_validation.engine import (
    _enqueue_url_sink_probes,
    build_plan_context,
    make_param_uuid,
)
from talos.input_validation.fingerprint import (
    CANARY_HOST,
    analyze_url_sink_response,
    classify_url_error_phrases,
    location_reflects_canary,
    timing_suggests_fetch,
)
from talos.input_validation.outcomes import (
    OUTCOME_ACCEPTED,
    OUTCOME_MODIFIED,
    OUTCOME_REJECTED,
)
from talos.input_validation.planner import (
    ACTION_URL_SINK_PROBES,
    DEFAULT_MAX_REQUESTS,
    PlanAction,
    PlanContext,
    URL_SINK_ACTION_TOKENS,
    plan_next,
)
from talos.input_validation.profile import empty_param_profile
from talos.input_validation.synthesize import synthesize_param_profile
from talos.input_validation.url_sink_probes import (
    apply_url_sink_synthesis_to_profile,
    select_url_sink_probes,
    synthesize_url_sink_state,
    url_sink_is_warranted,
)
from talos.input_validation.db import upsert_probe_result
from talos.projects.db import init_project_db
from talos.scheduler.job import IV_URL_SINK


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


def _seed_param(
    db_path: Path,
    *,
    host: str = "api.example.com",
    path: str = "/v1/fetch",
    param_name: str = "url",
    location: str = "query",
    semantic_type: str = "url",
    url_features: dict | None = None,
    sample: str = "https://cdn.example/x",
) -> tuple[str, str]:
    ep_id = str(uuid.uuid4())
    param_uuid = make_param_uuid(host, location, param_name)
    uf = url_features
    if uf is None:
        uf = {
            "possible_network_resource": True,
            "score": 95,
            "possible_url_value": True,
            "name_category": "remote_fetch",
            "name_categories": ["remote_fetch"],
            "evidence": ["value_scheme:https"],
        }
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, host, method, path, normalized_path,
                 first_seen, last_seen)
            VALUES (?, 'proj', ?, 'GET', ?, ?, datetime('now'), datetime('now'))
            """,
            (ep_id, host, path, path),
        )
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, qualified, excluded, updated_at)
            VALUES (?, 1, 0, datetime('now'))
            """,
            (ep_id,),
        )
        conn.execute(
            """
            INSERT INTO parameters
                (id, endpoint_id, name, location, param_type, semantic_type,
                 example_values, url_features)
            VALUES (?, ?, ?, ?, 'string', ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                ep_id,
                param_name,
                location,
                semantic_type,
                json.dumps([sample]),
                json.dumps(uf),
            ),
        )
        conn.commit()
    return ep_id, param_uuid


def _base_ctx(**overrides) -> PlanContext:
    defaults = dict(
        budget_tier="standard",
        max_requests=DEFAULT_MAX_REQUESTS["standard"],
        requests_used=2,
        completed_analyses=frozenset({"baseline", "multiprobe"}),
        multiprobe_completed_count=1,
        reflection_state="reflected",
        reflection_confidence=90,
        reflection_uncertainty="low",
        acceptance_class_count=3,
        analyses_enabled={
            "baseline": True,
            "multiprobe": True,
            "identifier": True,
            "characters": True,
            "length": True,
            "types": True,
            "transformations": True,
            "reflection": True,
            "validation": True,
        },
        has_endpoint=True,
    )
    defaults.update(overrides)
    return PlanContext(**defaults)


# ---------------------------------------------------------------------------
# Warrant / selection
# ---------------------------------------------------------------------------

class TestUrlSinkWarrant:
    def test_value_network_resource(self) -> None:
        assert url_sink_is_warranted(
            url_features={"possible_network_resource": True, "score": 95}
        )

    def test_name_category_redirect(self) -> None:
        assert url_sink_is_warranted(
            url_features={
                "score": 25,
                "possible_network_resource": False,
                "name_category": "redirect",
                "name_categories": ["redirect"],
            }
        )

    def test_semantic_type_url(self) -> None:
        assert url_sink_is_warranted(semantic_type="url")

    def test_plain_string_not_warranted(self) -> None:
        assert not url_sink_is_warranted(
            url_features={"score": 0, "possible_network_resource": False},
            semantic_type="string",
            param_name="q",
        )

    def test_score_threshold(self) -> None:
        assert url_sink_is_warranted(url_features={"score": 50})
        assert not url_sink_is_warranted(
            url_features={"score": 30, "possible_network_resource": False},
            semantic_type="string",
            param_name="id",
        )


class TestSelectUrlSinkProbes:
    def test_not_warranted_empty(self) -> None:
        plan = select_url_sink_probes(
            strategy="standard",
            url_features={"score": 0},
            semantic_type="string",
            param_name="q",
        )
        assert plan.probes == ()
        assert plan.warranted is False

    def test_standard_five_canaries(self) -> None:
        plan = select_url_sink_probes(
            strategy="standard",
            url_features={"possible_network_resource": True, "score": 90},
        )
        assert plan.warranted is True
        assert len(plan.probes) == 5
        types = {p.payload_type for p in plan.probes}
        assert "url_sink:https" in types
        assert "url_sink:hostname" in types
        assert "url_sink:ipv4_loopback" in types
        assert all(CANARY_HOST in p.payload or p.payload.startswith("/") or p.payload == "127.0.0.1"
                   for p in plan.probes)
        # No deep protocols on standard.
        assert "url_sink:ftp" not in types
        assert "url_sink:gopher" not in types

    def test_deep_expands_protocols(self) -> None:
        plan = select_url_sink_probes(
            strategy="deep",
            url_features={"possible_network_resource": True, "score": 90},
        )
        types = {p.payload_type for p in plan.probes}
        assert "url_sink:ftp" in types or "url_sink:gopher" in types
        assert "url_sink:file" in types or "url_sink:unc" in types
        assert len(plan.probes) >= 6

    def test_quick_minimal(self) -> None:
        plan = select_url_sink_probes(
            strategy="quick",
            url_features={"possible_network_resource": True, "score": 90},
        )
        assert 1 <= len(plan.probes) <= 2
        types = {p.payload_type for p in plan.probes}
        assert "url_sink:https" in types

    def test_force_without_warrant(self) -> None:
        plan = select_url_sink_probes(
            strategy="standard",
            force=True,
        )
        assert plan.warranted is True
        assert len(plan.probes) == 5

    def test_canaries_are_invalid_tld(self) -> None:
        plan = select_url_sink_probes(
            strategy="exhaustive",
            url_features={"score": 95, "possible_network_resource": True},
        )
        for p in plan.probes:
            if "://" in p.payload or p.form_kind in ("hostname", "unc"):
                assert "talos-canary.invalid" in p.payload or p.payload.startswith("\\\\")


# ---------------------------------------------------------------------------
# Fingerprint analyzers (PR-7)
# ---------------------------------------------------------------------------

class TestUrlSinkFingerprint:
    def test_dns_phrase(self) -> None:
        classes = classify_url_error_phrases("Error: DNS lookup failed for host")
        assert "dns_lookup_failed" in classes

    def test_malformed_url_phrase(self) -> None:
        classes = classify_url_error_phrases("invalid url: must be absolute URL")
        assert "malformed_url" in classes or "requires_absolute_url" in classes

    def test_location_canary(self) -> None:
        assert location_reflects_canary(
            f"https://{CANARY_HOST}/landing",
            None,
        )
        assert not location_reflects_canary("https://example.com/ok", None)

    def test_timing_suggests_fetch(self) -> None:
        assert timing_suggests_fetch(50.0, 1200.0) is True
        assert timing_suggests_fetch(50.0, 100.0) is False
        assert timing_suggests_fetch(None, 5000.0) is False

    def test_analyze_combined_signals(self) -> None:
        sigs = analyze_url_sink_response(
            body="cannot resolve host: connection refused",
            status_code=502,
            response_headers={"Location": f"https://{CANARY_HOST}/x"},
            redirect=f"https://{CANARY_HOST}/x",
            baseline_duration_ms=40.0,
            probe_duration_ms=2000.0,
        )
        assert sigs.dns_resolution_detected is True
        assert sigs.redirect_behavior is True
        assert sigs.fetch_behavior is True
        assert "connection_refused" in sigs.error_classes or "dns_lookup_failed" in sigs.error_classes


# ---------------------------------------------------------------------------
# Synthesis
# ---------------------------------------------------------------------------

class TestUrlSinkSynthesis:
    def test_accepts_url_and_redirect(self) -> None:
        rows = [
            {
                "payload_type": "url_sink:https",
                "payload": f"https://{CANARY_HOST}/",
                "outcome": OUTCOME_ACCEPTED,
                "confidence": 90,
                "body": "ok",
                "status_code": 302,
                "response_headers": {"Location": f"https://{CANARY_HOST}/next"},
                "redirect": f"https://{CANARY_HOST}/next",
                "flow_id": "f1",
            },
            {
                "payload_type": "url_sink:hostname",
                "payload": CANARY_HOST,
                "outcome": OUTCOME_REJECTED,
                "confidence": 85,
                "body": "must be absolute URL",
                "status_code": 400,
                "flow_id": "f2",
            },
        ]
        synth = synthesize_url_sink_state(rows)
        assert synth.accepts_url is True
        assert synth.accepts_hostname is False
        assert synth.requires_absolute is True
        assert synth.redirect_behavior is True
        assert synth.confidence >= 55
        block = synth.to_observed_block()
        assert "accepts_url" in block
        assert "error_classes" in block

        profile = empty_param_profile(param_uuid="x", host="h", location="query", name="url")
        apply_url_sink_synthesis_to_profile(profile, synth)
        assert profile["observed"]["url_sink"]["accepts_url"] is True
        assert "url_sink:https" in (profile.get("tested") or {})

    def test_dns_and_timeout_classes(self) -> None:
        rows = [
            {
                "payload_type": "url_sink:http",
                "payload": f"http://{CANARY_HOST}/",
                "outcome": OUTCOME_MODIFIED,
                "confidence": 70,
                "body": "getaddrinfo ENOTFOUND: timed out waiting for upstream",
                "status_code": 504,
                "duration_ms": 5000,
                "flow_id": "f3",
            },
        ]
        synth = synthesize_url_sink_state(rows, baseline_duration_ms=50.0)
        assert synth.dns_resolution_detected is True
        assert synth.fetch_behavior is True
        assert any(
            c in synth.error_classes
            for c in ("dns_lookup_failed", "timeout", "unable_to_fetch")
        )

    def test_empty_rows(self) -> None:
        synth = synthesize_url_sink_state([])
        assert synth.confidence == 0
        assert synth.accepts_url is False


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

class TestUrlSinkPlanner:
    def test_action_token_registered(self) -> None:
        assert ACTION_URL_SINK_PROBES in URL_SINK_ACTION_TOKENS

    def test_schedules_when_warranted_despite_early_stop(self) -> None:
        ctx = _base_ctx(
            url_sink_warranted=True,
            semantic_type="url",
            param_name="abc",
            url_features={"score": 95, "possible_network_resource": True},
        )
        result = plan_next(ctx)
        actions = [a.action for a in result.actions]
        assert ACTION_URL_SINK_PROBES in actions
        act = next(a for a in result.actions if a.action == ACTION_URL_SINK_PROBES)
        assert act.estimated_requests >= 1
        assert act.estimated_requests <= 5

    def test_skips_when_not_warranted(self) -> None:
        ctx = _base_ctx(url_sink_warranted=False)
        result = plan_next(ctx)
        assert ACTION_URL_SINK_PROBES not in [a.action for a in result.actions]

    def test_skips_when_already_known(self) -> None:
        ctx = _base_ctx(
            url_sink_warranted=True,
            url_sink_known=True,
            url_sink_completed_count=5,
        )
        result = plan_next(ctx)
        assert ACTION_URL_SINK_PROBES not in [a.action for a in result.actions]

    def test_deep_schedules_url_sink(self) -> None:
        ctx = _base_ctx(
            budget_tier="deep",
            max_requests=DEFAULT_MAX_REQUESTS["deep"],
            url_sink_warranted=True,
            types_known=True,
            types_completed_count=4,
            validation_completed_count=5,
            characters_completed_count=10,
            identifier_completed_count=3,
            length_completed_count=5,
            length_state="bounded",
            length_confidence=90,
            length_uncertainty="low",
            parser_known=True,
            parser_completed_count=3,
        )
        result = plan_next(ctx)
        actions = [a.action for a in result.actions]
        # May include other deep follow-ups; url_sink should be present.
        assert ACTION_URL_SINK_PROBES in actions or result.state == "EVALUATE"

    def test_types_toggle_off_skips(self) -> None:
        ctx = _base_ctx(
            url_sink_warranted=True,
            analyses_enabled={
                "baseline": True,
                "multiprobe": True,
                "types": False,
                "transformations": True,
                "reflection": True,
                "validation": True,
                "identifier": True,
                "characters": True,
                "length": True,
            },
        )
        result = plan_next(ctx)
        assert ACTION_URL_SINK_PROBES not in [a.action for a in result.actions]


# ---------------------------------------------------------------------------
# Engine enqueue + plan context
# ---------------------------------------------------------------------------

class TestUrlSinkEngine:
    def test_build_plan_context_reads_url_features(self, db_path: Path) -> None:
        ep_id, param_uuid = _seed_param(db_path)
        # Seed baseline + multiprobe so planner can evaluate.
        upsert_probe_result(
            db_path, param_uuid, ep_id, "api.example.com", "query", "url",
            "baseline", None, "baseline", 0, str(uuid.uuid4()), "completed",
        )
        upsert_probe_result(
            db_path, param_uuid, ep_id, "api.example.com", "query", "url",
            "multiprobe", "TL" + "a" * 20, "multiprobe", 0, str(uuid.uuid4()),
            "completed",
        )
        cfg = IVConfig(enabled=True, probe_strategy="standard")
        ctx = build_plan_context(
            db_path,
            param_uuid=param_uuid,
            host="api.example.com",
            location="query",
            name="url",
            endpoint_id=ep_id,
            config=cfg,
        )
        assert ctx.url_sink_warranted is True
        assert ctx.url_features.get("score") == 95
        assert ctx.semantic_type == "url"

    def test_enqueue_inserts_iv_url_sink_jobs(self, db_path: Path) -> None:
        ep_id, param_uuid = _seed_param(db_path)
        cfg = IVConfig(enabled=True, probe_strategy="standard")
        action = PlanAction(
            action=ACTION_URL_SINK_PROBES,
            hypothesis="url_sink.characterize",
            estimated_requests=5,
            meta={
                "semantic_type": "url",
                "param_name": "url",
                "url_features": {
                    "score": 95,
                    "possible_network_resource": True,
                },
            },
        )
        n = _enqueue_url_sink_probes(
            db_path,
            "proj",
            "api.example.com",
            "query",
            "url",
            param_uuid,
            ep_id,
            cfg,
            action,
            ignore_cache=True,
        )
        assert n == 5
        with sqlite3.connect(str(db_path)) as conn:
            rows = conn.execute(
                "SELECT job_type, meta FROM scheduler_jobs WHERE job_type = ?",
                (IV_URL_SINK,),
            ).fetchall()
        assert len(rows) == 5
        meta0 = json.loads(rows[0][1])
        assert meta0["analysis"] == "url_sink"
        assert meta0["planner_action"] == ACTION_URL_SINK_PROBES
        assert meta0["payload_type"].startswith("url_sink:")
        assert "talos-canary.invalid" in meta0["payload"] or meta0["payload"] in (
            "127.0.0.1", "/talos-canary",
        )


# ---------------------------------------------------------------------------
# Offline synthesize from probe rows
# ---------------------------------------------------------------------------

class TestUrlSinkOfflineSynthesize:
    def test_synthesize_fills_observed_url_sink(self, db_path: Path) -> None:
        host = "api.example.com"
        location = "query"
        name = "callback"
        ep_id, param_uuid = _seed_param(
            db_path,
            param_name=name,
            url_features={
                "score": 30,
                "name_category": "webhook",
                "name_categories": ["webhook"],
                "possible_network_resource": False,
            },
            semantic_type="string",
        )
        # Minimal flow rows for join.
        flow_base = str(uuid.uuid4())
        flow_https = str(uuid.uuid4())
        flow_host = str(uuid.uuid4())
        with sqlite3.connect(str(db_path)) as conn:
            role = conn.execute(
                "SELECT id FROM roles WHERE name = 'global' LIMIT 1"
            ).fetchone()
            mod = conn.execute(
                "SELECT id FROM modules WHERE name = 'global' LIMIT 1"
            ).fetchone()
            role_id = role[0] if role else "global-role"
            module_id = mod[0] if mod else "global-module"
            for fid, status, body, headers, ct in (
                (
                    flow_base, 200, '{"ok":true}',
                    {"Content-Type": "application/json"},
                    "application/json",
                ),
                (
                    flow_https, 302, "redirect",
                    {
                        "Content-Type": "text/html",
                        "Location": f"https://{CANARY_HOST}/cb",
                    },
                    "text/html",
                ),
                (
                    flow_host, 400,
                    "invalid hostname: DNS lookup failed",
                    {"Content-Type": "application/json"},
                    "application/json",
                ),
            ):
                conn.execute(
                    """
                    INSERT INTO flows
                        (id, project_id, role_id, module_id, method, url, host,
                         path, status_code, content_type, response_headers,
                         response_body, captured_at)
                    VALUES (?, 'proj', ?, ?, 'GET', ?, ?, '/v1/fetch', ?,
                            ?, ?, ?, datetime('now'))
                    """,
                    (
                        fid, role_id, module_id,
                        f"https://{host}/v1/fetch", host, status, ct,
                        json.dumps(headers), body,
                    ),
                )
            conn.commit()

        upsert_probe_result(
            db_path, param_uuid, ep_id, host, location, name,
            "baseline", None, "baseline", 0, flow_base, "completed",
        )
        upsert_probe_result(
            db_path, param_uuid, ep_id, host, location, name,
            "url_sink", f"https://{CANARY_HOST}/", "url_sink:https", 0,
            flow_https, "completed",
        )
        upsert_probe_result(
            db_path, param_uuid, ep_id, host, location, name,
            "url_sink", CANARY_HOST, "url_sink:hostname", 1,
            flow_host, "completed",
        )

        profile = synthesize_param_profile(db_path, param_uuid, persist=True)
        us = (profile.get("observed") or {}).get("url_sink") or {}
        assert us.get("confidence", 0) > 0
        # Accepts absolute URL soft (302 vs baseline often modified/accepted).
        assert us.get("accepts_url") is True or us.get("redirect_behavior") is True
        assert us.get("dns_resolution_detected") is True or us.get("error_classes")
        tested = profile.get("tested") or {}
        assert any(k.startswith("url_sink:") for k in tested)
