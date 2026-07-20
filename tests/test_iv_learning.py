"""
Unit tests for Input Validation Module 10 — Multi-Level Learning.

Covers pure aggregation/inheritance (no HTTP):
    - endpoint aggregation from param profiles
    - app aggregation from endpoint profiles
    - confidence decay (cap 75)
    - local observed wins over inherited
    - second param on same endpoint plans fewer HTTP under standard
    - host-level control reject suppresses standard probes, not deep
    - DB refresh + CLI format helpers
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from talos.input_validation.db import (
    get_app_profile,
    get_endpoint_profile,
    list_param_profiles_for_endpoint,
    make_param_uuid,
    upsert_param_profile,
)
from talos.input_validation.learning import (
    INHERITED_CONFIDENCE_CAP,
    InheritancePriors,
    aggregate_app_from_endpoints,
    aggregate_endpoint_from_params,
    build_inheritance_priors,
    decay_inherited_confidence,
    filter_probes_by_inheritance,
    format_app_intel_lines,
    format_endpoint_intel_lines,
    load_inheritance_priors,
    merge_local_over_inherited,
    refresh_multi_level,
    should_skip_parser_probes,
)
from talos.input_validation.outcomes import OUTCOME_REJECTED, OUTCOME_ACCEPTED
from talos.input_validation.planner import (
    ACTION_PARSER_PROBES,
    ACTION_SEMANTIC_RULES,
    PlanContext,
    plan_next,
)
from talos.input_validation.profile import (
    empty_param_profile,
    set_tested,
)
from talos.projects.db import init_project_db


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


def _param_with_tested(
    *,
    host: str = "api.example.com",
    location: str = "query",
    name: str = "q",
    tested: dict | None = None,
    classes: dict | None = None,
    parser: dict | None = None,
    capabilities: list | None = None,
    requests_used: int = 12,
) -> dict:
    p = empty_param_profile(
        param_uuid=make_param_uuid(host, location, name),
        host=host,
        location=location,
        name=name,
    )
    for key, entry in (tested or {}).items():
        set_tested(
            p,
            key,
            outcome=entry["outcome"],
            confidence=entry.get("confidence", 90),
        )
    if classes:
        p["observed"]["acceptance"]["classes"] = classes
    if parser:
        p["parser"] = parser
        p["observed"]["parser"] = parser
    if capabilities:
        p["capabilities"] = list(capabilities)
    p["requests_used"] = requests_used
    return p


# ---------------------------------------------------------------------------
# Pure confidence / merge
# ---------------------------------------------------------------------------

class TestConfidenceDecay:
    def test_cap_at_75(self) -> None:
        assert decay_inherited_confidence(95) == INHERITED_CONFIDENCE_CAP
        assert decay_inherited_confidence(70) == 70
        assert decay_inherited_confidence(0) == 0

    def test_local_wins_over_inherited(self) -> None:
        local = {"null": {"outcome": "accepted", "confidence": 92}}
        inherited = {
            "null": {
                "outcome": "rejected",
                "confidence": 75,
                "source": "inherited_endpoint",
            },
            "control": {
                "outcome": "rejected",
                "confidence": 70,
                "source": "inherited_application",
            },
        }
        merged = merge_local_over_inherited(local, inherited)
        assert merged["null"]["outcome"] == "accepted"
        assert merged["null"]["provenance"] == "local_observed"
        assert merged["control"]["outcome"] == "rejected"
        assert "inherited" in merged["control"]["provenance"]


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

class TestAggregation:
    def test_endpoint_from_single_param(self) -> None:
        p = _param_with_tested(
            name="id",
            tested={
                "null": {"outcome": OUTCOME_REJECTED, "confidence": 95},
                "control": {"outcome": OUTCOME_REJECTED, "confidence": 88},
            },
            classes={
                "control": {"outcome": OUTCOME_REJECTED, "confidence": 90},
                "alpha": {"outcome": OUTCOME_ACCEPTED, "confidence": 85},
            },
            parser={"duplicate_query": {"state": "last_wins", "behavior": "last"}},
            capabilities=["reflective_input"],
        )
        ep = aggregate_endpoint_from_params(
            [p],
            endpoint_id="ep-1",
            host="api.example.com",
            method="GET",
            path="/v1/items",
        )
        assert ep["level"] == "endpoint"
        assert ep["endpoint_id"] == "ep-1"
        assert ep["tested"]["null"]["outcome"] == OUTCOME_REJECTED
        assert "control" in ep["observed"]["acceptance"]["rejected_classes"]
        assert "alpha" in ep["observed"]["acceptance"]["accepted_classes"]
        assert "duplicate_query" in ep["parser"]
        assert "reflective_input" in ep["capabilities"]
        assert ep["param_defaults"]["tested"]["null"]["outcome"] == OUTCOME_REJECTED

    def test_endpoint_conflict_drops_tested_key(self) -> None:
        a = _param_with_tested(
            name="a",
            tested={"unicode": {"outcome": OUTCOME_REJECTED, "confidence": 90}},
        )
        b = _param_with_tested(
            name="b",
            tested={"unicode": {"outcome": OUTCOME_ACCEPTED, "confidence": 90}},
        )
        ep = aggregate_endpoint_from_params([a, b], endpoint_id="ep-x")
        assert "unicode" not in ep["tested"]

    def test_app_from_endpoints(self) -> None:
        p1 = _param_with_tested(
            name="x",
            tested={"null": {"outcome": OUTCOME_REJECTED, "confidence": 95}},
            classes={"control": {"outcome": OUTCOME_REJECTED, "confidence": 90}},
        )
        ep1 = aggregate_endpoint_from_params(
            [p1], endpoint_id="e1", host="api.example.com"
        )
        p2 = _param_with_tested(
            name="y",
            tested={"null": {"outcome": OUTCOME_REJECTED, "confidence": 90}},
            classes={"control": {"outcome": OUTCOME_REJECTED, "confidence": 88}},
        )
        ep2 = aggregate_endpoint_from_params(
            [p2], endpoint_id="e2", host="api.example.com"
        )
        app = aggregate_app_from_endpoints([ep1, ep2], host="api.example.com")
        assert app["level"] == "application"
        assert app["host"] == "api.example.com"
        assert app["tested"]["null"]["outcome"] == OUTCOME_REJECTED
        assert "control" in app["observed"]["acceptance"]["rejected_classes"]


# ---------------------------------------------------------------------------
# Inheritance + planner request savings
# ---------------------------------------------------------------------------

class TestInheritancePriors:
    def test_confidence_capped_and_local_excluded(self) -> None:
        ep = aggregate_endpoint_from_params(
            [
                _param_with_tested(
                    name="first",
                    tested={
                        "null": {"outcome": OUTCOME_REJECTED, "confidence": 95},
                        "empty": {"outcome": OUTCOME_REJECTED, "confidence": 90},
                    },
                    classes={
                        "control": {"outcome": OUTCOME_REJECTED, "confidence": 90},
                    },
                    parser={"json_null": {"state": "rejected", "behavior": "error"}},
                )
            ],
            endpoint_id="ep-1",
            host="api.example.com",
        )
        local = _param_with_tested(
            name="second",
            tested={"empty": {"outcome": OUTCOME_ACCEPTED, "confidence": 80}},
        )
        priors = build_inheritance_priors(
            endpoint_profile=ep,
            local_profile=local,
            budget_tier="standard",
        )
        assert priors.is_active()
        assert priors.tested["null"]["confidence"] <= INHERITED_CONFIDENCE_CAP
        assert "empty" not in priors.tested  # local wins — excluded from inherit
        assert "control" in priors.rejected_classes
        assert priors.suppress_control_probes is True
        assert priors.suppress_parser_probes is True
        assert priors.reduced_request_estimate > 0

    def test_host_control_reject_not_suppress_under_deep(self) -> None:
        app = aggregate_app_from_endpoints(
            [
                aggregate_endpoint_from_params(
                    [
                        _param_with_tested(
                            name="a",
                            tested={
                                "null": {
                                    "outcome": OUTCOME_REJECTED,
                                    "confidence": 95,
                                },
                            },
                            classes={
                                "control": {
                                    "outcome": OUTCOME_REJECTED,
                                    "confidence": 90,
                                },
                                "null": {
                                    "outcome": OUTCOME_REJECTED,
                                    "confidence": 90,
                                },
                            },
                        )
                    ],
                    endpoint_id="e1",
                    host="api.example.com",
                )
            ],
            host="api.example.com",
        )
        std = build_inheritance_priors(app_profile=app, budget_tier="standard")
        deep = build_inheritance_priors(app_profile=app, budget_tier="deep")
        assert std.suppress_control_probes is True
        assert deep.suppress_control_probes is False
        # Deep re-confirms control classes in known_class_outcomes.
        assert "control" not in deep.known_class_outcomes(budget_tier="deep")
        assert "control" in std.known_class_outcomes(budget_tier="standard")

    def test_filter_probes_skips_inherited_rejects_standard(self) -> None:
        priors = InheritancePriors(
            tested={
                "null": {
                    "outcome": OUTCOME_REJECTED,
                    "confidence": 75,
                    "source": "inherited_endpoint",
                },
            },
            suppress_control_probes=True,
        )
        probes = [
            ("null_byte", "\x00"),
            ("empty", ""),
            ("integer", "1"),
        ]
        filtered = filter_probes_by_inheritance(
            probes, priors, budget_tier="standard",
        )
        types = {t for t, _ in filtered}
        assert "null_byte" not in types
        assert "empty" in types
        assert "integer" in types
        # Deep re-includes control-related.
        deep_filtered = filter_probes_by_inheritance(
            probes, priors, budget_tier="deep",
        )
        deep_types = {t for t, _ in deep_filtered}
        assert "null_byte" in deep_types

    def test_second_param_standard_fewer_requests(self) -> None:
        """
        Acceptance: second parameter on same endpoint spends fewer requests
        in standard mode when inheritance applies (unit-level on planner).
        """
        # After multiprobe retries exhausted, reflection still uncertain →
        # standard schedules length / types / semantic / parser follow-ups.
        # (Avoid high-confidence early stop so inheritance can reduce HTTP.)
        base_kw = dict(
            budget_tier="standard",
            max_requests=18,
            requests_used=3,  # baseline + 2 multiprobe
            completed_analyses=frozenset({"baseline", "multiprobe"}),
            multiprobe_completed_count=2,
            reflection_state="reflected",
            reflection_confidence=45,
            reflection_uncertainty="high",
            acceptance_class_count=0,
            length_state="unknown",
            length_confidence=0,
            length_uncertainty="high",
            types_known=False,
            types_uncertainty="high",
            parser_known=False,
            analyses_enabled={
                "baseline": True,
                "multiprobe": True,
                "identifier": True,
                "characters": True,
                "length": True,
                "types": True,
                "validation": True,
                "transformations": True,
                "reflection": True,
            },
        )
        ctx_cold = PlanContext(**base_kw)
        cold = plan_next(ctx_cold)
        cold_http = sum(
            a.estimated_requests for a in cold.actions if a.estimated_requests > 0
        )

        # Warm: same state + inheritance covering validation + parser.
        ctx_warm = PlanContext(
            **base_kw,
            inheritance_active=True,
            inherited_tested={
                "null": {"outcome": "rejected", "confidence": 75},
                "control": {"outcome": "rejected", "confidence": 75},
                "empty": {"outcome": "rejected", "confidence": 70},
                "unicode": {"outcome": "rejected", "confidence": 70},
            },
            inherited_rejected_classes=frozenset({"control", "null", "unicode"}),
            suppress_control_probes=True,
            suppress_parser_probes=True,
            inheritance_reduced_estimate=8,
        )
        warm = plan_next(ctx_warm)
        warm_http = sum(
            a.estimated_requests for a in warm.actions if a.estimated_requests > 0
        )

        warm_actions = {a.action for a in warm.actions}
        cold_actions = {a.action for a in cold.actions}

        assert cold_http > 0, f"cold should schedule HTTP: {cold_actions}"
        # Inheritance should suppress semantic and/or parser waves.
        assert ACTION_PARSER_PROBES not in warm_actions
        if ACTION_SEMANTIC_RULES in cold_actions:
            assert ACTION_SEMANTIC_RULES not in warm_actions
        assert warm_http < cold_http, (
            f"expected fewer HTTP with inheritance: cold={cold_http} "
            f"actions={cold_actions} warm={warm_http} actions={warm_actions}"
        )
        assert ctx_warm.inheritance_reduced_estimate > 0


class TestShouldSkipParser:
    def test_standard_skips_when_parent_known(self) -> None:
        priors = InheritancePriors(
            parser={"dup": {"state": "last_wins"}},
            parser_known=True,
            suppress_parser_probes=True,
        )
        assert should_skip_parser_probes(priors, budget_tier="standard") is True
        assert should_skip_parser_probes(priors, budget_tier="deep") is False


# ---------------------------------------------------------------------------
# DB orchestration
# ---------------------------------------------------------------------------

class TestDbRefresh:
    def test_refresh_endpoint_and_app(self, db_path: Path) -> None:
        host = "api.example.com"
        ep_id = str(uuid.uuid4())
        with __import__("sqlite3").connect(str(db_path)) as conn:
            conn.execute(
                """
                INSERT INTO endpoints
                    (id, project_id, host, method, path, normalized_path,
                     first_seen, last_seen)
                VALUES (?, 'proj', ?, 'GET', '/v1/a', '/v1/a',
                        datetime('now'), datetime('now'))
                """,
                (ep_id, host),
            )
            for name in ("alpha", "beta"):
                conn.execute(
                    """
                    INSERT INTO parameters
                        (id, endpoint_id, name, location, param_type)
                    VALUES (?, ?, ?, 'query', 'string')
                    """,
                    (str(uuid.uuid4()), ep_id, name),
                )
            conn.commit()

        for name in ("alpha", "beta"):
            p = _param_with_tested(
                host=host,
                name=name,
                tested={
                    "null": {"outcome": OUTCOME_REJECTED, "confidence": 95},
                },
                classes={
                    "control": {"outcome": OUTCOME_REJECTED, "confidence": 90},
                },
            )
            upsert_param_profile(
                db_path,
                param_uuid=p["param_uuid"],
                host=host,
                location="query",
                param_name=name,
                profile=p,
            )

        listed = list_param_profiles_for_endpoint(db_path, ep_id)
        assert len(listed) == 2

        summary = refresh_multi_level(
            db_path, endpoint_id=ep_id, host=host, bump_version=True,
        )
        assert summary["endpoint"] is not None
        assert summary["app"] is not None

        ep = get_endpoint_profile(db_path, ep_id)
        assert ep is not None
        assert ep["tested"]["null"]["outcome"] == OUTCOME_REJECTED

        app = get_app_profile(db_path, host)
        assert app is not None
        assert app["tested"]["null"]["outcome"] == OUTCOME_REJECTED

        priors = load_inheritance_priors(
            db_path, host=host, endpoint_id=ep_id, budget_tier="standard",
        )
        assert priors.is_active()
        assert priors.suppress_control_probes is True

    def test_format_helpers(self) -> None:
        lines = format_endpoint_intel_lines(None)
        assert any("no endpoint" in ln for ln in lines)
        app_lines = format_app_intel_lines(None)
        assert any("no application" in ln for ln in app_lines)

        stored = aggregate_endpoint_from_params(
            [
                _param_with_tested(
                    tested={"null": {"outcome": "rejected", "confidence": 90}},
                )
            ],
            endpoint_id="ep",
            host="h",
            method="GET",
            path="/p",
        )
        elines = format_endpoint_intel_lines(stored)
        assert any("endpoint" in ln for ln in elines)
        alines = format_app_intel_lines(
            aggregate_app_from_endpoints([stored], host="h")
        )
        assert any("application" in ln for ln in alines)
