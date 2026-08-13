"""
Unit tests for Input Validation Module 5 — Event-Driven Planner.

Covers pure planner decisions (no HTTP):
    - high-confidence early stop after multiprobe (standard)
    - reflection unknown → extra multiprobe
    - budget hard stop
    - never finalize before evidence
    - exhaustive still requests matrix follow-ups
    - engine schedule under standard enqueues far fewer than ~70 jobs
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

import pytest

from talos.input_validation.config import (
    IVAnalysesConfig,
    IVConfig,
    load_config,
    save_config,
)
from talos.input_validation.engine import (
    build_plan_context,
    make_param_uuid,
    plan_and_enqueue_for_param,
    schedule_endpoint,
)
from talos.input_validation.planner import (
    ACTION_BASELINE,
    ACTION_CHAR_DRILLDOWN,
    ACTION_IDENTIFIER,
    ACTION_LENGTH,
    ACTION_LENGTH_BINARY,
    ACTION_MULTIPROBE,
    ACTION_REFLECTION,
    ACTION_SYNTHESIZE,
    ACTION_TRANSFORMATIONS,
    ACTION_TYPES,
    ACTION_VALIDATION,
    DEFAULT_MAX_REQUESTS,
    PlanContext,
    confidence_is_high,
    plan_next,
    reflection_needs_retry,
    resolve_max_requests,
    signals_from_profile,
)
from talos.input_validation.db import upsert_probe_result
from talos.projects.db import init_project_db
from talos.scheduler.job import IV_BASELINE, IV_MULTIPROBE


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


def _seed_endpoint_param(
    db_path: Path,
    *,
    host: str = "api.example.com",
    path: str = "/v1/items",
    param_name: str = "q",
    location: str = "query",
) -> tuple[str, str]:
    ep_id = str(uuid.uuid4())
    param_uuid = make_param_uuid(host, location, param_name)
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
            INSERT INTO parameters (id, endpoint_id, name, location, param_type)
            VALUES (?, ?, ?, ?, 'string')
            """,
            (str(uuid.uuid4()), ep_id, param_name, location),
        )
        conn.commit()
    return ep_id, param_uuid


def _base_ctx(**overrides) -> PlanContext:
    """Standard-tier context with all analyses on."""
    defaults = dict(
        budget_tier="standard",
        max_requests=DEFAULT_MAX_REQUESTS["standard"],
        requests_used=0,
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
# Pure helpers
# ---------------------------------------------------------------------------

class TestPlannerHelpers:
    def test_resolve_max_requests_tier_defaults(self) -> None:
        assert resolve_max_requests("quick") == 8
        assert resolve_max_requests("standard") == 18
        assert resolve_max_requests("deep") == 40
        assert resolve_max_requests("exhaustive") == 256

    def test_resolve_max_requests_override(self) -> None:
        assert resolve_max_requests("standard", 5) == 5
        assert resolve_max_requests("standard", 0) == 18
        assert resolve_max_requests("standard", None) == 18

    def test_confidence_is_high(self) -> None:
        assert confidence_is_high(95, "low") is True
        assert confidence_is_high(95, "none") is True
        assert confidence_is_high(95, "high") is False
        assert confidence_is_high(50, "low") is False

    def test_reflection_needs_retry(self) -> None:
        assert reflection_needs_retry("unknown", 0, "high") is True
        assert reflection_needs_retry("reflected", 95, "low") is False
        assert reflection_needs_retry("conflicting", 80, "low") is True

    def test_signals_from_profile(self) -> None:
        profile = {
            "observed": {
                "reflection": {
                    "state": "reflected",
                    "confidence": 92,
                    "uncertainty": "low",
                },
                "acceptance": {"classes": {"alpha": {}, "quote": {}}},
                "length": {"state": "unknown", "confidence": 0, "uncertainty": "high"},
                "types": {},
            },
            "inferred": {"synthesis": {"source": "offline_probes"}},
            "requests_used": 2,
        }
        sig = signals_from_profile(profile)
        assert sig["reflection_state"] == "reflected"
        assert sig["reflection_confidence"] == 92
        assert sig["acceptance_class_count"] == 2
        assert sig["synthesize_done"] is True


# ---------------------------------------------------------------------------
# plan_next decisions
# ---------------------------------------------------------------------------

class TestPlanNext:
    def test_init_requests_baseline(self) -> None:
        ctx = _base_ctx()
        result = plan_next(ctx)
        assert result.done is False
        assert len(result.actions) == 1
        assert result.actions[0].action == ACTION_BASELINE
        assert result.state == "ENSURE_BASELINE"

    def test_after_baseline_requests_multiprobe(self) -> None:
        ctx = _base_ctx(
            completed_analyses=frozenset({"baseline"}),
            requests_used=1,
        )
        result = plan_next(ctx)
        assert result.actions[0].action == ACTION_MULTIPROBE
        assert result.state == "MULTIPROBE"

    def test_high_confidence_early_stop(self) -> None:
        """After multiprobe with high-confidence reflection → finalize, not matrix."""
        ctx = _base_ctx(
            completed_analyses=frozenset({"baseline", "multiprobe"}),
            multiprobe_completed_count=1,
            requests_used=2,
            reflection_state="reflected",
            reflection_confidence=95,
            reflection_uncertainty="low",
            acceptance_class_count=4,
            length_uncertainty="low",
            length_confidence=80,
            types_known=True,
            types_uncertainty="low",
        )
        result = plan_next(ctx)
        actions = {a.action for a in result.actions}
        assert ACTION_TRANSFORMATIONS in actions or ACTION_REFLECTION in actions
        assert ACTION_IDENTIFIER not in actions
        assert ACTION_LENGTH not in actions
        assert ACTION_TYPES not in actions
        assert ACTION_VALIDATION not in actions
        assert ACTION_CHAR_DRILLDOWN not in actions
        assert "high-confidence" in result.reason or "finalize" in result.reason

    def test_reflection_unknown_extra_multiprobe(self) -> None:
        ctx = _base_ctx(
            completed_analyses=frozenset({"baseline", "multiprobe"}),
            multiprobe_completed_count=1,
            requests_used=2,
            reflection_state="unknown",
            reflection_confidence=0,
            reflection_uncertainty="high",
            acceptance_class_count=0,
        )
        result = plan_next(ctx)
        assert len(result.actions) == 1
        assert result.actions[0].action == ACTION_MULTIPROBE
        assert result.actions[0].meta.get("multiprobe_index") == 1
        assert "reflection unknown" in result.reason

    def test_budget_hard_stop(self) -> None:
        """When requests_used >= max_requests, no more HTTP — finalize only."""
        ctx = _base_ctx(
            completed_analyses=frozenset({"baseline", "multiprobe"}),
            multiprobe_completed_count=1,
            requests_used=18,
            max_requests=18,
            reflection_state="unknown",
            reflection_confidence=0,
            reflection_uncertainty="high",
            acceptance_class_count=0,
        )
        result = plan_next(ctx)
        for a in result.actions:
            assert a.estimated_requests == 0
            assert a.action in (
                ACTION_TRANSFORMATIONS,
                ACTION_REFLECTION,
                ACTION_SYNTHESIZE,
            )
        assert "budget" in result.reason or "finalize" in result.reason

    def test_never_finalize_before_evidence(self) -> None:
        """Without baseline, planner must not emit transformations/reflection."""
        ctx = _base_ctx(
            completed_analyses=frozenset(),
            multiprobe_completed_count=0,
        )
        result = plan_next(ctx)
        actions = {a.action for a in result.actions}
        assert ACTION_TRANSFORMATIONS not in actions
        assert ACTION_REFLECTION not in actions
        assert ACTION_SYNTHESIZE not in actions
        assert ACTION_BASELINE in actions

    def test_exhaustive_requests_matrix(self) -> None:
        ctx = _base_ctx(
            budget_tier="exhaustive",
            max_requests=80,
            completed_analyses=frozenset({"baseline", "multiprobe"}),
            multiprobe_completed_count=1,
            requests_used=2,
        )
        result = plan_next(ctx)
        actions = {a.action for a in result.actions}
        # Should request multiple matrix phases (not early-stop only finalize)
        assert ACTION_IDENTIFIER in actions or ACTION_CHARACTERS in actions or ACTION_LENGTH in actions
        assert ACTION_TRANSFORMATIONS not in actions  # evidence wave first

    def test_pending_baseline_waits(self) -> None:
        ctx = _base_ctx(pending_actions=frozenset({ACTION_BASELINE}))
        result = plan_next(ctx)
        assert result.actions == []
        assert result.done is False

    def test_done_after_synthesize(self) -> None:
        ctx = _base_ctx(
            completed_analyses=frozenset({"baseline", "multiprobe"}),
            multiprobe_completed_count=1,
            requests_used=2,
            reflection_state="reflected",
            reflection_confidence=95,
            reflection_uncertainty="low",
            acceptance_class_count=3,
            transformations_done=True,
            reflection_done=True,
            synthesize_done=True,
        )
        result = plan_next(ctx)
        assert result.done is True
        assert result.actions == []

    def test_quick_early_stop_on_any_reflection_state(self) -> None:
        ctx = _base_ctx(
            budget_tier="quick",
            max_requests=8,
            completed_analyses=frozenset({"baseline", "multiprobe"}),
            multiprobe_completed_count=1,
            requests_used=2,
            reflection_state="not_reflected",
            reflection_confidence=70,
            reflection_uncertainty="low",
            acceptance_class_count=1,
        )
        result = plan_next(ctx)
        actions = {a.action for a in result.actions}
        assert ACTION_LENGTH not in actions
        assert ACTION_TYPES not in actions
        assert ACTION_TRANSFORMATIONS in actions or ACTION_REFLECTION in actions

    def test_length_binary_token_recognized(self) -> None:
        """Standard with high length uncertainty may emit length_binary (M6 stub)."""
        ctx = _base_ctx(
            completed_analyses=frozenset({"baseline", "multiprobe"}),
            multiprobe_completed_count=2,  # no more multiprobe retries
            requests_used=3,
            # Not early-stop: medium reflection confidence, few classes
            reflection_state="reflected",
            reflection_confidence=70,
            reflection_uncertainty="high",
            acceptance_class_count=1,
            length_uncertainty="high",
            length_confidence=0,
        )
        # Second multiprobe already done so evaluate moves past retry
        result = plan_next(ctx)
        actions = {a.action for a in result.actions}
        # Either length_binary or type_confirm or finalize — not full 70 matrix
        assert ACTION_IDENTIFIER not in actions
        assert ACTION_VALIDATION not in actions
        assert (
            ACTION_LENGTH_BINARY in actions
            or ACTION_TRANSFORMATIONS in actions
            or ACTION_REFLECTION in actions
            or ACTION_TYPES in actions
            or "type_confirm" in actions
        )


# ---------------------------------------------------------------------------
# Engine integration (scheduling, no HTTP)
# ---------------------------------------------------------------------------

class TestEnginePlannerScheduling:
    def test_standard_run_does_not_enqueue_full_matrix(
        self, db_path: Path
    ) -> None:
        save_config(
            db_path,
            IVConfig(
                enabled=True,
                probe_strategy="standard",
                analyses=IVAnalysesConfig(),  # all on
            ),
        )
        ep_id, _ = _seed_endpoint_param(db_path)
        n = schedule_endpoint(
            db_path, "proj", ep_id, phase_filter=None, ignore_cache=True
        )
        # Must not enqueue ~70 jobs up front
        assert n < 10
        assert n == 1  # baseline first wave
        with sqlite3.connect(str(db_path)) as conn:
            rows = conn.execute(
                "SELECT job_type FROM scheduler_jobs"
            ).fetchall()
        types = [r[0] for r in rows]
        assert types == [IV_BASELINE]
        assert "iv_length" not in types
        assert "iv_types" not in types
        assert "iv_validation" not in types
        assert "iv_characters" not in types

    def test_exhaustive_also_starts_with_baseline_only(
        self, db_path: Path
    ) -> None:
        """Even exhaustive is progressive — first wave is baseline, not 70."""
        save_config(
            db_path,
            IVConfig(enabled=True, probe_strategy="exhaustive"),
        )
        ep_id, _ = _seed_endpoint_param(db_path)
        n = schedule_endpoint(
            db_path, "proj", ep_id, phase_filter=None, ignore_cache=True
        )
        assert n == 1
        with sqlite3.connect(str(db_path)) as conn:
            types = [
                r[0]
                for r in conn.execute(
                    "SELECT job_type FROM scheduler_jobs"
                ).fetchall()
            ]
        assert types == [IV_BASELINE]

    def test_plan_after_baseline_enqueues_multiprobe(
        self, db_path: Path
    ) -> None:
        save_config(
            db_path,
            IVConfig(
                enabled=True,
                probe_strategy="standard",
                analyses=IVAnalysesConfig(
                    length=False,
                    types=False,
                    validation=False,
                    transformations=False,
                    reflection=False,
                ),
            ),
        )
        ep_id, param_uuid = _seed_endpoint_param(db_path)
        host, location, name = "api.example.com", "query", "q"
        # Simulate completed baseline
        upsert_probe_result(
            db_path, param_uuid, ep_id, host, location, name,
            "baseline", None, "baseline", 0, "flow-base", "completed",
        )
        n = plan_and_enqueue_for_param(
            db_path, "proj",
            host=host, location=location, name=name, endpoint_id=ep_id,
        )
        assert n == 1
        with sqlite3.connect(str(db_path)) as conn:
            rows = conn.execute(
                "SELECT job_type, meta FROM scheduler_jobs"
            ).fetchall()
        assert rows[0][0] == IV_MULTIPROBE
        meta = json.loads(rows[0][1])
        assert meta.get("planner_action") == "multiprobe"
        assert meta.get("hypothesis")

    def test_max_requests_config_persists(self, db_path: Path) -> None:
        save_config(
            db_path,
            IVConfig(
                enabled=True,
                probe_strategy="standard",
                max_requests_per_param=6,
            ),
        )
        cfg = load_config(db_path)
        assert cfg.max_requests_per_param == 6
        assert resolve_max_requests(cfg.probe_strategy, cfg.max_requests_per_param) == 6

    def test_build_plan_context_counts_probes(self, db_path: Path) -> None:
        ep_id, param_uuid = _seed_endpoint_param(db_path)
        host, location, name = "api.example.com", "query", "q"
        upsert_probe_result(
            db_path, param_uuid, ep_id, host, location, name,
            "baseline", None, "baseline", 0, "f1", "completed",
        )
        upsert_probe_result(
            db_path, param_uuid, ep_id, host, location, name,
            "multiprobe", "TL…", "multiprobe", 0, "f2", "completed",
        )
        cfg = IVConfig(probe_strategy="standard")
        ctx = build_plan_context(
            db_path,
            param_uuid=param_uuid,
            host=host,
            location=location,
            name=name,
            endpoint_id=ep_id,
            config=cfg,
        )
        assert ctx.requests_used == 2
        assert "baseline" in ctx.completed_analyses
        assert "multiprobe" in ctx.completed_analyses
        assert ctx.multiprobe_completed_count == 1
