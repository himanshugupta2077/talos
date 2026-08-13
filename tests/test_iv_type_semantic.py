"""
Tests: Module 7 — Types, semantic validation & negative evidence.

Coverage:
    - Integer-like params prune the 12-type matrix under standard
    - URL / name-hint params prioritize URL-shaped confirms
    - Exhaustive still uses full type matrix
    - Default validation excludes SQLi/XSS-shaped strings
    - very_long skipped when max_accepted is known
    - Type conflict detection (integer examples vs UUID accepted)
    - Negative evidence merge into tested{}
    - Planner emits type_confirm / semantic_rules (not FUTURE stubs)
    - Engine expands type_confirm / semantic_rules via type_intel
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

import pytest

from talos.input_validation.config import IVAnalysesConfig, IVConfig
from talos.input_validation.engine import (
    _probes_for_phase,
    _type_or_semantic_probes_for_action,
    make_param_uuid,
)
from talos.input_validation.outcomes import OUTCOME_ACCEPTED, OUTCOME_REJECTED
from talos.input_validation.phases import IV_TYPE_PROBES
from talos.input_validation.planner import (
    ACTION_SEMANTIC_RULES,
    ACTION_TYPE_CONFIRM,
    FUTURE_ACTION_TOKENS,
    M7_ACTION_TOKENS,
    PlanAction,
    PlanContext,
    plan_next,
)
from talos.input_validation.profile import empty_param_profile, set_tested
from talos.input_validation import type_intel as type_intel_mod
from talos.input_validation.type_intel import (
    VALIDATION_CORE_LABELS,
    VALIDATION_EDGE_LABELS,
    estimated_type_probe_count,
    is_url_prioritized,
    json_native_probe_value,
    merge_type_tested,
    resolve_passive_type,
    select_semantic_probes,
    select_type_probes,
    synthesize_type_state,
    type_family_probes,
    validation_probes_for_strategy,
)
from talos.scheduler.job import IV_TYPES, IV_VALIDATION


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "proj.db"
    with sqlite3.connect(str(path)) as conn:
        conn.executescript(
            """
            CREATE TABLE endpoints (
                id TEXT PRIMARY KEY,
                host TEXT,
                method TEXT,
                path TEXT,
                project_id TEXT,
                normalized_path TEXT
            );
            CREATE TABLE parameters (
                id TEXT PRIMARY KEY,
                endpoint_id TEXT,
                name TEXT,
                location TEXT,
                host TEXT,
                semantic_type TEXT DEFAULT 'unknown',
                example_values TEXT DEFAULT '[]',
                seen_count INTEGER DEFAULT 1
            );
            CREATE TABLE scheduler_jobs (
                job_id TEXT PRIMARY KEY,
                endpoint_id TEXT,
                job_type TEXT,
                priority INTEGER,
                status TEXT,
                created_at TEXT,
                meta TEXT
            );
            CREATE TABLE iv_param_profiles (
                param_uuid TEXT PRIMARY KEY,
                host TEXT,
                location TEXT,
                param_name TEXT,
                profile_json TEXT,
                profile_version INTEGER DEFAULT 1,
                updated_at TEXT
            );
            CREATE TABLE iv_probe_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                param_uuid TEXT,
                host TEXT,
                location TEXT,
                param_name TEXT,
                analysis TEXT,
                payload TEXT,
                payload_type TEXT,
                payload_index INTEGER,
                status TEXT,
                flow_id TEXT,
                status_code INTEGER,
                created_at TEXT
            );
            """
        )
    return path


def _seed_param(
    db_path: Path,
    *,
    host: str = "api.example.com",
    location: str = "query",
    name: str = "limit",
    semantic_type: str = "integer",
    examples: list[str] | None = None,
) -> tuple[str, str]:
    ep_id = str(uuid.uuid4())
    param_uuid = make_param_uuid(host, location, name)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO endpoints (id, host, method, path, project_id, normalized_path) "
            "VALUES (?, ?, 'GET', '/x', 'p', '/x')",
            (ep_id, host),
        )
        conn.execute(
            "INSERT INTO parameters "
            "(id, endpoint_id, name, location, host, semantic_type, example_values, seen_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 3)",
            (
                str(uuid.uuid4()),
                ep_id,
                name,
                location,
                host,
                semantic_type,
                json.dumps(examples or ["1", "10", "25"]),
            ),
        )
    return param_uuid, ep_id


# ---------------------------------------------------------------------------
# Pure type pruning
# ---------------------------------------------------------------------------

class TestTypePruning:
    def test_integer_skips_most_of_matrix_standard(self) -> None:
        plan = select_type_probes(semantic_type="integer", strategy="standard")
        labels = [p[0] for p in plan.probes]
        assert plan.passive_type == "integer"
        assert len(plan.probes) <= 4
        assert len(plan.probes) < len(IV_TYPE_PROBES)
        assert labels[0] == "integer"
        assert "email" not in labels
        assert "hash_md5" not in labels
        assert "uuid" not in labels

    def test_url_name_hint_prioritizes_url(self) -> None:
        plan = select_type_probes(
            semantic_type="unknown",
            param_name="return_url",
            strategy="standard",
        )
        assert plan.passive_type == "url"
        assert plan.probes[0][0] == "url"
        assert is_url_prioritized(param_name="redirect")

    def test_url_semantic_type_first(self) -> None:
        plan = select_type_probes(semantic_type="url", strategy="standard")
        assert plan.probes[0][0] == "url"
        assert "https://" in plan.probes[0][1]

    def test_exhaustive_full_matrix(self) -> None:
        plan = select_type_probes(semantic_type="integer", strategy="exhaustive")
        assert len(plan.probes) == len(IV_TYPE_PROBES)
        assert plan.hypothesis == "types.exhaustive_matrix"

    def test_estimated_count_matches_plan(self) -> None:
        n = estimated_type_probe_count("standard", semantic_type="uuid")
        plan = select_type_probes(semantic_type="uuid", strategy="standard")
        assert n == len(plan.probes)
        assert n < 12

    def test_resolve_passive_from_examples(self) -> None:
        st = resolve_passive_type(
            semantic_type="unknown",
            examples=["550e8400-e29b-41d4-a716-446655440000"],
        )
        assert st == "uuid"


# ---------------------------------------------------------------------------
# Semantic + validation core/edge
# ---------------------------------------------------------------------------

class TestSemanticAndValidation:
    def test_standard_validation_excludes_exploit_shapes(self) -> None:
        probes = validation_probes_for_strategy("standard")
        labels = {n for n, _ in probes}
        assert "special_chars" not in labels
        assert "html_injection" not in labels
        assert labels <= VALIDATION_CORE_LABELS | {"crlf"}
        # Core families present
        assert "empty" in labels
        assert "null_byte" in labels

    def test_deep_includes_edge(self) -> None:
        probes = validation_probes_for_strategy("deep")
        labels = {n for n, _ in probes}
        assert "special_chars" in labels
        assert "html_injection" in labels
        assert "crlf" in labels
        assert VALIDATION_EDGE_LABELS & labels

    def test_skip_very_long_when_bound_known(self) -> None:
        plan = select_semantic_probes(
            semantic_type="string",
            strategy="standard",
            max_accepted_length=128,
        )
        labels = [p[0] for p in plan.probes]
        assert "very_long" not in labels
        assert "very_long" in plan.skipped

    def test_integer_semantic_range_probes(self) -> None:
        plan = select_semantic_probes(
            semantic_type="integer",
            examples=["1", "5", "20"],
            strategy="standard",
            max_accepted_length=64,
            max_probes=8,
        )
        labels = [p[0] for p in plan.probes]
        assert "negative_int" in labels
        assert "zero" in labels or "huge_int" in labels
        assert "enum_outside" not in labels  # numeric examples not enums

    def test_boolean_type_confirm_includes_both_polarities(self) -> None:
        plan = select_type_probes(semantic_type="boolean", strategy="standard")
        labels = [p[0] for p in plan.probes]
        assert "boolean" in labels
        assert "boolean_false" in labels
        values = dict(plan.probes)
        assert values["boolean"].lower() == "true"
        assert values["boolean_false"].lower() == "false"

    def test_boolean_family_flips_observed_true(self) -> None:
        probes = type_family_probes(
            passive="boolean", examples=["true"], strategy="standard",
        )
        labels = [p[0] for p in probes]
        assert "bool_false" in labels
        assert dict(probes)["bool_false"] == "false"

    def test_email_family_standard_shapes(self) -> None:
        plan = select_semantic_probes(
            semantic_type="email",
            examples=["user@example.com"],
            strategy="standard",
            max_probes=8,
        )
        labels = [p[0] for p in plan.probes]
        assert "email_plus" in labels
        assert "email_display" in labels
        assert "email_comma" in labels
        assert "email_newline" not in labels  # deep only

    def test_email_family_deep_includes_newline(self) -> None:
        probes = type_family_probes(
            passive="email", examples=["a@b.co"], strategy="deep",
        )
        labels = [p[0] for p in probes]
        assert "email_newline" in labels

    def test_array_family_standard(self) -> None:
        plan = select_semantic_probes(
            semantic_type="array",
            strategy="standard",
            max_probes=8,
        )
        labels = [p[0] for p in plan.probes]
        assert "array_empty" in labels
        assert "array_single" in labels
        assert "array_string" in labels

    def test_json_host_leaf_is_url(self) -> None:
        assert resolve_passive_type(param_name="headers.Host") == "url"
        assert resolve_passive_type(param_name="headers.Location") == "url"
        assert is_url_prioritized(param_name="headers.Origin")

    def test_json_native_coercion(self) -> None:
        assert json_native_probe_value("false", "boolean_false") is False
        assert json_native_probe_value("true", "boolean") is True
        assert json_native_probe_value("-1", "negative_int") == -1
        assert json_native_probe_value("null", "null_str") is None
        assert json_native_probe_value("[]", "array_empty") == []
        assert json_native_probe_value('["talos"]', "array_single") == ["talos"]
        assert json_native_probe_value("notabool", "string") == "notabool"
        assert json_native_probe_value("true", "character") == "true"

    def test_enum_outside_for_string_set(self) -> None:
        plan = select_semantic_probes(
            semantic_type="string",
            examples=["draft", "published", "archived"],
            strategy="standard",
            max_probes=6,
        )
        labels = [p[0] for p in plan.probes]
        assert "enum_outside" in labels
        outside = dict(plan.probes)["enum_outside"]
        assert outside not in {"draft", "published", "archived"}


# ---------------------------------------------------------------------------
# Type synthesis + negative evidence
# ---------------------------------------------------------------------------

class TestTypeSynthesisAndTested:
    def test_conflict_integer_vs_uuid(self) -> None:
        outcomes = {
            "integer": {"outcome": OUTCOME_REJECTED, "confidence": 90},
            "uuid": {"outcome": OUTCOME_ACCEPTED, "confidence": 88},
        }
        synth = synthesize_type_state(outcomes, passive_type="integer")
        assert synth.state == "conflicting"
        assert synth.uncertainty == "high"
        assert "uuid" in (synth.conflict_note or synth.primary)

    def test_typed_primary_matches_passive(self) -> None:
        outcomes = {
            "integer": {"outcome": OUTCOME_ACCEPTED, "confidence": 95},
            "string": {"outcome": OUTCOME_REJECTED, "confidence": 80},
        }
        synth = synthesize_type_state(outcomes, passive_type="integer")
        assert synth.state == "typed"
        assert synth.primary == "integer"
        assert synth.confidence >= 90

    def test_merge_type_tested_rejects(self) -> None:
        profile = empty_param_profile(param_uuid="x", host="h", location="q", name="n")
        types = {
            "integer": {
                "outcome": OUTCOME_REJECTED,
                "confidence": 88,
                "evidence_flow_ids": ["f1"],
            },
            "string": {
                "outcome": OUTCOME_ACCEPTED,
                "confidence": 70,
                "evidence_flow_ids": ["f2"],
            },
        }
        merge_type_tested(profile, types)
        assert "type:integer" in profile["tested"]
        assert profile["tested"]["type:integer"]["outcome"] == OUTCOME_REJECTED
        assert profile["tested"]["type:integer"]["confidence"] == 88
        assert "type:string" not in profile["tested"]

    def test_tested_key_for_null_and_crlf(self) -> None:
        # Import via module attr — name starts with "test" and would be
        # collected as a pytest test if imported at module level.
        key_fn = type_intel_mod.tested_key_for_payload_type
        assert key_fn("null_byte") == "null"
        assert key_fn("crlf") == "crlf"
        assert key_fn("unicode") == "unicode"
        assert key_fn("integer") == "type:integer"

    def test_rejected_unicode_null_in_tested(self) -> None:
        profile = empty_param_profile(param_uuid="x", host="h", location="q", name="n")
        set_tested(profile, "unicode", outcome=OUTCOME_REJECTED, confidence=88)
        set_tested(profile, "null", outcome=OUTCOME_REJECTED, confidence=95)
        set_tested(profile, "crlf", outcome=OUTCOME_REJECTED, confidence=90)
        assert profile["tested"]["unicode"]["confidence"] == 88
        assert profile["tested"]["null"]["confidence"] == 95
        assert profile["tested"]["crlf"]["outcome"] == OUTCOME_REJECTED


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

class TestPlannerM7:
    def test_m7_tokens_not_future_stubs(self) -> None:
        assert ACTION_TYPE_CONFIRM in M7_ACTION_TOKENS
        assert ACTION_SEMANTIC_RULES in M7_ACTION_TOKENS
        assert ACTION_TYPE_CONFIRM not in FUTURE_ACTION_TOKENS
        assert ACTION_SEMANTIC_RULES not in FUTURE_ACTION_TOKENS

    def test_deep_emits_type_confirm_and_semantic_rules(self) -> None:
        ctx = PlanContext(
            budget_tier="deep",
            max_requests=40,
            requests_used=4,
            completed_analyses=frozenset({
                "baseline", "multiprobe", "identifier", "characters", "length",
            }),
            multiprobe_completed_count=1,
            identifier_completed_count=1,
            characters_completed_count=1,
            length_completed_count=5,
            length_state="bounded",
            length_confidence=90,
            length_uncertainty="low",
            reflection_state="reflected",
            reflection_confidence=90,
            reflection_uncertainty="low",
            types_known=False,
            types_completed_count=0,
            validation_completed_count=0,
            semantic_type="integer",
            param_name="limit",
            acceptance_class_count=4,
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
        result = plan_next(ctx)
        actions = {a.action for a in result.actions}
        assert ACTION_TYPE_CONFIRM in actions
        assert ACTION_SEMANTIC_RULES in actions
        type_act = next(a for a in result.actions if a.action == ACTION_TYPE_CONFIRM)
        assert type_act.estimated_requests <= 8
        assert type_act.estimated_requests < 12
        assert "integer" in type_act.hypothesis

    def test_standard_type_confirm_estimate_small(self) -> None:
        ctx = PlanContext(
            budget_tier="standard",
            max_requests=18,
            requests_used=2,
            completed_analyses=frozenset({"baseline", "multiprobe"}),
            multiprobe_completed_count=1,
            reflection_state="unknown",
            reflection_confidence=40,
            reflection_uncertainty="high",
            types_known=False,
            types_completed_count=0,
            acceptance_class_count=0,
            semantic_type="integer",
            param_name="count",
            analyses_enabled={
                "baseline": True,
                "multiprobe": True,
                "types": True,
                "validation": True,
                "length": False,
                "characters": False,
                "identifier": False,
                "transformations": True,
                "reflection": True,
            },
        )
        result = plan_next(ctx)
        type_acts = [a for a in result.actions if a.action == ACTION_TYPE_CONFIRM]
        if type_acts:
            assert type_acts[0].estimated_requests <= 4

    def test_typed_boolean_not_skipped_when_classes_solid(self) -> None:
        ctx = PlanContext(
            budget_tier="standard",
            max_requests=18,
            requests_used=3,
            completed_analyses=frozenset({"baseline", "multiprobe"}),
            multiprobe_completed_count=1,
            reflection_state="reflected",
            reflection_confidence=95,
            reflection_uncertainty="none",
            types_known=False,
            types_completed_count=0,
            validation_completed_count=0,
            acceptance_class_count=5,
            semantic_type="boolean",
            param_name="enabled",
            analyses_enabled={
                "baseline": True,
                "multiprobe": True,
                "types": True,
                "validation": True,
                "length": False,
                "characters": False,
                "identifier": False,
                "transformations": True,
                "reflection": True,
            },
        )
        result = plan_next(ctx)
        actions = {a.action for a in result.actions}
        assert ACTION_TYPE_CONFIRM in actions
        assert ACTION_SEMANTIC_RULES in actions


# ---------------------------------------------------------------------------
# Engine expansion
# ---------------------------------------------------------------------------

class TestEngineTypeSemantic:
    def test_type_confirm_pruned_from_db_passive(self, db_path: Path) -> None:
        param_uuid, _ = _seed_param(
            db_path,
            name="limit",
            semantic_type="integer",
            examples=["1", "10"],
        )
        config = IVConfig(probe_strategy="standard")
        action = PlanAction(
            action=ACTION_TYPE_CONFIRM,
            hypothesis="types.confirm.integer",
            estimated_requests=4,
            meta={"semantic_type": "integer", "param_name": "limit", "tier": "standard"},
        )
        probes = _type_or_semantic_probes_for_action(
            db_path,
            "api.example.com",
            "query",
            "limit",
            param_uuid,
            config,
            action,
            ACTION_TYPE_CONFIRM,
        )
        labels = [p[0] for p in probes]
        assert len(probes) <= 4
        assert labels[0] == "integer"
        assert "hash_md5" not in labels

    def test_semantic_rules_skip_very_long(self, db_path: Path) -> None:
        param_uuid, _ = _seed_param(db_path, name="q", semantic_type="string")
        # Pass max_accepted via action meta (no full profile schema required).
        config = IVConfig(probe_strategy="standard")
        action = PlanAction(
            action=ACTION_SEMANTIC_RULES,
            hypothesis="semantic.rules.string",
            estimated_requests=5,
            meta={"max_accepted_length": 64, "tier": "standard"},
        )
        probes = _type_or_semantic_probes_for_action(
            db_path,
            "api.example.com",
            "query",
            "q",
            param_uuid,
            config,
            action,
            ACTION_SEMANTIC_RULES,
        )
        assert all(p[0] != "very_long" for p in probes)
        assert all(p[0] not in ("special_chars", "html_injection") for p in probes)

    def test_phase_shortcut_validation_no_exploit_standard(self) -> None:
        config = IVConfig(
            probe_strategy="standard",
            analyses=IVAnalysesConfig(validation=True),
        )
        probes = _probes_for_phase(IV_VALIDATION, config)
        labels = {p[0] for p in probes}
        assert "special_chars" not in labels
        assert "html_injection" not in labels

    def test_phase_shortcut_types_pruned_standard(self) -> None:
        config = IVConfig(probe_strategy="standard")
        probes = _probes_for_phase(IV_TYPES, config)
        assert len(probes) < len(IV_TYPE_PROBES)
        assert len(probes) <= 4
