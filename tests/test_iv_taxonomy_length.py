"""
Tests: Module 6 — Character taxonomy & binary length search.

Coverage:
    - Taxonomy class selection by tier (standard = representatives, not 30)
    - char_probes_for_strategy sizes and skip-known multiprobe outcomes
    - Exhaustive extended character list
    - Length seed < 10 for standard; binary refine midpoints
    - Truncation vs hard reject in synthesize_length_state
    - Engine executors expand planner tokens correctly
    - Planner emits length_binary / char_drilldown with Module 6 estimates
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

import pytest

from talos.input_validation.config import IVAnalysesConfig, IVConfig, save_config
from talos.input_validation.engine import (
    _char_probes_for_action,
    _length_probes_for_action,
    _probes_for_phase,
    schedule_endpoint,
)
from talos.input_validation.length_search import (
    EXHAUSTIVE_LENGTHS,
    MAX_LENGTH_PROBES,
    SEED_LENGTHS,
    length_search_complete,
    next_length_targets,
    parse_length_outcomes,
    seed_lengths,
    synthesize_length_state,
)
from talos.input_validation.outcomes import (
    OUTCOME_ACCEPTED,
    OUTCOME_REJECTED,
    OUTCOME_TRUNCATED,
)
from talos.input_validation.phases import IV_TEST_CHARS, IV_TEST_LENGTHS
from talos.input_validation.planner import (
    ACTION_CHAR_DRILLDOWN,
    ACTION_LENGTH_BINARY,
    ACTION_TRANSFORMATIONS,
    M6_ACTION_TOKENS,
    PlanAction,
    PlanContext,
    plan_next,
)
from talos.input_validation.taxonomy import (
    CLASS_SPECS,
    CORE_CLASSES,
    EXHAUSTIVE_TEST_CHARS,
    INJECTION_CLASSES,
    STRUCTURE_CLASSES,
    char_probes_for_strategy,
    char_to_classes,
    classes_for_tier,
    estimated_char_probe_count,
    multiprobe_default_samples,
)
from talos.scheduler.job import IV_CHARACTERS, IV_LENGTH


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
                project_id TEXT
            );
            CREATE TABLE parameters (
                id TEXT PRIMARY KEY,
                endpoint_id TEXT,
                name TEXT,
                location TEXT,
                host TEXT
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
            CREATE TABLE iv_probe_results (
                id TEXT PRIMARY KEY,
                param_uuid TEXT,
                endpoint_id TEXT,
                host TEXT,
                location TEXT,
                param_name TEXT,
                analysis TEXT,
                payload TEXT,
                payload_type TEXT,
                payload_index INTEGER,
                flow_id TEXT,
                status TEXT,
                created_at TEXT,
                completed_at TEXT,
                UNIQUE(param_uuid, analysis, payload_type, payload_index)
            );
            CREATE TABLE iv_param_profiles (
                param_uuid TEXT PRIMARY KEY,
                host TEXT,
                location TEXT,
                name TEXT,
                profile_json TEXT,
                profile_version INTEGER,
                updated_at TEXT
            );
            CREATE TABLE input_validation_config (
                project_id TEXT PRIMARY KEY,
                enabled INTEGER DEFAULT 0,
                analyses_baseline INTEGER DEFAULT 1,
                analyses_multiprobe INTEGER DEFAULT 1,
                analyses_identifier INTEGER DEFAULT 1,
                analyses_characters INTEGER DEFAULT 1,
                analyses_length INTEGER DEFAULT 1,
                analyses_types INTEGER DEFAULT 1,
                analyses_transformations INTEGER DEFAULT 1,
                analyses_reflection INTEGER DEFAULT 1,
                analyses_validation INTEGER DEFAULT 1,
                probe_strategy TEXT DEFAULT 'standard',
                max_requests_per_param INTEGER DEFAULT 0
            );
            CREATE TABLE flows (
                id TEXT PRIMARY KEY,
                status_code INTEGER,
                content_type TEXT,
                response_body BLOB,
                response_headers TEXT
            );
            """
        )
    return path


def _seed_endpoint_param(db_path: Path) -> tuple[str, str]:
    ep_id = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO endpoints (id, host, method, path, project_id) "
            "VALUES (?, 'api.test', 'GET', '/x', 'proj')",
            (ep_id,),
        )
        conn.execute(
            "INSERT INTO parameters (id, endpoint_id, name, location, host) "
            "VALUES (?, ?, 'q', 'query', 'api.test')",
            (str(uuid.uuid4()), ep_id),
        )
        conn.commit()
    return ep_id, "q"


# ---------------------------------------------------------------------------
# Taxonomy pure logic
# ---------------------------------------------------------------------------

class TestTaxonomyClasses:
    def test_standard_uses_core_and_injection_not_structure(self) -> None:
        classes = classes_for_tier("standard")
        for c in CORE_CLASSES:
            assert c in classes
        for c in INJECTION_CLASSES:
            assert c in classes
        for c in STRUCTURE_CLASSES:
            assert c not in classes

    def test_deep_includes_structure(self) -> None:
        classes = classes_for_tier("deep")
        for c in STRUCTURE_CLASSES:
            assert c in classes

    def test_standard_probe_count_well_below_legacy_30(self) -> None:
        probes = char_probes_for_strategy("standard")
        assert 1 <= len(probes) < 30
        # Representatives only — one per selected class (no full drill-down).
        assert len(probes) == estimated_char_probe_count("standard")
        assert len(probes) <= 15  # core+injection reps

    def test_exhaustive_extends_legacy_list(self) -> None:
        probes = char_probes_for_strategy("exhaustive")
        chars = [p[1] for p in probes]
        for c in IV_TEST_CHARS:
            assert c in chars
        assert len(chars) >= len(IV_TEST_CHARS)
        assert "\x00" in chars  # structure

    def test_skip_known_accepted_classes(self) -> None:
        known = {"alpha": "accepted", "digit": "accepted", "quote": "rejected"}
        full = char_probes_for_strategy("standard")
        reduced = char_probes_for_strategy(
            "standard", known_class_outcomes=known,
        )
        assert len(reduced) < len(full)
        # Rejected/accepted classes should not contribute their representatives
        # when settled under standard.
        reduced_chars = {p[1] for p in reduced}
        assert CLASS_SPECS["alpha"].representatives[0] not in reduced_chars
        assert CLASS_SPECS["quote"].representatives[0] not in reduced_chars

    def test_char_to_classes_known_labels(self) -> None:
        assert "quote" in char_to_classes("'")
        assert "alpha" in char_to_classes("a")
        assert "digit" in char_to_classes("7")
        assert "null" in char_to_classes("\x00")
        assert "markup" in char_to_classes("<")
        assert char_to_classes("ab") == []

    def test_multiprobe_samples_align_with_taxonomy(self) -> None:
        samples = multiprobe_default_samples()
        assert samples
        for cls, sample in samples:
            assert cls in CLASS_SPECS
            assert sample in CLASS_SPECS[cls].representatives or sample in (
                CLASS_SPECS[cls].drilldown
            )


# ---------------------------------------------------------------------------
# Length search pure logic
# ---------------------------------------------------------------------------

class TestLengthSearch:
    def test_standard_seed_fewer_than_10(self) -> None:
        seeds = seed_lengths("standard")
        assert len(seeds) < 10
        assert len(seeds) == len(SEED_LENGTHS["standard"])
        assert seeds[0] == 1
        assert seeds[-1] == 1024

    def test_first_wave_is_seeds(self) -> None:
        targets = next_length_targets("standard", {})
        assert targets == list(seed_lengths("standard"))
        assert len(targets) < 10

    def test_binary_refine_midpoint(self) -> None:
        observed = {
            1: OUTCOME_ACCEPTED,
            32: OUTCOME_ACCEPTED,
            128: OUTCOME_ACCEPTED,
            512: OUTCOME_REJECTED,
            1024: OUTCOME_REJECTED,
        }
        targets = next_length_targets("standard", observed)
        assert targets
        assert all(128 < t < 512 for t in targets)
        # Midpoint of 128 and 512 is 320
        assert 320 in targets

    def test_complete_when_bound_tight(self) -> None:
        observed = {
            64: OUTCOME_ACCEPTED,
            65: OUTCOME_REJECTED,
        }
        assert length_search_complete("standard", observed) is True

    def test_complete_at_probe_cap(self) -> None:
        observed = {i: OUTCOME_ACCEPTED for i in range(1, MAX_LENGTH_PROBES["standard"] + 1)}
        assert length_search_complete("standard", observed) is True

    def test_bounded_state_from_accept_reject(self) -> None:
        state = synthesize_length_state({
            1: OUTCOME_ACCEPTED,
            32: OUTCOME_ACCEPTED,
            128: OUTCOME_ACCEPTED,
            512: OUTCOME_REJECTED,
            1024: OUTCOME_REJECTED,
        })
        assert state["state"] == "bounded"
        assert state["max_accepted"] == 128
        assert state["min_rejected"] == 512
        assert state["truncation_at"] is None
        assert state["method"] == "binary"
        assert state["confidence"] >= 60

    def test_truncation_distinguishable_from_reject(self) -> None:
        # Hard reject path
        rejected = synthesize_length_state({
            1: OUTCOME_ACCEPTED,
            64: OUTCOME_ACCEPTED,
            256: OUTCOME_REJECTED,
        })
        assert rejected["state"] == "bounded"
        assert rejected["min_rejected"] == 256
        assert rejected["truncation_at"] is None

        # Truncation path (reflection / truncated outcome)
        truncated = synthesize_length_state({
            1: OUTCOME_ACCEPTED,
            64: OUTCOME_ACCEPTED,
            256: OUTCOME_TRUNCATED,
            512: OUTCOME_TRUNCATED,
        })
        assert truncated["state"] == "truncated"
        assert truncated["truncation_at"] == 256
        assert truncated["min_rejected"] is None

    def test_truncation_via_reflected_prefix(self) -> None:
        state = synthesize_length_state(
            {128: OUTCOME_ACCEPTED, 512: OUTCOME_ACCEPTED},
            reflected_prefix_lengths={512: 100},
        )
        assert state["state"] == "truncated"
        assert state["truncation_at"] == 100

    def test_exhaustive_uses_full_matrix(self) -> None:
        targets = next_length_targets("exhaustive", {})
        assert targets == list(EXHAUSTIVE_LENGTHS)
        assert len(targets) == len(IV_TEST_LENGTHS)

    def test_parse_length_outcomes(self) -> None:
        rows = [
            {"payload": "a" * 32, "outcome": OUTCOME_ACCEPTED},
            {"length_value": 64, "outcome": OUTCOME_REJECTED},
        ]
        obs = parse_length_outcomes(rows)
        assert obs[32] == OUTCOME_ACCEPTED
        assert obs[64] == OUTCOME_REJECTED


# ---------------------------------------------------------------------------
# Planner integration
# ---------------------------------------------------------------------------

class TestPlannerM6:
    def test_m6_tokens_not_in_future_stubs(self) -> None:
        from talos.input_validation.planner import FUTURE_ACTION_TOKENS
        assert ACTION_CHAR_DRILLDOWN in M6_ACTION_TOKENS
        assert ACTION_LENGTH_BINARY in M6_ACTION_TOKENS
        assert ACTION_CHAR_DRILLDOWN not in FUTURE_ACTION_TOKENS
        assert ACTION_LENGTH_BINARY not in FUTURE_ACTION_TOKENS

    def test_deep_emits_char_drilldown_and_length_binary(self) -> None:
        ctx = PlanContext(
            budget_tier="deep",
            max_requests=40,
            requests_used=2,
            completed_analyses=frozenset({"baseline", "multiprobe"}),
            multiprobe_completed_count=1,
            reflection_state="reflected",
            reflection_confidence=90,
            reflection_uncertainty="low",
            acceptance_class_count=5,
            analyses_enabled={
                "baseline": True,
                "multiprobe": True,
                "identifier": True,
                "characters": True,
                "length": True,
                "types": False,
                "validation": False,
                "transformations": True,
                "reflection": True,
            },
        )
        result = plan_next(ctx)
        actions = {a.action for a in result.actions}
        assert ACTION_CHAR_DRILLDOWN in actions or "identifier" in actions
        # After multiprobe+baseline, deep should want chars and/or length
        char_or_len = ACTION_CHAR_DRILLDOWN in actions or ACTION_LENGTH_BINARY in actions
        assert char_or_len

    def test_length_binary_estimate_under_10_for_standard(self) -> None:
        ctx = PlanContext(
            budget_tier="standard",
            max_requests=18,
            requests_used=3,
            completed_analyses=frozenset({"baseline", "multiprobe"}),
            multiprobe_completed_count=2,
            reflection_state="reflected",
            reflection_confidence=70,
            reflection_uncertainty="high",
            acceptance_class_count=1,
            length_uncertainty="high",
            length_confidence=0,
            analyses_enabled={
                "baseline": True,
                "multiprobe": True,
                "identifier": True,
                "characters": True,
                "length": True,
                "types": False,
                "validation": False,
                "transformations": True,
                "reflection": True,
            },
        )
        result = plan_next(ctx)
        length_actions = [a for a in result.actions if a.action == ACTION_LENGTH_BINARY]
        if length_actions:
            assert length_actions[0].estimated_requests < 10
            assert length_actions[0].meta.get("method") == "binary"


# ---------------------------------------------------------------------------
# Engine executors
# ---------------------------------------------------------------------------

class TestEngineM6Executors:
    def test_standard_phase_chars_are_representatives(self) -> None:
        cfg = IVConfig(
            probe_strategy="standard",
            analyses=IVAnalysesConfig(multiprobe=False),
        )
        probes = _probes_for_phase(IV_CHARACTERS, cfg)
        assert 0 < len(probes) < 30
        assert all(p[0] == "character" for p in probes)

    def test_standard_phase_length_is_seed_not_full_matrix(self) -> None:
        cfg = IVConfig(probe_strategy="standard")
        probes = _probes_for_phase(IV_LENGTH, cfg)
        assert len(probes) < 10
        assert len(probes) == len(seed_lengths("standard"))
        lengths = [len(p[1]) for p in probes]
        assert lengths == list(seed_lengths("standard"))

    def test_exhaustive_phase_chars_include_legacy(self) -> None:
        cfg = IVConfig(probe_strategy="exhaustive")
        probes = _probes_for_phase(IV_CHARACTERS, cfg)
        chars = [p[1] for p in probes]
        for c in IV_TEST_CHARS:
            assert c in chars

    def test_char_drilldown_action_expansion(self, db_path: Path) -> None:
        action = PlanAction(
            action=ACTION_CHAR_DRILLDOWN,
            hypothesis="charset.char_drilldown",
            estimated_requests=20,
            meta={"tier": "deep", "drilldown": True},
        )
        cfg = IVConfig(probe_strategy="deep")
        probes = _char_probes_for_action(db_path, "uuid", cfg, action)
        assert probes
        assert len(probes) <= 20  # respects estimated_requests cap
        assert all(p[0] == "character" for p in probes)

    def test_length_binary_action_seed_expansion(self, db_path: Path) -> None:
        action = PlanAction(
            action=ACTION_LENGTH_BINARY,
            hypothesis="length.binary_seed",
            estimated_requests=5,
            meta={"tier": "standard", "method": "binary"},
        )
        cfg = IVConfig(probe_strategy="standard")
        probes = _length_probes_for_action(db_path, "uuid", cfg, action)
        assert len(probes) <= 5
        assert len(probes) < 10
        assert all(p[0] == "length" for p in probes)

    def test_standard_multiprobe_still_skips_char_phase(self) -> None:
        cfg = IVConfig(
            probe_strategy="standard",
            analyses=IVAnalysesConfig(multiprobe=True),
        )
        assert _probes_for_phase(IV_CHARACTERS, cfg) == []
