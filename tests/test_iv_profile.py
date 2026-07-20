"""
Unit tests for Input Validation Module 2 — Profile Data Model.

Covers:
    - Parameter / endpoint / app profile skeletons and required keys
    - serialize / deserialize round-trip
    - schema_version + observed/inferred always present
    - mutation history bounds, tested map, capabilities
    - DB CRUD round-trip on fresh and migrated project DBs
    - No dependency on probe scheduling
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from talos.input_validation.db import (
    clear_all_iv_profiles,
    delete_param_profile,
    get_app_profile,
    get_endpoint_profile,
    get_param_profile,
    get_param_profile_by_identity,
    list_param_profiles,
    make_param_uuid,
    upsert_app_profile,
    upsert_endpoint_profile,
    upsert_param_profile,
)
from talos.input_validation.outcomes import (
    IV_ENGINE_VERSION,
    IV_PROFILE_SCHEMA_VERSION,
    OUTCOME_REJECTED,
)
from talos.input_validation.profile import (
    BUDGET_STANDARD,
    CAPABILITY_REFLECTIVE_INPUT,
    LEVEL_APPLICATION,
    LEVEL_ENDPOINT,
    LEVEL_PARAMETER,
    MAX_ATTEMPTS,
    add_capability,
    append_attempt,
    bump_profile_version,
    deserialize_profile,
    empty_app_profile,
    empty_characteristic,
    empty_endpoint_profile,
    empty_param_profile,
    ensure_profile_shape,
    profile_has_required_envelope,
    serialize_profile,
    set_tested,
)
from talos.projects.db import SCHEMA_VERSION, get_schema_version, init_project_db, migrate_project_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


# ---------------------------------------------------------------------------
# Skeleton / shape
# ---------------------------------------------------------------------------

class TestEmptyParamProfile:
    def test_required_envelope_and_layers(self) -> None:
        p = empty_param_profile(
            param_uuid="abc",
            host="https://api.example.com",
            location="query",
            name="redirect",
        )
        assert p["schema_version"] == IV_PROFILE_SCHEMA_VERSION
        assert p["engine_version"] == IV_ENGINE_VERSION
        assert p["profile_version"] == 1
        assert p["level"] == LEVEL_PARAMETER
        assert isinstance(p["observed"], dict)
        assert isinstance(p["inferred"], dict)
        assert p["tested"] == {}
        assert p["attempts"] == []
        assert p["capabilities"] == []
        assert p["candidates"] == []
        assert p["parser"] == {}
        assert p["normalization_pipeline"] == []
        assert p["budget_tier"] == BUDGET_STANDARD
        assert p["requests_used"] == 0
        assert profile_has_required_envelope(p)

    def test_observed_nested_placeholders(self) -> None:
        p = empty_param_profile()
        obs = p["observed"]
        assert "baseline_fingerprint" in obs
        assert obs["reflection"]["state"] == "unknown"
        assert "contexts" in obs["reflection"]
        assert "classes" in obs["acceptance"]
        assert "chars" in obs["acceptance"]
        assert obs["length"]["state"] == "unknown"
        assert obs["timing"]["samples_ms"] == []

    def test_endpoint_and_app_skeletons(self) -> None:
        ep = empty_endpoint_profile(endpoint_id="e1", host="h")
        assert ep["level"] == LEVEL_ENDPOINT
        assert ep["schema_version"] == 1
        assert isinstance(ep["observed"], dict)
        assert isinstance(ep["inferred"], dict)
        assert "param_defaults" in ep

        app = empty_app_profile(host="https://api.example.com")
        assert app["level"] == LEVEL_APPLICATION
        assert "endpoint_defaults" in app
        assert profile_has_required_envelope(app)


class TestEnsureProfileShape:
    def test_fills_missing_keys(self) -> None:
        partial = {"param_uuid": "x", "host": "h", "observed": {"types": {"int": True}}}
        shaped = ensure_profile_shape(partial, level=LEVEL_PARAMETER)
        assert shaped["schema_version"] == IV_PROFILE_SCHEMA_VERSION
        assert shaped["inferred"] == {}
        assert "reflection" in shaped["observed"]
        assert shaped["observed"]["types"] == {"int": True}
        assert shaped["capabilities"] == []

    def test_none_returns_full_skeleton(self) -> None:
        shaped = ensure_profile_shape(None)
        assert shaped["schema_version"] == 1
        assert shaped["level"] == LEVEL_PARAMETER

    def test_invalid_budget_reset(self) -> None:
        shaped = ensure_profile_shape({"budget_tier": "nope"})
        assert shaped["budget_tier"] == BUDGET_STANDARD


class TestSerializeDeserialize:
    def test_round_trip_param(self) -> None:
        original = empty_param_profile(
            param_uuid="u1",
            host="https://ex.com",
            location="body",
            name="id",
        )
        original["inferred"] = {"middleware": "express"}
        add_capability(original, CAPABILITY_REFLECTIVE_INPUT)
        set_tested(original, "unicode", outcome=OUTCOME_REJECTED, confidence=88)
        append_attempt(
            original,
            payload="'",
            hypothesis="charset.quote_accepted",
            result=OUTCOME_REJECTED,
            confidence=90,
            flow_id="flow-1",
        )
        raw = serialize_profile(original)
        loaded = deserialize_profile(raw)
        assert loaded["schema_version"] == original["schema_version"]
        assert loaded["param_uuid"] == "u1"
        assert loaded["inferred"]["middleware"] == "express"
        assert CAPABILITY_REFLECTIVE_INPUT in loaded["capabilities"]
        assert loaded["tested"]["unicode"]["outcome"] == OUTCOME_REJECTED
        assert len(loaded["attempts"]) == 1
        assert loaded["attempts"][0]["flow_id"] == "flow-1"
        assert profile_has_required_envelope(loaded)

    def test_deserialize_invalid_json_returns_skeleton(self) -> None:
        loaded = deserialize_profile("not-json{{{")
        assert loaded["schema_version"] == 1
        assert loaded["observed"] is not None

    def test_deserialize_dict_passthrough(self) -> None:
        loaded = deserialize_profile({"host": "h", "schema_version": 1})
        assert loaded["host"] == "h"
        assert isinstance(loaded["inferred"], dict)


class TestAttemptsAndCapabilities:
    def test_append_attempt_bounded(self) -> None:
        p = empty_param_profile()
        for i in range(MAX_ATTEMPTS + 10):
            append_attempt(
                p,
                payload=str(i),
                hypothesis="h",
                result="accepted",
                confidence=50,
                max_attempts=MAX_ATTEMPTS,
            )
        assert len(p["attempts"]) == MAX_ATTEMPTS
        assert p["attempts"][0]["payload"] == "10"
        assert p["attempts"][-1]["payload"] == str(MAX_ATTEMPTS + 9)

    def test_add_capability_dedupes(self) -> None:
        p = empty_param_profile()
        add_capability(p, CAPABILITY_REFLECTIVE_INPUT)
        add_capability(p, CAPABILITY_REFLECTIVE_INPUT)
        assert p["capabilities"] == [CAPABILITY_REFLECTIVE_INPUT]

    def test_bump_profile_version(self) -> None:
        p = empty_param_profile()
        assert p["profile_version"] == 1
        bump_profile_version(p)
        assert p["profile_version"] == 2

    def test_empty_characteristic_clamps(self) -> None:
        c = empty_characteristic(confidence=150, uncertainty="weird")
        assert c["confidence"] == 100
        assert c["uncertainty"] == "high"


# ---------------------------------------------------------------------------
# DB CRUD
# ---------------------------------------------------------------------------

class TestParamProfileCRUD:
    def test_round_trip(self, db_path: Path) -> None:
        host = "https://api.example.com"
        location = "query"
        name = "redirect"
        p_uuid = make_param_uuid(host, location, name)

        profile = empty_param_profile(
            param_uuid=p_uuid,
            host=host,
            location=location,
            name=name,
        )
        profile["observed"]["baseline_fingerprint"] = {"status_code": 200}
        add_capability(profile, CAPABILITY_REFLECTIVE_INPUT)
        set_tested(profile, "null_byte", outcome=OUTCOME_REJECTED, confidence=95)

        stored = upsert_param_profile(
            db_path,
            host=host,
            location=location,
            param_name=name,
            profile=profile,
        )
        assert stored["schema_version"] == 1
        assert stored["param_uuid"] == p_uuid
        assert "updated_at" in stored

        loaded = get_param_profile(db_path, p_uuid)
        assert loaded is not None
        assert loaded["schema_version"] == 1
        assert loaded["name"] == name
        assert loaded["observed"]["baseline_fingerprint"]["status_code"] == 200
        assert CAPABILITY_REFLECTIVE_INPUT in loaded["capabilities"]
        assert loaded["tested"]["null_byte"]["confidence"] == 95
        assert isinstance(loaded["inferred"], dict)

        by_id = get_param_profile_by_identity(db_path, host, location, name)
        assert by_id is not None
        assert by_id["param_uuid"] == p_uuid

    def test_upsert_bumps_version(self, db_path: Path) -> None:
        host, location, name = "h", "query", "q"
        upsert_param_profile(
            db_path, host=host, location=location, param_name=name, profile={}
        )
        second = upsert_param_profile(
            db_path,
            host=host,
            location=location,
            param_name=name,
            profile={"inferred": {"x": 1}},
            bump_version=True,
        )
        assert second["profile_version"] == 2
        assert second["inferred"]["x"] == 1

    def test_list_and_delete(self, db_path: Path) -> None:
        upsert_param_profile(
            db_path, host="h1", location="query", param_name="a", profile={}
        )
        upsert_param_profile(
            db_path, host="h1", location="query", param_name="b", profile={}
        )
        upsert_param_profile(
            db_path, host="h2", location="body", param_name="c", profile={}
        )
        all_p = list_param_profiles(db_path)
        assert len(all_p) == 3
        h1 = list_param_profiles(db_path, host="h1")
        assert len(h1) == 2
        p_uuid = make_param_uuid("h1", "query", "a")
        assert delete_param_profile(db_path, p_uuid) is True
        assert get_param_profile(db_path, p_uuid) is None
        assert delete_param_profile(db_path, p_uuid) is False

    def test_missing_returns_none(self, db_path: Path) -> None:
        assert get_param_profile(db_path, "nonexistent") is None


class TestEndpointAndAppProfiles:
    def test_endpoint_round_trip(self, db_path: Path) -> None:
        ep = upsert_endpoint_profile(
            db_path,
            endpoint_id="ep-1",
            host="https://api.example.com",
            method="GET",
            path="/v1/items",
            profile={"inferred": {"middleware": "nginx"}},
        )
        assert ep["schema_version"] == 1
        assert ep["level"] == LEVEL_ENDPOINT
        loaded = get_endpoint_profile(db_path, "ep-1")
        assert loaded is not None
        assert loaded["inferred"]["middleware"] == "nginx"
        assert loaded["endpoint_id"] == "ep-1"
        assert isinstance(loaded["observed"], dict)

    def test_app_round_trip(self, db_path: Path) -> None:
        app = upsert_app_profile(
            db_path,
            host="https://api.example.com",
            profile={"capabilities": [CAPABILITY_REFLECTIVE_INPUT]},
        )
        assert app["host"] == "https://api.example.com"
        loaded = get_app_profile(db_path, "https://api.example.com")
        assert loaded is not None
        assert CAPABILITY_REFLECTIVE_INPUT in loaded["capabilities"]
        assert loaded["level"] == LEVEL_APPLICATION

    def test_clear_all_profiles(self, db_path: Path) -> None:
        upsert_param_profile(
            db_path, host="h", location="q", param_name="n", profile={}
        )
        upsert_endpoint_profile(db_path, endpoint_id="e", host="h")
        upsert_app_profile(db_path, host="h")
        p, e, a = clear_all_iv_profiles(db_path)
        assert p == 1 and e == 1 and a == 1
        assert get_param_profile(db_path, make_param_uuid("h", "q", "n")) is None


class TestSchemaMigration:
    def test_new_db_is_current_schema(self, db_path: Path) -> None:
        assert get_schema_version(db_path) == SCHEMA_VERSION
        assert SCHEMA_VERSION >= 36
        with sqlite3.connect(str(db_path)) as conn:
            tables = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        assert "iv_param_profiles" in tables
        assert "iv_endpoint_profiles" in tables
        assert "iv_app_profiles" in tables

    def test_migrate_from_v34_adds_tables(self, tmp_path: Path) -> None:
        """Simulate a v34 DB and upgrade via migrate_project_db."""
        path = tmp_path / "old.db"
        init_project_db(path)
        # Downgrade version and drop new tables to simulate pre-v35.
        with sqlite3.connect(str(path)) as conn:
            conn.execute("DROP TABLE IF EXISTS iv_param_profiles")
            conn.execute("DROP TABLE IF EXISTS iv_endpoint_profiles")
            conn.execute("DROP TABLE IF EXISTS iv_app_profiles")
            conn.execute("UPDATE schema_version SET version = 34")
            conn.commit()
        assert get_schema_version(path) == 34

        migrate_project_db(path)
        assert get_schema_version(path) == SCHEMA_VERSION

        # CRUD works after migration
        upsert_param_profile(
            path, host="h", location="query", param_name="p", profile={}
        )
        loaded = get_param_profile(path, make_param_uuid("h", "query", "p"))
        assert loaded is not None
        assert loaded["schema_version"] == 1

    def test_init_project_db_idempotent_with_profiles(self, db_path: Path) -> None:
        upsert_param_profile(
            db_path, host="h", location="query", param_name="p", profile={}
        )
        init_project_db(db_path)  # re-run
        loaded = get_param_profile(db_path, make_param_uuid("h", "query", "p"))
        assert loaded is not None


class TestJsonShapeStability:
    def test_serialized_json_always_has_schema_version(self) -> None:
        raw = serialize_profile({"name": "only"})
        data = json.loads(raw)
        assert "schema_version" in data
        assert "observed" in data
        assert "inferred" in data
