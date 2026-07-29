"""
Tests for cross-flow / stored reflection pure helpers (PR1 schema + PR2 pure).

Covers:
  - Schema v42: fresh init tables/columns; migrate 41 → 42
  - Index eligibility (entropy fixtures including test32343)
  - Secret param-name denylist
  - find_value_in_body encodings/transforms
  - format_cross_flow_reason
  - merge_cross_flow_reflection top-level merge rules
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from talos.projects.db import (
    SCHEMA_VERSION,
    get_schema_version,
    init_project_db,
    migrate_project_db,
)
from talos.projects.value_reflection import (
    MAX_INDEX_VALUE_LEN,
    BodyMatch,
    find_value_in_body,
    format_cross_flow_reason,
    infer_sink_context,
    is_indexable_value,
    is_secret_param_name,
    is_soft_skip_value_shape,
    iso_ts_le,
    iso_ts_max,
    match_confidence,
    merge_cross_flow_reflection,
    parse_iso_timestamp,
    shannon_entropy,
    value_hash,
)


# ------------------------------------------------------------------ #
# Schema v42                                                           #
# ------------------------------------------------------------------ #


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


def test_schema_version_is_current():
    assert SCHEMA_VERSION >= 42


def test_fresh_db_has_cross_flow_tables(db_path: Path):
    assert get_schema_version(db_path) == SCHEMA_VERSION
    with sqlite3.connect(str(db_path)) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        param_cols = {
            row[1] for row in conn.execute("PRAGMA table_info(parameters)").fetchall()
        }
        vi_cols = {
            row[1] for row in conn.execute("PRAGMA table_info(value_index)").fetchall()
        }
        cfr_cols = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(cross_flow_reflections)"
            ).fetchall()
        }

    assert "value_index" in tables
    assert "cross_flow_reflections" in tables
    for col in (
        "cross_flow_reflected",
        "cross_flow_reflection_count",
        "cross_flow_sink_endpoints",
    ):
        assert col in param_cols

    for col in (
        "value_hash",
        "value_match",
        "source_param_uuid",
        "first_source_flow_id",
        "is_canary",
        "expires_at",
    ):
        assert col in vi_cols

    for col in (
        "source_param_uuid",
        "sink_flow_id",
        "value_hash",
        "source_role_id",
        "sink_role_id",
        "detection_mode",
        "encoding",
    ):
        assert col in cfr_cols


def test_fresh_db_value_index_unique_index(db_path: Path):
    with sqlite3.connect(str(db_path)) as conn:
        indexes = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            ).fetchall()
        }
    assert "idx_value_index_host_hash_param" in indexes
    assert "idx_cross_flow_reflections_param" in indexes


def test_migrate_from_41_adds_cross_flow(tmp_path: Path):
    """
    Simulate a v41 DB with a parameters table, then migrate to v42.
    """
    path = tmp_path / "old41.db"
    with sqlite3.connect(str(path)) as conn:
        conn.executescript(
            """
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version (version) VALUES (41);

            CREATE TABLE endpoints (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                method TEXT NOT NULL,
                host TEXT NOT NULL,
                path TEXT NOT NULL,
                normalized_path TEXT NOT NULL
            );

            CREATE TABLE parameters (
                id TEXT PRIMARY KEY,
                endpoint_id TEXT NOT NULL,
                name TEXT NOT NULL,
                location TEXT NOT NULL,
                is_reflected INTEGER NOT NULL DEFAULT 0,
                reflection_count INTEGER NOT NULL DEFAULT 0,
                reflection_locations TEXT NOT NULL DEFAULT '[]',
                reflection_encoding TEXT NOT NULL DEFAULT '[]'
            );
            """
        )
        conn.commit()

    assert get_schema_version(path) == 41
    migrate_project_db(path)
    assert get_schema_version(path) == SCHEMA_VERSION

    with sqlite3.connect(str(path)) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        param_cols = {
            row[1] for row in conn.execute("PRAGMA table_info(parameters)").fetchall()
        }

    assert "value_index" in tables
    assert "cross_flow_reflections" in tables
    assert "cross_flow_reflected" in param_cols
    assert "cross_flow_reflection_count" in param_cols
    assert "cross_flow_sink_endpoints" in param_cols


def test_init_project_db_migrates_from_41(tmp_path: Path):
    path = tmp_path / "init_migrate41.db"
    with sqlite3.connect(str(path)) as conn:
        conn.executescript(
            """
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version (version) VALUES (41);
            CREATE TABLE parameters (
                id TEXT PRIMARY KEY,
                endpoint_id TEXT NOT NULL,
                name TEXT NOT NULL,
                location TEXT NOT NULL
            );
            """
        )
        conn.commit()

    init_project_db(path)
    assert get_schema_version(path) == SCHEMA_VERSION
    with sqlite3.connect(str(path)) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    assert "value_index" in tables
    assert "cross_flow_reflections" in tables


# ------------------------------------------------------------------ #
# Shannon entropy                                                      #
# ------------------------------------------------------------------ #


def test_shannon_entropy_known_values():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaa") == 0.0
    assert shannon_entropy("111111") == 0.0
    # Motivating example: test32343 ≈ 2.42 bits/char
    h = shannon_entropy("test32343")
    assert 2.3 <= h <= 2.5
    # hello1 ≈ 2.25
    assert shannon_entropy("hello1") >= 2.0
    # Canary is high entropy
    assert shannon_entropy("TLa1b2c3d4e5f67890") > 3.5


def test_value_hash_stable():
    h1 = value_hash("test32343")
    h2 = value_hash("test32343")
    assert h1 == h2
    assert len(h1) == 32
    assert h1 != value_hash("test32344")


# ------------------------------------------------------------------ #
# Secret denylist                                                      #
# ------------------------------------------------------------------ #


@pytest.mark.parametrize(
    "name,location",
    [
        ("password", "body"),
        ("passwd", "body"),
        ("user_password", "body"),  # substring
        ("access_token", "body"),
        ("api_key", "query"),
        ("Authorization", "header"),
        ("authorization", "header"),
        ("Cookie", "header"),
        ("x-api-key", "header"),
        ("X-CSRF-Token", "header"),
        ("sessionid", "cookie"),
        ("csrf_token", "body"),
        ("client_secret", "body"),
        ("credit_card", "body"),
        ("ssn", "body"),
    ],
)
def test_secret_param_names_denied(name: str, location: str):
    assert is_secret_param_name(name, location) is True
    elig = is_indexable_value("SuperSecret99!", name, location)
    assert elig.indexable is False
    assert elig.rule == "secret_name"


@pytest.mark.parametrize(
    "name,location",
    [
        ("username", "body"),
        ("email", "query"),
        ("comment", "body"),
        ("q", "query"),
        ("id", "path"),
        ("Accept", "header"),
        ("content-type", "header"),
    ],
)
def test_non_secret_param_names_allowed(name: str, location: str):
    assert is_secret_param_name(name, location) is False


# ------------------------------------------------------------------ #
# Index eligibility fixtures (Appendix C + §1.1)                       #
# ------------------------------------------------------------------ #


def test_accept_test32343_rule_b():
    """Motivating operator example: must index under Rule B."""
    elig = is_indexable_value("test32343", "username", "body")
    assert elig.indexable is True
    assert elig.rule == "B_length_strong"
    assert elig.is_canary is False
    assert elig.entropy >= 2.0


def test_accept_hello1_rule_c():
    elig = is_indexable_value("hello1", "name", "body")
    assert elig.indexable is True
    assert elig.rule == "C_medium_token"


def test_accept_xss_test_rule_b():
    elig = is_indexable_value("xss_test", "q", "query")
    assert elig.indexable is True
    assert elig.rule == "B_length_strong"


def test_accept_canary_rule_a():
    elig = is_indexable_value("TLa1b2c3d4e5f67890", "username", "body")
    assert elig.indexable is True
    assert elig.rule == "A_canary"
    assert elig.is_canary is True


def test_accept_user_alpha_99():
    elig = is_indexable_value("user_alpha_99", "username", "body")
    assert elig.indexable is True
    assert elig.rule == "B_length_strong"


def test_test99_only_if_rare_on_host():
    """H≈1.92 < 2.0 → fails C; Rule D only when prior sources < 2."""
    rare = is_indexable_value("test99", "username", "body", prior_source_count=0)
    assert rare.indexable is True
    assert rare.rule == "D_rare_on_host"

    common = is_indexable_value("test99", "username", "body", prior_source_count=2)
    assert common.indexable is False


@pytest.mark.parametrize(
    "value,reason",
    [
        ("", "empty"),
        ("   ", "empty"),
        ("aaaaaa", "pure_repeat"),
        ("111111", "pure_repeat"),
        ("true", "booleanish"),
        ("FALSE", "booleanish"),
        ("null", "booleanish"),
        ("1", "short_integer"),
        ("12345", "short_integer"),
        ("-99", "short_integer"),
    ],
)
def test_reject_hard_cases(value: str, reason: str):
    elig = is_indexable_value(value, "username", "body")
    assert elig.indexable is False
    assert elig.rule == reason


def test_reject_too_long():
    # Construct length > 256 without pure-repeat pattern
    blob = "ab12" * 70  # 280 chars
    assert len(blob) > MAX_INDEX_VALUE_LEN
    elig = is_indexable_value(blob, "n", "body")
    assert elig.indexable is False
    assert elig.rule == "too_long"


def test_password_value_rejected_by_name_not_value():
    """High-entropy password value still rejected when name is denylisted."""
    elig = is_indexable_value("password123", "password", "body")
    assert elig.indexable is False
    assert elig.rule == "secret_name"


def test_jwt_semantic_only_if_rare():
    # High-entropy JWT-like value; soft-skip only indexes under Rule D.
    jwt_like = "eyJhbGciOiJIUzI1NiJ9.abc.def"
    rare = is_indexable_value(
        jwt_like,
        "session_blob",
        "body",
        prior_source_count=0,
        semantic_type="jwt",
    )
    assert rare.indexable is True
    assert rare.rule == "D_rare_on_host"

    common = is_indexable_value(
        jwt_like,
        "session_blob",
        "body",
        prior_source_count=2,
        semantic_type="jwt",
    )
    assert common.indexable is False
    assert common.rule == "soft_skip_semantic"


# ------------------------------------------------------------------ #
# Body matching                                                        #
# ------------------------------------------------------------------ #


def test_find_value_raw():
    m = find_value_in_body("test32343", "Hello test32343 world")
    assert m.found is True
    assert m.encoding == "raw"
    assert m.transforms == ()


def test_find_value_html_encoded():
    m = find_value_in_body('a<"b', "prefix a&lt;&quot;b suffix")
    assert m.found is True
    assert m.encoding == "html_encoded"


def test_find_value_url_encoded():
    m = find_value_in_body("a b", "x=a%20b&y=1")
    assert m.found is True
    assert m.encoding == "url_encoded"


def test_find_value_trim_transform():
    m = find_value_in_body("  tokenX  ", "seen tokenX here")
    assert m.found is True
    assert m.encoding == "raw"
    assert "trim" in m.transforms


def test_find_value_case_transform():
    m = find_value_in_body("AbCdEf12", "got abcdef12 back")
    assert m.found is True
    assert "lowercase" in m.transforms


def test_find_value_missing():
    m = find_value_in_body("test32343", "nothing here")
    assert m.found is False
    assert isinstance(m, BodyMatch)


def test_infer_sink_context():
    assert infer_sink_context("text/html; charset=utf-8") == "html"
    assert infer_sink_context("application/json") == "json"
    assert infer_sink_context("application/javascript") == "javascript"
    assert infer_sink_context("image/png") == "other"
    assert infer_sink_context("") == "other"


def test_match_confidence_canary_html():
    assert match_confidence(
        is_canary=True, value_len=18, encoding="raw", transforms=(), sink_context="html"
    ) == 95


def test_match_confidence_operator_token():
    conf = match_confidence(
        is_canary=False,
        value_len=9,
        encoding="raw",
        transforms=(),
        sink_context="html",
    )
    assert conf == 80


def test_match_confidence_soft_skip_haircut():
    base = match_confidence(
        is_canary=False,
        value_len=36,
        encoding="raw",
        transforms=(),
        sink_context="html",
        soft_skip_semantic=False,
    )
    soft = match_confidence(
        is_canary=False,
        value_len=36,
        encoding="raw",
        transforms=(),
        sink_context="html",
        soft_skip_semantic=True,
    )
    assert soft == max(40, base - 10)


def test_match_confidence_multi_sink_haircut():
    one = match_confidence(
        is_canary=False,
        value_len=12,
        encoding="raw",
        transforms=(),
        sink_context="html",
        unrelated_sink_count=1,
    )
    many = match_confidence(
        is_canary=False,
        value_len=12,
        encoding="raw",
        transforms=(),
        sink_context="html",
        unrelated_sink_count=3,
    )
    assert many == max(40, one - 10)


def test_iso_timestamp_z_vs_offset_equal():
    z = "2026-07-26T12:00:00Z"
    offset = "2026-07-26T12:00:00+00:00"
    assert parse_iso_timestamp(z) == parse_iso_timestamp(offset)
    assert iso_ts_le(z, offset) is True
    assert iso_ts_le(offset, z) is True
    # Lexical string compare would wrongly treat Z as later than +00:00.
    assert ("2026-07-26T12:00:00Z" > "2026-07-26T12:00:00+00:00") is True
    assert iso_ts_max(z, offset) in (z, offset)


def test_iso_ts_max_picks_later():
    early = "2026-07-26T08:00:00+00:00"
    late = "2026-07-26T10:00:00Z"
    assert parse_iso_timestamp(iso_ts_max(early, late)) == parse_iso_timestamp(late)
    assert parse_iso_timestamp(iso_ts_max(late, early)) == parse_iso_timestamp(late)


def test_min_value_len_applies_to_rules_b_and_c():
    """Raising min_value_len must reject hello1 / short B tokens; canaries exempt."""
    assert is_indexable_value("hello1", "name", "body", min_value_len=6).indexable is True
    assert is_indexable_value("hello1", "name", "body", min_value_len=10).indexable is False
    assert (
        is_indexable_value("hello1", "name", "body", min_value_len=10).rule == "too_short"
    )
    # Rule B fixture is 9 chars — blocked when floor is 10.
    assert is_indexable_value("test32343", "username", "body", min_value_len=10).indexable is False
    # Canary still indexes under high floor.
    canary = is_indexable_value(
        "TLa1b2c3d4e5f67890", "username", "body", min_value_len=50
    )
    assert canary.indexable is True
    assert canary.rule == "A_canary"


def test_soft_skip_value_shape_jwt_uuid():
    assert is_soft_skip_value_shape("550e8400-e29b-41d4-a716-446655440000") is True
    assert is_soft_skip_value_shape("eyJhbGciOiJIUzI1NiJ9.abc.def") is True
    assert is_soft_skip_value_shape("test32343") is False


# ------------------------------------------------------------------ #
# Reason formatter                                                     #
# ------------------------------------------------------------------ #


def test_format_cross_flow_reason_full():
    s = format_cross_flow_reason({
        "source_param_name": "username",
        "source_method": "POST",
        "source_path": "/register",
        "sink_method": "GET",
        "sink_path": "/profile",
        "sink_context": "html",
        "encoding": "raw",
    })
    assert s == (
        "value from username@POST /register reflected on GET /profile (html, raw)"
    )


def test_format_cross_flow_reason_fallback_location():
    s = format_cross_flow_reason({
        "source_param_name": "q",
        "source_location": "query",
        "sink_method": "GET",
        "sink_path": "/search",
        "sink_context": "json",
        "encoding": "url_encoded",
    })
    assert s == "value from q@query reflected on GET /search (json, url_encoded)"


# ------------------------------------------------------------------ #
# merge_cross_flow_reflection                                          #
# ------------------------------------------------------------------ #


def _probe_profile(
    *,
    state: str = "not_reflected",
    confidence: int = 88,
    uncertainty: str = "none",
    contexts: list | None = None,
    encoding: str = "",
    evidence: list | None = None,
) -> dict:
    return {
        "param_uuid": "abc",
        "observed": {
            "reflection": {
                "state": state,
                "confidence": confidence,
                "uncertainty": uncertainty,
                "evidence_flow_ids": list(evidence or ["probe-flow"]),
                "contexts": list(contexts or []),
                "encoding": encoding,
            }
        },
    }


def _link(
    *,
    sink_path: str = "/profile",
    confidence: int = 80,
    sink_context: str = "html",
    encoding: str = "raw",
) -> dict:
    return {
        "source_param_name": "username",
        "source_method": "POST",
        "source_path": "/register",
        "source_flow_id": "src-flow",
        "first_source_flow_id": "src-flow",
        "sink_flow_id": "sink-flow",
        "sink_method": "GET",
        "sink_path": sink_path,
        "sink_context": sink_context,
        "encoding": encoding,
        "confidence": confidence,
        "detection_mode": "passive",
    }


def test_merge_stored_only_sets_top_level_reflected():
    """same not_reflected + cross reflected → top reflected with cross conf."""
    profile = _probe_profile(state="not_reflected", confidence=88)
    out = merge_cross_flow_reflection(profile, [_link(confidence=80)])
    refl = out["observed"]["reflection"]

    assert refl["same_request"]["state"] == "not_reflected"
    assert refl["same_request"]["confidence"] == 88
    assert refl["cross_flow"]["state"] == "reflected"
    assert refl["cross_flow"]["link_count"] == 1
    assert refl["state"] == "reflected"
    # Must NOT dilute with multiprobe "not reflected" conf
    assert refl["confidence"] == 80
    assert "cross_flow" in refl["modes"]
    assert "same_request" in refl["modes"]
    assert "html" in refl["contexts"]
    assert "src-flow" in refl["evidence_flow_ids"]
    assert "sink-flow" in refl["evidence_flow_ids"]
    sink = refl["cross_flow"]["sinks"][0]
    assert "username@POST /register" in sink["reason"]
    assert "GET /profile" in sink["reason"]


def test_merge_both_reflected_takes_max_conf():
    profile = _probe_profile(
        state="reflected", confidence=90, contexts=["html"], encoding="raw"
    )
    out = merge_cross_flow_reflection(profile, [_link(confidence=75)])
    refl = out["observed"]["reflection"]
    assert refl["state"] == "reflected"
    assert refl["confidence"] == 90
    assert set(refl["modes"]) >= {"same_request", "cross_flow"}


def test_merge_empty_links_preserves_same_request():
    profile = _probe_profile(state="reflected", confidence=70, contexts=["json"])
    out = merge_cross_flow_reflection(profile, [])
    refl = out["observed"]["reflection"]
    assert refl["same_request"]["state"] == "reflected"
    assert refl["cross_flow"]["state"] == "not_reflected"
    assert refl["state"] == "reflected"
    assert refl["confidence"] == 70


def test_merge_no_probes_no_links_unknown():
    profile = {
        "observed": {
            "reflection": {
                "state": "unknown",
                "confidence": 0,
                "uncertainty": "high",
                "evidence_flow_ids": [],
                "contexts": [],
                "encoding": "",
            }
        }
    }
    out = merge_cross_flow_reflection(profile, [])
    refl = out["observed"]["reflection"]
    assert refl["state"] == "unknown"
    assert refl["cross_flow"]["state"] == "not_reflected"


def test_merge_snapshots_same_request_once():
    profile = _probe_profile(state="not_reflected", confidence=50)
    merge_cross_flow_reflection(profile, [_link()])
    # Second merge with empty links must not overwrite same_request with
    # top-level reflected from the previous merge.
    merge_cross_flow_reflection(profile, [])
    refl = profile["observed"]["reflection"]
    assert refl["same_request"]["state"] == "not_reflected"
    assert refl["same_request"]["confidence"] == 50


# ================================================================== #
# PR3 — Config + CRUD + on_flow_committed                             #
# ================================================================== #

import json
import time
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from talos.configuration.defaults import (
    BUILTIN_DEFAULTS,
    CONFIG_SECTIONS,
    KNOWN_LEAF_PATHS,
    SETTING_SCHEMA,
    SECTION_META,
)
from talos.configuration.manager import ConfigurationManager
from talos.projects.db import seed_default_context
from talos.projects.parameters import ExtractedParam
from talos.projects.value_reflection import (
    CrossFlowConfig,
    batch_list_cross_flow_reflections,
    ensure_process_cross_flow_config,
    extract_canary_from_meta,
    get_process_cross_flow_config,
    list_cross_flow_reflections,
    load_cross_flow_config_for_project,
    load_hot_set,
    normalize_flow_fields,
    on_flow_committed,
    reset_process_cross_flow_config,
    set_process_cross_flow_config,
    upsert_value_index,
)


HOST = "https://app.example.com"
CFG_ON = CrossFlowConfig(enabled=True, scan_time_budget_ms=50, scan_hot_set_k=2000)


@pytest.fixture(autouse=True)
def _reset_cross_flow_cfg():
    reset_process_cross_flow_config()
    yield
    reset_process_cross_flow_config()


def _seed_endpoints_and_params(db_path: Path) -> dict:
    """Seed two endpoints + username param on register. Return id map."""
    seed_default_context(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        role = conn.execute("SELECT id FROM roles LIMIT 1").fetchone()["id"]
        module = conn.execute("SELECT id FROM modules LIMIT 1").fetchone()["id"]
        ep_reg = str(uuid.uuid4())
        ep_prof = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        for eid, method, path in (
            (ep_reg, "POST", "/register"),
            (ep_prof, "GET", "/profile"),
        ):
            conn.execute(
                """
                INSERT INTO endpoints (
                    id, project_id, method, host, path, normalized_path,
                    first_seen, last_seen, content_type, auth_required, roles_seen
                ) VALUES (?, 'demo', ?, ?, ?, ?, ?, ?, 'text/html', 0, '[]')
                """,
                (eid, method, HOST, path, path, now, now),
            )
        param_id = str(uuid.uuid4())
        conn.execute(
            """
            INSERT INTO parameters (
                id, endpoint_id, name, location, param_type, semantic_type,
                example_values, appears_in_roles, appears_in_modules,
                is_reflected, reflection_count, reflection_locations,
                reflection_encoding, seen_count
            ) VALUES (?, ?, 'username', 'body', 'string', 'string',
                      '[]', '[]', '[]', 0, 0, '[]', '[]', 1)
            """,
            (param_id, ep_reg),
        )
        conn.commit()
    return {
        "role_id": role,
        "module_id": module,
        "ep_register": ep_reg,
        "ep_profile": ep_prof,
        "param_id": param_id,
    }


def _proxy_flow(
    *,
    flow_id: str,
    method: str,
    path: str,
    body: bytes | None,
    response: bytes,
    endpoint_id: str,
    role_id: str,
    module_id: str,
    t: str | None = None,
    request_body: bytes | None = None,
) -> dict:
    ts = t or datetime.now(timezone.utc).isoformat()
    return {
        "flow_id": flow_id,
        "project_id": "demo",
        "request_start": ts,
        "method": method,
        "url": f"{HOST}{path}",
        "host": HOST,
        "path": path,
        "query": "",
        "request_headers": {"content-type": "application/x-www-form-urlencoded"},
        "request_cookies": {},
        "request_body": request_body,
        "response_headers": {"content-type": "text/html"},
        "response_body": response,
        "content_type": "text/html",
        "endpoint_id": endpoint_id,
        "role_id": role_id,
        "module_id": module_id,
        "status_code": 200,
    }


def _replay_flow(
    *,
    flow_id: str,
    method: str,
    path: str,
    response: bytes,
    endpoint_id: str,
    role_id: str,
    module_id: str,
    t: str | None = None,
    flow_meta: dict | None = None,
    request_body: bytes | None = None,
) -> dict:
    ts = t or datetime.now(timezone.utc).isoformat()
    return {
        "id": flow_id,
        "project_id": "demo",
        "captured_at": ts,
        "method": method,
        "url": f"{HOST}{path}",
        "host": HOST,
        "path": path,
        "query": "",
        "request_headers": {},
        "request_cookies": {},
        "request_body": request_body,
        "response_headers": {"content-type": "text/html"},
        "response_body": response,
        "content_type": "text/html",
        "endpoint_id": endpoint_id,
        "role_id": role_id,
        "module_id": module_id,
        "status_code": 200,
        "source": "auto_replay",
        "original_flow_id": str(uuid.uuid4()),
        "replay_reason": "input_validation",
        "flow_meta": flow_meta or {},
    }


# ------------------------------------------------------------------ #
# Config registration                                                  #
# ------------------------------------------------------------------ #


def test_parameter_intel_in_builtin_defaults():
    assert "parameter_intel" in BUILTIN_DEFAULTS
    cf = BUILTIN_DEFAULTS["parameter_intel"]["cross_flow"]
    assert cf["enabled"] is False
    assert cf["feed_iv"] is True
    assert cf["scan_time_budget_ms"] == 20
    assert "parameter_intel" in CONFIG_SECTIONS
    assert "parameter_intel" in SECTION_META
    leafs = [p for p in KNOWN_LEAF_PATHS if p.startswith("parameter_intel.")]
    assert "parameter_intel.cross_flow.enabled" in leafs
    assert len(leafs) >= 11
    schema_keys = {e["key"] for e in SETTING_SCHEMA if e["section"] == "parameter_intel"}
    assert "parameter_intel.cross_flow.enabled" in schema_keys
    assert "parameter_intel.cross_flow.scan_time_budget_ms" in schema_keys


def test_effective_config_has_parameter_intel(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "projects").mkdir()
    mgr = ConfigurationManager(data_dir)
    eff = mgr.load()
    assert eff.parameter_intel.cross_flow.enabled is False
    assert eff.parameter_intel.cross_flow.scan_hot_set_k == 2000


def test_normalize_proxy_and_replay_shapes():
    proxy = {
        "flow_id": "f1",
        "request_start": "2026-01-01T00:00:00+00:00",
        "role_id": "r1",
        "response_body": b"hi",
        "response_headers": {"Content-Type": "text/html"},
    }
    n = normalize_flow_fields(proxy)
    assert n["flow_id"] == "f1"
    assert n["captured_at"] == "2026-01-01T00:00:00+00:00"
    assert n["content_type"] == "text/html"

    replay = {
        "id": "f2",
        "captured_at": "2026-01-02T00:00:00+00:00",
        "role_id": "r2",
        "response_body": b"x",
        "content_type": "application/json",
    }
    n2 = normalize_flow_fields(replay)
    assert n2["flow_id"] == "f2"
    assert n2["captured_at"] == "2026-01-02T00:00:00+00:00"
    assert n2["content_type"] == "application/json"


def test_extract_canary_from_flow_meta():
    meta = {
        "parameter_name": "username",
        "parameter_uuid": "abc123",
        "mutation": {"location": "body", "host": HOST},
        "multiprobe": {"canary": "TLa1b2c3d4e5f67890", "payload": "TLa1b2c3d4e5f67890||x"},
    }
    info = extract_canary_from_meta(None, meta)
    assert info is not None
    assert info["canary"] == "TLa1b2c3d4e5f67890"
    assert info["param_name"] == "username"
    assert info["location"] == "body"


def test_organic_two_flow_cross_page(db_path: Path):
    """Motivating scenario: test32343 on POST /register → GET /profile."""
    ids = _seed_endpoints_and_params(db_path)
    t0 = "2026-07-26T10:00:00+00:00"
    t1 = "2026-07-26T10:01:00+00:00"
    flow_a = str(uuid.uuid4())
    flow_b = str(uuid.uuid4())

    params = [
        ExtractedParam(
            name="username",
            location="body",
            param_type="string",
            semantic_type="string",
            sample_value="test32343",
            role_id=ids["role_id"],
            module_id=ids["module_id"],
        )
    ]

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        on_flow_committed(
            conn,
            flow=_proxy_flow(
                flow_id=flow_a,
                method="POST",
                path="/register",
                body=None,
                response=b"ok",
                endpoint_id=ids["ep_register"],
                role_id=ids["role_id"],
                module_id=ids["module_id"],
                t=t0,
                request_body=b"username=test32343",
            ),
            endpoint_id=ids["ep_register"],
            params=params,
            cfg=CFG_ON,
        )
        # Index only so far — no sink yet.
        n_idx = conn.execute("SELECT COUNT(*) FROM value_index").fetchone()[0]
        assert n_idx == 1
        n_links = conn.execute("SELECT COUNT(*) FROM cross_flow_reflections").fetchone()[0]
        assert n_links == 0

        on_flow_committed(
            conn,
            flow=_proxy_flow(
                flow_id=flow_b,
                method="GET",
                path="/profile",
                body=None,
                response=b"<html><body>Hello test32343</body></html>",
                endpoint_id=ids["ep_profile"],
                role_id=ids["role_id"],
                module_id=ids["module_id"],
                t=t1,
            ),
            endpoint_id=ids["ep_profile"],
            params=[],
            cfg=CFG_ON,
        )
        conn.commit()

    links = list_cross_flow_reflections(db_path)
    assert len(links) == 1
    link = links[0]
    assert link["source_param_name"] == "username"
    assert link["source_method"] == "POST"
    assert link["source_path"] == "/register"
    assert link["sink_method"] == "GET"
    assert link["sink_path"] == "/profile"
    assert link["sink_context"] == "html"
    assert link["encoding"] == "raw"
    assert "value_match" not in link  # secrets not on link table
    assert link["value_len"] == len("test32343")

    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT cross_flow_reflected, cross_flow_reflection_count FROM parameters WHERE id = ?",
            (ids["param_id"],),
        ).fetchone()
    assert row[0] == 1
    assert row[1] >= 1


def test_same_flow_excluded(db_path: Path):
    ids = _seed_endpoints_and_params(db_path)
    flow_id = str(uuid.uuid4())
    t0 = "2026-07-26T10:00:00+00:00"
    params = [
        ExtractedParam(
            name="username",
            location="body",
            param_type="string",
            semantic_type="string",
            sample_value="test32343",
        )
    ]
    # Value reflects in the same response — must not create cross_flow link.
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        on_flow_committed(
            conn,
            flow=_proxy_flow(
                flow_id=flow_id,
                method="POST",
                path="/register",
                body=None,
                response=b"echo test32343",
                endpoint_id=ids["ep_register"],
                role_id=ids["role_id"],
                module_id=ids["module_id"],
                t=t0,
            ),
            endpoint_id=ids["ep_register"],
            params=params,
            cfg=CFG_ON,
        )
        conn.commit()
    assert list_cross_flow_reflections(db_path) == []


def test_disabled_short_circuit(db_path: Path):
    ids = _seed_endpoints_and_params(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        on_flow_committed(
            conn,
            flow=_proxy_flow(
                flow_id=str(uuid.uuid4()),
                method="POST",
                path="/register",
                body=None,
                response=b"ok",
                endpoint_id=ids["ep_register"],
                role_id=ids["role_id"],
                module_id=ids["module_id"],
            ),
            endpoint_id=ids["ep_register"],
            params=[
                ExtractedParam(
                    name="username",
                    location="body",
                    param_type="string",
                    semantic_type="string",
                    sample_value="test32343",
                )
            ],
            cfg=CrossFlowConfig(enabled=False),
        )
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM value_index").fetchone()[0] == 0


def test_config_not_reloaded_per_flow(db_path: Path):
    """Happy path must not call ConfigurationManager.load per flow."""
    ids = _seed_endpoints_and_params(db_path)
    cfg = CrossFlowConfig(enabled=True)
    set_process_cross_flow_config(cfg)
    params = [
        ExtractedParam(
            name="username",
            location="body",
            param_type="string",
            semantic_type="string",
            sample_value="test32343",
        )
    ]
    with patch(
        "talos.configuration.manager.ConfigurationManager.load",
        side_effect=AssertionError("must not load per flow"),
    ), patch(
        "talos.configuration.manager.load_effective_config",
        side_effect=AssertionError("must not load per flow"),
    ):
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            for i in range(3):
                on_flow_committed(
                    conn,
                    flow=_proxy_flow(
                        flow_id=str(uuid.uuid4()),
                        method="POST",
                        path="/register",
                        body=None,
                        response=b"ok",
                        endpoint_id=ids["ep_register"],
                        role_id=ids["role_id"],
                        module_id=ids["module_id"],
                        t=f"2026-07-26T10:0{i}:00+00:00",
                    ),
                    endpoint_id=ids["ep_register"],
                    params=params,
                    cfg=cfg,
                )
            conn.commit()


def test_scan_budget_abort(db_path: Path):
    """With a 0ms budget, large hot sets must abort (fail open)."""
    ids = _seed_endpoints_and_params(db_path)
    t0 = "2026-07-26T09:00:00+00:00"
    t1 = "2026-07-26T10:00:00+00:00"

    # Seed many index rows manually (synthetic 2k).
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        for i in range(2000):
            val = f"tok{i:05d}xx"  # len 10, distinctive enough under B
            upsert_value_index(
                conn,
                project_id="demo",
                host=HOST,
                value=val,
                source_flow_id=str(uuid.uuid4()),
                captured_at=t0,
                source_param_uuid=f"{'a' * 30}{i:02d}"[:32],
                source_param_name="q",
                source_location="query",
                source_endpoint_id=ids["ep_register"],
                source_method="GET",
                source_path="/search",
                cfg=CFG_ON,
            )
        # Place a matchable value that would hit if we scanned far enough.
        upsert_value_index(
            conn,
            project_id="demo",
            host=HOST,
            value="zzz_budget_marker",
            source_flow_id=str(uuid.uuid4()),
            captured_at=t0,
            source_param_uuid="b" * 32,
            source_param_name="marker",
            source_location="body",
            source_endpoint_id=ids["ep_register"],
            source_method="POST",
            source_path="/register",
            cfg=CFG_ON,
        )
        # Budget 0 → deadline immediately; fail open without raising.
        on_flow_committed(
            conn,
            flow=_proxy_flow(
                flow_id=str(uuid.uuid4()),
                method="GET",
                path="/profile",
                body=None,
                response=b"contains zzz_budget_marker somewhere",
                endpoint_id=ids["ep_profile"],
                role_id=ids["role_id"],
                module_id=ids["module_id"],
                t=t1,
            ),
            endpoint_id=ids["ep_profile"],
            params=[],
            cfg=CrossFlowConfig(enabled=True, scan_time_budget_ms=0, scan_hot_set_k=2000),
        )
        conn.commit()
    # Fail open: may or may not have links depending on loop interleaving;
    # critical is no exception and function returned.
    assert isinstance(list_cross_flow_reflections(db_path), list)


def test_hot_set_10k_smoke(db_path: Path):
    """Smoke: load_hot_set with large index stays bounded by K."""
    ids = _seed_endpoints_and_params(db_path)
    t0 = "2026-07-26T09:00:00+00:00"
    with sqlite3.connect(str(db_path)) as conn:
        for i in range(10_000):
            upsert_value_index(
                conn,
                project_id="demo",
                host=HOST,
                value=f"v{i:06d}ab",
                source_flow_id=str(uuid.uuid4()),
                captured_at=t0,
                source_param_uuid=f"{i:032d}",
                source_param_name="q",
                source_location="query",
                source_endpoint_id=ids["ep_register"],
                cfg=CFG_ON,
            )
        conn.commit()
        rows = load_hot_set(conn, HOST, k=2000)
    assert len(rows) == 2000


# ------------------------------------------------------------------ #
# PR3b — Replay / multiprobe canary                                   #
# ------------------------------------------------------------------ #


def test_replay_canary_index_and_sink(db_path: Path):
    ids = _seed_endpoints_and_params(db_path)
    canary = "TLa1b2c3d4e5f67890"
    t0 = "2026-07-26T11:00:00+00:00"
    t1 = "2026-07-26T11:05:00+00:00"
    from talos.input_validation.db import make_param_uuid

    p_uuid = make_param_uuid(HOST, "body", "username")
    flow_meta = {
        "generated_by": "input_validation",
        "analysis": "multiprobe",
        "parameter_name": "username",
        "parameter_uuid": p_uuid,
        "mutation": {"location": "body", "host": HOST, "endpoint_id": ids["ep_register"]},
        "multiprobe": {"canary": canary, "payload": canary, "prefix": "TL"},
    }

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        on_flow_committed(
            conn,
            flow=_replay_flow(
                flow_id=str(uuid.uuid4()),
                method="POST",
                path="/register",
                response=b"created",
                endpoint_id=ids["ep_register"],
                role_id=ids["role_id"],
                module_id=ids["module_id"],
                t=t0,
                flow_meta=flow_meta,
                request_body=canary.encode(),
            ),
            endpoint_id=ids["ep_register"],
            params=None,  # canary-only path
            multiprobe_meta=flow_meta.get("multiprobe"),
            cfg=CFG_ON,
        )
        n = conn.execute(
            "SELECT COUNT(*) FROM value_index WHERE is_canary = 1"
        ).fetchone()[0]
        assert n == 1

        on_flow_committed(
            conn,
            flow=_replay_flow(
                flow_id=str(uuid.uuid4()),
                method="GET",
                path="/profile",
                response=f"<div>{canary}</div>".encode(),
                endpoint_id=ids["ep_profile"],
                role_id=ids["role_id"],
                module_id=ids["module_id"],
                t=t1,
            ),
            endpoint_id=ids["ep_profile"],
            params=[],
            cfg=CFG_ON,
        )
        conn.commit()

    links = list_cross_flow_reflections(db_path)
    assert len(links) >= 1
    assert links[0]["source_param_name"] == "username"
    assert links[0]["sink_path"] == "/profile"
    # Flag bump when parameters row exists
    with sqlite3.connect(str(db_path)) as conn:
        flags = conn.execute(
            "SELECT cross_flow_reflected FROM parameters WHERE id = ?",
            (ids["param_id"],),
        ).fetchone()
    assert flags[0] == 1


def test_insert_replayed_flow_hooks(db_path: Path):
    """PR3b: insert_replayed_flow invokes on_flow_committed when enabled."""
    ids = _seed_endpoints_and_params(db_path)
    set_process_cross_flow_config(CFG_ON)
    from talos.replay import db as replay_db

    canary = "TLdeadbeefcafebabe"
    p_uuid = "c" * 32
    t0 = "2026-07-26T12:00:00+00:00"
    flow = {
        "id": str(uuid.uuid4()),
        "project_id": "demo",
        "captured_at": t0,
        "response_end": t0,
        "method": "POST",
        "url": f"{HOST}/register",
        "host": HOST,
        "path": "/register",
        "query": "",
        "request_headers": {},
        "request_cookies": {},
        "request_body": canary.encode(),
        "request_body_truncated": 0,
        "status_code": 200,
        "response_headers": {"content-type": "text/html"},
        "response_body": b"ok",
        "response_body_truncated": 0,
        "content_type": "text/html",
        "endpoint_id": ids["ep_register"],
        "role_id": ids["role_id"],
        "module_id": ids["module_id"],
        "source": "auto_replay",
        "original_flow_id": str(uuid.uuid4()),
        "replay_error": None,
        "replay_reason": "input_validation",
        "flow_meta": {
            "parameter_name": "username",
            "parameter_uuid": p_uuid,
            "mutation": {"location": "body", "host": HOST},
            "multiprobe": {"canary": canary},
        },
    }
    replay_db.insert_replayed_flow(db_path, flow)
    with sqlite3.connect(str(db_path)) as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM value_index WHERE is_canary = 1"
        ).fetchone()[0]
    assert n == 1


# ------------------------------------------------------------------ #
# PR4 — list / batch                                                   #
# ------------------------------------------------------------------ #


def test_list_and_batch_reflections(db_path: Path):
    ids = _seed_endpoints_and_params(db_path)
    t0 = "2026-07-26T13:00:00+00:00"
    t1 = "2026-07-26T13:01:00+00:00"
    params = [
        ExtractedParam(
            name="username",
            location="body",
            param_type="string",
            semantic_type="string",
            sample_value="xss_test1",
        )
    ]
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        on_flow_committed(
            conn,
            flow=_proxy_flow(
                flow_id=str(uuid.uuid4()),
                method="POST",
                path="/register",
                body=None,
                response=b"ok",
                endpoint_id=ids["ep_register"],
                role_id=ids["role_id"],
                module_id=ids["module_id"],
                t=t0,
            ),
            endpoint_id=ids["ep_register"],
            params=params,
            cfg=CFG_ON,
        )
        on_flow_committed(
            conn,
            flow=_proxy_flow(
                flow_id=str(uuid.uuid4()),
                method="GET",
                path="/profile",
                body=None,
                response=b"user xss_test1",
                endpoint_id=ids["ep_profile"],
                role_id=ids["role_id"],
                module_id=ids["module_id"],
                t=t1,
            ),
            endpoint_id=ids["ep_profile"],
            params=[],
            cfg=CFG_ON,
        )
        conn.commit()

    rows = list_cross_flow_reflections(db_path, host=HOST, limit=10)
    assert len(rows) == 1
    p_uuid = rows[0]["source_param_uuid"]
    batched = batch_list_cross_flow_reflections(db_path, [p_uuid, "nope"])
    assert len(batched[p_uuid]) == 1
    assert batched["nope"] == []


def test_process_config_cache_not_yaml_per_call():
    reset_process_cross_flow_config()
    set_process_cross_flow_config(CrossFlowConfig(enabled=True, scan_hot_set_k=99))
    assert get_process_cross_flow_config().scan_hot_set_k == 99
    # ensure when already loaded must not re-read
    with patch(
        "talos.projects.value_reflection.load_cross_flow_config_for_project",
        side_effect=AssertionError("no reload"),
    ):
        cfg = ensure_process_cross_flow_config(Path("/tmp"))
        assert cfg.scan_hot_set_k == 99


def test_load_cross_flow_config_for_project_reads_yaml(tmp_path: Path):
    """project_data_dir path must load project.yaml (not silent defaults)."""
    reset_process_cross_flow_config()
    (tmp_path / "project.yaml").write_text(
        "parameter_intel:\n"
        "  cross_flow:\n"
        "    enabled: true\n"
        "    feed_iv: false\n"
        "    scan_hot_set_k: 1234\n",
        encoding="utf-8",
    )
    cfg = load_cross_flow_config_for_project(tmp_path)
    assert cfg.enabled is True
    assert cfg.feed_iv is False
    assert cfg.scan_hot_set_k == 1234


# ------------------------------------------------------------------ #
# QA medium fixes — upsert recency, time gate, count semantics         #
# ------------------------------------------------------------------ #


def test_upsert_last_seen_max_and_source_flow_recency(db_path: Path):
    """Out-of-order re-index must not rewind last_seen_at or source_flow_id."""
    ids = _seed_endpoints_and_params(db_path)
    param_uuid = "a" * 32
    flow_new = str(uuid.uuid4())
    flow_old = str(uuid.uuid4())
    t_late = "2026-07-26T10:00:00+00:00"
    t_early = "2026-07-26T08:00:00+00:00"

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        upsert_value_index(
            conn,
            project_id="demo",
            host=HOST,
            value="test32343",
            source_flow_id=flow_new,
            captured_at=t_late,
            source_param_uuid=param_uuid,
            source_param_name="username",
            source_location="body",
            source_endpoint_id=ids["ep_register"],
            source_method="POST",
            source_path="/register",
            cfg=CFG_ON,
        )
        # Backdated observation (clock skew / out-of-order commit).
        upsert_value_index(
            conn,
            project_id="demo",
            host=HOST,
            value="test32343",
            source_flow_id=flow_old,
            captured_at=t_early,
            source_param_uuid=param_uuid,
            source_param_name="username",
            source_location="body",
            source_endpoint_id=ids["ep_register"],
            source_method="POST",
            source_path="/register",
            cfg=CFG_ON,
        )
        conn.commit()
        row = conn.execute(
            """
            SELECT source_flow_id, first_seen_at, last_seen_at, hit_count
            FROM value_index
            WHERE source_param_uuid = ?
            """,
            (param_uuid,),
        ).fetchone()

    assert row["source_flow_id"] == flow_new
    assert row["first_seen_at"] == t_late
    assert parse_iso_timestamp(row["last_seen_at"]) == parse_iso_timestamp(t_late)
    assert int(row["hit_count"]) == 2


def test_upsert_source_flow_updates_when_newer(db_path: Path):
    ids = _seed_endpoints_and_params(db_path)
    param_uuid = "b" * 32
    flow_a = str(uuid.uuid4())
    flow_b = str(uuid.uuid4())
    t0 = "2026-07-26T09:00:00+00:00"
    t1 = "2026-07-26T11:00:00Z"  # Z form; must still count as later

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        upsert_value_index(
            conn,
            project_id="demo",
            host=HOST,
            value="test32343",
            source_flow_id=flow_a,
            captured_at=t0,
            source_param_uuid=param_uuid,
            source_param_name="username",
            source_location="body",
            source_endpoint_id=ids["ep_register"],
            cfg=CFG_ON,
        )
        upsert_value_index(
            conn,
            project_id="demo",
            host=HOST,
            value="test32343",
            source_flow_id=flow_b,
            captured_at=t1,
            source_param_uuid=param_uuid,
            source_param_name="username",
            source_location="body",
            source_endpoint_id=ids["ep_register"],
            cfg=CFG_ON,
        )
        conn.commit()
        row = conn.execute(
            "SELECT source_flow_id, last_seen_at FROM value_index WHERE source_param_uuid = ?",
            (param_uuid,),
        ).fetchone()

    assert row["source_flow_id"] == flow_b
    assert parse_iso_timestamp(row["last_seen_at"]) == parse_iso_timestamp(t1)


def test_time_gate_allows_z_vs_offset_same_instant(db_path: Path):
    """Source first_seen Z and sink +00:00 at same instant must still link."""
    ids = _seed_endpoints_and_params(db_path)
    flow_a = str(uuid.uuid4())
    flow_b = str(uuid.uuid4())
    t_z = "2026-07-26T12:00:00Z"
    t_off = "2026-07-26T12:00:00+00:00"
    params = [
        ExtractedParam(
            name="username",
            location="body",
            param_type="string",
            semantic_type="string",
            sample_value="test32343",
        )
    ]
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        on_flow_committed(
            conn,
            flow=_proxy_flow(
                flow_id=flow_a,
                method="POST",
                path="/register",
                body=None,
                response=b"ok",
                endpoint_id=ids["ep_register"],
                role_id=ids["role_id"],
                module_id=ids["module_id"],
                t=t_z,
            ),
            endpoint_id=ids["ep_register"],
            params=params,
            cfg=CFG_ON,
        )
        on_flow_committed(
            conn,
            flow=_proxy_flow(
                flow_id=flow_b,
                method="GET",
                path="/profile",
                body=None,
                response=b"<html>test32343</html>",
                endpoint_id=ids["ep_profile"],
                role_id=ids["role_id"],
                module_id=ids["module_id"],
                t=t_off,
            ),
            endpoint_id=ids["ep_profile"],
            params=[],
            cfg=CFG_ON,
        )
        conn.commit()

    links = list_cross_flow_reflections(db_path)
    assert len(links) == 1


def test_reflection_count_only_increments_on_new_edge(db_path: Path):
    """Re-scanning the same sink flow must not inflate cross_flow_reflection_count."""
    ids = _seed_endpoints_and_params(db_path)
    flow_a = str(uuid.uuid4())
    flow_b = str(uuid.uuid4())
    t0 = "2026-07-26T10:00:00+00:00"
    t1 = "2026-07-26T10:05:00+00:00"
    params = [
        ExtractedParam(
            name="username",
            location="body",
            param_type="string",
            semantic_type="string",
            sample_value="test32343",
        )
    ]
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        on_flow_committed(
            conn,
            flow=_proxy_flow(
                flow_id=flow_a,
                method="POST",
                path="/register",
                body=None,
                response=b"ok",
                endpoint_id=ids["ep_register"],
                role_id=ids["role_id"],
                module_id=ids["module_id"],
                t=t0,
            ),
            endpoint_id=ids["ep_register"],
            params=params,
            cfg=CFG_ON,
        )
        sink_flow = _proxy_flow(
            flow_id=flow_b,
            method="GET",
            path="/profile",
            body=None,
            response=b"<html>test32343</html>",
            endpoint_id=ids["ep_profile"],
            role_id=ids["role_id"],
            module_id=ids["module_id"],
            t=t1,
        )
        on_flow_committed(
            conn,
            flow=sink_flow,
            endpoint_id=ids["ep_profile"],
            params=[],
            cfg=CFG_ON,
        )
        # Re-process the same sink flow (observation bump, not new edge).
        on_flow_committed(
            conn,
            flow=sink_flow,
            endpoint_id=ids["ep_profile"],
            params=[],
            cfg=CFG_ON,
        )
        conn.commit()
        flags = conn.execute(
            """
            SELECT cross_flow_reflection_count, cross_flow_reflected
            FROM parameters WHERE id = ?
            """,
            (ids["param_id"],),
        ).fetchone()
        obs = conn.execute(
            "SELECT observation_count FROM cross_flow_reflections"
        ).fetchone()[0]

    assert flags[1] == 1
    assert flags[0] == 1  # distinct edge count, not re-observations
    assert int(obs) == 2  # link observations still accumulate
