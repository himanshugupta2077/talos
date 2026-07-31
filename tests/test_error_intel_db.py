"""
Tests for Error Intelligence schema v43 + talos.error_intel.db CRUD.

Covers:
  - Fresh init_project_db creates error tables and seeds config
  - migrate_project_db upgrades from schema 42 → 43
  - Cluster upsert / observation insert / fingerprint dedup
  - Config get/update
  - store_classified_error high-level path
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from talos.error_intel import (
    ATTACK_TYPE_IV,
    ATTACK_TYPE_PROXY,
    ATTACK_TYPE_UNKNOWN,
    CATEGORY_STACK_TRACE,
    SEVERITY_HIGH,
    classify_error,
)
from talos.error_intel.config import default_config
from talos.error_intel.db import (
    count_clusters,
    count_observations,
    ensure_config,
    get_cluster,
    get_cluster_by_fingerprint,
    get_config,
    get_observation,
    insert_error_observation,
    list_clusters,
    list_observations,
    store_classified_error,
    update_config,
    update_observations_context,
    upsert_error_cluster,
)
from talos.projects.db import (
    SCHEMA_VERSION,
    get_schema_version,
    init_project_db,
    migrate_project_db,
)

JAVA_SQL = """\
java.sql.SQLSyntaxErrorException: syntax error
\tat com.example.UserService.load(UserService.java:142)
"""

JAVA_SQL_OTHER_LINE = """\
java.sql.SQLSyntaxErrorException: syntax error
\tat com.example.UserService.load(UserService.java:888)
"""


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


# ------------------------------------------------------------------ #
# Schema                                                               #
# ------------------------------------------------------------------ #

def test_schema_version_at_least_error_intel() -> None:
    # Error Intelligence landed at v43/v44; later phases bump SCHEMA_VERSION.
    assert SCHEMA_VERSION >= 44


def test_fresh_db_has_error_intel_tables(db_path: Path) -> None:
    assert get_schema_version(db_path) == SCHEMA_VERSION
    with sqlite3.connect(str(db_path)) as conn:
        names = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    for required in (
        "error_clusters",
        "error_observations",
        "error_intel_config",
    ):
        assert required in names


def test_fresh_db_seeds_error_intel_config(db_path: Path) -> None:
    cfg = get_config(db_path)
    defaults = default_config()
    assert cfg.enabled is True
    assert cfg.store_generic_http_errors is False
    assert cfg.max_body_scan == defaults.max_body_scan
    assert cfg.queue_maxsize == defaults.queue_maxsize


def test_migrate_from_42_creates_error_intel_tables(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    with sqlite3.connect(str(path)) as conn:
        conn.executescript(
            """
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version (version) VALUES (42);
            """
        )
        conn.commit()

    assert get_schema_version(path) == 42
    migrate_project_db(path)
    assert get_schema_version(path) == SCHEMA_VERSION
    with sqlite3.connect(str(path)) as conn:
        names = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    assert "error_clusters" in names
    assert "error_observations" in names
    assert "error_intel_config" in names


def test_get_config_migrates_pre_v43_db(tmp_path: Path) -> None:
    """Proxy addon calls get_config at startup — must not fail on old DBs."""
    path = tmp_path / "old.db"
    # Full v42-ish project DB (schema version only is enough for migrate path
    # when error tables are absent).
    init_project_db(path)
    with sqlite3.connect(str(path)) as conn:
        conn.execute("DROP TABLE error_intel_config")
        conn.execute("DROP TABLE error_observations")
        conn.execute("DROP TABLE error_clusters")
        conn.execute("UPDATE schema_version SET version = 42")
        conn.commit()

    assert get_schema_version(path) == 42
    cfg = get_config(path)
    assert cfg.enabled is True
    assert get_schema_version(path) == SCHEMA_VERSION
    with sqlite3.connect(str(path)) as conn:
        row = conn.execute(
            "SELECT 1 FROM error_intel_config WHERE id = 'default'"
        ).fetchone()
    assert row is not None


# ------------------------------------------------------------------ #
# Config                                                               #
# ------------------------------------------------------------------ #

def test_update_config_roundtrip(db_path: Path) -> None:
    cfg = get_config(db_path)
    cfg.enabled = False
    cfg.store_generic_http_errors = True
    cfg.queue_maxsize = 99
    update_config(db_path, cfg)
    loaded = get_config(db_path)
    assert loaded.enabled is False
    assert loaded.store_generic_http_errors is True
    assert loaded.queue_maxsize == 99


# ------------------------------------------------------------------ #
# Cluster + observation                                                #
# ------------------------------------------------------------------ #

def test_store_classified_error_dedups_fingerprint(db_path: Path) -> None:
    c1 = classify_error(JAVA_SQL, status_code=500)
    c2 = classify_error(JAVA_SQL_OTHER_LINE, status_code=500)
    assert c1 is not None and c2 is not None
    assert c1.fingerprint == c2.fingerprint

    cluster_a, obs_a, created_a = store_classified_error(
        db_path,
        "proj-1",
        c1,
        flow_id="flow-a",
        attack_type=ATTACK_TYPE_PROXY,
        response_status=500,
    )
    assert created_a is True
    assert cluster_a.observation_count == 1
    assert obs_a.error_id == cluster_a.id
    assert obs_a.attack_type == ATTACK_TYPE_PROXY

    cluster_b, obs_b, created_b = store_classified_error(
        db_path,
        "proj-1",
        c2,
        flow_id="flow-b",
        attack_type=ATTACK_TYPE_IV,
        parameter_uuid="param-uuid-1",
        parameter_name="username",
        response_status=500,
    )
    assert created_b is False
    assert cluster_b.id == cluster_a.id
    assert cluster_b.observation_count == 2
    assert obs_b.parameter_name == "username"
    assert obs_b.attack_type == ATTACK_TYPE_IV

    by_fp = get_cluster_by_fingerprint(db_path, "proj-1", c1.fingerprint)
    assert by_fp is not None
    assert by_fp.id == cluster_a.id
    assert by_fp.observation_count == 2

    obs_list = list_observations(db_path, error_id=cluster_a.id)
    assert len(obs_list) == 2
    attack_types = {o.attack_type for o in obs_list}
    assert attack_types == {ATTACK_TYPE_PROXY, ATTACK_TYPE_IV}


def test_list_clusters_filter(db_path: Path) -> None:
    c = classify_error(JAVA_SQL, status_code=500)
    assert c is not None
    store_classified_error(db_path, "proj-1", c, flow_id="f1")
    rows = list_clusters(db_path, "proj-1", category=CATEGORY_STACK_TRACE)
    assert len(rows) == 1
    assert rows[0].category == CATEGORY_STACK_TRACE
    empty = list_clusters(db_path, "proj-1", category="validation")
    assert empty == []


def test_list_clusters_multi_severity_and_flags(db_path: Path) -> None:
    """PR2 filters: multi-severity, tech flags, q, min_observations, hide_low_noise."""
    import sqlite3

    c = classify_error(JAVA_SQL, status_code=500)
    assert c is not None
    cluster, _obs, _ = store_classified_error(
        db_path, "proj-1", c, flow_id="f-sql", response_status=500
    )

    # Inject a low infrastructure row directly for filter parity tests
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO error_clusters (
                id, project_id, fingerprint, category, severity,
                language, exception_type, message_norm,
                has_stack_trace, has_path_leak, has_internal_host,
                has_version_leak, confidence, observation_count,
                first_seen, last_seen, scanner_version
            ) VALUES (
                'low-infra-1', 'proj-1', 'fp-low-infra',
                'infrastructure', 'low', 'unknown',
                'NotFound', 'not found',
                0, 0, 0, 0, 10, 1,
                '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z', '0.4.3'
            )
            """
        )
        conn.execute(
            """
            INSERT INTO error_clusters (
                id, project_id, fingerprint, category, severity,
                language, exception_type, message_norm,
                has_stack_trace, has_path_leak, has_internal_host,
                has_version_leak, confidence, observation_count,
                first_seen, last_seen, scanner_version
            ) VALUES (
                'med-http-1', 'proj-1', 'fp-med-http',
                'http', 'medium', 'unknown',
                'InternalError', 'internal error',
                0, 0, 0, 0, 40, 3,
                '2026-01-01T00:00:00Z', '2026-01-03T00:00:00Z', '0.4.3'
            )
            """
        )
        conn.commit()

    multi = list_clusters(
        db_path,
        "proj-1",
        severities=["medium", "high", "critical"],
        limit=50,
    )
    multi_ids = {r.id for r in multi}
    assert cluster.id in multi_ids
    assert "med-http-1" in multi_ids
    assert "low-infra-1" not in multi_ids

    total_medium_plus = count_clusters(
        db_path,
        "proj-1",
        severities=["medium", "high", "critical"],
    )
    assert total_medium_plus == len(multi)

    # Single severity still works (CLI backward compat)
    lows = list_clusters(db_path, "proj-1", severity="low")
    assert any(r.id == "low-infra-1" for r in lows)

    # hide_low_noise strips low infra/http even when severity includes low
    all_sev = list_clusters(
        db_path,
        "proj-1",
        severities=["low", "medium", "high", "critical"],
        hide_low_noise=True,
    )
    all_ids = {r.id for r in all_sev}
    assert "low-infra-1" not in all_ids
    assert "med-http-1" in all_ids

    # q search on exception_type
    q_rows = list_clusters(db_path, "proj-1", q="SQLSyntax")
    assert any(r.id == cluster.id for r in q_rows)

    # min_observations
    min_rows = list_clusters(db_path, "proj-1", min_observations=3)
    assert any(r.id == "med-http-1" for r in min_rows)
    assert not any(r.id == "low-infra-1" for r in min_rows)

    # Tech flag: stack trace on SQL cluster
    stack_rows = list_clusters(
        db_path, "proj-1", has_stack_trace=True
    )
    assert any(r.id == cluster.id for r in stack_rows)


def test_upsert_and_get_observation(db_path: Path) -> None:
    c = classify_error(JAVA_SQL, status_code=500)
    assert c is not None
    cluster, created = upsert_error_cluster(db_path, "p", c)
    assert created is True
    assert cluster.severity in (SEVERITY_HIGH, "critical", "high")
    obs = insert_error_observation(
        db_path,
        cluster.id,
        flow_id="flow-x",
        endpoint_id="ep-1",
        detectors=c.detectors,
    )
    loaded = get_observation(db_path, obs.id)
    assert loaded is not None
    assert loaded.flow_id == "flow-x"
    cl = get_cluster(db_path, cluster.id)
    assert cl is not None
    assert cl.fingerprint == c.fingerprint


def test_ensure_config_idempotent(db_path: Path) -> None:
    a = ensure_config(db_path)
    b = ensure_config(db_path)
    assert a.enabled == b.enabled


def test_update_observations_context_does_not_overwrite_attack_type(
    db_path: Path,
) -> None:
    """BUG-06: non-empty attack_type must not be replaced."""
    c = classify_error(JAVA_SQL, status_code=500)
    assert c is not None
    store_classified_error(
        db_path,
        "proj-1",
        c,
        flow_id="flow-proxy",
        attack_type=ATTACK_TYPE_PROXY,
        response_status=500,
    )
    n = update_observations_context(
        db_path,
        "flow-proxy",
        attack_type=ATTACK_TYPE_IV,
        parameter_uuid="param-1",
        parameter_name="id",
    )
    assert n >= 1
    obs = list_observations(db_path, flow_id="flow-proxy")
    assert len(obs) == 1
    assert obs[0].attack_type == ATTACK_TYPE_PROXY
    assert obs[0].parameter_uuid == "param-1"
    assert obs[0].parameter_name == "id"

    # Unknown can still be filled.
    store_classified_error(
        db_path,
        "proj-1",
        c,
        flow_id="flow-unknown",
        attack_type=ATTACK_TYPE_UNKNOWN,
        response_status=500,
    )
    update_observations_context(
        db_path, "flow-unknown", attack_type=ATTACK_TYPE_IV
    )
    obs2 = list_observations(db_path, flow_id="flow-unknown")
    assert obs2[0].attack_type == ATTACK_TYPE_IV


def test_one_observation_per_flow_id(db_path: Path) -> None:
    """BUG-07: duplicate store for same flow_id does not create a second row."""
    c = classify_error(JAVA_SQL, status_code=500)
    assert c is not None
    store_classified_error(
        db_path, "proj-1", c, flow_id="same-flow", attack_type=ATTACK_TYPE_PROXY
    )
    store_classified_error(
        db_path, "proj-1", c, flow_id="same-flow", attack_type=ATTACK_TYPE_IV
    )
    assert count_observations(db_path, flow_id="same-flow") == 1
    # Original attack_type preserved (no replace_flow)
    obs = list_observations(db_path, flow_id="same-flow")
    assert obs[0].attack_type == ATTACK_TYPE_PROXY

    # replace_flow replaces the row
    _, obs_new, _ = store_classified_error(
        db_path,
        "proj-1",
        c,
        flow_id="same-flow",
        attack_type=ATTACK_TYPE_IV,
        replace_flow=True,
    )
    assert count_observations(db_path, flow_id="same-flow") == 1
    assert obs_new.attack_type == ATTACK_TYPE_IV


def test_store_classified_error_atomic_count_matches(db_path: Path) -> None:
    """BUG-08: observation_count tracks real observation rows, not bare upserts."""
    c = classify_error(JAVA_SQL, status_code=500)
    assert c is not None
    cluster, obs, created = store_classified_error(
        db_path, "proj-1", c, flow_id="f1"
    )
    assert created is True
    assert cluster.observation_count == 1
    assert obs.error_id == cluster.id

    # Bare upserts must not inflate the counter.
    upsert_error_cluster(db_path, "proj-1", c)
    upsert_error_cluster(db_path, "proj-1", c)
    reloaded = get_cluster(db_path, cluster.id)
    assert reloaded is not None
    assert reloaded.observation_count == 1
    assert count_observations(db_path, error_id=cluster.id) == 1

    cluster2, _, created2 = store_classified_error(
        db_path, "proj-1", c, flow_id="f2"
    )
    assert created2 is False
    assert cluster2.id == cluster.id
    assert cluster2.observation_count == 2
    assert count_observations(db_path, error_id=cluster.id) == 2


def test_fresh_db_has_unique_flow_index(db_path: Path) -> None:
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index'"
        ).fetchall()
    names = {r[0] for r in rows}
    assert "idx_error_observations_flow_unique" in names


def test_migrate_43_to_44_adds_unique_flow_index(tmp_path: Path) -> None:
    path = tmp_path / "v43.db"
    with sqlite3.connect(str(path)) as conn:
        conn.executescript(
            """
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version (version) VALUES (43);
            CREATE TABLE error_clusters (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                language TEXT NOT NULL DEFAULT 'unknown',
                framework TEXT,
                database TEXT,
                server TEXT,
                exception_type TEXT,
                message_norm TEXT,
                technologies_json TEXT NOT NULL DEFAULT '[]',
                has_stack_trace INTEGER NOT NULL DEFAULT 0,
                has_path_leak INTEGER NOT NULL DEFAULT 0,
                has_internal_host INTEGER NOT NULL DEFAULT 0,
                has_version_leak INTEGER NOT NULL DEFAULT 0,
                confidence INTEGER NOT NULL DEFAULT 0,
                evidence_snippet TEXT,
                first_seen TEXT,
                last_seen TEXT,
                observation_count INTEGER NOT NULL DEFAULT 0,
                scanner_version TEXT
            );
            CREATE TABLE error_observations (
                id TEXT PRIMARY KEY,
                error_id TEXT NOT NULL,
                flow_id TEXT,
                endpoint_id TEXT,
                parameter_uuid TEXT,
                parameter_name TEXT,
                attack_type TEXT NOT NULL DEFAULT 'unknown',
                payload_redacted TEXT,
                response_status INTEGER,
                response_length INTEGER,
                duration_ms REAL,
                response_hash TEXT,
                artifacts_json TEXT NOT NULL DEFAULT '[]',
                detectors_json TEXT NOT NULL DEFAULT '[]',
                observed_at TEXT NOT NULL
            );
            CREATE TABLE error_intel_config (id TEXT PRIMARY KEY DEFAULT 'default');
            INSERT INTO error_clusters (
                id, project_id, fingerprint, category, severity, observation_count
            ) VALUES ('e1', 'p', 'fp', 'stack_trace', 'high', 3);
            INSERT INTO error_observations (id, error_id, flow_id, observed_at)
            VALUES
                ('o1', 'e1', 'flow-dup', '2020-01-01T00:00:00'),
                ('o2', 'e1', 'flow-dup', '2020-01-02T00:00:00'),
                ('o3', 'e1', 'flow-other', '2020-01-03T00:00:00');
            """
        )
        conn.commit()

    migrate_project_db(path)
    assert get_schema_version(path) == SCHEMA_VERSION
    with sqlite3.connect(str(path)) as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM error_observations WHERE flow_id = 'flow-dup'"
        ).fetchone()[0]
        assert n == 1
        count = conn.execute(
            "SELECT observation_count FROM error_clusters WHERE id = 'e1'"
        ).fetchone()[0]
        assert count == 2  # one flow-dup kept + flow-other
        idx = conn.execute(
            "SELECT name FROM sqlite_master WHERE name = "
            "'idx_error_observations_flow_unique'"
        ).fetchone()
        assert idx is not None
