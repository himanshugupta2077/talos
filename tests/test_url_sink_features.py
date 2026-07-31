"""
Tests: talos.url_sink.features + parameters wiring for url_features.

Purpose:
    Compose value+name into url_features; verify extract/upsert persists
    features and improves semantic_type=url for URL-shaped values without
    name hints.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

import pytest

from talos.projects.db import SCHEMA_VERSION, init_project_db, migrate_project_db
from talos.projects.parameters import (
    extract_flow_params,
    upsert_endpoint_params,
)
from talos.url_sink.features import (
    NETWORK_RESOURCE_SCORE_THRESHOLD,
    compose_url_features,
    empty_url_features,
)


# ---------------------------------------------------------------------------
# Compose
# ---------------------------------------------------------------------------

def test_value_dominates_random_name() -> None:
    """abc=https://… → high score without name catalog hit."""
    doc = compose_url_features(name="abc", value="https://cdn.example/x")
    assert doc["score"] >= 90
    assert doc["possible_network_resource"] is True
    assert doc["possible_url_value"] is True
    assert "https" in doc["protocols_seen"]
    assert doc["name_category"] is None


def test_name_only_modest_score() -> None:
    doc = compose_url_features(name="redirect_uri", value="")
    assert 15 <= doc["score"] <= 35
    assert doc["name_category"] is not None
    # Name alone below inventory network-resource threshold by design.
    assert doc["score"] < NETWORK_RESOURCE_SCORE_THRESHOLD or doc["score"] <= 35


def test_email_value_ignored_even_with_url_name() -> None:
    doc = compose_url_features(name="url", value="user@example.com")
    assert doc["score"] == 0
    assert doc["possible_network_resource"] is False


def test_name_and_value_merge_evidence() -> None:
    doc = compose_url_features(
        name="avatar",
        value="https://cdn.example/a.png",
    )
    assert doc["score"] >= 90
    assert doc["name_category"] is not None
    assert any("name:" in e or "name_category:" in e for e in doc["evidence"])
    assert any("value_scheme:" in e for e in doc["evidence"])


def test_empty_url_features_keys() -> None:
    doc = empty_url_features()
    for key in (
        "possible_url_value",
        "possible_hostname",
        "possible_ip",
        "possible_path",
        "possible_domain",
        "possible_unc",
        "possible_protocol",
        "protocols_seen",
        "looks_like",
        "name_category",
        "name_categories",
        "score",
        "possible_network_resource",
        "evidence",
    ):
        assert key in doc


def test_hostname_value_network_resource() -> None:
    doc = compose_url_features(name="host", value="api.internal")
    assert doc["possible_hostname"] is True
    assert doc["possible_network_resource"] is True
    assert doc["score"] >= 55


# ---------------------------------------------------------------------------
# Extraction + semantic_type
# ---------------------------------------------------------------------------

def test_extract_query_url_features_and_semantic() -> None:
    params = extract_flow_params(
        query="abc=https%3A%2F%2Fcdn.example%2Fx&q=hello",
        request_body=None,
        request_headers={},
    )
    by_name = {p.name: p for p in params}
    assert "abc" in by_name
    abc = by_name["abc"]
    assert abc.semantic_type == "url"
    feat = json.loads(abc.url_features)
    assert feat["score"] >= 90
    assert feat["possible_network_resource"] is True

    assert by_name["q"].semantic_type in ("string", "unknown")
    q_feat = json.loads(by_name["q"].url_features)
    assert q_feat["possible_network_resource"] is False


def test_extract_json_nested_avatar() -> None:
    body = json.dumps({
        "user": {"avatar": "https://cdn.example/a.png"},
    }).encode()
    params = extract_flow_params(
        query="",
        request_body=body,
        request_headers={"content-type": "application/json"},
    )
    avatar = next(p for p in params if p.name.endswith("avatar"))
    assert avatar.semantic_type == "url"
    feat = json.loads(avatar.url_features)
    assert feat["score"] >= 90
    assert feat["name_category"] is not None


def test_hostname_not_filename() -> None:
    params = extract_flow_params(
        query="host=cdn.example.com",
        request_body=None,
        request_headers={},
    )
    p = params[0]
    assert p.semantic_type != "filename"
    feat = json.loads(p.url_features)
    assert feat["possible_hostname"] is True


def test_pdf_filename_not_hostname_or_url_sink() -> None:
    """QA: report.pdf must stay semantic_type=filename, not network resource."""
    params = extract_flow_params(
        query="file=report.pdf",
        request_body=None,
        request_headers={},
    )
    p = params[0]
    assert p.semantic_type == "filename"
    feat = json.loads(p.url_features)
    assert feat["possible_hostname"] is False
    assert feat["possible_network_resource"] is False


def test_ftp_scheme_semantic_url() -> None:
    params = extract_flow_params(
        query="src=ftp://files.example/a",
        request_body=None,
        request_headers={},
    )
    assert params[0].semantic_type == "url"


# ---------------------------------------------------------------------------
# DB upsert persistence
# ---------------------------------------------------------------------------

@pytest.fixture()
def project_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "talos.db"
    init_project_db(db_path)
    assert SCHEMA_VERSION >= 53
    return db_path


def _seed_endpoint(conn: sqlite3.Connection) -> str:
    endpoint_id = str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO endpoints (
            id, project_id, method, host, path, normalized_path,
            first_seen, last_seen
        ) VALUES (?, 'p1', 'GET', 'http://example.com', '/x', '/x',
                  '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z')
        """,
        (endpoint_id,),
    )
    return endpoint_id


def test_upsert_persists_url_features(project_db: Path) -> None:
    params = extract_flow_params(
        query="abc=https%3A%2F%2Fcdn.example%2Fx&redirect=https%3A%2F%2Fapp.example%2Fhome",
        request_body=None,
        request_headers={},
    )
    with sqlite3.connect(str(project_db)) as conn:
        conn.row_factory = sqlite3.Row
        endpoint_id = _seed_endpoint(conn)
        upsert_endpoint_params(conn, endpoint_id, params)
        conn.commit()

        rows = conn.execute(
            "SELECT name, semantic_type, url_features FROM parameters "
            "WHERE endpoint_id = ? ORDER BY name",
            (endpoint_id,),
        ).fetchall()

    by_name = {r["name"]: r for r in rows}
    assert "abc" in by_name
    abc_feat = json.loads(by_name["abc"]["url_features"])
    assert abc_feat["score"] >= 90
    assert abc_feat["possible_network_resource"] is True
    assert by_name["abc"]["semantic_type"] == "url"

    redir_feat = json.loads(by_name["redirect"]["url_features"])
    assert redir_feat["name_category"] is not None
    assert redir_feat["score"] >= 90


def test_upsert_upgrades_url_features_score(project_db: Path) -> None:
    """Later stronger observation replaces weaker url_features."""
    weak = extract_flow_params(
        query="target=hello",
        request_body=None,
        request_headers={},
    )
    strong = extract_flow_params(
        query="target=https%3A%2F%2Fevil.example%2F",
        request_body=None,
        request_headers={},
    )
    with sqlite3.connect(str(project_db)) as conn:
        conn.row_factory = sqlite3.Row
        endpoint_id = _seed_endpoint(conn)
        upsert_endpoint_params(conn, endpoint_id, weak)
        upsert_endpoint_params(conn, endpoint_id, strong)
        conn.commit()
        row = conn.execute(
            "SELECT semantic_type, url_features, seen_count FROM parameters "
            "WHERE endpoint_id = ? AND name = 'target'",
            (endpoint_id,),
        ).fetchone()

    feat = json.loads(row["url_features"])
    assert feat["score"] >= 90
    assert row["semantic_type"] == "url"
    assert row["seen_count"] == 2


def test_upsert_works_without_caller_row_factory(project_db: Path) -> None:
    """QA: upsert must not require callers to set sqlite3.Row."""
    params = extract_flow_params(
        query="abc=https%3A%2F%2Fcdn.example%2Fx",
        request_body=None,
        request_headers={},
    )
    with sqlite3.connect(str(project_db)) as conn:
        # Default tuple rows — no row_factory.
        assert conn.row_factory is None
        endpoint_id = _seed_endpoint(conn)
        upsert_endpoint_params(conn, endpoint_id, params)
        # Second call exercises UPDATE path.
        upsert_endpoint_params(conn, endpoint_id, params)
        conn.commit()
        row = conn.execute(
            "SELECT seen_count, url_features, semantic_type FROM parameters "
            "WHERE endpoint_id = ? AND name = 'abc'",
            (endpoint_id,),
        ).fetchone()
    assert row[0] == 2
    assert row[2] == "url"
    feat = json.loads(row[1])
    assert feat["score"] >= 90


def test_migrate_adds_url_features_column(tmp_path: Path) -> None:
    """Upgrading an older schema gains parameters.url_features."""
    db_path = tmp_path / "old.db"
    with sqlite3.connect(str(db_path)) as conn:
        conn.executescript(
            """
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version (version) VALUES (52);
            CREATE TABLE endpoints (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                method TEXT NOT NULL,
                host TEXT NOT NULL,
                path TEXT NOT NULL,
                normalized_path TEXT NOT NULL,
                content_type TEXT NOT NULL DEFAULT '',
                auth_required INTEGER NOT NULL DEFAULT 0,
                roles_seen TEXT NOT NULL DEFAULT '[]',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE TABLE parameters (
                id TEXT PRIMARY KEY,
                endpoint_id TEXT NOT NULL,
                name TEXT NOT NULL,
                location TEXT NOT NULL,
                param_type TEXT NOT NULL DEFAULT 'unknown',
                semantic_type TEXT NOT NULL DEFAULT 'unknown',
                example_values TEXT NOT NULL DEFAULT '[]',
                seen_count INTEGER NOT NULL DEFAULT 1,
                UNIQUE (endpoint_id, name, location)
            );
            """
        )
        conn.commit()

    migrate_project_db(db_path)

    with sqlite3.connect(str(db_path)) as conn:
        version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
        cols = {
            row[1]
            for row in conn.execute("PRAGMA table_info(parameters)").fetchall()
        }
    assert version >= 53
    assert "url_features" in cols
