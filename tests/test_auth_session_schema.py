"""
Tests: auth-session schema v54 (bindings / candidates / results).

Covers:
  - SCHEMA_VERSION >= 54
  - init_project_db creates the three tables + indexes
  - migrate_project_db upgrades from v53 → current with tables present
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


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


def test_schema_version_is_at_least_54() -> None:
    assert SCHEMA_VERSION >= 54


def test_init_creates_auth_session_tables(db_path: Path) -> None:
    assert get_schema_version(db_path) == SCHEMA_VERSION
    assert SCHEMA_VERSION >= 54
    with sqlite3.connect(str(db_path)) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "auth_session_bindings" in tables
        assert "auth_session_candidates" in tables
        assert "auth_session_results" in tables

        # Unique + FK constraints present via table info / indexes.
        indexes = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        assert "idx_auth_session_cand_status" in indexes
        assert "idx_auth_session_results_endpoint_test" in indexes
        assert "idx_auth_session_results_original_test" in indexes

        # Column spot-checks
        bind_cols = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(auth_session_bindings)"
            ).fetchall()
        }
        assert {
            "id", "location", "name", "auth_type", "role_id",
            "config_json", "created_at", "updated_at",
        } <= bind_cols

        cand_cols = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(auth_session_candidates)"
            ).fetchall()
        }
        assert {
            "id", "binding_id", "baseline_flow_id", "test_id",
            "test_family", "status", "endpoint_id",
        } <= cand_cols

        res_cols = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(auth_session_results)"
            ).fetchall()
        }
        assert {
            "replay_flow_id", "original_flow_id", "candidate_id",
            "verdict", "test_id", "endpoint_id",
        } <= res_cols


def test_migrate_from_53_adds_auth_session_tables(tmp_path: Path) -> None:
    """Upgrading a v53-style DB gains auth_session_* tables."""
    db_path = tmp_path / "old.db"
    with sqlite3.connect(str(db_path)) as conn:
        conn.executescript(
            """
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version (version) VALUES (53);
            CREATE TABLE flows (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                captured_at TEXT NOT NULL,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                host TEXT NOT NULL,
                path TEXT NOT NULL,
                query TEXT NOT NULL DEFAULT '',
                request_headers TEXT NOT NULL DEFAULT '{}',
                request_cookies TEXT NOT NULL DEFAULT '{}',
                status_code INTEGER,
                response_headers TEXT NOT NULL DEFAULT '{}',
                content_type TEXT NOT NULL DEFAULT '',
                role_id TEXT,
                module_id TEXT,
                tags TEXT NOT NULL DEFAULT '[]',
                source TEXT NOT NULL DEFAULT 'proxy_capture',
                flow_meta TEXT NOT NULL DEFAULT '{}'
            );
            """
        )
        conn.commit()

    assert get_schema_version(db_path) == 53
    migrate_project_db(db_path)
    assert get_schema_version(db_path) == SCHEMA_VERSION
    assert get_schema_version(db_path) >= 54

    with sqlite3.connect(str(db_path)) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert "auth_session_bindings" in tables
    assert "auth_session_candidates" in tables
    assert "auth_session_results" in tables


def test_binding_unique_location_name(db_path: Path) -> None:
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO auth_session_bindings
                (id, location, name, auth_type, config_json, created_at, updated_at)
            VALUES ('b1', 'header', 'Authorization', 'jwt', '{}',
                    '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z')
            """
        )
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO auth_session_bindings
                    (id, location, name, auth_type, config_json,
                     created_at, updated_at)
                VALUES ('b2', 'header', 'Authorization', 'jwt', '{}',
                        '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z')
                """
            )
