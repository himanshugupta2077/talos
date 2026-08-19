"""Tests: XSS schema v64 (xss_results + unique-flow PK)."""

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


def test_schema_version_is_at_least_64() -> None:
    assert SCHEMA_VERSION >= 64


def test_init_creates_xss_results(db_path: Path) -> None:
    assert get_schema_version(db_path) == SCHEMA_VERSION
    with sqlite3.connect(str(db_path)) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "xss_results" in tables
        cols = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(xss_results)"
            ).fetchall()
        }
        assert {
            "replay_flow_id",
            "original_flow_id",
            "technique",
            "param_name",
            "payload_sent",
            "verdict",
            "context_hint",
            "encoding_hint",
            "evidence",
        } <= cols


def test_migrate_from_v63_adds_xss_results(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    init_project_db(path)
    with sqlite3.connect(str(path)) as conn:
        conn.execute("DROP TABLE IF EXISTS xss_results")
        conn.execute("UPDATE schema_version SET version = 63")
        conn.commit()
    migrate_project_db(path)
    assert get_schema_version(path) == SCHEMA_VERSION
    with sqlite3.connect(str(path)) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert "xss_results" in tables
