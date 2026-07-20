"""
Dashboard aggregate route tests.

Verifies 404 for unknown projects, zero-shape without DB, and populated
status keys when SQLite has minimal tables.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


@pytest.fixture()
def home(tmp_path, monkeypatch):
    talos_home = tmp_path / "talos-home"
    talos_home.mkdir()
    projects = talos_home / "projects"
    projects.mkdir()
    registry = projects / "registry.json"
    monkeypatch.setenv("TALOS_HOME", str(talos_home))
    # Reload config paths bound at import time.
    import talos_ui.config as cfg

    monkeypatch.setattr(cfg, "TALOS_HOME", talos_home)
    monkeypatch.setattr(cfg, "PROJECTS_ROOT", projects)
    monkeypatch.setattr(cfg, "REGISTRY_PATH", registry)
    return talos_home, projects, registry


def _write_registry(registry: Path, projects: dict):
    registry.write_text(json.dumps(projects), encoding="utf-8")


def _init_minimal_db(db_path: Path):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE flows (
              id TEXT PRIMARY KEY,
              host TEXT,
              method TEXT,
              status_code INTEGER,
              source TEXT DEFAULT 'proxy_capture',
              captured_at TEXT
            );
            CREATE TABLE endpoints (id TEXT PRIMARY KEY);
            CREATE TABLE findings (
              id TEXT PRIMARY KEY,
              project_id TEXT,
              attack_type TEXT,
              verdict TEXT,
              status TEXT,
              title TEXT,
              created_at TEXT
            );
            CREATE TABLE finding_groups (
              id TEXT PRIMARY KEY,
              project_id TEXT,
              name TEXT,
              created_at TEXT
            );
            CREATE TABLE scheduler_jobs (
              job_id TEXT PRIMARY KEY,
              job_type TEXT,
              status TEXT,
              failure_reason TEXT,
              priority INTEGER,
              created_at TEXT,
              finished_at TEXT
            );
            CREATE TABLE scheduler_config (
              min_delay REAL,
              max_delay REAL,
              max_queue_size INTEGER
            );
            CREATE TABLE scheduler_state (
              state TEXT,
              reason TEXT
            );
            CREATE TABLE roles (
              id TEXT PRIMARY KEY,
              name TEXT,
              is_active INTEGER
            );
            CREATE TABLE modules (
              id TEXT PRIMARY KEY,
              name TEXT,
              is_active INTEGER
            );
            CREATE TABLE out_of_scope_domains (
              id TEXT PRIMARY KEY,
              project_id TEXT,
              domain TEXT,
              created_at TEXT
            );
            CREATE TABLE role_auth_provider (
              role_id TEXT PRIMARY KEY,
              provider TEXT,
              updated_at TEXT
            );
            CREATE TABLE role_auth_state (
              role_id TEXT,
              key TEXT,
              value TEXT,
              collected_at TEXT
            );
            CREATE TABLE session_health_config (
              role_id TEXT PRIMARY KEY,
              ttl_seconds INTEGER,
              refresh_before_seconds INTEGER
            );
            CREATE TABLE session_health_control_flows (
              role_id TEXT,
              flow_id TEXT
            );
            CREATE TABLE session_suspicion_state (
              role_id TEXT PRIMARY KEY,
              suspicion_count INTEGER,
              last_checked_at TEXT
            );
            CREATE TABLE manual_session_config (
              role_id TEXT PRIMARY KEY,
              expires_at TEXT,
              ttl_seconds INTEGER,
              updated_at TEXT
            );

            INSERT INTO flows VALUES
              ('f1','api.example.com','GET',200,'proxy_capture','2026-07-01T12:00:00'),
              ('f2','api.example.com','POST',401,'auto_replay','2026-07-01T12:01:00');
            INSERT INTO findings VALUES
              ('n1','demo','bac','POSSIBLE_BAC','TRIAGING','BAC on /users','2026-07-01T12:00:00'),
              ('n2','demo','unauth','BYPASS','CONFIRMED','Unauth bypass','2026-07-01T11:00:00');
            INSERT INTO scheduler_jobs VALUES
              ('j1','replay_flow','pending',NULL,10,'2026-07-01T12:00:00',NULL),
              ('j2','bac','failed','timeout',5,'2026-07-01T11:00:00','2026-07-01T11:05:00');
            INSERT INTO scheduler_config VALUES (2.0, 6.0, 200);
            INSERT INTO scheduler_state VALUES ('running', NULL);
            INSERT INTO roles VALUES ('r1','admin',1), ('r2','user',0);
            INSERT INTO modules VALUES ('m1','global',1);
            INSERT INTO out_of_scope_domains VALUES
              ('o1','demo','cdn.example.com','2026-07-01T10:00:00');
            """
        )
        conn.commit()
    finally:
        conn.close()


@pytest.fixture()
def client(home):
    from talos_ui.main import app

    return TestClient(app)


def test_dashboard_unknown_project(client, home):
    res = client.get("/api/projects/missing/dashboard")
    assert res.status_code == 404


def test_dashboard_no_db_zeros(client, home):
    _talos_home, _projects, registry = home
    _write_registry(
        registry,
        {
            "demo": {
                "name": "Demo",
                "description": "test",
                "status": "active",
                "scope": ["https://example.com"],
                "constraints": {},
                "created_at": "2026-07-01T00:00:00",
            }
        },
    )
    with (
        patch("talos_ui.dashboard_reads._proxy_block") as proxy,
        patch("talos_ui.dashboard_reads._http_rules_block") as http,
        patch("talos_ui.dashboard_reads._talos_config_block") as cfg,
        patch("talos_ui.dashboard_reads._endpoints_block") as ends,
    ):
        proxy.return_value = {
            "state": "stopped",
            "running": False,
            "transitional": False,
        }
        http.return_value = {
            "enabled": True,
            "summary": {
                "active": 0,
                "request": 0,
                "response": 0,
                "disabled": 0,
                "total": 0,
            },
        }
        cfg.return_value = {
            "source_counts": {"default": 5},
            "sections": [],
            "key_flags": {},
        }
        ends.return_value = {
            "inventory": {
                "total": 0,
                "testable": 0,
                "excluded": 0,
                "dangerous": 0,
                "logout": 0,
                "unqualified": 0,
            },
            "policy": {
                "by_priority": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "NORMAL": 0,
                    "LOW": 0,
                },
                "manual_overrides": 0,
                "rule_controlled": 0,
                "auto_controlled": 0,
                "total": 0,
            },
            "coverage": {
                "qualified_pct": 0,
                "baseline_pct": 0,
                "multi_role_pct": 0,
                "params_pct": 0,
                "excluded_pct": 0,
            },
        }
        res = client.get("/api/projects/demo/dashboard")
    assert res.status_code == 200
    body = res.json()
    assert body["project"]["id"] == "demo"
    assert body["project"]["db_exists"] is False
    assert body["findings"]["by_status"]["TRIAGING"] == 0
    assert body["flows"]["total"] == 0
    assert body["scheduler"]["active_queue"] == 0
    assert "readiness" in body
    assert body["readiness"]["active"] is True
    assert body["readiness"]["db"] is False


def test_dashboard_populated_counts(client, home):
    _talos_home, projects, registry = home
    data_dir = projects / "demo"
    data_dir.mkdir()
    db_path = data_dir / "talos.db"
    _init_minimal_db(db_path)
    _write_registry(
        registry,
        {
            "demo": {
                "name": "Demo",
                "description": "test",
                "status": "active",
                "scope": ["https://example.com"],
                "constraints": {"store_bodies": True},
                "created_at": "2026-07-01T00:00:00",
                "data_dir": str(data_dir),
            }
        },
    )

    with (
        patch("talos_ui.dashboard_reads._proxy_block") as proxy,
        patch("talos_ui.dashboard_reads._http_rules_block") as http,
        patch("talos_ui.dashboard_reads._talos_config_block") as cfg,
        patch("talos_ui.dashboard_reads._endpoints_block") as ends,
        patch("talos_ui.config.project_db_path", return_value=db_path),
        patch("talos_ui.config.project_data_dir", return_value=data_dir),
    ):
        proxy.return_value = {
            "state": "running",
            "running": True,
            "transitional": False,
            "listen_host": "127.0.0.1",
            "listen_port": 8080,
        }
        http.return_value = {
            "enabled": True,
            "summary": {
                "active": 2,
                "request": 2,
                "response": 0,
                "disabled": 0,
                "total": 2,
            },
        }
        cfg.return_value = {
            "source_counts": {"default": 3, "project": 1},
            "sections": [
                {
                    "section": "proxy",
                    "label": "Proxy",
                    "summary": "Direct",
                    "source": "default",
                }
            ],
            "key_flags": {"http_enabled": True},
        }
        ends.return_value = {
            "inventory": {
                "total": 10,
                "testable": 7,
                "excluded": 1,
                "dangerous": 1,
                "logout": 0,
                "unqualified": 2,
            },
            "policy": {
                "by_priority": {
                    "CRITICAL": 1,
                    "HIGH": 2,
                    "NORMAL": 5,
                    "LOW": 2,
                },
                "manual_overrides": 1,
                "rule_controlled": 2,
                "auto_controlled": 7,
                "total": 10,
            },
            "coverage": {
                "qualified_pct": 70,
                "baseline_pct": 50,
                "multi_role_pct": 20,
                "params_pct": 40,
                "excluded_pct": 10,
            },
        }
        res = client.get("/api/projects/demo/dashboard")

    assert res.status_code == 200
    body = res.json()
    assert body["project"]["db_exists"] is True
    assert body["findings"]["by_status"]["TRIAGING"] == 1
    assert body["findings"]["by_status"]["CONFIRMED"] == 1
    assert body["findings"]["by_attack_type"]
    assert body["flows"]["total"] == 2
    assert body["flows"]["by_source"].get("proxy_capture") == 1
    assert body["flows"]["by_status_class"]["2xx"] == 1
    assert body["flows"]["by_status_class"]["4xx"] == 1
    assert body["scheduler"]["active_queue"] == 1
    assert body["scheduler"]["counts"].get("failed") == 1
    assert body["project"]["outscope_count"] == 1
    assert body["project"]["roles"] == 2
    assert body["http_rules"]["summary"]["active"] == 2
    assert body["endpoints"]["inventory"]["testable"] == 7
    assert body["proxy"]["running"] is True
    assert body["readiness"]["proxy"] is True
    assert len(body["session_health"]) == 2
