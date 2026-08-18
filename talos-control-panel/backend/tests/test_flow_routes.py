"""
Flow inspection workspace API tests.

Covers detail derived fields, related joins, list flags, filter-aware adjacent,
and export CLI wiring. Mutations must go through CLI; reads are SQL-only.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    import talos_ui.config as cfg

    monkeypatch.setattr(cfg, "TALOS_HOME", talos_home)
    monkeypatch.setattr(cfg, "PROJECTS_ROOT", projects)
    monkeypatch.setattr(cfg, "REGISTRY_PATH", registry)
    return talos_home, projects, registry


def _write_registry(registry: Path, projects: dict):
    registry.write_text(json.dumps(projects), encoding="utf-8")


def _init_flow_db(db_path: Path):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE roles (id TEXT PRIMARY KEY, name TEXT);
            CREATE TABLE modules (id TEXT PRIMARY KEY, name TEXT);
            CREATE TABLE endpoints (
              id TEXT PRIMARY KEY, project_id TEXT, method TEXT, host TEXT,
              path TEXT, normalized_path TEXT
            );
            CREATE TABLE endpoint_policy (
              endpoint_id TEXT PRIMARY KEY,
              qualified INTEGER DEFAULT 0,
              qualification_reason TEXT,
              baseline_flow_id TEXT,
              baseline_status INTEGER,
              excluded INTEGER DEFAULT 0,
              dangerous INTEGER DEFAULT 0,
              logout INTEGER DEFAULT 0,
              manual_priority TEXT,
              auto_priority TEXT DEFAULT 'NORMAL',
              notes TEXT,
              tags TEXT DEFAULT '[]'
            );
            CREATE TABLE parameters (
              id TEXT PRIMARY KEY, endpoint_id TEXT, name TEXT, location TEXT
            );
            CREATE TABLE flows (
              id TEXT PRIMARY KEY,
              project_id TEXT,
              captured_at TEXT,
              response_end TEXT,
              method TEXT,
              url TEXT,
              host TEXT,
              path TEXT,
              query TEXT DEFAULT '',
              request_headers TEXT DEFAULT '{}',
              request_cookies TEXT DEFAULT '{}',
              request_body BLOB,
              request_body_truncated INTEGER DEFAULT 0,
              status_code INTEGER,
              response_headers TEXT DEFAULT '{}',
              response_body BLOB,
              response_body_truncated INTEGER DEFAULT 0,
              content_type TEXT DEFAULT '',
              session_id TEXT,
              endpoint_id TEXT,
              role_id TEXT,
              module_id TEXT,
              tags TEXT DEFAULT '[]',
              source TEXT DEFAULT 'proxy_capture',
              original_flow_id TEXT,
              replay_error TEXT,
              replay_reason TEXT,
              flow_meta TEXT DEFAULT '{}'
            );
            CREATE TABLE replay_diffs (
              replay_flow_id TEXT PRIMARY KEY,
              original_flow_id TEXT,
              verdict TEXT,
              status_diff TEXT,
              length_diff INTEGER
            );
            CREATE TABLE bac_results (
              replay_flow_id TEXT PRIMARY KEY,
              verdict TEXT,
              attack_type TEXT,
              variant TEXT
            );
            CREATE TABLE unauth_results (
              replay_flow_id TEXT PRIMARY KEY,
              verdict TEXT,
              auth_mutation TEXT
            );
            CREATE TABLE cors_results (
              replay_flow_id TEXT PRIMARY KEY,
              original_flow_id TEXT,
              host TEXT,
              technique TEXT,
              verdict TEXT
            );
            CREATE TABLE auth_test_results (
              replay_flow_id TEXT PRIMARY KEY,
              verdict TEXT
            );
            CREATE TABLE findings (
              id TEXT PRIMARY KEY,
              project_id TEXT,
              title TEXT,
              status TEXT,
              attack_type TEXT,
              verdict TEXT
            );
            CREATE TABLE finding_evidence (
              id TEXT PRIMARY KEY,
              finding_id TEXT,
              evidence_type TEXT,
              reference_id TEXT,
              label TEXT DEFAULT '',
              data TEXT DEFAULT '{}',
              created_at TEXT
            );
            CREATE TABLE scheduler_jobs (
              job_id TEXT PRIMARY KEY,
              endpoint_id TEXT,
              flow_id TEXT,
              job_type TEXT,
              priority INTEGER DEFAULT 10,
              status TEXT,
              created_at TEXT,
              scheduled_at TEXT,
              started_at TEXT,
              finished_at TEXT,
              failure_reason TEXT,
              replayed_flow_id TEXT,
              verdict TEXT,
              meta TEXT
            );
            CREATE TABLE role_auth_provider (
              role_id TEXT PRIMARY KEY, provider TEXT, updated_at TEXT
            );
            CREATE TABLE role_auth_state (
              role_id TEXT, key TEXT, value TEXT, collected_at TEXT
            );
            CREATE TABLE session_health_config (
              role_id TEXT PRIMARY KEY,
              ttl_seconds INTEGER,
              refresh_before_seconds INTEGER
            );
            CREATE TABLE session_suspicion_state (
              role_id TEXT PRIMARY KEY,
              suspicion_count INTEGER DEFAULT 0,
              last_checked_at TEXT
            );
            """
        )
        conn.execute("INSERT INTO roles VALUES ('role-1', 'admin')")
        conn.execute("INSERT INTO modules VALUES ('mod-1', 'api')")
        conn.execute(
            "INSERT INTO endpoints VALUES ('ep-1', 'demo', 'GET', 'ex.com', '/u', '/u')"
        )
        conn.execute(
            """
            INSERT INTO endpoint_policy
            (endpoint_id, qualified, qualification_reason, baseline_flow_id, tags)
            VALUES ('ep-1', 1, 'flow_2xx', 'flow-orig', '[]')
            """
        )
        conn.execute(
            "INSERT INTO parameters VALUES ('p1', 'ep-1', 'id', 'query')"
        )
        # original capture
        conn.execute(
            """
            INSERT INTO flows (
              id, project_id, captured_at, response_end, method, url, host, path, query,
              request_headers, request_cookies, request_body, request_body_truncated,
              status_code, response_headers, response_body, response_body_truncated,
              content_type, endpoint_id, role_id, module_id, tags, source, flow_meta
            ) VALUES (
              'flow-orig', 'demo', '2024-01-01T10:00:00+00:00', '2024-01-01T10:00:00.250+00:00',
              'GET', 'https://ex.com/u?id=1', 'ex.com', '/u', 'id=1',
              '{"Host":"ex.com","Cookie":"session=abc","Authorization":"Bearer x.y.z"}',
              '{"session":"abc"}',
              'hello', 0,
              200, '{"Content-Type":"application/json"}', '{"ok":true}', 0,
              'application/json', 'ep-1', 'role-1', 'mod-1', '["t1"]', 'proxy_capture',
              '{"generated_by":"proxy"}'
            )
            """
        )
        # replay child with diff + bac
        conn.execute(
            """
            INSERT INTO flows (
              id, project_id, captured_at, response_end, method, url, host, path, query,
              request_headers, request_cookies, status_code, response_headers,
              content_type, endpoint_id, role_id, module_id, tags, source,
              original_flow_id, replay_reason, flow_meta
            ) VALUES (
              'flow-replay', 'demo', '2024-01-01T11:00:00+00:00', '2024-01-01T11:00:00.100+00:00',
              'GET', 'https://ex.com/u?id=1', 'ex.com', '/u', 'id=1',
              '{}', '{}', 200, '{}',
              '', 'ep-1', 'role-1', 'mod-1', '[]', 'manual_replay',
              'flow-orig', 'testing', '{}'
            )
            """
        )
        conn.execute(
            "INSERT INTO replay_diffs VALUES ('flow-replay', 'flow-orig', 'same', '200→200', 0)"
        )
        # Attack-module replay flows (newer than capture so adjacent of orig is unchanged)
        conn.execute(
            """
            INSERT INTO flows (
              id, project_id, captured_at, method, url, host, path, query,
              request_headers, request_cookies, status_code, response_headers,
              content_type, endpoint_id, role_id, module_id, tags, source,
              original_flow_id, replay_reason, flow_meta
            ) VALUES
            (
              'flow-iv', 'demo', '2024-01-01T12:00:00+00:00',
              'GET', 'https://ex.com/u?id=1', 'ex.com', '/u', 'id=1',
              '{}', '{}', 200, '{}',
              '', 'ep-1', 'role-1', 'mod-1', '[]', 'auto_replay',
              'flow-orig', 'input_validation',
              '{"generated_by":"input_validation","analysis":"baseline"}'
            ),
            (
              'flow-cors', 'demo', '2024-01-01T12:30:00+00:00',
              'GET', 'https://ex.com/u?id=1', 'ex.com', '/u', 'id=1',
              '{}', '{}', 200, '{}',
              '', 'ep-1', 'role-1', 'mod-1', '[]', 'auto_replay',
              'flow-orig', 'cors_attack',
              '{"attack_module":"cors","technique":"reflected_origin"}'
            ),
            (
              'flow-bac', 'demo', '2024-01-01T13:00:00+00:00',
              'GET', 'https://ex.com/u?id=1', 'ex.com', '/u', 'id=1',
              '{}', '{}', 200, '{}',
              '', 'ep-1', 'role-1', 'mod-1', '[]', 'auto_replay',
              'flow-orig', 'bac_session_swap',
              '{"attack_module":"bac","attack_type":"bac_session_swap"}'
            )
            """
        )
        conn.execute(
            "INSERT INTO bac_results VALUES ('flow-replay', 'likely', 'horizontal', 'id')"
        )
        conn.execute(
            "INSERT INTO bac_results VALUES ('flow-bac', 'POSSIBLE_BAC', 'bac_session_swap', 'id')"
        )
        conn.execute(
            """
            INSERT INTO cors_results
            (replay_flow_id, original_flow_id, host, technique, verdict)
            VALUES ('flow-cors', 'flow-orig', 'ex.com', 'reflected_origin', 'CORS_MISCONFIG')
            """
        )
        conn.execute(
            """
            INSERT INTO findings VALUES
            ('find-1', 'demo', 'IDOR', 'TRIAGING', 'bac', 'likely')
            """
        )
        conn.execute(
            """
            INSERT INTO finding_evidence VALUES
            ('ev-1', 'find-1', 'replay_flow', 'flow-replay', 'replay', '{}',
             '2024-01-01T12:00:00+00:00')
            """
        )
        conn.execute(
            """
            INSERT INTO scheduler_jobs
            (job_id, flow_id, job_type, status, priority, created_at)
            VALUES ('job-1', 'flow-orig', 'replay_flow', 'done', 100, '2024-01-01T10:30:00+00:00')
            """
        )
        conn.execute(
            "INSERT INTO role_auth_provider VALUES ('role-1', 'auto', '2024-01-01')"
        )
        conn.execute(
            "INSERT INTO role_auth_state VALUES ('role-1', 'cookie:session', 'abc', '2024-01-01T09:00:00+00:00')"
        )
        conn.execute(
            "INSERT INTO session_health_config (role_id, ttl_seconds, refresh_before_seconds) VALUES ('role-1', 3600, 300)"
        )
        conn.execute(
            "INSERT INTO session_suspicion_state VALUES ('role-1', 0, NULL)"
        )
        conn.commit()
    finally:
        conn.close()


@pytest.fixture()
def client(home):
    _talos_home, projects, registry = home
    proj_dir = projects / "demo"
    proj_dir.mkdir()
    db_path = proj_dir / "talos.db"
    _init_flow_db(db_path)
    _write_registry(
        registry,
        {
            "demo": {
                "id": "demo",
                "name": "Demo",
                "status": "active",
                "data_dir": str(proj_dir),
            }
        },
    )
    from talos_ui.main import app

    return TestClient(app)


def test_flow_detail_derived_and_results(client):
    res = client.get("/api/flows/flow-orig", params={"project_id": "demo"})
    assert res.status_code == 200
    body = res.json()
    assert body["flow"]["id"] == "flow-orig"
    assert body["flow"]["request_cookies"]["session"] == "abc"
    assert body["flow"]["flow_meta"]["generated_by"] == "proxy"
    assert body["derived"]["duration_ms"] == 250
    assert body["derived"]["request_body_size"] == 5
    assert body["derived"]["has_auth_material"] is True
    assert body["derived"]["has_request_body"] is True
    # child has diff — surface on original for chip purposes
    assert body["results"]["diff"] is not None
    assert body["results"]["diff"].get("_from_child") is True
    # backward-compatible keys
    assert "diff" in body
    assert body["endpoint_policy"]["qualified"] == 1


def test_flow_detail_replay_has_bac(client):
    res = client.get("/api/flows/flow-replay", params={"project_id": "demo"})
    assert res.status_code == 200
    body = res.json()
    assert body["results"]["bac"]["verdict"] == "likely"
    assert body["bac_result"]["verdict"] == "likely"
    assert body["derived"]["is_replay"] is True


def test_flow_related(client):
    res = client.get("/api/flows/flow-orig/related", params={"project_id": "demo"})
    assert res.status_code == 200
    body = res.json()
    assert body["original"] is None
    child_ids = {c["id"] for c in body["children"]}
    assert child_ids == {"flow-replay", "flow-iv", "flow-cors", "flow-bac"}
    replay = next(c for c in body["children"] if c["id"] == "flow-replay")
    assert replay["diff_verdict"] == "same"
    assert body["jobs"][0]["job_id"] == "job-1"
    assert body["param_count"] == 1
    # PR5: optional url_sinks strip when endpoint_id present
    assert "url_sinks" in body
    if body["url_sinks"] is not None:
        assert body["url_sinks"]["endpoint_id"]
        assert "nrs_count" in body["url_sinks"]
        assert "max_score" in body["url_sinks"]


def test_flow_related_findings_on_replay(client):
    res = client.get("/api/flows/flow-replay/related", params={"project_id": "demo"})
    assert res.status_code == 200
    body = res.json()
    assert body["original"]["id"] == "flow-orig"
    assert len(body["findings"]) == 1
    assert body["findings"][0]["finding_id"] == "find-1"


def test_flow_intelligence(client):
    res = client.get("/api/flows/flow-orig/intelligence", params={"project_id": "demo"})
    assert res.status_code == 200
    body = res.json()
    assert body["endpoint"]["id"] == "ep-1"
    assert body["endpoint"]["qualified"] == 1
    assert body["session"]["provider"] == "auto"
    assert body["session"]["has_artifacts"] is True
    assert body["session"]["health_degraded"] is False


def test_list_with_flags(client):
    res = client.get(
        "/api/flows", params={"project_id": "demo", "include": "flags", "limit": 50}
    )
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 5
    by_id = {f["id"]: f for f in body["flows"]}
    assert by_id["flow-replay"]["is_replay"] is True
    assert by_id["flow-replay"]["has_diff"] is True
    assert by_id["flow-replay"]["has_bac"] is True
    assert by_id["flow-replay"]["has_finding_evidence"] is True
    assert by_id["flow-orig"]["has_diff"] is True  # via child


def test_adjacent_global(client):
    res = client.get(
        "/api/flows/flow-orig/adjacent", params={"project_id": "demo"}
    )
    assert res.status_code == 200
    body = res.json()
    # ordered by captured_at DESC: flow-replay (newer), flow-orig (older)
    assert body["prev_id"] == "flow-replay"
    assert body["next_id"] is None


def test_adjacent_filter_aware(client):
    res = client.get(
        "/api/flows/flow-orig/adjacent",
        params={"project_id": "demo", "source": "proxy_capture"},
    )
    assert res.status_code == 200
    body = res.json()
    # only one proxy_capture flow
    assert body["prev_id"] is None
    assert body["next_id"] is None


def test_export_uses_cli(client):
    with patch("talos_ui.routers.flows.cli.run_scoped") as run_scoped:
        r = MagicMock()
        r.to_dict.return_value = {
            "cmd": ["flow", "export", "flow-orig"],
            "ok": True,
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 1,
        }
        run_scoped.return_value = [r]
        res = client.post(
            "/api/flows/flow-orig/export", params={"project_id": "demo"}
        )
        assert res.status_code == 200
        run_scoped.assert_called_once()
        assert run_scoped.call_args[0][1][:3] == ["flow", "export", "flow-orig"]


def test_filters_include_attack_modules(client):
    res = client.get("/api/flows/filters", params={"project_id": "demo"})
    assert res.status_code == 200
    body = res.json()
    mods = body["attack_modules"]
    for expected in ("iv", "bac", "unauth", "cors", "sqli", "auth_session", "auth_test", "intruder"):
        assert expected in mods


def test_list_filter_by_attack_module(client):
    res = client.get(
        "/api/flows",
        params={"project_id": "demo", "attack_module": "iv", "limit": 50},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 1
    assert body["flows"][0]["id"] == "flow-iv"
    assert body["flows"][0]["attack_module"] == "iv"

    res = client.get(
        "/api/flows",
        params={"project_id": "demo", "attack_module": "cors", "limit": 50},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 1
    assert body["flows"][0]["id"] == "flow-cors"
    assert body["flows"][0]["attack_module"] == "cors"
    assert body["flows"][0]["attack_verdict"] == "CORS_MISCONFIG"

    # Alias: input_validation → iv
    res = client.get(
        "/api/flows",
        params={"project_id": "demo", "attack_module": "input_validation", "limit": 50},
    )
    assert res.status_code == 200
    assert res.json()["total"] == 1

    res = client.get(
        "/api/flows",
        params={"project_id": "demo", "attack_module": "bac", "limit": 50},
    )
    assert res.status_code == 200
    assert res.json()["flows"][0]["attack_module"] == "bac"
    assert res.json()["flows"][0]["attack_verdict"] == "POSSIBLE_BAC"


def test_adjacent_attack_module_filter(client):
    res = client.get(
        "/api/flows/flow-iv/adjacent",
        params={"project_id": "demo", "attack_module": "iv"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["prev_id"] is None
    assert body["next_id"] is None


def test_flow_not_found(client):
    res = client.get("/api/flows/missing", params={"project_id": "demo"})
    assert res.status_code == 404
