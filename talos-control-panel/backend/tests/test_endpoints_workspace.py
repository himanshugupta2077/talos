"""
Endpoint Workspace API tests.

Covers bulk multi-ID CLI mutation wiring, static route ordering, and
resolved-read helpers. Mutations must use a single multi-ID CLI argv —
never N sequential mark/priority commands for bulk.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("TALOS_HOME", str(tmp_path / "talos-home"))
    from talos_ui.main import app

    return TestClient(app)


def _ok_result(cmd=None, stdout=""):
    r = MagicMock()
    r.ok = True
    r.to_dict.return_value = {
        "cmd": cmd or [],
        "cmd_str": " ".join(cmd or []),
        "stdout": stdout,
        "stderr": "",
        "exit_code": 0,
        "ok": True,
        "duration_ms": 1,
    }
    return r


def test_test_flows_ranks_top_per_endpoint(tmp_path, monkeypatch):
    import sqlite3

    monorepo = Path(__file__).resolve().parents[3]
    if str(monorepo) not in sys.path:
        sys.path.insert(0, str(monorepo))
    from talos.projects.db import init_project_db

    talos_home = tmp_path / "talos-home"
    projects = talos_home / "projects"
    data_dir = projects / "demo"
    data_dir.mkdir(parents=True)
    db_path = data_dir / "talos.db"
    init_project_db(db_path)
    now = "2026-01-01T00:00:00+00:00"
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute("SELECT id FROM roles WHERE name='global'").fetchone()[0]
        module = conn.execute("SELECT id FROM modules WHERE name='global'").fetchone()[0]
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES ('ep-a', 'demo', 'GET', 'https://app.example.com', '/a', '/a',
                    'application/json', 0, '[]', ?, ?)
            """,
            (now, now),
        )
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, auto_priority, auto_score, excluded,
                 dangerous, logout, qualified, qualification_reason,
                 baseline_flow_id, baseline_status, updated_at)
            VALUES ('ep-a', 'HIGH', 50, 0, 0, 0, 1, 'flow_2xx', 'flow-base', 200, ?)
            """,
            (now,),
        )
        for fid, method, captured in (
            ("flow-base", "GET", "2026-01-01T00:00:00+00:00"),
            ("flow-post", "POST", "2026-01-02T00:00:00+00:00"),
        ):
            conn.execute(
                """
                INSERT INTO flows
                    (id, project_id, captured_at, method, url, host, path,
                     query, request_headers, status_code, endpoint_id,
                     role_id, module_id, tags, source)
                VALUES (?, 'demo', ?, ?, 'https://app.example.com/a',
                        'app.example.com', '/a', '', '{}', 200, 'ep-a',
                        ?, ?, '[]', 'proxy_capture')
                """,
                (fid, captured, method, role, module),
            )
        conn.commit()

    monkeypatch.setenv("TALOS_HOME", str(talos_home))
    import talos_ui.config as cfg
    import talos_ui.db as ui_db

    monkeypatch.setattr(cfg, "TALOS_HOME", talos_home)
    monkeypatch.setattr(
        ui_db,
        "get_project_record",
        lambda _pid: {"id": "demo", "data_dir": str(data_dir)},
    )
    monkeypatch.setattr(
        cfg, "project_db_path", lambda _pid, _rec=None: db_path
    )

    from talos_ui.main import app

    tc = TestClient(app)
    res = tc.post(
        "/api/endpoints/test-flows",
        params={"project_id": "demo"},
        json={"endpoint_ids": ["ep-a"], "limit": 5},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["flow_ids"][0] == "flow-base"
    assert "flow-post" in body["flow_ids"]
    assert body["limit_per_endpoint"] == 5


def test_bulk_mark_uses_multi_id_single_cli(client):
    bulk_json = (
        '{"action":"mark --dangerous","affected":2,"unchanged":0,'
        '"affected_ids":["a","b"],"unchanged_ids":[],"count":2,"endpoints":[]}'
    )
    with patch("talos_ui.routers.endpoints.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [
            _ok_result(["project", "open", "demo"]),
            _ok_result(
                ["endpoint", "mark", "id-1", "id-2", "--dangerous", "--format", "json"],
                stdout=bulk_json,
            ),
        ]
        res = client.post(
            "/api/endpoints/bulk/mark",
            params={"project_id": "demo"},
            json={"endpoint_ids": ["id-1", "id-2"], "tag": "dangerous"},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        assert body["bulk"]["affected"] == 2
        run_scoped.assert_called_once()
        args = run_scoped.call_args[0]
        assert args[0] == "demo"
        assert args[1][0:2] == ["endpoint", "mark"]
        assert "id-1" in args[1] and "id-2" in args[1]
        assert "--dangerous" in args[1]
        assert "--format" in args[1] and "json" in args[1]
        # Single mutation argv — not two separate mark calls
        assert run_scoped.call_count == 1


def test_bulk_priority_set_and_clear(client):
    with patch("talos_ui.routers.endpoints.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result(stdout='{"affected":1,"unchanged":0,"count":1}')]
        res = client.post(
            "/api/endpoints/bulk/priority",
            params={"project_id": "demo"},
            json={"endpoint_ids": ["e1", "e2"], "priority": "HIGH"},
        )
        assert res.status_code == 200
        argv = run_scoped.call_args[0][1]
        assert argv[:4] == ["endpoint", "priority", "set", "endpoint"]
        assert argv[-3] == "HIGH" or "HIGH" in argv

        run_scoped.reset_mock()
        run_scoped.return_value = [_ok_result(stdout='{"affected":1,"unchanged":1,"count":2}')]
        res = client.post(
            "/api/endpoints/bulk/priority",
            params={"project_id": "demo"},
            json={"endpoint_ids": ["e1"], "clear": True},
        )
        assert res.status_code == 200
        argv = run_scoped.call_args[0][1]
        assert argv[:4] == ["endpoint", "priority", "clear", "endpoint"]


def test_bulk_requires_ids(client):
    res = client.post(
        "/api/endpoints/bulk/exclude",
        params={"project_id": "demo"},
        json={"endpoint_ids": []},
    )
    assert res.status_code == 400


def test_rule_create_uses_cli(client):
    with patch("talos_ui.routers.endpoints.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [
            _ok_result(stdout='{"action":"rule add","rule":{"id":"r1","pattern":"/api/*"}}')
        ]
        res = client.post(
            "/api/endpoints/rules",
            params={"project_id": "demo"},
            json={"pattern": "/api/admin/*", "priority": "HIGH", "exclude": False},
        )
        assert res.status_code == 200
        argv = run_scoped.call_args[0][1]
        assert argv[:3] == ["endpoint", "rule", "add"]
        assert "/api/admin/*" in argv
        assert "--priority" in argv and "HIGH" in argv


def test_rule_preview_static_route_not_captured_as_id(client):
    """POST /rules/preview must not be routed as /rules/{rule_id}."""
    with patch("talos_ui.routers.endpoints.endpoint_reads.policy_mod") as pol_mod:
        with patch("talos_ui.routers.endpoints.db.db_exists", return_value=True):
            with patch("talos_ui.routers.endpoints.db.get_project_record", return_value={}):
                with patch(
                    "talos_ui.routers.endpoints.config.project_db_path",
                    return_value=Path("/tmp/nope"),
                ):
                    mock_pol = MagicMock()
                    mock_pol.preview_path_rule_impact.return_value = {
                        "pattern": "/x/*",
                        "matching_count": 0,
                        "endpoints": [],
                    }
                    pol_mod.return_value = mock_pol
                    res = client.post(
                        "/api/endpoints/rules/preview",
                        params={"project_id": "demo"},
                        json={"pattern": "/x/*", "priority": "HIGH"},
                    )
                    assert res.status_code == 200
                    assert res.json()["matching_count"] == 0


def test_decision_and_state_helpers():
    from talos_ui.endpoint_reads import decision_for, state_for

    assert decision_for({"qualified": True, "excluded": False}) == "TESTABLE"
    assert decision_for({"qualified": True, "excluded": True}) == "SKIPPED"
    assert state_for({"logout": True}) == "LOGOUT"
    assert state_for({"dangerous": True, "logout": False}) == "DANGEROUS"
    assert state_for({"excluded": True, "dangerous": False, "logout": False}) == "EXCLUDED"
    assert state_for(
        {"qualified": False, "excluded": False, "dangerous": False, "logout": False}
    ) == "UNQUALIFIED"
    assert state_for(
        {"qualified": True, "excluded": False, "dangerous": False, "logout": False}
    ) == "TESTABLE"


def test_parse_bulk_stdout():
    from talos_ui.endpoint_reads import parse_bulk_stdout

    raw = '{"affected": 3, "unchanged": 1, "count": 4}'
    assert parse_bulk_stdout(raw)["affected"] == 3
    assert parse_bulk_stdout("") == {}


def test_suggest_path_not_in_backend():
    """Sanity: inventory filters empty project returns empty list without crash."""
    from talos_ui import endpoint_reads
    from talos_ui import config as cfg

    with patch.object(endpoint_reads, "_db_path", return_value=Path("/nonexistent/talos.db")):
        with patch.object(endpoint_reads.db, "db_exists", return_value=False):
            assert endpoint_reads.list_resolved("missing") == []
            assert endpoint_reads.inventory_summary("missing")["total"] == 0


def test_enrich_parameter_url_sink_uuid_parity():
    """param_uuid must match make_param_uuid(raw host, location, name) — K10."""
    import json

    from talos.input_validation.db import make_param_uuid
    from talos_ui.routers.endpoints import _enrich_parameter_url_sink

    host_raw = "https://api.example.com"
    p = {
        "name": "callback",
        "location": "query",
        "url_features": json.dumps(
            {
                "score": 95,
                "possible_network_resource": True,
                "name_category": "redirect",
                "looks_like": ["url"],
            }
        ),
    }
    _enrich_parameter_url_sink(p, host_raw)
    assert p["url_score"] == 95
    assert p["possible_network_resource"] is True
    assert p["name_category"] == "redirect"
    assert p["param_uuid"] == make_param_uuid(host_raw, "query", "callback")
    assert p["inventory_only"] is False

    jwt_p = {
        "name": "jwt.jku",
        "location": "header",
        "url_features": {"score": 90, "possible_network_resource": True},
    }
    _enrich_parameter_url_sink(jwt_p, "api.example.com")
    assert jwt_p["inventory_only"] is True

    resp_p = {
        "name": "href",
        "location": "response",
        "url_features": {},
    }
    _enrich_parameter_url_sink(resp_p, "api.example.com")
    assert resp_p["inventory_only"] is True
    assert resp_p["url_score"] == 0


def test_endpoint_detail_parses_url_features(tmp_path, monkeypatch):
    """GET /api/endpoints/{id} exposes url_score / param_uuid from url_features."""
    import json
    import sqlite3

    from talos.input_validation.db import make_param_uuid

    talos_home = tmp_path / "talos-home"
    projects = talos_home / "projects"
    data_dir = projects / "demo"
    data_dir.mkdir(parents=True)
    db_path = data_dir / "talos.db"
    registry = projects / "registry.json"
    monkeypatch.setenv("TALOS_HOME", str(talos_home))

    host = "https://api.example.com"
    uf = {
        "score": 95,
        "possible_network_resource": True,
        "name_category": None,
        "looks_like": ["url"],
        "evidence": ["value_scheme:https"],
    }
    conn = sqlite3.connect(str(db_path))
    conn.executescript(
        f"""
        CREATE TABLE endpoints (
          id TEXT PRIMARY KEY, host TEXT, method TEXT, path TEXT,
          normalized_path TEXT, first_seen TEXT, last_seen TEXT
        );
        CREATE TABLE endpoint_policy (endpoint_id TEXT PRIMARY KEY, tags TEXT);
        CREATE TABLE endpoint_annotations (endpoint_id TEXT, tag TEXT, created_at TEXT);
        CREATE TABLE endpoint_roles (endpoint_id TEXT, role_id TEXT, first_seen TEXT, last_seen TEXT);
        CREATE TABLE roles (id TEXT PRIMARY KEY, name TEXT);
        CREATE TABLE modules (id TEXT PRIMARY KEY, name TEXT);
        CREATE TABLE flows (
          id TEXT PRIMARY KEY, endpoint_id TEXT, method TEXT, path TEXT,
          status_code INTEGER, captured_at TEXT, source TEXT, role_id TEXT, module_id TEXT
        );
        CREATE TABLE parameters (
          id TEXT PRIMARY KEY, endpoint_id TEXT, name TEXT, location TEXT,
          param_type TEXT, semantic_type TEXT, example_values TEXT,
          seen_count INTEGER, appears_in_roles TEXT, appears_in_modules TEXT,
          reflection_locations TEXT, is_reflected INTEGER, reflection_count INTEGER,
          url_features TEXT
        );
        INSERT INTO endpoints (id, host, method, path, normalized_path)
        VALUES ('ep1', '{host}', 'GET', '/avatar', '/avatar');
        INSERT INTO parameters (
          id, endpoint_id, name, location, param_type, semantic_type,
          example_values, seen_count, appears_in_roles, appears_in_modules,
          reflection_locations, is_reflected, reflection_count, url_features
        ) VALUES (
          'p1', 'ep1', 'callback', 'query', 'string', 'url',
          '["https://cdn.example/x"]', 2, '[]', '[]', '[]', 0, 0,
          '{json.dumps(uf)}'
        );
        """
    )
    conn.commit()
    conn.close()
    registry.write_text(
        json.dumps(
            {
                "demo": {
                    "id": "demo",
                    "name": "demo",
                    "status": "active",
                    "data_dir": str(data_dir),
                }
            }
        ),
        encoding="utf-8",
    )

    import talos_ui.config as cfg

    monkeypatch.setattr(cfg, "TALOS_HOME", talos_home)
    monkeypatch.setattr(cfg, "PROJECTS_ROOT", projects)
    monkeypatch.setattr(cfg, "REGISTRY_PATH", registry)
    monorepo = Path(__file__).resolve().parents[3]
    monkeypatch.setattr(cfg, "TALOS_ROOT", monorepo)

    from talos_ui.main import app

    tc = TestClient(app)
    with patch("talos_ui.endpoint_reads.explain_policy", return_value=None):
        res = tc.get("/api/endpoints/ep1", params={"project_id": "demo"})
    assert res.status_code == 200
    body = res.json()
    params = body["parameters"]
    assert len(params) == 1
    p = params[0]
    assert p["url_score"] == 95
    assert p["possible_network_resource"] is True
    assert p["param_uuid"] == make_param_uuid(host, "query", "callback")
    assert p["inventory_only"] is False
    assert isinstance(p["url_features"], dict)
