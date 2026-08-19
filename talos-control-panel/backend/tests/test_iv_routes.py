"""
Control Panel IV workspace routes — smoke tests.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

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
    monorepo = Path(__file__).resolve().parents[3]
    monkeypatch.setattr(cfg, "TALOS_ROOT", monorepo)
    return talos_home, projects, registry


def _write_registry(registry: Path, projects: dict):
    registry.write_text(json.dumps(projects), encoding="utf-8")


def _init_iv_db(db_path: Path):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE input_validation_config (
              id TEXT PRIMARY KEY,
              enabled INTEGER DEFAULT 1,
              workers INTEGER DEFAULT 2,
              probe_strategy TEXT DEFAULT 'standard',
              max_requests_per_param INTEGER DEFAULT 0,
              include_auth_artifacts INTEGER DEFAULT 0,
              analyses_baseline INTEGER DEFAULT 1,
              analyses_multiprobe INTEGER DEFAULT 1,
              analyses_identifier INTEGER DEFAULT 1,
              analyses_characters INTEGER DEFAULT 1,
              analyses_length INTEGER DEFAULT 1,
              analyses_types INTEGER DEFAULT 1,
              analyses_transformations INTEGER DEFAULT 1,
              analyses_reflection INTEGER DEFAULT 1,
              analyses_validation INTEGER DEFAULT 1,
              excluded_hosts TEXT DEFAULT '[]',
              excluded_endpoints TEXT DEFAULT '[]'
            );
            INSERT INTO input_validation_config (id) VALUES ('default');
            CREATE TABLE iv_param_cache (
              id TEXT PRIMARY KEY,
              host TEXT, location TEXT, param_name TEXT, phase TEXT,
              status TEXT DEFAULT 'completed', result TEXT DEFAULT '{}'
            );
            CREATE TABLE iv_reflection_cache (
              id TEXT PRIMARY KEY, status TEXT DEFAULT 'completed'
            );
            CREATE TABLE iv_probe_results (
              id TEXT PRIMARY KEY, param_uuid TEXT, status TEXT, analysis TEXT
            );
            CREATE TABLE scheduler_jobs (
              id TEXT PRIMARY KEY, job_type TEXT, status TEXT, meta TEXT
            );
            CREATE TABLE endpoints (
              id TEXT PRIMARY KEY,
              host TEXT, method TEXT, path TEXT, normalized_path TEXT
            );
            CREATE TABLE parameters (
              id TEXT PRIMARY KEY,
              endpoint_id TEXT, name TEXT, location TEXT
            );
            CREATE TABLE iv_param_profiles (
              param_uuid TEXT PRIMARY KEY,
              host TEXT, location TEXT, param_name TEXT,
              profile TEXT, updated_at TEXT
            );
            CREATE TABLE iv_endpoint_profiles (
              id TEXT,
              endpoint_id TEXT PRIMARY KEY,
              host TEXT,
              profile TEXT,
              updated_at TEXT
            );
            CREATE TABLE iv_app_profiles (
              id TEXT,
              host TEXT PRIMARY KEY,
              profile TEXT,
              updated_at TEXT
            );
            INSERT INTO endpoints (id, host, method, path, normalized_path)
            VALUES ('ep1', 'api.example.com', 'GET', '/q', '/q');
            INSERT INTO parameters (id, endpoint_id, name, location)
            VALUES ('p1', 'ep1', 'q', 'query');
            INSERT INTO iv_param_profiles
              (param_uuid, host, location, param_name, profile, updated_at)
            VALUES (
              'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
              'api.example.com', 'query', 'q',
              '{"schema_version":1,"engine_version":"test","profile_version":1,
                "param_uuid":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "host":"api.example.com","location":"query","name":"q",
                "capabilities":["reflective_input","network_resource_sink","fetch_sink"],
                "candidates":[{"attack":"xss","score":90,"confidence":80,
                  "reasons":["test"],"evidence_flow_ids":[]},
                  {"attack":"ssrf","score":72,"confidence":60,"reasons":["url sink"]}],
                "observed":{"reflection":{"state":"reflected","confidence":90},
                  "length":{"state":"bounded","max_accepted":64},
                  "types":{"_summary":{"primary":"string"}},
                  "url_features":{"score":95,"possible_network_resource":true,
                    "name_category":"remote_fetch","looks_like":["url"]},
                  "url_sink":{"confidence":92,"accepts_url":true,"accepts_hostname":false,
                    "redirect_behavior":false,"fetch_behavior":true,
                    "dns_resolution_detected":false,"accepted_protocols":["https"],
                    "error_classes":[]},
                  "acceptance":{"classes":{"quote":{"outcome":"accepted","confidence":80}}}},
                "inferred":{},"tested":{"unicode":{"outcome":"rejected","confidence":88}},
                "requests_used":6,"budget_tier":"standard"}',
              '2026-01-01T00:00:00Z'
            );
            INSERT INTO iv_endpoint_profiles
              (id, endpoint_id, host, profile, updated_at)
            VALUES (
              'eprow1', 'ep1', 'api.example.com',
              '{"schema_version":1,"endpoint_id":"ep1","host":"api.example.com",
                "method":"GET","path":"/q","capabilities":["json_parser"],
                "tested":{"null_byte":{"outcome":"rejected","confidence":90}},
                "parser":{"dup_query":"last_wins"}}',
              '2026-01-01T00:00:00Z'
            );
            INSERT INTO iv_app_profiles
              (id, host, profile, updated_at)
            VALUES (
              'arow1', 'api.example.com',
              '{"schema_version":1,"host":"api.example.com",
                "capabilities":["unicode_support"],
                "tested":{"control":{"outcome":"rejected","confidence":80}}}',
              '2026-01-01T00:00:00Z'
            );
            INSERT INTO iv_probe_results (id, param_uuid, status, analysis)
            VALUES ('pr1', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'completed', 'baseline');
            """
        )
        conn.commit()
    finally:
        conn.close()


@pytest.fixture()
def client(home):
    talos_home, projects, registry = home
    pid = "proj1"
    data_dir = projects / pid
    data_dir.mkdir()
    db_path = data_dir / "talos.db"
    _init_iv_db(db_path)
    _write_registry(
        registry,
        {
            pid: {
                "id": pid,
                "name": "proj1",
                "status": "active",
                "data_dir": str(data_dir),
            }
        },
    )
    from talos_ui.main import app

    return TestClient(app), pid


def test_iv_status_route(client):
    tc, pid = client
    r = tc.get("/api/input-validation/status", params={"project_id": pid})
    assert r.status_code == 200
    body = r.json()
    assert "budget_tier" in body or "param_cache" in body
    if "confidence" in body:
        assert "buckets" in body["confidence"]


def test_iv_overview_route(client):
    tc, pid = client
    r = tc.get("/api/input-validation/overview", params={"project_id": pid, "top_n": 5})
    assert r.status_code == 200
    body = r.json()
    assert "status" in body
    assert "top_candidates" in body
    assert "empty_state" in body
    assert "note" in body


def test_iv_candidates_route(client):
    tc, pid = client
    r = tc.get(
        "/api/input-validation/candidates",
        params={"project_id": pid, "min_score": 1},
    )
    assert r.status_code == 200
    body = r.json()
    assert "candidates" in body
    assert body.get("count", 0) >= 1 or body.get("error")
    if body.get("count", 0) >= 1:
        assert "note" in body
        assert body["candidates"][0]["attack"] == "xss"


def test_iv_profiles_route(client):
    tc, pid = client
    r = tc.get("/api/input-validation/profiles", params={"project_id": pid})
    assert r.status_code == 200
    body = r.json()
    assert "profiles" in body
    assert body["count"] >= 1
    row = body["profiles"][0]
    assert row.get("name") == "q" or row.get("param_uuid")
    # Extended summary fields for Parameters tab
    assert "reflection_state" in row
    assert "top_candidate" in row
    # URL Sink Discovery slim fields (PR2)
    assert row.get("url_score") == 95
    assert row.get("possible_network_resource") is True
    assert row.get("name_category") == "remote_fetch"
    assert row.get("url_sink_confidence") == 92
    assert row.get("has_network_resource_sink") is True
    assert row.get("inventory_only") is False


def test_iv_profiles_filter_capability(client):
    tc, pid = client
    r = tc.get(
        "/api/input-validation/profiles",
        params={"project_id": pid, "capability": "reflective_input"},
    )
    assert r.status_code == 200
    assert r.json()["count"] >= 1
    r2 = tc.get(
        "/api/input-validation/profiles",
        params={"project_id": pid, "capability": "does_not_exist_cap"},
    )
    assert r2.status_code == 200
    assert r2.json()["count"] == 0


def test_iv_show_includes_candidates(client):
    tc, pid = client
    uid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    r = tc.get(
        f"/api/input-validation/show/{uid}",
        params={"project_id": pid},
    )
    assert r.status_code == 200
    body = r.json()
    assert "probes" in body
    if body.get("candidates"):
        assert body["candidates"][0]["attack"] == "xss"


def test_iv_endpoints_list_and_detail(client):
    tc, pid = client
    r = tc.get("/api/input-validation/endpoints", params={"project_id": pid})
    assert r.status_code == 200
    body = r.json()
    assert body.get("count", 0) >= 1
    r2 = tc.get(
        "/api/input-validation/endpoints/ep1",
        params={"project_id": pid},
    )
    assert r2.status_code == 200
    detail = r2.json()
    assert detail.get("endpoint_id") == "ep1"
    assert "parameters" in detail


def test_iv_hosts_list_and_detail(client):
    tc, pid = client
    r = tc.get("/api/input-validation/hosts", params={"project_id": pid})
    assert r.status_code == 200
    body = r.json()
    assert body.get("count", 0) >= 1
    r2 = tc.get(
        "/api/input-validation/hosts/api.example.com",
        params={"project_id": pid},
    )
    assert r2.status_code == 200
    detail = r2.json()
    assert detail.get("host") == "api.example.com"
    assert "candidates" in detail


def test_iv_export_parameter_json(client):
    tc, pid = client
    uid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    r = tc.get(
        f"/api/input-validation/export/parameter/{uid}/json",
        params={"project_id": pid},
    )
    assert r.status_code == 200
    body = r.json()
    if not body.get("error"):
        assert body.get("schema_version") == 1
        assert "capabilities" in body
        assert "candidates" in body
        assert "note" in body


def test_iv_config_returns_phases(client):
    tc, pid = client
    r = tc.get("/api/input-validation/config", params={"project_id": pid})
    assert r.status_code == 200
    body = r.json()
    assert "config" in body
    assert "phases" in body
    assert "parser" not in body["phases"]
    assert "multiprobe" in body["phases"]
    assert "validation" in body["phases"]


def test_iv_run_with_flows(client):
    from unittest.mock import MagicMock, patch

    tc, pid = client

    def _ok():
        r = MagicMock()
        r.ok = True
        r.to_dict.return_value = {
            "cmd": [],
            "stdout": "ok",
            "stderr": "",
            "exit_code": 0,
            "ok": True,
        }
        return r

    with patch("talos_ui.routers.input_validation.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok()]
        res = tc.post(
            "/api/input-validation/run",
            params={"project_id": pid},
            json={"flows": ["flow-a", "flow-b"]},
        )
    assert res.status_code == 200
    assert run_scoped.call_args[0][1] == [
        "input-validation",
        "run",
        "--flow",
        "flow-a",
        "--flow",
        "flow-b",
    ]


def _ok_cli():
    from unittest.mock import MagicMock

    r = MagicMock()
    r.ok = True
    r.to_dict.return_value = {
        "cmd": [],
        "stdout": "enqueued",
        "stderr": "",
        "exit_code": 0,
        "ok": True,
    }
    return r


def test_candidates_run_rejects_unknown_attack(client):
    tc, pid = client
    res = tc.post(
        "/api/input-validation/candidates/run",
        params={"project_id": pid},
        json={"attack": "mass_assignment"},
    )
    assert res.status_code == 400
    assert "dedicated attack runner" in res.json()["detail"]


def test_candidates_run_with_supplied_targets(client):
    from unittest.mock import patch

    tc, pid = client
    with (
        patch(
            "talos_ui.routers.input_validation._lookup_param_row",
            return_value={
                "id": "p1",
                "endpoint_id": "ep1",
                "name": "file",
                "location": "query",
            },
        ),
        patch(
            "talos_ui.routers.input_validation._flows_for_param",
            return_value=["flow-a", "flow-b"],
        ),
        patch("talos_ui.routers.input_validation.cli.run_scoped") as run_scoped,
    ):
        run_scoped.return_value = [_ok_cli()]
        res = tc.post(
            "/api/input-validation/candidates/run",
            params={"project_id": pid},
            json={
                "attack": "path_traversal",
                "candidates": [
                    {
                        "param_uuid": "p1",
                        "name": "file",
                        "location": "query",
                        "attack": "path_traversal",
                        "score": 80,
                    },
                    {
                        "param_uuid": "p2",
                        "name": "path",
                        "location": "query",
                        "attack": "path_traversal",
                        "score": 70,
                    },
                ],
            },
        )
    assert res.status_code == 200
    body = res.json()
    assert body["attack"] == "path_traversal"
    assert body["burp_engine"] == "path-traversal"
    assert body["workspace"] == "/testing/path-traversal"
    assert body["candidate_count"] == 2
    assert body["flow_count"] == 2
    argv = run_scoped.call_args[0][1]
    assert argv[:3] == ["attack", "path-traversal", "run"]
    assert argv.count("--flow") == 2
    assert "--param" in argv
    assert "query:file" in argv
    assert "query:path" in argv
    assert "--high-priority" in argv
    assert "Burp" in body["note"]


def test_candidates_run_no_usable_flows(client):
    from unittest.mock import patch

    tc, pid = client
    with (
        patch(
            "talos_ui.routers.input_validation._lookup_param_row",
            return_value={"id": "p1", "endpoint_id": "ep1", "name": "q", "location": "query"},
        ),
        patch(
            "talos_ui.routers.input_validation._flows_for_param",
            return_value=[],
        ),
        patch("talos_ui.routers.input_validation.cli.run_scoped") as run_scoped,
    ):
        res = tc.post(
            "/api/input-validation/candidates/run",
            params={"project_id": pid},
            json={
                "attack": "xss",
                "candidates": [{"param_uuid": "p1", "name": "q", "location": "query"}],
            },
        )
    assert res.status_code == 400
    assert "usable captured flow" in res.json()["detail"]
    run_scoped.assert_not_called()


def test_candidates_run_skips_inventory_only(client):
    from unittest.mock import patch

    tc, pid = client
    with (
        patch(
            "talos_ui.routers.input_validation._lookup_param_row",
            return_value=None,
        ),
        patch(
            "talos_ui.routers.input_validation._flows_for_param",
            return_value=["flow-a"],
        ),
        patch("talos_ui.routers.input_validation.cli.run_scoped") as run_scoped,
    ):
        run_scoped.return_value = [_ok_cli()]
        res = tc.post(
            "/api/input-validation/candidates/run",
            params={"project_id": pid},
            json={
                "attack": "xss",
                "candidates": [
                    {
                        "param_uuid": "jwt-1",
                        "name": "jwt.sub",
                        "location": "header",
                        "attack": "xss",
                    },
                    {
                        "param_uuid": "p-ok",
                        "name": "q",
                        "location": "query",
                        "attack": "xss",
                    },
                ],
            },
        )
    assert res.status_code == 200
    body = res.json()
    assert body["candidate_count"] == 1
    assert body["targets"][0]["name"] == "q"
    assert any("inventory-only" in (s.get("reason") or "") for s in body["skipped"])
    argv = run_scoped.call_args[0][1]
    assert argv == [
        "attack",
        "xss",
        "run",
        "--flow",
        "flow-a",
        "--param",
        "query:q",
        "--high-priority",
    ]


def test_candidates_run_loads_from_board_when_no_targets(client):
    from unittest.mock import patch

    tc, pid = client
    board = [
        {
            "param_uuid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "name": "q",
            "location": "query",
            "attack": "xss",
            "score": 90,
        }
    ]
    with (
        patch(
            "talos_ui.routers.input_validation._list_candidates_for_run",
            return_value=board,
        ),
        patch(
            "talos_ui.routers.input_validation._lookup_param_row",
            return_value={
                "id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "endpoint_id": "ep1",
                "name": "q",
                "location": "query",
            },
        ),
        patch(
            "talos_ui.routers.input_validation._flows_for_param",
            return_value=["flow-cap"],
        ),
        patch("talos_ui.routers.input_validation.cli.run_scoped") as run_scoped,
    ):
        run_scoped.return_value = [_ok_cli()]
        res = tc.post(
            "/api/input-validation/candidates/run",
            params={"project_id": pid},
            json={"attack": "xss", "min_score": 1},
        )
    assert res.status_code == 200
    body = res.json()
    assert body["candidate_count"] >= 1
    argv = run_scoped.call_args[0][1]
    assert argv[:3] == ["attack", "xss", "run"]
    assert "--flow" in argv
    assert "flow-cap" in argv
    assert "--param" in argv


def test_candidates_run_uses_evidence_flows_when_endpoint_lookup_fails(client):
    """IV param_uuid is not parameters.id — still run from candidate evidence."""
    from unittest.mock import patch

    tc, pid = client
    with (
        patch(
            "talos_ui.routers.input_validation._lookup_param_row",
            return_value=None,
        ),
        patch(
            "talos_ui.routers.input_validation._flows_for_param",
            return_value=[],
        ),
        patch("talos_ui.routers.input_validation.cli.run_scoped") as run_scoped,
    ):
        run_scoped.return_value = [_ok_cli()]
        res = tc.post(
            "/api/input-validation/candidates/run",
            params={"project_id": pid},
            json={
                "attack": "xss",
                "candidates": [
                    {
                        "param_uuid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "name": "q",
                        "location": "query",
                        "host": "api.example.com",
                        "attack": "xss",
                        "score": 90,
                        "evidence_flow_ids": ["flow-evidence"],
                    }
                ],
            },
        )
    assert res.status_code == 200
    body = res.json()
    assert body["candidate_count"] == 1
    assert body["flow_count"] == 1
    argv = run_scoped.call_args[0][1]
    assert argv[:3] == ["attack", "xss", "run"]
    assert "flow-evidence" in argv
    assert "query:q" in argv


def test_candidates_run_uses_iv_probe_flow_when_no_evidence(client):
    from unittest.mock import patch

    tc, pid = client
    with (
        patch(
            "talos_ui.routers.input_validation._lookup_param_row",
            return_value=None,
        ),
        patch(
            "talos_ui.routers.input_validation._flows_for_param",
            return_value=[],
        ),
        patch(
            "talos_ui.routers.input_validation._existing_flow_ids",
            return_value=[],
        ),
        patch(
            "talos_ui.routers.input_validation._iv_source_flow_ids",
            return_value=["flow-baseline"],
        ),
        patch("talos_ui.routers.input_validation.cli.run_scoped") as run_scoped,
    ):
        run_scoped.return_value = [_ok_cli()]
        res = tc.post(
            "/api/input-validation/candidates/run",
            params={"project_id": pid},
            json={
                "attack": "sqli",
                "candidates": [
                    {
                        "param_uuid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "name": "q",
                        "location": "query",
                        "attack": "sqli",
                    }
                ],
            },
        )
    assert res.status_code == 200
    argv = run_scoped.call_args[0][1]
    assert argv[:3] == ["attack", "sqli", "run"]
    assert "flow-baseline" in argv


def test_lookup_param_row_resolves_sha256_profile_uuid(client, home):
    _tc, pid = client
    _talos_home, projects, _registry = home
    db_path = projects / pid / "talos.db"
    from talos_ui.routers.input_validation import _lookup_param_row

    row = _lookup_param_row(
        db_path,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        name="q",
        location="query",
        host="api.example.com",
    )
    assert row is not None
    assert row["endpoint_id"] == "ep1"
    assert row["name"] == "q"
    assert row["id"] == "p1"
