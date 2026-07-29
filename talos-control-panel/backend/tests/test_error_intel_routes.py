"""
Control Panel Error Intelligence routes — smoke tests (Phase 9 / PR2).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parents[1]
MONOREPO = Path(__file__).resolve().parents[3]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
if str(MONOREPO) not in sys.path:
    sys.path.insert(0, str(MONOREPO))


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
    monkeypatch.setattr(cfg, "TALOS_ROOT", MONOREPO)
    return talos_home, projects, registry


def _write_registry(registry: Path, projects: dict):
    registry.write_text(json.dumps(projects), encoding="utf-8")


def _seed_error_intel(db_path: Path, project_id: str = "proj1") -> dict[str, str]:
    """Init full project schema and store a stack-trace cluster + observation."""
    from talos.error_intel import classify_error
    from talos.error_intel.db import store_classified_error
    from talos.projects.db import init_project_db

    init_project_db(db_path)

    body = (
        "java.sql.SQLSyntaxErrorException: syntax error\n"
        "\tat com.example.UserService.load(UserService.java:142)\n"
    )
    classified = classify_error(body, status_code=500)
    assert classified is not None
    cluster, _obs, _created = store_classified_error(
        db_path,
        project_id,
        classified,
        flow_id="flow-ei-1",
        endpoint_id="ep-1",
        attack_type="proxy",
        response_status=500,
    )

    return {
        "error_id": cluster.id,
        "flow_id": "flow-ei-1",
        "exception_type": cluster.exception_type or "",
    }


@pytest.fixture()
def client(home):
    talos_home, projects, registry = home
    pid = "proj1"
    data_dir = projects / pid
    data_dir.mkdir()
    db_path = data_dir / "talos.db"
    seed = _seed_error_intel(db_path, pid)
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

    return TestClient(app), pid, seed


def test_error_intel_status(client):
    tc, pid, seed = client
    r = tc.get("/api/error-intel/status", params={"project_id": pid})
    assert r.status_code == 200
    body = r.json()
    assert body["clusters"] >= 1
    assert body["observations"] >= 1
    assert "scanner_version" in body
    assert "by_severity" in body
    assert "enabled" in body


def test_error_intel_overview(client):
    tc, pid, seed = client
    r = tc.get(
        "/api/error-intel/overview",
        params={"project_id": pid, "top_n": 8},
    )
    assert r.status_code == 200
    body = r.json()
    assert "status" in body
    assert "top_clusters" in body
    assert body["empty_state"]["no_clusters"] is False
    assert "note" in body
    assert "Intelligence only" in body["note"]


def test_error_intel_config_get(client):
    tc, pid, seed = client
    r = tc.get("/api/error-intel/config", params={"project_id": pid})
    assert r.status_code == 200
    body = r.json()
    assert "enabled" in body["config"]
    assert "enabled" in body["keys"]
    assert "scanner_version" in body


def test_error_intel_config_set_argv(client):
    tc, pid, seed = client

    class FakeResult:
        ok = True

        def to_dict(self):
            return {"ok": True, "cmd": ["error-intel", "config", "set"]}

    with patch("talos_ui.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [FakeResult()]
        r = tc.post(
            "/api/error-intel/config",
            params={"project_id": pid},
            json={"key": "enabled", "value": True},
        )
    assert r.status_code == 200
    body = r.json()
    assert "steps" in body
    argv = run_scoped.call_args[0][1]
    assert argv[:3] == ["error-intel", "config", "set"]
    assert argv[3] == "enabled"
    assert argv[4] == "true"


def test_error_intel_errors_list_multi_severity(client):
    tc, pid, seed = client
    r = tc.get(
        "/api/error-intel/errors",
        params={
            "project_id": pid,
            "severity": "medium,high,critical",
            "limit": 50,
            "offset": 0,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert "errors" in body
    assert "total" in body
    assert body["count"] == len(body["errors"])
    # Stack-trace SQL error should be medium+
    ids = {e["id"] for e in body["errors"]}
    assert seed["error_id"] in ids
    for e in body["errors"]:
        assert e["severity"] in ("medium", "high", "critical")


def test_error_intel_errors_missing_project_id(client):
    tc, pid, seed = client
    r = tc.get("/api/error-intel/errors")
    # FastAPI validation — missing required query param
    assert r.status_code in (400, 422)


def test_error_intel_error_detail(client):
    tc, pid, seed = client
    r = tc.get(
        f"/api/error-intel/errors/{seed['error_id']}",
        params={"project_id": pid},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["error"]["id"] == seed["error_id"]
    assert "observations" in body
    assert len(body["observations"]) >= 1
    assert "sibling_clusters" in body
    # Evidence may be present; never require logging it
    assert "evidence_snippet" in body["error"]


def test_error_intel_by_flow(client):
    tc, pid, seed = client
    r = tc.get(
        f"/api/error-intel/by-flow/{seed['flow_id']}",
        params={"project_id": pid},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["observation_count"] >= 1
    assert len(body["observations"]) >= 1
    assert "scanner_enabled" in body
    assert isinstance(body["clusters"], list)


def test_error_intel_rescan_outdated_argv(client):
    tc, pid, seed = client

    class FakeResult:
        ok = True

        def to_dict(self):
            return {"ok": True}

    with patch("talos_ui.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [FakeResult()]
        r = tc.post(
            "/api/error-intel/rescan",
            params={"project_id": pid},
            json={
                "mode": "all",
                "outdated": True,
                "force": False,
                "limit": 200,
            },
        )
    assert r.status_code == 200
    argv = run_scoped.call_args[0][1]
    assert argv[0:2] == ["error-intel", "rescan"]
    assert "--all" in argv
    assert "--outdated" in argv
    assert "--limit" in argv
    assert "200" in argv
    assert "--force" not in argv


def test_error_intel_rescan_flow_argv(client):
    tc, pid, seed = client

    class FakeResult:
        ok = True

        def to_dict(self):
            return {"ok": True}

    with patch("talos_ui.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [FakeResult()]
        r = tc.post(
            "/api/error-intel/rescan",
            params={"project_id": pid},
            json={"mode": "flow", "id": seed["flow_id"], "force": True},
        )
    assert r.status_code == 200
    argv = run_scoped.call_args[0][1]
    assert "--flow" in argv
    assert seed["flow_id"] in argv
    assert "--force" in argv


def test_error_intel_rollups(client):
    tc, pid, seed = client
    r = tc.get(
        "/api/error-intel/rollups/parameter",
        params={"project_id": pid},
    )
    assert r.status_code == 200
    assert "rollup" in r.json()

    r2 = tc.get(
        "/api/error-intel/rollups/endpoint",
        params={"project_id": pid},
    )
    assert r2.status_code == 200
    assert "rollup" in r2.json()


def test_error_intel_observations(client):
    tc, pid, seed = client
    r = tc.get(
        "/api/error-intel/observations",
        params={
            "project_id": pid,
            "error_id": seed["error_id"],
            "limit": 20,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 1
    assert body["observations"][0]["error_id"] == seed["error_id"]
