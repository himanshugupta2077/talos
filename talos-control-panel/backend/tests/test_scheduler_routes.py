"""
Scheduler control panel route tests.

Verifies enriched status shape, process lifecycle argv, cancel/prune argv,
job show prefix resolution, and family type filter on list.
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


def _init_scheduler_db(db_path: Path):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE flows (
              id TEXT PRIMARY KEY,
              endpoint_id TEXT,
              role_id TEXT,
              module_id TEXT
            );
            CREATE TABLE roles (id TEXT PRIMARY KEY, name TEXT);
            CREATE TABLE modules (id TEXT PRIMARY KEY, name TEXT);
            CREATE TABLE scheduler_jobs (
              job_id TEXT PRIMARY KEY,
              job_type TEXT,
              status TEXT,
              priority INTEGER DEFAULT 100,
              endpoint_id TEXT,
              flow_id TEXT,
              created_at TEXT,
              scheduled_at TEXT,
              started_at TEXT,
              finished_at TEXT,
              failure_reason TEXT,
              replayed_flow_id TEXT,
              verdict TEXT,
              meta TEXT
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
            INSERT INTO scheduler_config VALUES (2.0, 6.0, 200);
            INSERT INTO scheduler_state VALUES ('running', NULL);
            INSERT INTO roles VALUES ('r1', 'admin');
            INSERT INTO modules VALUES ('m1', 'api');
            """
        )
        conn.commit()
    finally:
        conn.close()


def _seed_jobs(db_path: Path):
    conn = sqlite3.connect(str(db_path))
    try:
        rows = [
            (
                "aaaaaaaa-1111-1111-1111-111111111111",
                "bac_session_swap",
                "failed",
                100,
                None,
                "flow-1",
                "2024-01-01T00:00:00+00:00",
                None,
                None,
                "2024-01-01T00:01:00+00:00",
                "session dead",
                None,
                "vulnerable",
                json.dumps({"attacker_role_id": "r1", "module_id": "m1"}),
            ),
            (
                "bbbbbbbb-2222-2222-2222-222222222222",
                "replay_flow",
                "pending",
                50,
                None,
                "flow-2",
                "2024-01-02T00:00:00+00:00",
                None,
                None,
                None,
                None,
                None,
                None,
                "{}",
            ),
            (
                "cccccccc-3333-3333-3333-333333333333",
                "iv_baseline",
                "done",
                10,
                "ep-1",
                None,
                "2024-01-03T00:00:00+00:00",
                "2024-01-03T00:00:01+00:00",
                "2024-01-03T00:00:01+00:00",
                "2024-01-03T00:00:05+00:00",
                None,
                None,
                None,
                "{}",
            ),
            (
                "dddddddd-4444-4444-4444-444444444444",
                "bac_method_fuzz",
                "pending",
                80,
                None,
                "flow-3",
                "2024-01-04T00:00:00+00:00",
                None,
                None,
                None,
                None,
                None,
                None,
                "{}",
            ),
        ]
        conn.executemany(
            """
            INSERT INTO scheduler_jobs (
              job_id, job_type, status, priority, endpoint_id, flow_id,
              created_at, scheduled_at, started_at, finished_at,
              failure_reason, replayed_flow_id, verdict, meta
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            rows,
        )
        conn.execute(
            "INSERT INTO flows (id, endpoint_id, role_id, module_id) VALUES (?,?,?,?)",
            ("flow-1", "ep-resolved", "r1", "m1"),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.fixture()
def client(home):
    talos_home, projects, registry = home
    project_id = "demo"
    proj_dir = projects / project_id
    proj_dir.mkdir()
    db_path = proj_dir / "talos.db"
    _init_scheduler_db(db_path)
    _seed_jobs(db_path)
    _write_registry(
        registry,
        {
            project_id: {
                "id": project_id,
                "name": "Demo",
                "status": "active",
                "data_dir": str(proj_dir),
            }
        },
    )
    from talos_ui.main import app

    return TestClient(app), project_id, db_path, talos_home


def _ok_result(stdout: str = "", cmd=None):
    r = MagicMock()
    r.ok = True
    r.stdout = stdout
    r.stderr = ""
    r.to_dict.return_value = {
        "cmd": cmd or [],
        "stdout": stdout,
        "stderr": "",
        "exit_code": 0,
        "ok": True,
        "duration_ms": 1,
        "timed_out": False,
    }
    return r


def test_status_includes_process_metrics_shape(client):
    tc, project_id, _db_path, _home = client
    fake_proc = {
        "state": "running",
        "pid": 4242,
        "create_time": 1.0,
        "project_id": project_id,
        "startup_time": "2024-01-01T00:00:00+00:00",
        "runtime_version": 1,
        "last_error": None,
        "validation_deferred": False,
        "transitional": False,
        "log_path": "/tmp/scheduler.log",
    }

    # Patch the status helper (CP backend venv may not have talos installed).
    with patch(
        "talos_ui.routers.scheduler._process_status", return_value=fake_proc
    ):
        res = tc.get(
            "/api/scheduler/status", params={"project_id": project_id}
        )

    assert res.status_code == 200
    body = res.json()
    assert "counts" in body
    assert body["counts"]["pending"] == 2
    assert body["counts"]["failed"] == 1
    assert body["counts"]["done"] == 1
    # Zero-filled known statuses
    assert body["counts"]["cancelled"] == 0
    assert body["process"]["pid"] == 4242
    assert body["process"]["state"] == "running"
    assert "metrics" in body
    assert "total_jobs" in body["metrics"]
    assert body["active_queue"] == 2  # pending only (no running/paused)
    assert "queue_fill_pct" in body
    assert body["config"]["max_queue_size"] == 200
    assert body["state"]["state"] == "running"
    by_family = {r["family"]: r["n"] for r in body["by_family"]}
    assert by_family["bac"] == 2
    assert by_family["iv"] == 1
    assert by_family["replay"] == 1
    by_type = {r["job_type"]: r for r in body["by_job_type"]}
    assert by_type["iv_baseline"]["family"] == "iv"
    assert by_type["iv_baseline"]["n"] == 1
    assert by_type["bac_session_swap"]["family"] == "bac"


def test_process_status_puts_talos_on_path_and_reads_manager(home):
    """
    Regression: without TALOS_ROOT on sys.path, import fails in the CP
    backend venv and the Process toggle always shows OFF / always starts.
    """
    from talos_ui.routers import scheduler as sched_router

    fake_proc = {
        "state": "running",
        "pid": 99,
        "create_time": 1.0,
        "project_id": "demo",
        "startup_time": None,
        "runtime_version": 1,
        "last_error": None,
        "validation_deferred": False,
        "transitional": False,
        "log_path": "/tmp/scheduler.log",
    }

    class FakeInfo:
        def to_dict(self):
            return fake_proc

    fake_mgr_cls = MagicMock()
    fake_mgr_cls.return_value.status.return_value = FakeInfo()

    runtime_mod = MagicMock()
    runtime_mod.SchedulerRuntimeManager = fake_mgr_cls

    with patch.object(sched_router, "_ensure_talos_on_path") as ensure:
        with patch.dict(
            sys.modules,
            {
                "talos": MagicMock(),
                "talos.scheduler": MagicMock(),
                "talos.scheduler.runtime": runtime_mod,
            },
        ):
            out = sched_router._process_status()

    ensure.assert_called_once()
    fake_mgr_cls.assert_called_once()
    assert out["state"] == "running"
    assert out["pid"] == 99


def test_start_stop_call_expected_argv(client):
    tc, project_id, _db, _home = client
    with patch("talos_ui.routers.scheduler.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result(cmd=["scheduler", "start"])]
        res = tc.post(
            "/api/scheduler/start", params={"project_id": project_id}
        )
        assert res.status_code == 200
        argv = run_scoped.call_args[0][1]
        assert argv == ["scheduler", "start"]

    with patch("talos_ui.routers.scheduler.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result(cmd=["scheduler", "stop"])]
        res = tc.post(
            "/api/scheduler/stop", params={"project_id": project_id}
        )
        assert res.status_code == 200
        argv = run_scoped.call_args[0][1]
        assert argv == ["scheduler", "stop"]

    with patch("talos_ui.routers.scheduler.cli.run") as run:
        run.return_value = _ok_result(cmd=["scheduler", "stop"])
        res = tc.post("/api/scheduler/stop")
        assert res.status_code == 200
        assert run.call_args[0][0] == ["scheduler", "stop"]


def test_cancel_and_prune_argv(client):
    tc, project_id, _db, _home = client
    with patch("talos_ui.routers.scheduler.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = tc.post(
            "/api/scheduler/cancel",
            params={"project_id": project_id},
            json={"job_id": "bbbbbbbb-2222-2222-2222-222222222222"},
        )
        assert res.status_code == 200
        assert run_scoped.call_args[0][1] == [
            "scheduler",
            "cancel",
            "bbbbbbbb-2222-2222-2222-222222222222",
        ]

    with patch("talos_ui.routers.scheduler.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = tc.post(
            "/api/scheduler/prune",
            params={"project_id": project_id},
            json={"status": "done", "force": True},
        )
        assert res.status_code == 200
        assert run_scoped.call_args[0][1] == [
            "scheduler",
            "prune",
            "--status",
            "done",
            "--force",
        ]

    res = tc.post(
        "/api/scheduler/prune",
        params={"project_id": project_id},
        json={"status": "pending", "force": True},
    )
    assert res.status_code == 400


def test_job_show_prefix_resolution(client):
    tc, project_id, _db, _home = client
    res = tc.get(
        "/api/scheduler/jobs/aaaaaaaa-1111-1111-1111-111111111111",
        params={"project_id": project_id},
    )
    assert res.status_code == 200
    job = res.json()["job"]
    assert job["job_type"] == "bac_session_swap"
    assert job["role_name"] == "admin"
    assert job["module_name"] == "api"
    assert job["resolved_endpoint_id"] == "ep-resolved"
    assert isinstance(job["meta"], dict)

    # Unique prefix
    res = tc.get(
        "/api/scheduler/jobs/bbbb",
        params={"project_id": project_id},
    )
    assert res.status_code == 200
    assert res.json()["job"]["job_id"].startswith("bbbb")

    # Not found
    res = tc.get(
        "/api/scheduler/jobs/zzzzzzzz",
        params={"project_id": project_id},
    )
    assert res.status_code == 404


def test_list_family_type_filter_and_total(client):
    tc, project_id, _db, _home = client
    res = tc.get(
        "/api/scheduler/jobs",
        params={"project_id": project_id, "job_type": "bac", "limit": 50},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 2
    assert len(body["jobs"]) == 2
    assert all(j["job_type"].startswith("bac") for j in body["jobs"])
    assert body["limit"] == 50
    assert body["offset"] == 0

    res = tc.get(
        "/api/scheduler/jobs",
        params={"project_id": project_id, "status": "active"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 2
    assert all(j["status"] == "pending" for j in body["jobs"])

    res = tc.get(
        "/api/scheduler/jobs",
        params={
            "project_id": project_id,
            "job_type": "bac_session_swap",
        },
    )
    assert res.status_code == 200
    assert res.json()["total"] == 1


def test_filters_include_static_statuses_and_families(client):
    tc, project_id, _db, _home = client
    res = tc.get("/api/scheduler/filters", params={"project_id": project_id})
    assert res.status_code == 200
    body = res.json()
    for s in (
        "pending",
        "running",
        "paused",
        "done",
        "failed",
        "skipped",
        "cancelled",
    ):
        assert s in body["statuses"]
    for f in ("replay", "bac", "iv", "unauth", "cors", "sqli", "auth_session", "intruder"):
        assert f in body["job_types"] or f in body.get("families", [])
    assert "done" in body["pruneable_statuses"]
