"""P0: CORS run argv must match live CLI (`talos attack cors run`)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import sys

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("TALOS_HOME", str(tmp_path / "talos-home"))
    from talos_ui.main import app

    return TestClient(app)


def _ok_result(cmd=None):
    r = MagicMock()
    r.ok = True
    r.to_dict.return_value = {
        "cmd": cmd or [],
        "stdout": "ok",
        "stderr": "",
        "exit_code": 0,
        "ok": True,
    }
    return r


def test_cors_techniques_list(client):
    res = client.get("/api/attack/cors/techniques")
    assert res.status_code == 200
    body = res.json()
    assert "arbitrary_https" in body["techniques"]
    assert "preflight" in body["techniques"]
    assert body["items"]
    assert body["items"][0]["name"]


def test_cors_run_default(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post("/api/attack/cors/run", params={"project_id": "demo"}, json={})
        assert res.status_code == 200
        args = run_scoped.call_args[0]
        assert args[0] == "demo"
        assert args[1] == ["attack", "cors", "run"]


def test_cors_run_with_technique(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/cors/run",
            params={"project_id": "demo"},
            json={"technique": "arbitrary_https"},
        )
        assert res.status_code == 200
        assert run_scoped.call_args[0][1] == [
            "attack",
            "cors",
            "run",
            "--technique",
            "arbitrary_https",
        ]


def test_cors_run_with_flows(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/cors/run",
            params={"project_id": "demo"},
            json={"flows": ["flow-a", "flow-b"]},
        )
        assert res.status_code == 200
        assert run_scoped.call_args[0][1] == [
            "attack",
            "cors",
            "run",
            "--flow",
            "flow-a",
            "--flow",
            "flow-b",
        ]


def test_cors_run_flows_skip_auto_filters(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/cors/run",
            params={"project_id": "demo"},
            json={"flows": ["flow-a"], "limit": 5, "host": "example.com"},
        )
        assert res.status_code == 200
        argv = run_scoped.call_args[0][1]
        assert argv == ["attack", "cors", "run", "--flow", "flow-a"]
        assert "--limit" not in argv
        assert "--host" not in argv


def test_cors_run_unknown_technique(client):
    res = client.post(
        "/api/attack/cors/run",
        params={"project_id": "demo"},
        json={"technique": "not-a-real-tech"},
    )
    assert res.status_code == 400
