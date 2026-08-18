"""P0: smuggle run argv must match live CLI (`talos attack smuggle run`)."""

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


def test_smuggle_techniques_list(client):
    res = client.get("/api/attack/smuggle/techniques")
    assert res.status_code == 200
    body = res.json()
    assert "cl_te" in body["techniques"]
    assert "te_cl" in body["techniques"]
    assert body["items"]
    assert body["items"][0]["name"]


def test_smuggle_run_requires_flow(client):
    res = client.post("/api/attack/smuggle/run", params={"project_id": "demo"}, json={})
    assert res.status_code == 400


def test_smuggle_run_with_flow(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/smuggle/run",
            params={"project_id": "demo"},
            json={"flows": ["flow-a"]},
        )
        assert res.status_code == 200
        assert run_scoped.call_args[0][1] == [
            "attack",
            "smuggle",
            "run",
            "--flow",
            "flow-a",
        ]


def test_smuggle_run_with_technique(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/smuggle/run",
            params={"project_id": "demo"},
            json={"flows": ["flow-a"], "technique": "cl_te"},
        )
        assert res.status_code == 200
        assert run_scoped.call_args[0][1] == [
            "attack",
            "smuggle",
            "run",
            "--flow",
            "flow-a",
            "--technique",
            "cl_te",
        ]


def test_smuggle_run_unknown_technique(client):
    res = client.post(
        "/api/attack/smuggle/run",
        params={"project_id": "demo"},
        json={"flows": ["flow-a"], "technique": "not-a-real-tech"},
    )
    assert res.status_code == 400
