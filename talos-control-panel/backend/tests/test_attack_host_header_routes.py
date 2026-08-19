"""P0: host-header run argv must match live CLI (`talos attack host-header run`)."""

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


def test_host_header_techniques_list(client):
    res = client.get("/api/attack/host-header/techniques")
    assert res.status_code == 200
    body = res.json()
    assert "abs_canary" in body["techniques"]
    assert "crlf_xfh" in body["techniques"]
    assert "absolute" in body["families"]
    assert body["items"]
    assert body["items"][0]["name"]
    assert body["total_techniques"] >= 35


def test_host_header_run_requires_flow(client):
    res = client.post(
        "/api/attack/host-header/run",
        params={"project_id": "demo"},
        json={},
    )
    assert res.status_code == 400


def test_host_header_run_with_flows(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/host-header/run",
            params={"project_id": "demo"},
            json={"flows": ["flow-a", "flow-b"]},
        )
        assert res.status_code == 200
        assert run_scoped.call_args[0][1] == [
            "attack",
            "host-header",
            "run",
            "--flow",
            "flow-a",
            "--flow",
            "flow-b",
            "--high-priority",
        ]


def test_host_header_run_with_header_and_family(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/host-header/run",
            params={"project_id": "demo"},
            json={
                "flows": ["flow-a"],
                "technique": "abs_canary",
                "family": "absolute",
                "param": "Host",
            },
        )
        assert res.status_code == 200
        argv = run_scoped.call_args[0][1]
        assert argv == [
            "attack",
            "host-header",
            "run",
            "--flow",
            "flow-a",
            "--header",
            "Host",
            "--technique",
            "abs_canary",
            "--family",
            "absolute",
            "--high-priority",
        ]


def test_host_header_run_no_high_priority(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/host-header/run",
            params={"project_id": "demo"},
            json={"flows": ["flow-a"], "high_priority": False},
        )
        assert res.status_code == 200
        assert run_scoped.call_args[0][1] == [
            "attack",
            "host-header",
            "run",
            "--flow",
            "flow-a",
            "--no-high-priority",
        ]


def test_host_header_run_unknown_technique(client):
    res = client.post(
        "/api/attack/host-header/run",
        params={"project_id": "demo"},
        json={"flows": ["flow-a"], "technique": "not-a-real-tech"},
    )
    assert res.status_code == 400
