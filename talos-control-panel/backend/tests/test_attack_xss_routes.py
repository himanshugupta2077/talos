"""P0: XSS run argv must match live CLI (`talos attack xss run`)."""

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


def test_xss_techniques_list(client):
    res = client.get("/api/attack/xss/techniques")
    assert res.status_code == 200
    body = res.json()
    assert "script_alert" in body["techniques"]
    assert "h1_tag" in body["techniques"]
    assert "html_tag" in body["families"]
    assert body["items"]
    assert body["items"][0]["name"]
    assert body["total_techniques"] >= 60


def test_xss_run_requires_flow(client):
    res = client.post(
        "/api/attack/xss/run",
        params={"project_id": "demo"},
        json={},
    )
    assert res.status_code == 400


def test_xss_run_with_flows(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/xss/run",
            params={"project_id": "demo"},
            json={"flows": ["flow-a", "flow-b"]},
        )
        assert res.status_code == 200
        assert run_scoped.call_args[0][1] == [
            "attack",
            "xss",
            "run",
            "--flow",
            "flow-a",
            "--flow",
            "flow-b",
            "--high-priority",
        ]


def test_xss_run_with_param_and_family(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/xss/run",
            params={"project_id": "demo"},
            json={
                "flows": ["flow-a"],
                "technique": "script_alert",
                "family": "html_tag",
                "param": "query:q",
            },
        )
        assert res.status_code == 200
        argv = run_scoped.call_args[0][1]
        assert argv == [
            "attack",
            "xss",
            "run",
            "--flow",
            "flow-a",
            "--param",
            "query:q",
            "--technique",
            "script_alert",
            "--family",
            "html_tag",
            "--high-priority",
        ]


def test_xss_run_no_high_priority(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/xss/run",
            params={"project_id": "demo"},
            json={"flows": ["flow-a"], "high_priority": False},
        )
        assert res.status_code == 200
        assert run_scoped.call_args[0][1] == [
            "attack",
            "xss",
            "run",
            "--flow",
            "flow-a",
            "--no-high-priority",
        ]


def test_xss_run_unknown_technique(client):
    res = client.post(
        "/api/attack/xss/run",
        params={"project_id": "demo"},
        json={"flows": ["flow-a"], "technique": "not-a-real-tech"},
    )
    assert res.status_code == 400
