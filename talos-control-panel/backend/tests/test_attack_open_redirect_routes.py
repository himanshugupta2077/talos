"""P0: open-redirect run argv must match live CLI."""

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


def test_open_redirect_techniques_list(client):
    res = client.get("/api/attack/open-redirect/techniques")
    assert res.status_code == 200
    body = res.json()
    assert "abs_https" in body["techniques"]
    assert "absolute" in body["families"]
    assert body["total_techniques"] >= 20


def test_open_redirect_run_requires_flow(client):
    res = client.post(
        "/api/attack/open-redirect/run",
        params={"project_id": "demo"},
        json={},
    )
    assert res.status_code == 400


def test_open_redirect_run_with_param(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/open-redirect/run",
            params={"project_id": "demo"},
            json={"flows": ["flow-a"], "param": "next", "family": "absolute"},
        )
        assert res.status_code == 200
        assert run_scoped.call_args[0][1] == [
            "attack",
            "open-redirect",
            "run",
            "--flow",
            "flow-a",
            "--param",
            "next",
            "--family",
            "absolute",
            "--high-priority",
        ]
