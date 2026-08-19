"""P0: SSRF run argv must match live CLI (`talos attack ssrf run`)."""

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


def test_ssrf_techniques_list(client):
    res = client.get("/api/attack/ssrf/techniques")
    assert res.status_code == 200
    body = res.json()
    assert "lb_http_127" in body["techniques"]
    assert "cloud_aws_meta" in body["techniques"]
    assert "loopback" in body["families"]
    assert "oast" in body["families"]
    assert body["total_techniques"] >= 40


def test_ssrf_run_requires_flow(client):
    res = client.post(
        "/api/attack/ssrf/run",
        params={"project_id": "demo"},
        json={},
    )
    assert res.status_code == 400


def test_ssrf_run_with_collaborator(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/ssrf/run",
            params={"project_id": "demo"},
            json={
                "flows": ["flow-a"],
                "param": "query:url",
                "family": "cloud",
                "collaborator": "abc.oastify.com",
            },
        )
        assert res.status_code == 200
        assert run_scoped.call_args[0][1] == [
            "attack",
            "ssrf",
            "run",
            "--flow",
            "flow-a",
            "--param",
            "query:url",
            "--family",
            "cloud",
            "--collaborator",
            "abc.oastify.com",
            "--high-priority",
        ]


def test_ssrf_run_unknown_technique(client):
    res = client.post(
        "/api/attack/ssrf/run",
        params={"project_id": "demo"},
        json={"flows": ["flow-a"], "technique": "not-a-real-tech"},
    )
    assert res.status_code == 400
