"""
Control Panel configuration router tests.

Mutations must go through Talos CLI (run / run_scoped). Global writes must not
use run_scoped. Reads consume config show/effective/schema JSON.
"""

from __future__ import annotations

import json
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


def _ok_result(stdout: str = "{}", cmd=None):
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


def _fail_result(stderr: str = "error"):
    r = MagicMock()
    r.ok = False
    r.stdout = ""
    r.stderr = stderr
    r.to_dict.return_value = {
        "cmd": [],
        "stdout": "",
        "stderr": stderr,
        "exit_code": 1,
        "ok": False,
        "duration_ms": 1,
        "timed_out": False,
    }
    return r


EFFECTIVE_JSON = json.dumps(
    {
        "values": {
            "proxy.upstream.enabled": False,
            "proxy.upstream.url": None,
            "scheduler.min_delay": 2.0,
            "scheduler.max_delay": 6.0,
            "scheduler.max_queue_size": 200,
            "http.enabled": True,
            "http.rules": [],
            "attack.unauth_auto_run": False,
            "capture.store_bodies": True,
            "capture.max_body_size": 1048576,
            "capture.drop_headers": ["Via"],
        },
        "sources": {
            "proxy.upstream.enabled": "default",
            "proxy.upstream.url": "default",
            "scheduler.min_delay": "default",
            "scheduler.max_delay": "project",
            "scheduler.max_queue_size": "default",
            "http.enabled": "default",
            "http.rules": "default",
            "attack.unauth_auto_run": "default",
            "capture.store_bodies": "default",
            "capture.max_body_size": "default",
            "capture.drop_headers": "default",
        },
        "global_path": "/tmp/config.yaml",
        "project_path": "/tmp/project.yaml",
    }
)

SHOW_JSON = json.dumps(
    {
        "global": {"path": "/tmp/config.yaml", "exists": False},
        "project": {
            "path": "/tmp/project.yaml",
            "exists": True,
            "bound": True,
            "project_id": "demo",
        },
        "precedence": ["defaults", "global", "legacy", "project.yaml", "CLI"],
        "sections": ["proxy", "capture", "scheduler", "attack", "mutation"],
    }
)

SCHEMA_JSON = json.dumps(
    {
        "precedence": ["defaults", "global", "legacy", "project", "cli"],
        "sources": ["default", "global", "legacy", "project", "cli"],
        "sections": [
            {
                "id": "scheduler",
                "label": "Scheduler",
                "description": "Rate limits",
                "settings": [
                    {
                        "key": "scheduler.max_delay",
                        "section": "scheduler",
                        "label": "Max delay",
                        "type": "float",
                        "default": 6.0,
                        "description": "Max delay",
                    }
                ],
            }
        ],
        "known_keys": ["scheduler.max_delay"],
    }
)


def test_context_uses_config_show(client):
    with patch("talos_ui.routers.configuration.cli.run") as run:
        run.return_value = _ok_result(SHOW_JSON)
        res = client.get("/api/configuration/context", params={"project_id": "demo"})
        assert res.status_code == 200
        body = res.json()
        assert body["project_id"] == "demo"
        assert body["global_config_path"] == "/tmp/config.yaml"
        argv = run.call_args[0][0]
        assert argv[:2] == ["--project", "demo"]
        assert "config" in argv and "show" in argv


def test_effective_includes_source_counts(client):
    with patch("talos_ui.routers.configuration.cli.run") as run:
        run.return_value = _ok_result(EFFECTIVE_JSON)
        res = client.get("/api/configuration/effective", params={"project_id": "demo"})
        assert res.status_code == 200
        body = res.json()
        assert body["values"]["scheduler.max_delay"] == 6.0
        assert body["sources"]["scheduler.max_delay"] == "project"
        assert "source_counts" in body
        assert body["source_counts"]["project"] >= 1
        assert body["section_cards"]


def test_effective_section_url_sink_accepted(client):
    """CP _SECTIONS includes url_sink so section filter is not 400 (PR3b / K6)."""
    with patch("talos_ui.routers.configuration.cli.run") as run:
        run.return_value = _ok_result(
            json.dumps(
                {
                    "values": {
                        "url_sink.passive.enabled": True,
                        "url_sink.score_threshold": 45,
                        "url_sink.iv_probes.enabled": True,
                        "url_sink.html_js.enabled": True,
                    },
                    "sources": {
                        "url_sink.passive.enabled": "default",
                        "url_sink.score_threshold": "default",
                        "url_sink.iv_probes.enabled": "default",
                        "url_sink.html_js.enabled": "default",
                    },
                }
            )
        )
        res = client.get(
            "/api/configuration/effective",
            params={"project_id": "demo", "section": "url_sink"},
        )
        assert res.status_code == 200
        argv = run.call_args[0][0]
        assert "--section" in argv and "url_sink" in argv
        body = res.json()
        assert "url_sink.passive.enabled" in body["values"]
        # Section cards should include URL Sink when values present
        labels = {c.get("section") for c in body.get("section_cards") or []}
        assert "url_sink" in labels


def test_effective_section_burp_accepted(client):
    """CP _SECTIONS includes burp so the Burp filter is not 400."""
    with patch("talos_ui.routers.configuration.cli.run") as run:
        run.return_value = _ok_result(
            json.dumps(
                {
                    "values": {
                        "burp.enabled": True,
                        "burp.header_prefix": "X-Talos",
                    },
                    "sources": {
                        "burp.enabled": "default",
                        "burp.header_prefix": "default",
                    },
                }
            )
        )
        res = client.get(
            "/api/configuration/effective",
            params={"project_id": "demo", "section": "burp"},
        )
        assert res.status_code == 200
        argv = run.call_args[0][0]
        assert "--section" in argv and "burp" in argv
        body = res.json()
        assert body["values"]["burp.enabled"] is True
        labels = {c.get("section") for c in body.get("section_cards") or []}
        assert "burp" in labels


def test_effective_section_unknown_still_400(client):
    res = client.get(
        "/api/configuration/effective",
        params={"project_id": "demo", "section": "not_a_real_section"},
    )
    assert res.status_code == 400


def test_settings_merges_schema(client):
    with patch("talos_ui.routers.configuration.cli.run") as run:

        def side_effect(args, timeout=None):
            if "schema" in args:
                return _ok_result(SCHEMA_JSON)
            return _ok_result(EFFECTIVE_JSON)

        run.side_effect = side_effect
        res = client.get(
            "/api/configuration/settings",
            params={"project_id": "demo", "section": "scheduler"},
        )
        assert res.status_code == 200
        rows = res.json()["settings"]
        assert any(r["key"] == "scheduler.max_delay" for r in rows)
        max_row = next(r for r in rows if r["key"] == "scheduler.max_delay")
        assert max_row["source"] == "project"
        assert max_row["type"] == "float"


def test_set_project_uses_run_scoped(client):
    with patch("talos_ui.routers.configuration.cli.run_scoped") as scoped:
        scoped.return_value = [_ok_result("ok")]
        res = client.post(
            "/api/configuration/value",
            params={"project_id": "demo"},
            json={"key": "scheduler.max_delay", "value": 15, "scope": "project"},
        )
        assert res.status_code == 200
        scoped.assert_called_once()
        args = scoped.call_args[0]
        assert args[0] == "demo"
        assert args[1] == ["config", "set", "scheduler.max_delay", "15"]


def test_set_global_does_not_use_run_scoped(client):
    with patch("talos_ui.routers.configuration.cli.run_scoped") as scoped:
        with patch("talos_ui.routers.configuration.cli.run") as run:
            run.return_value = _ok_result("ok")
            res = client.post(
                "/api/configuration/value",
                json={
                    "key": "scheduler.max_delay",
                    "value": 12,
                    "scope": "global",
                },
            )
            assert res.status_code == 200
            scoped.assert_not_called()
            argv = run.call_args[0][0]
            assert argv == ["config", "set", "scheduler.max_delay", "12", "--global"]


def test_unset_project_uses_run_scoped(client):
    with patch("talos_ui.routers.configuration.cli.run_scoped") as scoped:
        scoped.return_value = [_ok_result("ok")]
        res = client.post(
            "/api/configuration/unset",
            params={"project_id": "demo"},
            json={"key": "scheduler.max_delay", "scope": "project"},
        )
        assert res.status_code == 200
        args = scoped.call_args[0]
        assert args[1] == ["config", "unset", "scheduler.max_delay"]


def test_unset_global_uses_cli_run(client):
    with patch("talos_ui.routers.configuration.cli.run_scoped") as scoped:
        with patch("talos_ui.routers.configuration.cli.run") as run:
            run.return_value = _ok_result("ok")
            res = client.post(
                "/api/configuration/unset",
                json={"key": "http.enabled", "scope": "global"},
            )
            assert res.status_code == 200
            scoped.assert_not_called()
            assert run.call_args[0][0] == [
                "config",
                "unset",
                "http.enabled",
                "--global",
            ]


def test_set_project_requires_project_id(client):
    res = client.post(
        "/api/configuration/value",
        json={"key": "scheduler.max_delay", "value": 9, "scope": "project"},
    )
    assert res.status_code == 400


def test_bool_value_serialized(client):
    with patch("talos_ui.routers.configuration.cli.run_scoped") as scoped:
        scoped.return_value = [_ok_result("ok")]
        res = client.post(
            "/api/configuration/value",
            params={"project_id": "demo"},
            json={"key": "http.enabled", "value": False, "scope": "project"},
        )
        assert res.status_code == 200
        assert scoped.call_args[0][1] == [
            "config",
            "set",
            "http.enabled",
            "false",
        ]


def test_list_value_serialized_as_json(client):
    with patch("talos_ui.routers.configuration.cli.run_scoped") as scoped:
        scoped.return_value = [_ok_result("ok")]
        res = client.post(
            "/api/configuration/value",
            params={"project_id": "demo"},
            json={
                "key": "capture.drop_headers",
                "value": ["Via", "X-Custom"],
                "scope": "project",
            },
        )
        assert res.status_code == 200
        argv = scoped.call_args[0][1]
        assert argv[0:3] == ["config", "set", "capture.drop_headers"]
        assert json.loads(argv[3]) == ["Via", "X-Custom"]


def test_cli_failure_surfaces_400(client):
    with patch("talos_ui.routers.configuration.cli.run") as run:
        run.return_value = _fail_result("no such key")
        res = client.get("/api/configuration/effective")
        assert res.status_code == 400
        assert "no such key" in res.json()["detail"]
