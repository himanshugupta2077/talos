"""
P0 regression: unauth run argv must match live CLI
(`talos attack unauth run [--technique NAME]` only).

Also covers overview, enriched techniques, results filters, and command-tree config.
"""

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


def test_unauth_techniques_list(client):
    res = client.get("/api/attack/unauth/techniques")
    assert res.status_code == 200
    body = res.json()
    techniques = body["techniques"]
    assert "baseline" in techniques
    assert "malformed_auth" in techniques
    assert "max-priority" not in techniques
    # Enriched items
    assert "items" in body
    assert isinstance(body["items"], list)
    assert body["items"]
    assert body["items"][0]["name"]
    assert "recipe_count" in body["items"][0]
    assert body.get("total_recipes", 0) >= len(techniques)


def test_unauth_run_default_all_recipes(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post("/api/attack/unauth/run", params={"project_id": "demo"}, json={})
        assert res.status_code == 200
        run_scoped.assert_called_once()
        args = run_scoped.call_args[0]
        assert args[0] == "demo"
        assert args[1] == ["attack", "unauth", "run"]


def test_unauth_run_with_technique(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/unauth/run",
            params={"project_id": "demo"},
            json={"technique": "baseline"},
        )
        assert res.status_code == 200
        args = run_scoped.call_args[0][1]
        assert args == ["attack", "unauth", "run", "--technique", "baseline"]


def test_unauth_run_rejects_unknown_technique(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        res = client.post(
            "/api/attack/unauth/run",
            params={"project_id": "demo"},
            json={"technique": "remove_authorization_header"},
        )
        assert res.status_code == 400
        run_scoped.assert_not_called()


def test_unauth_run_does_not_emit_dead_flags(client):
    """Regression: removed --max-priority / --auth-mutation must never appear."""
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        # Even if a stale client sends old body fields, pydantic ignores extras
        # and we must not forward dead flags.
        res = client.post(
            "/api/attack/unauth/run",
            params={"project_id": "demo"},
            json={"max_priority": 2, "auth_mutation": "remove_authorization_header"},
        )
        assert res.status_code == 200
        argv = run_scoped.call_args[0][1]
        flat = " ".join(argv)
        assert "--max-priority" not in flat
        assert "--auth-mutation" not in flat
        assert argv == ["attack", "unauth", "run"]


def test_unauth_overview_shape(client, tmp_path, monkeypatch):
    """Overview returns aggregate fields even when project DB is empty/missing."""
    import talos_ui.config as cfg

    monkeypatch.setattr(cfg, "TALOS_HOME", tmp_path / "talos-home")
    # Point project db to a non-existent path via registry stub
    with patch("talos_ui.routers.attack.db.get_project_record", return_value=None):
        with patch(
            "talos_ui.routers.attack.config.project_db_path",
            return_value=tmp_path / "missing.db",
        ):
            res = client.get(
                "/api/attack/unauth/overview",
                params={"project_id": "demo"},
            )
    assert res.status_code == 200
    body = res.json()
    assert "counts" in body
    assert "testable_endpoints" in body
    assert "total_recipes" in body
    assert "estimated_jobs_all" in body
    assert "jobs" in body
    assert "auto_run" in body
    assert "enabled" in body["auto_run"]
    assert "techniques" in body
    assert "recent_bypass" in body
    assert "empty_state" in body
    assert body["empty_state"]["no_results"] is True


def test_unauth_results_accepts_filters(client):
    with patch("talos_ui.routers.attack.db.get_project_record", return_value=None):
        with patch(
            "talos_ui.routers.attack.config.project_db_path",
            return_value=Path("/tmp/nonexistent-talos.db"),
        ):
            with patch("talos_ui.routers.attack.db.query_all", return_value=[]) as q:
                res = client.get(
                    "/api/attack/unauth/results",
                    params={
                        "project_id": "demo",
                        "verdict": "BYPASS",
                        "auth_mutation": "baseline",
                        "search": "/api",
                    },
                )
                assert res.status_code == 200
                assert res.json() == {"results": []}
                assert q.called
                sql = q.call_args[0][1]
                assert "ur.verdict" in sql
                assert "ur.auth_mutation" in sql
                assert "f.path LIKE" in sql


def test_command_tree_unauth_config():
    from talos_ui.command_tree import build_argv, find_command

    unauth_cfg = find_command("attack.unauth.config")
    assert unauth_cfg is not None
    argv = build_argv(unauth_cfg, {"auto_run": "on"})
    assert argv == ["attack", "unauth", "config", "--auto-run", "on"]
    argv_show = build_argv(unauth_cfg, {})
    assert argv_show == ["attack", "unauth", "config"]


def test_command_tree_unauth_filter_apply():
    from talos_ui.command_tree import build_argv, find_command

    apply_cmd = find_command("attack.unauth.filter.apply")
    assert apply_cmd is not None
    argv = build_argv(apply_cmd, {"dry_run": True, "force": True})
    assert argv == ["attack", "unauth", "filter", "apply", "--dry-run", "--force"]
    argv_plain = build_argv(apply_cmd, {})
    assert argv_plain == ["attack", "unauth", "filter", "apply"]


def test_unauth_filter_apply_endpoint_missing_filter(client, tmp_path, monkeypatch):
    """Native apply route returns 400 when filter file is absent."""
    from talos_ui import config as ui_config
    from talos_ui import db as ui_db
    from talos.projects.db import init_project_db

    data_dir = tmp_path / "proj"
    data_dir.mkdir()
    init_project_db(data_dir / "talos.db")

    monkeypatch.setattr(
        ui_db,
        "get_project_record",
        lambda _pid: {"id": "demo", "data_dir": str(data_dir)},
    )
    monkeypatch.setattr(
        ui_config,
        "project_data_dir",
        lambda _pid, _rec=None: data_dir,
    )
    monkeypatch.setattr(
        ui_config,
        "project_db_path",
        lambda _pid, _rec=None: data_dir / "talos.db",
    )

    res = client.post(
        "/api/attack/unauth/filter/apply",
        params={"project_id": "demo"},
        json={"dry_run": True, "force": False},
    )
    assert res.status_code == 400
    assert "filter" in res.json()["detail"].lower() or "No valid" in res.json()["detail"]
