"""
P0 regression: BAC run argv must match live CLI
(`talos attack bac <technique> [--role] [--module|--endpoint] [--auto-generate]`).

Also covers techniques meta, multi-run default (all 8), results filters,
overview shape, and command-tree shared flags.
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

ALL_TECHNIQUES = [
    "session-swap",
    "method-fuzz",
    "content-type",
    "url-fuzz",
    "header-inject",
    "host-fuzz",
    "role-inject",
    "parser-confuse",
]


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


def test_bac_techniques_list(client):
    res = client.get("/api/attack/bac/techniques")
    assert res.status_code == 200
    body = res.json()
    techniques = body["techniques"]
    assert techniques == ALL_TECHNIQUES
    assert "items" in body
    assert len(body["items"]) == 8
    for item in body["items"]:
        assert item["name"] in ALL_TECHNIQUES
        assert "description" in item
        assert "attack_type" in item
        assert item["attack_type"].startswith("bac_")
        assert item["variant_count"] >= 1
    assert body.get("total_variants", 0) >= 8


def test_bac_run_default_all_techniques(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/bac/run",
            params={"project_id": "demo"},
            json={},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["techniques_run"] == ALL_TECHNIQUES
        assert len(body["cli_previews"]) == 8
        assert run_scoped.call_count == 8
        for i, tech in enumerate(ALL_TECHNIQUES):
            args = run_scoped.call_args_list[i][0]
            assert args[0] == "demo"
            assert args[1] == ["attack", "bac", tech]


def test_bac_run_with_subset_and_flags(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/bac/run",
            params={"project_id": "demo"},
            json={
                "techniques": ["session-swap", "url-fuzz"],
                "role": "customer",
                "module": "payments",
                "auto_generate": True,
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["techniques_run"] == ["session-swap", "url-fuzz"]
        assert run_scoped.call_count == 2
        assert run_scoped.call_args_list[0][0][1] == [
            "attack",
            "bac",
            "session-swap",
            "--role",
            "customer",
            "--module",
            "payments",
            "--auto-generate",
        ]
        assert run_scoped.call_args_list[1][0][1] == [
            "attack",
            "bac",
            "url-fuzz",
            "--role",
            "customer",
            "--module",
            "payments",
            "--auto-generate",
        ]


def test_bac_run_with_endpoint_scope(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/bac/run",
            params={"project_id": "demo"},
            json={
                "techniques": ["method-fuzz"],
                "endpoint": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            },
        )
        assert res.status_code == 200
        assert run_scoped.call_args[0][1] == [
            "attack",
            "bac",
            "method-fuzz",
            "--endpoint",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        ]


def test_bac_run_with_flows(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/bac/run",
            params={"project_id": "demo"},
            json={"techniques": ["session-swap"], "flows": ["flow-a", "flow-b"]},
        )
        assert res.status_code == 200
        assert run_scoped.call_args[0][1] == [
            "attack",
            "bac",
            "session-swap",
            "--flow",
            "flow-a",
            "--flow",
            "flow-b",
        ]


def test_bac_run_rejects_flows_and_endpoint(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        res = client.post(
            "/api/attack/bac/run",
            params={"project_id": "demo"},
            json={"endpoint": "ep-1", "flows": ["flow-a"]},
        )
        assert res.status_code == 400
        run_scoped.assert_not_called()


def test_bac_run_rejects_unknown_technique(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        res = client.post(
            "/api/attack/bac/run",
            params={"project_id": "demo"},
            json={"techniques": ["session-swap", "not-a-real-tech"]},
        )
        assert res.status_code == 400
        run_scoped.assert_not_called()


def test_bac_run_rejects_module_and_endpoint(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        res = client.post(
            "/api/attack/bac/run",
            params={"project_id": "demo"},
            json={"module": "payments", "endpoint": "ep-1"},
        )
        assert res.status_code == 400
        run_scoped.assert_not_called()


def test_bac_legacy_single_technique(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/bac/session-swap",
            params={"project_id": "demo"},
            json={
                "role": "customer",
                "module": "admin",
                "auto_generate": True,
            },
        )
        assert res.status_code == 200
        run_scoped.assert_called_once()
        assert run_scoped.call_args[0][1] == [
            "attack",
            "bac",
            "session-swap",
            "--role",
            "customer",
            "--module",
            "admin",
            "--auto-generate",
        ]


def test_bac_legacy_unknown_technique_400(client):
    with patch("talos_ui.routers.attack.cli.run_scoped") as run_scoped:
        res = client.post(
            "/api/attack/bac/not-real",
            params={"project_id": "demo"},
            json={},
        )
        assert res.status_code == 400
        run_scoped.assert_not_called()


def test_bac_overview_shape(client, tmp_path, monkeypatch):
    import talos_ui.config as cfg

    monkeypatch.setattr(cfg, "TALOS_HOME", tmp_path / "talos-home")
    with patch("talos_ui.routers.attack.db.get_project_record", return_value=None):
        with patch(
            "talos_ui.routers.attack.config.project_db_path",
            return_value=tmp_path / "missing.db",
        ):
            res = client.get(
                "/api/attack/bac/overview",
                params={"project_id": "demo"},
            )
    assert res.status_code == 200
    body = res.json()
    assert "counts" in body
    assert "candidates" in body
    assert "candidate_count" in body["candidates"]
    assert "flow_count" in body["candidates"]
    assert "total_variants" in body
    assert "estimated_jobs_all" in body
    assert "jobs" in body
    assert "jobs_pending" in body
    assert "jobs_running" in body
    assert "auth" in body
    assert "techniques" in body
    assert "recent_possible" in body
    assert "empty_state" in body
    assert body["empty_state"]["no_results"] is True


def test_bac_results_accepts_filters(client):
    with patch("talos_ui.routers.attack.db.get_project_record", return_value=None):
        with patch(
            "talos_ui.routers.attack.config.project_db_path",
            return_value=Path("/tmp/nonexistent-talos.db"),
        ):
            with patch("talos_ui.routers.attack.db.query_all", return_value=[]) as q:
                res = client.get(
                    "/api/attack/bac/results",
                    params={
                        "project_id": "demo",
                        "verdict": "POSSIBLE_BAC",
                        "attack_type": "session-swap",
                        "module_name": "admin",
                        "attacker_role": "customer",
                        "search": "/api",
                    },
                )
                assert res.status_code == 200
                assert res.json() == {"results": []}
                assert q.called
                sql = q.call_args[0][1]
                assert "br.verdict" in sql
                assert "br.attack_type" in sql
                assert "mo.name" in sql
                assert "ar.name" in sql
                assert "f.path LIKE" in sql
                # CLI name mapped to job type
                params = q.call_args[0][2]
                assert "bac_session_swap" in params


def test_command_tree_bac_filter_apply():
    from talos_ui.command_tree import build_argv, find_command

    apply_cmd = find_command("attack.bac.filter.apply")
    assert apply_cmd is not None
    argv = build_argv(apply_cmd, {"dry_run": True, "force": True})
    assert argv == ["attack", "bac", "filter", "apply", "--dry-run", "--force"]
    argv_plain = build_argv(apply_cmd, {})
    assert argv_plain == ["attack", "bac", "filter", "apply"]


def test_bac_filter_apply_endpoint_missing_filter(client, tmp_path, monkeypatch):
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
        "/api/attack/bac/filter/apply",
        params={"project_id": "demo"},
        json={"dry_run": True, "force": False},
    )
    assert res.status_code == 400
    assert "filter" in res.json()["detail"].lower() or "No valid" in res.json()["detail"]


def test_command_tree_bac_shared_flags():
    from talos_ui.command_tree import build_argv, find_command

    cmd = find_command("attack.bac.session-swap")
    assert cmd is not None
    argv = build_argv(
        cmd,
        {
            "role": "customer",
            "module": "payments",
            "auto_generate": True,
        },
    )
    assert argv == [
        "attack",
        "bac",
        "session-swap",
        "--role",
        "customer",
        "--module",
        "payments",
        "--auto-generate",
    ]
    argv_ep = build_argv(cmd, {"endpoint": "ep-uuid"})
    assert argv_ep == [
        "attack",
        "bac",
        "session-swap",
        "--endpoint",
        "ep-uuid",
    ]
