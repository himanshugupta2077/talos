"""
Auth-Session Testing CP routes (Phase 1–2).

Covers summary/overview/bindings/candidates reads, bind/unbind/generate argv,
and command_tree registration for mutation commands.
"""

from __future__ import annotations

import sqlite3
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


def _make_project_db(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.executescript(
        """
        CREATE TABLE auth_config (
            type TEXT NOT NULL,
            name TEXT NOT NULL,
            PRIMARY KEY (type, name)
        );
        CREATE TABLE auth_session_bindings (
            id TEXT PRIMARY KEY,
            location TEXT NOT NULL,
            name TEXT NOT NULL,
            auth_type TEXT NOT NULL,
            role_id TEXT,
            config_json TEXT DEFAULT '{}',
            created_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE auth_session_candidates (
            id TEXT PRIMARY KEY,
            binding_id TEXT NOT NULL,
            endpoint_id TEXT,
            baseline_flow_id TEXT NOT NULL,
            auth_type TEXT NOT NULL,
            test_id TEXT NOT NULL,
            test_family TEXT NOT NULL,
            title TEXT,
            mutation_summary TEXT,
            token_fingerprint TEXT,
            risk_hint TEXT,
            status TEXT NOT NULL,
            reject_reason TEXT,
            skip_reason TEXT,
            meta_json TEXT DEFAULT '{}',
            created_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE auth_session_results (
            replay_flow_id TEXT PRIMARY KEY,
            original_flow_id TEXT,
            candidate_id TEXT,
            binding_id TEXT,
            auth_type TEXT,
            test_id TEXT,
            verdict TEXT,
            endpoint_id TEXT,
            test_family TEXT,
            mutation_summary TEXT,
            original_status INTEGER,
            replay_status INTEGER,
            diff_verdict TEXT,
            matched_section TEXT,
            matched_group TEXT,
            matched_rules TEXT,
            failure_reason TEXT,
            created_at TEXT
        );
        CREATE TABLE scheduler_jobs (
            id TEXT PRIMARY KEY,
            job_type TEXT,
            status TEXT
        );
        CREATE TABLE endpoints (
            id TEXT PRIMARY KEY,
            method TEXT,
            path TEXT
        );
        CREATE TABLE flows (
            id TEXT PRIMARY KEY,
            method TEXT,
            path TEXT,
            host TEXT,
            status_code INTEGER,
            captured_at TEXT
        );
        """
    )
    conn.execute(
        "INSERT INTO auth_config (type, name) VALUES ('header', 'Authorization')"
    )
    conn.execute(
        """
        INSERT INTO auth_session_bindings
        (id, location, name, auth_type, role_id, config_json, created_at, updated_at)
        VALUES
        ('bind-1', 'header', 'Authorization', 'jwt', NULL, '{}', '2026-01-01', '2026-01-01')
        """
    )
    conn.execute(
        """
        INSERT INTO auth_session_candidates
        (id, binding_id, endpoint_id, baseline_flow_id, auth_type, test_id,
         test_family, title, mutation_summary, token_fingerprint, risk_hint,
         status, meta_json, created_at, updated_at)
        VALUES
        ('cand-1', 'bind-1', 'ep-1', 'flow-1', 'jwt', 'jwt.alg_none',
         'algorithm', 'alg none', 'set alg=none', 'eyJ…abc1234567', 'critical',
         'pending', '{}', '2026-01-01', '2026-01-01'),
        ('cand-2', 'bind-1', 'ep-1', 'flow-1', 'jwt', 'jwt.sig_empty',
         'signature', 'empty sig', 'empty signature', 'eyJ…abc1234567', 'high',
         'approved', '{}', '2026-01-01', '2026-01-01')
        """
    )
    conn.execute(
        """
        INSERT INTO auth_session_results
        (replay_flow_id, original_flow_id, candidate_id, binding_id, auth_type,
         test_id, verdict, endpoint_id, test_family, mutation_summary, created_at)
        VALUES
        ('replay-1', 'flow-1', 'cand-x', 'bind-1', 'jwt',
         'jwt.alg_none', 'WEAK_VALIDATION', 'ep-1', 'algorithm', 'alg none', '2026-01-02'),
        ('replay-2', 'flow-1', 'cand-y', 'bind-1', 'jwt',
         'jwt.sig_empty', 'SECURE', 'ep-1', 'signature', 'empty sig', '2026-01-02')
        """
    )
    conn.execute(
        """
        INSERT INTO endpoints (id, method, path)
        VALUES ('ep-1', 'GET', '/api/me')
        """
    )
    conn.execute(
        """
        INSERT INTO flows (id, method, path, host, status_code, captured_at)
        VALUES ('replay-1', 'GET', '/api/me', 'app.example', 200, '2026-01-02T00:00:00Z')
        """
    )
    conn.execute(
        """
        INSERT INTO scheduler_jobs (id, job_type, status)
        VALUES ('j1', 'auth_session_attack', 'pending')
        """
    )
    conn.commit()
    conn.close()
    return path


# ------------------------------------------------------------------ #
# Reads                                                                #
# ------------------------------------------------------------------ #


def test_summary_empty_project(client, tmp_path, monkeypatch):
    import talos_ui.config as cfg

    monkeypatch.setattr(cfg, "TALOS_HOME", tmp_path / "talos-home")
    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value=None):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=tmp_path / "missing.db",
        ):
            with patch(
                "talos_ui.routers.attack_auth_session.config.project_data_dir",
                return_value=tmp_path,
            ):
                res = client.get(
                    "/api/attack/auth-session/summary",
                    params={"project_id": "demo"},
                )
    assert res.status_code == 200
    body = res.json()
    assert body["counts"] == {}
    assert body["candidates_by_status"] == {}
    assert body["bindings"] == 0


def test_summary_and_overview_shape(client, tmp_path, monkeypatch):
    db_path = _make_project_db(tmp_path / "proj" / "talos.db")
    data_dir = db_path.parent
    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=db_path,
        ):
            with patch(
                "talos_ui.routers.attack_auth_session.config.project_data_dir",
                return_value=data_dir,
            ):
                s = client.get(
                    "/api/attack/auth-session/summary",
                    params={"project_id": "demo"},
                )
                o = client.get(
                    "/api/attack/auth-session/overview",
                    params={"project_id": "demo", "top_n": 5},
                )
    assert s.status_code == 200
    summary = s.json()
    assert summary["counts"]["WEAK_VALIDATION"] == 1
    assert summary["counts"]["SECURE"] == 1
    assert summary["candidates_by_status"]["pending"] == 1
    assert summary["candidates_by_status"]["approved"] == 1
    assert summary["bindings"] == 1

    assert o.status_code == 200
    ov = o.json()
    assert ov["bindings"] == 1
    assert ov["candidates_total"] == 2
    assert ov["results_total"] == 2
    assert ov["estimated_jobs_approved"] == 1
    assert ov["jobs_pending"] == 1
    assert ov["auth_config_ready"] is True
    assert ov["bindings_valid"] is True
    assert ov["binding_details"][0]["in_auth_config"] is True
    assert ov["filter_filename"] == "auth-session-decision-filter.yaml"
    assert ov["filter_path"].endswith("auth-session-decision-filter.yaml")
    assert "empty_state" in ov
    assert ov["empty_state"]["no_bindings"] is False
    assert ov["empty_state"]["jobs_in_flight"] is True
    assert len(ov["recent_weak"]) == 1
    assert ov["recent_weak"][0]["verdict"] == "WEAK_VALIDATION"
    assert "disclaimer" in ov


def test_bindings_list(client, tmp_path):
    db_path = _make_project_db(tmp_path / "proj" / "talos.db")
    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=db_path,
        ):
            with patch(
                "talos_ui.routers.attack_auth_session.config.project_data_dir",
                return_value=db_path.parent,
            ):
                res = client.get(
                    "/api/attack/auth-session/bindings",
                    params={"project_id": "demo"},
                )
    assert res.status_code == 200
    body = res.json()
    assert body["count"] == 1
    item = body["items"][0]
    assert item["name"] == "Authorization"
    assert item["in_auth_config"] is True
    assert item["candidate_counts"]["pending"] == 1
    assert item["candidate_counts"]["approved"] == 1
    assert body["auth_config_ready"] is True


def test_candidates_list_filters_and_limit(client, tmp_path):
    db_path = _make_project_db(tmp_path / "proj" / "talos.db")
    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=db_path,
        ):
            res = client.get(
                "/api/attack/auth-session/candidates",
                params={
                    "project_id": "demo",
                    "status": "pending",
                    "binding_id": "bind-1",
                    "limit": 10,
                },
            )
    assert res.status_code == 200
    body = res.json()
    assert body["count"] == 1
    assert body["items"][0]["test_id"] == "jwt.alg_none"
    assert body["items"][0]["endpoint_path"] == "/api/me"
    assert body["filters_applied"]["status"] == "pending"
    # no offset in query schema
    assert "offset" not in body["filters_applied"]


def test_candidates_limit_cap(client, tmp_path):
    db_path = _make_project_db(tmp_path / "proj" / "talos.db")
    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=db_path,
        ):
            res = client.get(
                "/api/attack/auth-session/candidates",
                params={"project_id": "demo", "limit": 5000},
            )
    assert res.status_code == 200
    assert res.json()["filters_applied"]["limit"] == 1000


def test_candidate_detail_404(client, tmp_path):
    db_path = _make_project_db(tmp_path / "proj" / "talos.db")
    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=db_path,
        ):
            res = client.get(
                "/api/attack/auth-session/candidates/missing",
                params={"project_id": "demo"},
            )
    assert res.status_code == 404


def test_candidate_detail_ok(client, tmp_path):
    db_path = _make_project_db(tmp_path / "proj" / "talos.db")
    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=db_path,
        ):
            res = client.get(
                "/api/attack/auth-session/candidates/cand-1",
                params={"project_id": "demo"},
            )
    assert res.status_code == 200
    item = res.json()["item"]
    assert item["id"] == "cand-1"
    assert item["test_id"] == "jwt.alg_none"
    assert item["endpoint_method"] == "GET"


def test_candidates_unknown_family_400(client, tmp_path):
    db_path = _make_project_db(tmp_path / "proj" / "talos.db")
    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=db_path,
        ):
            res = client.get(
                "/api/attack/auth-session/candidates",
                params={"project_id": "demo", "family": "not-a-family"},
            )
    assert res.status_code == 400


# ------------------------------------------------------------------ #
# Mutations (argv)                                                     #
# ------------------------------------------------------------------ #


def test_bind_header_argv(client):
    with patch("talos_ui.routers.attack_auth_session.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/auth-session/bindings",
            params={"project_id": "demo"},
            json={"header": "Authorization", "role": "admin"},
        )
    assert res.status_code == 200
    assert run_scoped.call_args[0][1] == [
        "attack",
        "auth-session",
        "bind",
        "--type",
        "jwt",
        "--header",
        "Authorization",
        "--role",
        "admin",
    ]


def test_bind_cookie_argv(client):
    with patch("talos_ui.routers.attack_auth_session.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/auth-session/bindings",
            params={"project_id": "demo"},
            json={"cookie": "session", "config_json": '{"disabled_tests":[]}'},
        )
    assert res.status_code == 200
    assert run_scoped.call_args[0][1] == [
        "attack",
        "auth-session",
        "bind",
        "--type",
        "jwt",
        "--cookie",
        "session",
        "--config-json",
        '{"disabled_tests":[]}',
    ]


def test_bind_rejects_both_header_and_cookie(client):
    with patch("talos_ui.routers.attack_auth_session.cli.run_scoped") as run_scoped:
        res = client.post(
            "/api/attack/auth-session/bindings",
            params={"project_id": "demo"},
            json={"header": "Authorization", "cookie": "session"},
        )
    assert res.status_code == 400
    run_scoped.assert_not_called()


def test_bind_requires_field(client):
    with patch("talos_ui.routers.attack_auth_session.cli.run_scoped") as run_scoped:
        res = client.post(
            "/api/attack/auth-session/bindings",
            params={"project_id": "demo"},
            json={},
        )
    assert res.status_code == 400
    run_scoped.assert_not_called()


def test_unbind_force_argv(client):
    with patch("talos_ui.routers.attack_auth_session.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/auth-session/unbind",
            params={"project_id": "demo"},
            json={"binding_id": "bind-1", "force": True},
        )
    assert res.status_code == 200
    assert run_scoped.call_args[0][1] == [
        "attack",
        "auth-session",
        "unbind",
        "--id",
        "bind-1",
        "--force",
    ]


def test_unbind_rejects_multiple_selectors(client):
    with patch("talos_ui.routers.attack_auth_session.cli.run_scoped") as run_scoped:
        res = client.post(
            "/api/attack/auth-session/unbind",
            params={"project_id": "demo"},
            json={"header": "Authorization", "binding_id": "bind-1"},
        )
    assert res.status_code == 400
    run_scoped.assert_not_called()


def test_generate_project_scope(client):
    with patch("talos_ui.routers.attack_auth_session.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/auth-session/generate",
            params={"project_id": "demo"},
            json={},
        )
    assert res.status_code == 200
    assert run_scoped.call_args[0][1] == ["attack", "auth-session", "generate"]


def test_generate_endpoint_scope_with_families_and_unsafe(client):
    with patch("talos_ui.routers.attack_auth_session.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/auth-session/generate",
            params={"project_id": "demo"},
            json={
                "endpoint_id": "ep-1",
                "binding_id": "bind-1",
                "families": ["algorithm", "claims"],
                "test_ids": ["jwt.alg_none"],
                "force_refresh": True,
                "include_unsafe_methods": True,
            },
        )
    assert res.status_code == 200
    assert run_scoped.call_args[0][1] == [
        "attack",
        "auth-session",
        "generate",
        "--binding",
        "bind-1",
        "--endpoint",
        "ep-1",
        "--test-id",
        "jwt.alg_none",
        "--family",
        "algorithm",
        "--family",
        "claims",
        "--force-refresh",
        "--include-unsafe-methods",
    ]


def test_generate_rejects_endpoint_and_module(client):
    with patch("talos_ui.routers.attack_auth_session.cli.run_scoped") as run_scoped:
        res = client.post(
            "/api/attack/auth-session/generate",
            params={"project_id": "demo"},
            json={"endpoint_id": "ep-1", "module": "admin"},
        )
    assert res.status_code == 400
    run_scoped.assert_not_called()


def test_generate_rejects_unknown_family(client):
    with patch("talos_ui.routers.attack_auth_session.cli.run_scoped") as run_scoped:
        res = client.post(
            "/api/attack/auth-session/generate",
            params={"project_id": "demo"},
            json={"families": ["nope"]},
        )
    assert res.status_code == 400
    run_scoped.assert_not_called()


# ------------------------------------------------------------------ #
# Command tree                                                         #
# ------------------------------------------------------------------ #


def test_command_tree_auth_session_bind_generate():
    from talos_ui.command_tree import COMMAND_TREE, find_command, build_argv

    groups = {g["group"] for g in COMMAND_TREE}
    assert "attack.auth-session" in groups

    bind = find_command("attack.auth-session.bind")
    assert bind is not None
    argv = build_argv(
        bind,
        {"type": "jwt", "header": "Authorization", "role": "admin"},
    )
    assert argv == [
        "attack",
        "auth-session",
        "bind",
        "--type",
        "jwt",
        "--header",
        "Authorization",
        "--role",
        "admin",
    ]

    gen = find_command("attack.auth-session.generate")
    assert gen is not None
    argv2 = build_argv(
        gen,
        {
            "endpoint": "ep-1",
            "family": ["algorithm", "claims"],
            "include_unsafe_methods": True,
        },
    )
    assert argv2 == [
        "attack",
        "auth-session",
        "generate",
        "--endpoint",
        "ep-1",
        "--family",
        "algorithm",
        "--family",
        "claims",
        "--include-unsafe-methods",
    ]

    unbind = find_command("attack.auth-session.unbind")
    assert unbind is not None
    argv3 = build_argv(unbind, {"id": "bind-1", "force": True})
    assert argv3 == [
        "attack",
        "auth-session",
        "unbind",
        "--id",
        "bind-1",
        "--force",
    ]
