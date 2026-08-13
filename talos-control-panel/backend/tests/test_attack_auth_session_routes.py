"""
Auth-Session Testing CP routes (Phases 1–5).

Covers summary/overview/bindings/candidates reads, bind/unbind/generate,
approve/reject/unapprove (K19 binding expand), run/right-now (K11),
results, filter, suite, and command_tree registration.
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


def test_generate_with_flows(client):
    with patch("talos_ui.routers.attack_auth_session.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/auth-session/generate",
            params={"project_id": "demo"},
            json={"flows": ["flow-a", "flow-b"], "include_unsafe_methods": True},
        )
    assert res.status_code == 200
    assert run_scoped.call_args[0][1] == [
        "attack",
        "auth-session",
        "generate",
        "--flow",
        "flow-a",
        "--flow",
        "flow-b",
        "--include-unsafe-methods",
    ]


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


# ------------------------------------------------------------------ #
# Phase 3: approve / reject / unapprove                                #
# ------------------------------------------------------------------ #


def test_approve_all_pending_argv(client):
    with patch("talos_ui.routers.attack_auth_session.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/auth-session/approve",
            params={"project_id": "demo"},
            json={"all_pending": True, "endpoint_id": "ep-1"},
        )
    assert res.status_code == 200
    assert run_scoped.call_args[0][1] == [
        "attack",
        "auth-session",
        "approve",
        "--all-pending",
        "--endpoint",
        "ep-1",
    ]


def test_approve_selected_ids_argv(client):
    with patch("talos_ui.routers.attack_auth_session.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/auth-session/approve",
            params={"project_id": "demo"},
            json={"candidate_ids": ["cand-1", "cand-2"]},
        )
    assert res.status_code == 200
    assert run_scoped.call_args[0][1] == [
        "attack",
        "auth-session",
        "approve",
        "cand-1",
        "cand-2",
    ]


def test_approve_requires_ids_or_bulk(client):
    with patch("talos_ui.routers.attack_auth_session.cli.run_scoped") as run_scoped:
        res = client.post(
            "/api/attack/auth-session/approve",
            params={"project_id": "demo"},
            json={},
        )
    assert res.status_code == 400
    run_scoped.assert_not_called()


def test_approve_binding_expand_all_pending(client, tmp_path):
    """K19: binding + all_pending expands full ID set (no --binding on CLI)."""
    db_path = _make_project_db(tmp_path / "proj" / "talos.db")
    # seed extra pending under same binding
    conn = sqlite3.connect(str(db_path))
    for i in range(3, 10):
        conn.execute(
            """
            INSERT INTO auth_session_candidates
            (id, binding_id, endpoint_id, baseline_flow_id, auth_type, test_id,
             test_family, title, status, meta_json, created_at, updated_at)
            VALUES (?, 'bind-1', 'ep-1', 'flow-1', 'jwt', ?,
                    'algorithm', 't', 'pending', '{}', '2026-01-01', '2026-01-01')
            """,
            (f"cand-{i}", f"jwt.extra_{i}"),
        )
    conn.commit()
    conn.close()

    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=db_path,
        ):
            with patch(
                "talos_ui.routers.attack_auth_session.cli.run_scoped"
            ) as run_scoped:
                run_scoped.return_value = [_ok_result()]
                res = client.post(
                    "/api/attack/auth-session/approve",
                    params={"project_id": "demo"},
                    json={"all_pending": True, "binding_id": "bind-1"},
                )
    assert res.status_code == 200
    argv = run_scoped.call_args[0][1]
    assert argv[0:3] == ["attack", "auth-session", "approve"]
    assert "--all-pending" not in argv
    assert "--binding" not in argv
    # original cand-1 + 7 extra = 8 pending
    ids = argv[3:]
    assert "cand-1" in ids
    assert len(ids) == 8


def test_approve_binding_expand_over_200(client, tmp_path):
    """K19 acceptance: expand >200 pending under one binding (unpaginated)."""
    db_path = _make_project_db(tmp_path / "proj" / "talos.db")
    conn = sqlite3.connect(str(db_path))
    for i in range(2, 220):
        conn.execute(
            """
            INSERT INTO auth_session_candidates
            (id, binding_id, endpoint_id, baseline_flow_id, auth_type, test_id,
             test_family, title, status, meta_json, created_at, updated_at)
            VALUES (?, 'bind-1', 'ep-1', 'flow-1', 'jwt', ?,
                    'algorithm', 't', 'pending', '{}', '2026-01-01', '2026-01-01')
            """,
            (f"cand-bulk-{i}", f"jwt.bulk_{i}"),
        )
    conn.commit()
    conn.close()

    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=db_path,
        ):
            with patch(
                "talos_ui.routers.attack_auth_session.cli.run_scoped"
            ) as run_scoped:
                run_scoped.return_value = [_ok_result()]
                res = client.post(
                    "/api/attack/auth-session/approve",
                    params={"project_id": "demo"},
                    json={"all_pending": True, "binding_id": "bind-1"},
                )
    assert res.status_code == 200
    argv = run_scoped.call_args[0][1]
    # cand-1 + 218 bulk (2..219) = 219 pending
    assert len(argv) - 3 == 219
    assert "--binding" not in argv


def test_reject_with_reason_argv(client):
    with patch("talos_ui.routers.attack_auth_session.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/auth-session/reject",
            params={"project_id": "demo"},
            json={
                "all_pending": True,
                "reason": "out of scope",
                "families": ["algorithm"],
            },
        )
    assert res.status_code == 200
    assert run_scoped.call_args[0][1] == [
        "attack",
        "auth-session",
        "reject",
        "--all-pending",
        "--reason",
        "out of scope",
        "--family",
        "algorithm",
    ]


def test_unapprove_all_approved_argv(client):
    with patch("talos_ui.routers.attack_auth_session.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/attack/auth-session/unapprove",
            params={"project_id": "demo"},
            json={"all_approved": True},
        )
    assert res.status_code == 200
    assert run_scoped.call_args[0][1] == [
        "attack",
        "auth-session",
        "unapprove",
        "--all-approved",
    ]


def test_unapprove_binding_expand(client, tmp_path):
    db_path = _make_project_db(tmp_path / "proj" / "talos.db")
    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=db_path,
        ):
            with patch(
                "talos_ui.routers.attack_auth_session.cli.run_scoped"
            ) as run_scoped:
                run_scoped.return_value = [_ok_result()]
                res = client.post(
                    "/api/attack/auth-session/unapprove",
                    params={"project_id": "demo"},
                    json={"all_approved": True, "binding_id": "bind-1"},
                )
    assert res.status_code == 200
    argv = run_scoped.call_args[0][1]
    assert argv == ["attack", "auth-session", "unapprove", "cand-2"]
    assert "--binding" not in argv


# ------------------------------------------------------------------ #
# Phase 4: run + results                                               #
# ------------------------------------------------------------------ #


def test_run_enqueue_argv(client, tmp_path):
    db_path = _make_project_db(tmp_path / "proj" / "talos.db")
    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=db_path,
        ):
            with patch(
                "talos_ui.routers.attack_auth_session.cli.run_scoped"
            ) as run_scoped:
                run_scoped.return_value = [_ok_result()]
                res = client.post(
                    "/api/attack/auth-session/run",
                    params={"project_id": "demo"},
                    json={
                        "binding_id": "bind-1",
                        "families": ["signature"],
                        "right_now": False,
                    },
                )
    assert res.status_code == 200
    assert run_scoped.call_args[0][1] == [
        "attack",
        "auth-session",
        "run",
        "--family",
        "signature",
        "--binding",
        "bind-1",
    ]
    # enqueue uses default timeout (no elevated kwarg)
    assert run_scoped.call_args[1].get("timeout") is None or "timeout" not in run_scoped.call_args[1]
    body = res.json()
    assert body["right_now"] is False
    assert body["estimate"] == 1  # cand-2 approved signature? cand-2 is signature family approved


def test_run_right_now_elevated_timeout(client, tmp_path, monkeypatch):
    import talos_ui.config as cfg

    monkeypatch.setattr(cfg, "CLI_TIMEOUT", 60)
    db_path = _make_project_db(tmp_path / "proj" / "talos.db")
    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=db_path,
        ):
            with patch(
                "talos_ui.routers.attack_auth_session.cli.run_scoped"
            ) as run_scoped:
                run_scoped.return_value = [_ok_result()]
                res = client.post(
                    "/api/attack/auth-session/run",
                    params={"project_id": "demo"},
                    json={"right_now": True},
                )
    assert res.status_code == 200
    body = res.json()
    assert body["right_now"] is True
    assert body["estimate"] == 1
    assert body["timeout_seconds"] == 60  # max(60, min(600, 30*1)) = 60
    assert run_scoped.call_args[1]["timeout"] == 60
    assert "--right-now" in run_scoped.call_args[0][1]


def test_run_right_now_refuses_over_20(client, tmp_path):
    db_path = _make_project_db(tmp_path / "proj" / "talos.db")
    conn = sqlite3.connect(str(db_path))
    for i in range(25):
        conn.execute(
            """
            INSERT INTO auth_session_candidates
            (id, binding_id, endpoint_id, baseline_flow_id, auth_type, test_id,
             test_family, title, status, meta_json, created_at, updated_at)
            VALUES (?, 'bind-1', 'ep-1', 'flow-1', 'jwt', ?,
                    'algorithm', 't', 'approved', '{}', '2026-01-01', '2026-01-01')
            """,
            (f"appr-{i}", f"jwt.rn_{i}"),
        )
    conn.commit()
    conn.close()

    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=db_path,
        ):
            with patch(
                "talos_ui.routers.attack_auth_session.cli.run_scoped"
            ) as run_scoped:
                res = client.post(
                    "/api/attack/auth-session/run",
                    params={"project_id": "demo"},
                    json={"right_now": True},
                )
    assert res.status_code == 400
    assert "20" in res.json()["detail"]
    run_scoped.assert_not_called()


def test_run_right_now_refuses_zero(client, tmp_path):
    db_path = _make_project_db(tmp_path / "proj" / "talos.db")
    # no approved matching endpoint filter
    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=db_path,
        ):
            with patch(
                "talos_ui.routers.attack_auth_session.cli.run_scoped"
            ) as run_scoped:
                res = client.post(
                    "/api/attack/auth-session/run",
                    params={"project_id": "demo"},
                    json={"right_now": True, "endpoint_id": "ep-missing"},
                )
    assert res.status_code == 400
    run_scoped.assert_not_called()


def test_run_estimate(client, tmp_path):
    db_path = _make_project_db(tmp_path / "proj" / "talos.db")
    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=db_path,
        ):
            res = client.get(
                "/api/attack/auth-session/run-estimate",
                params={"project_id": "demo", "binding_id": "bind-1"},
            )
    assert res.status_code == 200
    assert res.json()["approved_matching"] == 1


def test_results_list_and_detail(client, tmp_path):
    db_path = _make_project_db(tmp_path / "proj" / "talos.db")
    # optional finding_evidence tables may be missing — detail should still work
    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_db_path",
            return_value=db_path,
        ):
            lst = client.get(
                "/api/attack/auth-session/results",
                params={
                    "project_id": "demo",
                    "verdict": "WEAK_VALIDATION",
                    "limit": 10,
                },
            )
            det = client.get(
                "/api/attack/auth-session/results/replay-1",
                params={"project_id": "demo"},
            )
            miss = client.get(
                "/api/attack/auth-session/results/missing",
                params={"project_id": "demo"},
            )
    assert lst.status_code == 200
    body = lst.json()
    assert body["count"] == 1
    assert body["items"][0]["verdict"] == "WEAK_VALIDATION"
    assert body["items"][0]["path"] == "/api/me"

    assert det.status_code == 200
    assert det.json()["item"]["replay_flow_id"] == "replay-1"
    assert det.json()["finding"] is None  # no finding_evidence table

    assert miss.status_code == 404


# ------------------------------------------------------------------ #
# Phase 5: filter + suite                                              #
# ------------------------------------------------------------------ #


def test_filter_init_show_validate_argv(client, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    with patch("talos_ui.routers.attack_auth_session.db.get_project_record", return_value={}):
        with patch(
            "talos_ui.routers.attack_auth_session.config.project_data_dir",
            return_value=data_dir,
        ):
            with patch(
                "talos_ui.routers.attack_auth_session.cli.run_scoped"
            ) as run_scoped:
                run_scoped.return_value = [_ok_result(["attack", "auth-session", "filter", "init"])]
                r1 = client.post(
                    "/api/attack/auth-session/filter/init",
                    params={"project_id": "demo"},
                )
                run_scoped.return_value = [_ok_result(["attack", "auth-session", "filter", "show"])]
                r2 = client.post(
                    "/api/attack/auth-session/filter/show",
                    params={"project_id": "demo"},
                )
                run_scoped.return_value = [_ok_result(["attack", "auth-session", "filter", "validate"])]
                r3 = client.post(
                    "/api/attack/auth-session/filter/validate",
                    params={"project_id": "demo"},
                )
    assert r1.status_code == 200
    assert run_scoped.call_args_list[0][0][1] == [
        "attack",
        "auth-session",
        "filter",
        "init",
    ]
    assert r1.json()["filter_filename"] == "auth-session-decision-filter.yaml"
    assert r2.status_code == 200
    assert "stdout" in r2.json()
    assert r3.status_code == 200


def test_suite_catalog_core(client):
    res = client.get(
        "/api/attack/auth-session/suite",
        params={"auth_type": "jwt"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["count"] > 0
    assert any(i["test_id"] == "jwt.alg_none" for i in body["items"])
    assert all(i["source"] == "core" for i in body["items"])


def test_suite_catalog_with_alg_and_family(client):
    res = client.get(
        "/api/attack/auth-session/suite",
        params={"auth_type": "jwt", "alg": "RS256", "family": "algorithm"},
    )
    assert res.status_code == 200
    body = res.json()
    # family filter applied — only algorithm family (core alg rows; degrade is algorithm_degrade)
    assert all(i["family"] == "algorithm" for i in body["items"])
    assert body["alg"] == "RS256"


def test_suite_rejects_non_jwt(client):
    res = client.get(
        "/api/attack/auth-session/suite",
        params={"auth_type": "cookie"},
    )
    assert res.status_code == 400


def test_command_tree_phase3_5_commands():
    from talos_ui.command_tree import find_command, build_argv

    approve = find_command("attack.auth-session.approve")
    assert approve is not None
    argv = build_argv(approve, {"all_pending": True, "endpoint": "ep-1"})
    assert argv == [
        "attack",
        "auth-session",
        "approve",
        "--all-pending",
        "--endpoint",
        "ep-1",
    ]

    run = find_command("attack.auth-session.run")
    assert run is not None
    argv2 = build_argv(
        run,
        {"binding": "bind-1", "right_now": True, "candidate": ["c1"]},
    )
    assert argv2 == [
        "attack",
        "auth-session",
        "run",
        "--candidate",
        "c1",
        "--binding",
        "bind-1",
        "--right-now",
    ]

    for cid in (
        "attack.auth-session.reject",
        "attack.auth-session.unapprove",
        "attack.auth-session.filter.init",
        "attack.auth-session.filter.show",
        "attack.auth-session.filter.validate",
        "attack.auth-session.suite.list",
    ):
        assert find_command(cid) is not None, cid
