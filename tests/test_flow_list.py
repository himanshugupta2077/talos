"""
Tests for talos flow list / list_flows().

Covers:
  - Full inventory ordered by captured_at DESC
  - Filters: endpoint, status_code, role, source, limit
  - Invalid limit raises ValueError
  - CLI wires list subcommand and prints table columns
  - Unknown role exits 1
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from talos.projects.db import init_project_db
from talos.projects.flow_cli import cmd_flow_list, list_flows, run_flow_cli
from talos.projects.manager import ProjectManager


PROJECT_ID = "proj-flow-list"
ROLE_ADMIN = "role-admin"
ROLE_USER = "role-user"
EP_LOGIN = "ep-login"
EP_ORDERS = "ep-orders"
FLOW_LOGIN = "flow-login-001"
FLOW_ORDERS = "flow-orders-002"
FLOW_REPLAY = "flow-replay-003"
FLOW_FAIL = "flow-fail-004"


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    _seed(path)
    return path


def _seed(db_path: Path) -> None:
    """Insert roles, endpoints, and flows spanning sources and statuses."""
    t1 = "2026-01-01T10:00:00+00:00"
    t2 = "2026-01-01T11:00:00+00:00"
    t3 = "2026-01-01T12:00:00+00:00"
    t4 = "2026-01-01T13:00:00+00:00"
    with sqlite3.connect(str(db_path)) as conn:
        conn.executemany(
            "INSERT INTO roles (id, name) VALUES (?, ?)",
            [(ROLE_ADMIN, "admin"), (ROLE_USER, "user")],
        )
        # global / unauthenticated may already exist from init — ignore.
        conn.executemany(
            """
            INSERT OR IGNORE INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (EP_LOGIN, PROJECT_ID, "POST", "api.example.com",
                 "/api/login", "/api/login", "application/json", 0,
                 f'["{ROLE_USER}"]', t1, t1),
                (EP_ORDERS, PROJECT_ID, "GET", "api.example.com",
                 "/api/orders", "/api/orders", "application/json", 1,
                 f'["{ROLE_ADMIN}"]', t2, t2),
            ],
        )
        # Ensure a module exists for FK if required — flows.module_id is NOT NULL.
        # init_project_db seeds "global" module; fetch it.
        mod_row = conn.execute(
            "SELECT id FROM modules ORDER BY name LIMIT 1"
        ).fetchone()
        module_id = mod_row[0] if mod_row else "mod-global"
        if not mod_row:
            conn.execute(
                "INSERT INTO modules (id, name, is_active) VALUES (?, 'global', 1)",
                (module_id,),
            )

        flows = [
            (FLOW_LOGIN, t1, "POST",
             "https://api.example.com/api/login", "api.example.com",
             "/api/login", 200, EP_LOGIN, ROLE_USER, "proxy_capture"),
            (FLOW_ORDERS, t2, "GET",
             "https://api.example.com/api/orders", "api.example.com",
             "/api/orders", 200, EP_ORDERS, ROLE_ADMIN, "proxy_capture"),
            (FLOW_REPLAY, t3, "GET",
             "https://api.example.com/api/orders", "api.example.com",
             "/api/orders", 200, EP_ORDERS, ROLE_ADMIN, "manual_replay"),
            (FLOW_FAIL, t4, "GET",
             "https://api.example.com/api/orders", "api.example.com",
             "/api/orders", 403, EP_ORDERS, ROLE_USER, "auto_replay"),
        ]
        for row in flows:
            conn.execute(
                """
                INSERT INTO flows
                    (id, project_id, captured_at, method, url, host, path,
                     query, request_headers, request_cookies, status_code,
                     response_headers, content_type, endpoint_id, role_id,
                     module_id, tags, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, '',
                        '{}', '{}', ?, '{}', 'application/json',
                        ?, ?, ?, '[]', ?)
                """,
                (
                    row[0], PROJECT_ID, row[1], row[2], row[3], row[4],
                    row[5], row[6], row[7], row[8], module_id, row[9],
                ),
            )
        conn.commit()


def _project(db_path: Path) -> MagicMock:
    project = MagicMock()
    project.db_path = db_path
    project.id = PROJECT_ID
    return project


# ------------------------------------------------------------------ #
# Core inventory                                                       #
# ------------------------------------------------------------------ #

def test_list_includes_all_flows(db_path: Path):
    rows = list_flows(db_path, PROJECT_ID)
    ids = {r["id"] for r in rows}
    assert ids == {FLOW_LOGIN, FLOW_ORDERS, FLOW_REPLAY, FLOW_FAIL}


def test_list_orders_by_captured_at_desc(db_path: Path):
    rows = list_flows(db_path, PROJECT_ID)
    assert [r["id"] for r in rows] == [
        FLOW_FAIL, FLOW_REPLAY, FLOW_ORDERS, FLOW_LOGIN,
    ]


def test_list_includes_role_name(db_path: Path):
    rows = list_flows(db_path, PROJECT_ID)
    by_id = {r["id"]: r for r in rows}
    assert by_id[FLOW_LOGIN]["role_name"] == "user"
    assert by_id[FLOW_ORDERS]["role_name"] == "admin"


def test_empty_project(tmp_path: Path):
    path = tmp_path / "empty.db"
    init_project_db(path)
    assert list_flows(path, PROJECT_ID) == []


# ------------------------------------------------------------------ #
# Filters                                                              #
# ------------------------------------------------------------------ #

def test_filter_endpoint(db_path: Path):
    rows = list_flows(db_path, PROJECT_ID, endpoint_id=EP_LOGIN)
    assert [r["id"] for r in rows] == [FLOW_LOGIN]


def test_filter_status_code(db_path: Path):
    rows = list_flows(db_path, PROJECT_ID, status_code=403)
    assert [r["id"] for r in rows] == [FLOW_FAIL]


def test_filter_role(db_path: Path):
    rows = list_flows(db_path, PROJECT_ID, role_id=ROLE_USER)
    ids = {r["id"] for r in rows}
    assert ids == {FLOW_LOGIN, FLOW_FAIL}


def test_filter_source(db_path: Path):
    rows = list_flows(db_path, PROJECT_ID, source="proxy_capture")
    ids = {r["id"] for r in rows}
    assert ids == {FLOW_LOGIN, FLOW_ORDERS}


def test_filter_limit(db_path: Path):
    rows = list_flows(db_path, PROJECT_ID, limit=2)
    assert len(rows) == 2
    assert [r["id"] for r in rows] == [FLOW_FAIL, FLOW_REPLAY]


def test_filter_limit_invalid(db_path: Path):
    with pytest.raises(ValueError, match="positive integer"):
        list_flows(db_path, PROJECT_ID, limit=0)


def test_combined_filters(db_path: Path):
    rows = list_flows(
        db_path,
        PROJECT_ID,
        endpoint_id=EP_ORDERS,
        source="manual_replay",
        status_code=200,
    )
    assert [r["id"] for r in rows] == [FLOW_REPLAY]


# ------------------------------------------------------------------ #
# CLI                                                                  #
# ------------------------------------------------------------------ #

def test_cli_list_prints_table(db_path: Path, capsys: pytest.CaptureFixture[str]):
    args = MagicMock(
        endpoint=None,
        status_code=None,
        role=None,
        source=None,
        limit=None,
    )
    cmd_flow_list(_project(db_path), args)
    out = capsys.readouterr().out
    assert "UUID" in out
    assert "Endpoint" in out
    assert "Method" in out
    assert "Status" in out
    assert "Role" in out
    assert "Source" in out
    assert "Created" in out
    assert FLOW_LOGIN in out
    assert FLOW_FAIL in out
    assert "api.example.com/api/login" in out
    assert "proxy_capture" in out
    assert "4 flow(s)." in out


def test_cli_list_filter_source(db_path: Path, capsys: pytest.CaptureFixture[str]):
    args = MagicMock(
        endpoint=None,
        status_code=None,
        role=None,
        source="manual_replay",
        limit=None,
    )
    cmd_flow_list(_project(db_path), args)
    out = capsys.readouterr().out
    assert FLOW_REPLAY in out
    assert FLOW_LOGIN not in out
    assert "1 flow(s)." in out


def test_cli_list_filter_status_code(
    db_path: Path, capsys: pytest.CaptureFixture[str]
):
    args = MagicMock(
        endpoint=None,
        status_code=403,
        role=None,
        source=None,
        limit=None,
    )
    cmd_flow_list(_project(db_path), args)
    out = capsys.readouterr().out
    assert FLOW_FAIL in out
    assert FLOW_LOGIN not in out


def test_cli_list_role_name_filter(
    db_path: Path, capsys: pytest.CaptureFixture[str]
):
    args = MagicMock(
        endpoint=None,
        status_code=None,
        role="admin",
        source=None,
        limit=None,
    )
    cmd_flow_list(_project(db_path), args)
    out = capsys.readouterr().out
    assert FLOW_ORDERS in out
    assert FLOW_REPLAY in out
    assert FLOW_LOGIN not in out


def test_cli_list_unknown_role(db_path: Path, capsys: pytest.CaptureFixture[str]):
    args = MagicMock(
        endpoint=None,
        status_code=None,
        role="ghost",
        source=None,
        limit=None,
    )
    with pytest.raises(SystemExit) as exc:
        cmd_flow_list(_project(db_path), args)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "Role 'ghost' not found" in err


def test_cli_list_invalid_limit(db_path: Path, capsys: pytest.CaptureFixture[str]):
    args = MagicMock(
        endpoint=None,
        status_code=None,
        role=None,
        source=None,
        limit=0,
    )
    with pytest.raises(SystemExit) as exc:
        cmd_flow_list(_project(db_path), args)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "positive integer" in err


def test_cli_list_empty_no_filters(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    path = tmp_path / "empty.db"
    init_project_db(path)
    args = MagicMock(
        endpoint=None,
        status_code=None,
        role=None,
        source=None,
        limit=None,
    )
    cmd_flow_list(_project(path), args)
    out = capsys.readouterr().out
    assert "No flows captured yet." in out


def test_cli_list_empty_with_filters(
    db_path: Path, capsys: pytest.CaptureFixture[str]
):
    args = MagicMock(
        endpoint="ep-does-not-exist",
        status_code=None,
        role=None,
        source=None,
        limit=None,
    )
    cmd_flow_list(_project(db_path), args)
    out = capsys.readouterr().out
    assert "No flows match the given filters." in out


def test_run_flow_cli_list_subcommand(
    db_path: Path, capsys: pytest.CaptureFixture[str]
):
    """Integration: run_flow_cli dispatches 'list' with active project."""
    project = _project(db_path)
    manager = MagicMock(spec=ProjectManager)
    manager.active.return_value = project

    run_flow_cli(manager, ["list", "--source", "proxy_capture", "--limit", "1"])
    out = capsys.readouterr().out
    # Newest proxy_capture is FLOW_ORDERS (t2 > t1).
    assert FLOW_ORDERS in out
    assert FLOW_LOGIN not in out
    assert "1 flow(s)." in out
