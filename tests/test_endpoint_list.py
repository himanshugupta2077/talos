"""
Tests for talos endpoint list / policy.list_endpoints().

Covers:
  - Full inventory includes unqualified and excluded endpoints
  - Filters: method, host, qualified, excluded, search, role, priority
  - Path-rule exclusion surfaces as excluded=True in list results
  - Invalid priority raises ValueError
  - CLI wires list subcommand and prints table columns
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from talos.projects.db import init_project_db
from talos.projects.policy import list_endpoints, set_excluded, set_path_rule
from talos.projects.endpoint_cli import cmd_endpoint_list, run_endpoint_cli
from talos.projects.manager import ProjectManager


PROJECT_ID = "proj-list-test"
ROLE_ADMIN = "role-admin"
ROLE_USER = "role-user"
EP_ORDERS = "ep-orders"
EP_ADMIN = "ep-admin"
EP_STATIC = "ep-static"
EP_UNQUAL = "ep-unqual"


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    _seed(path)
    return path


def _seed(db_path: Path) -> None:
    """Insert roles, endpoints, and policies for list filter tests."""
    now = "2026-01-01T00:00:00+00:00"
    with sqlite3.connect(str(db_path)) as conn:
        conn.executemany(
            "INSERT INTO roles (id, name) VALUES (?, ?)",
            [(ROLE_ADMIN, "admin"), (ROLE_USER, "user")],
        )
        conn.executemany(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (EP_ORDERS, PROJECT_ID, "GET", "api.example.com",
                 "/api/orders", "/api/orders", "application/json", 1,
                 f'["{ROLE_ADMIN}"]', now, now),
                (EP_ADMIN, PROJECT_ID, "POST", "api.example.com",
                 "/api/admin/users", "/api/admin/users", "application/json", 1,
                 f'["{ROLE_ADMIN}", "{ROLE_USER}"]', now, now),
                (EP_STATIC, PROJECT_ID, "GET", "cdn.example.com",
                 "/static/app.js", "/static/app.js", "application/javascript", 0,
                 f'["{ROLE_USER}"]', now, now),
                (EP_UNQUAL, PROJECT_ID, "GET", "api.example.com",
                 "/api/health", "/api/health", "text/plain", 0,
                 "[]", now, now),
            ],
        )
        # Qualified high-priority API endpoints
        for ep_id, score, excluded in [
            (EP_ORDERS, 50, 0),
            (EP_ADMIN, 80, 0),
            (EP_STATIC, 10, 0),
        ]:
            conn.execute(
                """
                INSERT INTO endpoint_policy
                    (endpoint_id, auto_priority, auto_score, excluded,
                     dangerous, logout, qualified, qualification_reason,
                     baseline_flow_id, baseline_status, updated_at)
                VALUES (?, 'HIGH', ?, ?, 0, 0, 1, 'flow_2xx', NULL, 200, ?)
                """,
                (ep_id, score, excluded, now),
            )
        # Unqualified endpoint
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, auto_priority, auto_score, excluded,
                 dangerous, logout, qualified, qualification_reason,
                 baseline_flow_id, baseline_status, updated_at)
            VALUES (?, 'LOW', 5, 0, 0, 0, 0, 'no_2xx_response', NULL, NULL, ?)
            """,
            (EP_UNQUAL, now),
        )
        conn.commit()


# ------------------------------------------------------------------ #
# Core inventory                                                       #
# ------------------------------------------------------------------ #

def test_list_includes_all_endpoints(db_path: Path):
    rows = list_endpoints(db_path, PROJECT_ID)
    ids = {r["id"] for r in rows}
    assert ids == {EP_ORDERS, EP_ADMIN, EP_STATIC, EP_UNQUAL}


def test_list_orders_by_effective_priority_then_score(db_path: Path):
    rows = list_endpoints(db_path, PROJECT_ID)
    # All HIGH/LOW — EP_ADMIN score 80, EP_ORDERS 50, EP_STATIC 10, EP_UNQUAL LOW
    assert rows[0]["id"] == EP_ADMIN
    assert rows[1]["id"] == EP_ORDERS
    assert rows[2]["id"] == EP_STATIC
    assert rows[3]["id"] == EP_UNQUAL
    assert rows[3]["qualified"] is False


# ------------------------------------------------------------------ #
# Filters                                                              #
# ------------------------------------------------------------------ #

def test_filter_method(db_path: Path):
    rows = list_endpoints(db_path, PROJECT_ID, method="post")
    assert [r["id"] for r in rows] == [EP_ADMIN]


def test_filter_host(db_path: Path):
    rows = list_endpoints(db_path, PROJECT_ID, host="CDN.EXAMPLE.COM")
    assert [r["id"] for r in rows] == [EP_STATIC]


def test_filter_qualified(db_path: Path):
    rows = list_endpoints(db_path, PROJECT_ID, qualified=True)
    ids = {r["id"] for r in rows}
    assert EP_UNQUAL not in ids
    assert {EP_ORDERS, EP_ADMIN, EP_STATIC} <= ids


def test_filter_excluded_endpoint_flag(db_path: Path):
    set_excluded(db_path, EP_ORDERS, excluded=True)
    rows = list_endpoints(db_path, PROJECT_ID, excluded=True)
    assert [r["id"] for r in rows] == [EP_ORDERS]
    assert rows[0]["excluded"] is True


def test_filter_excluded_path_rule(db_path: Path):
    set_path_rule(
        db_path, PROJECT_ID, "/static/*", priority=None, excluded=True
    )
    rows = list_endpoints(db_path, PROJECT_ID, excluded=True)
    assert [r["id"] for r in rows] == [EP_STATIC]


def test_filter_search_path(db_path: Path):
    rows = list_endpoints(db_path, PROJECT_ID, search="/api/orders")
    assert [r["id"] for r in rows] == [EP_ORDERS]


def test_filter_search_host(db_path: Path):
    rows = list_endpoints(db_path, PROJECT_ID, search="cdn.")
    assert [r["id"] for r in rows] == [EP_STATIC]


def test_filter_role_by_uuid(db_path: Path):
    rows = list_endpoints(db_path, PROJECT_ID, role_id=ROLE_USER)
    ids = {r["id"] for r in rows}
    assert ids == {EP_ADMIN, EP_STATIC}


def test_filter_priority(db_path: Path):
    rows = list_endpoints(db_path, PROJECT_ID, priority="low")
    assert [r["id"] for r in rows] == [EP_UNQUAL]


def test_filter_priority_invalid(db_path: Path):
    with pytest.raises(ValueError, match="Invalid priority"):
        list_endpoints(db_path, PROJECT_ID, priority="URGENT")


def test_combined_filters(db_path: Path):
    rows = list_endpoints(
        db_path, PROJECT_ID,
        method="GET",
        host="api.example.com",
        qualified=True,
    )
    assert [r["id"] for r in rows] == [EP_ORDERS]


def test_empty_project(tmp_path: Path):
    path = tmp_path / "empty.db"
    init_project_db(path)
    assert list_endpoints(path, PROJECT_ID) == []


# ------------------------------------------------------------------ #
# CLI                                                                  #
# ------------------------------------------------------------------ #

def _project(db_path: Path) -> MagicMock:
    project = MagicMock()
    project.db_path = db_path
    project.id = PROJECT_ID
    return project


def test_cli_list_prints_table(db_path: Path, capsys: pytest.CaptureFixture[str]):
    args = MagicMock(
        method=None,
        host=None,
        qualified=False,
        excluded=False,
        search=None,
        role=None,
        priority=None,
        output_format="table",
    )
    cmd_endpoint_list(_project(db_path), args)
    out = capsys.readouterr().out
    assert "UUID" in out
    assert "Method" in out
    assert "Host" in out
    assert "Path" in out
    assert "Priority" in out
    assert "Qualified" in out
    assert "Excluded" in out
    assert EP_ORDERS in out
    assert EP_UNQUAL in out
    assert "4 endpoint(s)." in out


def test_cli_list_json_format(db_path: Path, capsys: pytest.CaptureFixture[str]):
    import json

    args = MagicMock(
        method=None,
        host=None,
        qualified=False,
        excluded=False,
        search=None,
        role=None,
        priority=None,
        output_format="json",
    )
    cmd_endpoint_list(_project(db_path), args)
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, dict)
    assert data["count"] == 4
    assert isinstance(data["endpoints"], list)
    ids = {row["id"] for row in data["endpoints"]}
    assert ids == {EP_ORDERS, EP_ADMIN, EP_STATIC, EP_UNQUAL}
    sample = next(r for r in data["endpoints"] if r["id"] == EP_ORDERS)
    assert sample["method"] == "GET"
    assert sample["host"] == "api.example.com"
    assert sample["path"] == "/api/orders"
    assert sample["priority"]["effective"] in ("HIGH", "NORMAL", "LOW", "CRITICAL")
    assert "source" in sample["priority"]
    assert "qualified" in sample
    assert "tags" in sample
    assert "parameter_count" in sample


def test_cli_list_json_empty(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    import json

    path = tmp_path / "empty.db"
    init_project_db(path)
    args = MagicMock(
        method=None,
        host=None,
        qualified=False,
        excluded=False,
        search=None,
        role=None,
        priority=None,
        output_format="json",
    )
    cmd_endpoint_list(_project(path), args)
    assert json.loads(capsys.readouterr().out) == {"endpoints": [], "count": 0}


def test_cli_list_filter_qualified(db_path: Path, capsys: pytest.CaptureFixture[str]):
    args = MagicMock(
        method=None,
        host=None,
        qualified=True,
        excluded=False,
        search=None,
        role=None,
        priority=None,
        output_format="table",
    )
    cmd_endpoint_list(_project(db_path), args)
    out = capsys.readouterr().out
    assert EP_ORDERS in out
    assert EP_UNQUAL not in out
    assert "3 endpoint(s)." in out


def test_cli_list_unknown_role(db_path: Path, capsys: pytest.CaptureFixture[str]):
    args = MagicMock(
        method=None,
        host=None,
        qualified=False,
        excluded=False,
        search=None,
        role="ghost",
        priority=None,
    )
    with pytest.raises(SystemExit) as exc:
        cmd_endpoint_list(_project(db_path), args)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "Role 'ghost' not found" in err


def test_cli_list_role_name_filter(db_path: Path, capsys: pytest.CaptureFixture[str]):
    args = MagicMock(
        method=None,
        host=None,
        qualified=False,
        excluded=False,
        search=None,
        role="admin",
        priority=None,
    )
    cmd_endpoint_list(_project(db_path), args)
    out = capsys.readouterr().out
    assert EP_ORDERS in out
    assert EP_ADMIN in out
    assert EP_STATIC not in out


def test_run_endpoint_cli_list_subcommand(
    db_path: Path, capsys: pytest.CaptureFixture[str]
):
    """Integration: run_endpoint_cli dispatches 'list' with active project."""
    project = _project(db_path)
    manager = MagicMock(spec=ProjectManager)
    manager.active.return_value = project

    run_endpoint_cli(manager, ["list", "--method", "POST"])
    out = capsys.readouterr().out
    assert EP_ADMIN in out
    assert EP_ORDERS not in out
    assert "1 endpoint(s)." in out
