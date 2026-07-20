"""
Tests for endpoint core updates (bulk mutations, policy explain, rule CRUD, preview).

Covers:
  - Atomic bulk mark / priority / exclude / tags (validate-all, no partial write)
  - Invalid ID rejects entire operation
  - Dedupe of repeated IDs
  - explain_endpoint_policy structure
  - First-class policy rule add/update/delete/list/show
  - Path-rule impact preview using shared matcher
  - CLI multi-ID mark and rule commands
  - Canonical origin fields on list/show JSON
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from talos.projects.db import init_project_db
from talos.projects import policy as policy_mod
from talos.projects.endpoint_cli import (
    cmd_endpoint_mark,
    cmd_endpoint_policy,
    cmd_rule,
    run_endpoint_cli,
)
from talos.projects.manager import ProjectManager


PROJECT_ID = "proj-core"
EP_A = "ep-a"
EP_B = "ep-b"
EP_C = "ep-c"
EP_ADMIN = "ep-admin-core"


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    _seed(path)
    return path


def _seed(db_path: Path) -> None:
    now = "2026-01-01T00:00:00+00:00"
    with sqlite3.connect(str(db_path)) as conn:
        conn.executemany(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (EP_A, PROJECT_ID, "GET", "https://api.example.com:8443",
                 "/api/users", "/api/users", "application/json", 1, "[]", now, now),
                (EP_B, PROJECT_ID, "POST", "https://api.example.com:8443",
                 "/api/users", "/api/users", "application/json", 1, "[]", now, now),
                (EP_C, PROJECT_ID, "GET", "https://api.example.com:8443",
                 "/api/orders", "/api/orders", "application/json", 1, "[]", now, now),
                (EP_ADMIN, PROJECT_ID, "DELETE", "https://api.example.com:8443",
                 "/api/admin/users/1", "/api/admin/users/{id}", "application/json",
                 1, "[]", now, now),
            ],
        )
        for eid, score in [(EP_A, 40), (EP_B, 50), (EP_C, 30), (EP_ADMIN, 80)]:
            conn.execute(
                """
                INSERT INTO endpoint_policy
                    (endpoint_id, auto_priority, auto_score, auto_breakdown,
                     excluded, dangerous, logout, qualified, qualification_reason,
                     baseline_flow_id, baseline_status, updated_at)
                VALUES (?, 'HIGH', ?, '{}', 0, 0, 0, 1, 'flow_2xx', NULL, 200, ?)
                """,
                (eid, score, now),
            )
        conn.commit()


def _project(db_path: Path) -> MagicMock:
    project = MagicMock()
    project.db_path = db_path
    project.id = PROJECT_ID
    return project


# ------------------------------------------------------------------ #
# Bulk mutations                                                       #
# ------------------------------------------------------------------ #

def test_bulk_mark_dangerous_atomic(db_path: Path):
    result = policy_mod.bulk_set_safety(
        db_path, [EP_A, EP_B], dangerous=True,
    )
    assert result["affected"] == 2
    assert result["unchanged"] == 0
    assert set(result["affected_ids"]) == {EP_A, EP_B}

    # Second call is unchanged.
    result2 = policy_mod.bulk_set_safety(
        db_path, [EP_A, EP_B], dangerous=True,
    )
    assert result2["affected"] == 0
    assert result2["unchanged"] == 2


def test_bulk_rejects_invalid_id_no_partial(db_path: Path):
    with pytest.raises(policy_mod.BulkEndpointError, match="not found"):
        policy_mod.bulk_set_safety(
            db_path, [EP_A, "missing-id", EP_B], dangerous=True,
        )
    # EP_A must remain unmarked.
    ann = policy_mod.get_effective_policy(
        db_path, PROJECT_ID, EP_A, "/api/users",
    )
    assert ann.dangerous is False


def test_bulk_dedupes_ids(db_path: Path):
    result = policy_mod.bulk_set_safety(
        db_path, [EP_A, EP_A, EP_B], logout=True,
    )
    assert result["count"] == 2
    assert result["affected"] == 2


def test_bulk_priority_set_and_clear(db_path: Path):
    r1 = policy_mod.bulk_set_manual_priority(db_path, [EP_A, EP_C], "CRITICAL")
    assert r1["affected"] == 2
    pol = policy_mod.get_effective_policy(
        db_path, PROJECT_ID, EP_A, "/api/users",
    )
    assert pol.effective_level == "CRITICAL"
    assert pol.source == "manual"

    r2 = policy_mod.bulk_set_manual_priority(db_path, [EP_A, EP_C], None)
    assert r2["affected"] == 2
    pol2 = policy_mod.get_effective_policy(
        db_path, PROJECT_ID, EP_A, "/api/users",
    )
    assert pol2.source == "auto"


def test_bulk_exclude_include(db_path: Path):
    r1 = policy_mod.bulk_set_excluded(db_path, [EP_A, EP_B], True)
    assert r1["affected"] == 2
    listed = policy_mod.list_endpoints(db_path, PROJECT_ID, excluded=True)
    assert {e["id"] for e in listed} == {EP_A, EP_B}

    r2 = policy_mod.bulk_set_excluded(db_path, [EP_A, EP_B], False)
    assert r2["affected"] == 2


def test_bulk_tags_add_remove(db_path: Path):
    r1 = policy_mod.bulk_add_tags(db_path, [EP_A, EP_B], ["admin", "triage"])
    assert r1["affected"] == 2
    _, tags = policy_mod.get_notes_and_tags(db_path, EP_A)
    assert tags == ["admin", "triage"]

    r2 = policy_mod.bulk_remove_tags(db_path, [EP_A], ["admin"])
    assert r2["affected"] == 1
    _, tags2 = policy_mod.get_notes_and_tags(db_path, EP_A)
    assert tags2 == ["triage"]


# ------------------------------------------------------------------ #
# Origin identity on list                                              #
# ------------------------------------------------------------------ #

def test_list_exposes_canonical_origin(db_path: Path):
    rows = policy_mod.list_endpoints(db_path, PROJECT_ID, method="GET")
    sample = next(r for r in rows if r["id"] == EP_A)
    assert sample["origin"] == "https://api.example.com:8443"
    assert sample["host_display"] == "api.example.com"

    payload = policy_mod.format_endpoint_list_json([sample])
    assert payload["endpoints"][0]["origin"] == "https://api.example.com:8443"
    assert payload["endpoints"][0]["host"] == "api.example.com"
    assert payload["endpoints"][0]["path"] == "/api/users"
    assert "priority" in payload["endpoints"][0]


# ------------------------------------------------------------------ #
# Policy explanation                                                   #
# ------------------------------------------------------------------ #

def test_explain_policy_path_rule(db_path: Path):
    rule = policy_mod.add_path_rule(
        db_path, PROJECT_ID, "/api/admin/*",
        priority="CRITICAL", excluded=True,
    )
    explanation = policy_mod.explain_endpoint_policy(
        db_path, PROJECT_ID, EP_ADMIN, "/api/admin/users/{id}",
    )
    assert explanation["priority"]["effective"] == "CRITICAL"
    assert explanation["priority"]["source"] == "path_rule"
    assert explanation["priority"]["rule"]["pattern"] == "/api/admin/*"
    assert explanation["priority"]["rule"]["id"] == rule["id"]
    assert explanation["exclusion"]["effective"] is True
    assert explanation["exclusion"]["source"] == "path_rule"
    assert explanation["exclusion"]["rule_id"] == rule["id"]


def test_cli_policy_json(db_path: Path, capsys: pytest.CaptureFixture[str]):
    args = MagicMock(endpoint_id=EP_A, output_format="json")
    cmd_endpoint_policy(_project(db_path), args)
    data = json.loads(capsys.readouterr().out)
    assert data["endpoint_id"] == EP_A
    assert "priority" in data
    assert "exclusion" in data
    assert "qualification" in data
    assert "safety" in data
    assert "baseline" in data
    assert data["endpoint"]["origin"] == "https://api.example.com:8443"


# ------------------------------------------------------------------ #
# Rule CRUD + preview                                                  #
# ------------------------------------------------------------------ #

def test_rule_crud(db_path: Path):
    rule = policy_mod.add_path_rule(
        db_path, PROJECT_ID, "/api/admin/*",
        priority="HIGH", excluded=False,
    )
    assert rule["pattern"] == "/api/admin/*"
    assert rule["priority"] == "HIGH"
    assert rule["excluded"] is False

    updated = policy_mod.update_path_rule(
        db_path, PROJECT_ID, rule["id"],
        excluded=True,
    )
    assert updated["excluded"] is True
    assert updated["priority"] == "HIGH"

    updated2 = policy_mod.update_path_rule(
        db_path, PROJECT_ID, rule["id"],
        clear_priority=True,
    )
    assert updated2["priority"] is None
    assert updated2["excluded"] is True

    shown = policy_mod.get_path_rule(db_path, PROJECT_ID, rule["id"])
    assert shown is not None
    assert shown["id"] == rule["id"]

    assert policy_mod.delete_path_rule_by_id(db_path, PROJECT_ID, rule["id"])
    assert policy_mod.get_path_rule(db_path, PROJECT_ID, rule["id"]) is None


def test_rule_preview_exclude(db_path: Path):
    preview = policy_mod.preview_path_rule_impact(
        db_path, PROJECT_ID, "/api/admin/*", excluded=True,
    )
    assert preview["matching_count"] == 1
    assert preview["endpoints"][0]["id"] == EP_ADMIN
    assert preview["proposed"]["newly_excluded"] == 1
    assert preview["proposed"]["already_excluded"] == 0

    # After excluding via path rule, already_excluded rises.
    policy_mod.add_path_rule(
        db_path, PROJECT_ID, "/api/admin/*", excluded=True,
    )
    preview2 = policy_mod.preview_path_rule_impact(
        db_path, PROJECT_ID, "/api/admin/*", excluded=True,
    )
    assert preview2["proposed"]["already_excluded"] == 1
    assert preview2["proposed"]["newly_excluded"] == 0


def test_rule_preview_uses_same_matcher(db_path: Path):
    # Case-insensitive path matching (policy contract).
    preview = policy_mod.preview_path_rule_impact(
        db_path, PROJECT_ID, "/API/ADMIN/*",
    )
    assert preview["matching_count"] == 1


def test_legacy_path_priority_routes_through_set_path_rule(db_path: Path):
    rule_id = policy_mod.set_path_rule(
        db_path, PROJECT_ID, "/static/*", priority="LOW", excluded=False,
    )
    rule = policy_mod.get_path_rule(db_path, PROJECT_ID, rule_id)
    assert rule is not None
    assert rule["priority"] == "LOW"


# ------------------------------------------------------------------ #
# CLI bulk + rule commands                                             #
# ------------------------------------------------------------------ #

def test_cli_mark_multi_id(db_path: Path, capsys: pytest.CaptureFixture[str]):
    args = MagicMock(
        endpoint_ids=[EP_A, EP_B],
        logout=False,
        dangerous=True,
        safe=False,
        output_format="json",
    )
    cmd_endpoint_mark(_project(db_path), args)
    data = json.loads(capsys.readouterr().out)
    assert data["affected"] == 2
    assert data["count"] == 2
    assert data["action"] == "mark --dangerous"


def test_cli_mark_invalid_id_exits(db_path: Path, capsys: pytest.CaptureFixture[str]):
    args = MagicMock(
        endpoint_ids=[EP_A, "nope"],
        logout=False,
        dangerous=True,
        safe=False,
        output_format="table",
    )
    with pytest.raises(SystemExit) as exc:
        cmd_endpoint_mark(_project(db_path), args)
    assert exc.value.code == 1
    assert "not found" in capsys.readouterr().err


def test_cli_rule_add_and_preview(
    db_path: Path, capsys: pytest.CaptureFixture[str]
):
    project = _project(db_path)
    manager = MagicMock(spec=ProjectManager)
    manager.active.return_value = project

    run_endpoint_cli(
        manager,
        ["rule", "add", "/api/admin/*", "--priority", "HIGH", "--exclude",
         "--format", "json"],
    )
    data = json.loads(capsys.readouterr().out)
    assert data["rule"]["pattern"] == "/api/admin/*"
    assert data["rule"]["priority"] == "HIGH"
    assert data["rule"]["excluded"] is True
    rule_id = data["rule"]["id"]

    run_endpoint_cli(
        manager,
        ["rule", "preview", "/api/admin/*", "--exclude", "--format", "json"],
    )
    preview = json.loads(capsys.readouterr().out)
    assert preview["matching_count"] == 1

    run_endpoint_cli(manager, ["rule", "show", rule_id, "--format", "json"])
    shown = json.loads(capsys.readouterr().out)
    assert shown["id"] == rule_id

    run_endpoint_cli(manager, ["rule", "list", "--format", "json"])
    listed = json.loads(capsys.readouterr().out)
    assert listed["count"] == 1

    run_endpoint_cli(manager, ["rule", "delete", rule_id, "--format", "json"])
    deleted = json.loads(capsys.readouterr().out)
    assert deleted["deleted"] is True


def test_cli_priority_multi_id(
    db_path: Path, capsys: pytest.CaptureFixture[str]
):
    project = _project(db_path)
    manager = MagicMock(spec=ProjectManager)
    manager.active.return_value = project

    run_endpoint_cli(
        manager,
        ["priority", "set", "endpoint", EP_A, EP_B, "CRITICAL", "--format", "json"],
    )
    data = json.loads(capsys.readouterr().out)
    assert data["affected"] == 2
    assert data["action"] == "priority set CRITICAL"

    run_endpoint_cli(
        manager,
        ["priority", "clear", "endpoint", EP_A, EP_B, "--format", "json"],
    )
    data2 = json.loads(capsys.readouterr().out)
    assert data2["affected"] == 2


def test_cli_tags_multi_with_flag(
    db_path: Path, capsys: pytest.CaptureFixture[str]
):
    project = _project(db_path)
    manager = MagicMock(spec=ProjectManager)
    manager.active.return_value = project

    run_endpoint_cli(
        manager,
        ["tags", "add", EP_A, EP_B, "--tag", "admin", "--tag", "triage",
         "--format", "json"],
    )
    data = json.loads(capsys.readouterr().out)
    assert data["affected"] == 2
    _, tags = policy_mod.get_notes_and_tags(db_path, EP_A)
    assert tags == ["admin", "triage"]


def test_cli_tags_legacy_positional(
    db_path: Path, capsys: pytest.CaptureFixture[str]
):
    project = _project(db_path)
    manager = MagicMock(spec=ProjectManager)
    manager.active.return_value = project

    run_endpoint_cli(
        manager,
        ["tags", "add", EP_A, "legacy-tag", "--format", "json"],
    )
    data = json.loads(capsys.readouterr().out)
    assert data["affected"] == 1
    _, tags = policy_mod.get_notes_and_tags(db_path, EP_A)
    assert "legacy-tag" in tags


def test_cmd_rule_update_include(
    db_path: Path, capsys: pytest.CaptureFixture[str]
):
    rule = policy_mod.add_path_rule(
        db_path, PROJECT_ID, "/api/*", priority="NORMAL", excluded=True,
    )
    args = MagicMock(
        rule_cmd="update",
        rule_id=rule["id"],
        priority=None,
        clear_priority=False,
        exclude=False,
        include=True,
        output_format="json",
    )
    cmd_rule(_project(db_path), args)
    data = json.loads(capsys.readouterr().out)
    assert data["rule"]["excluded"] is False
