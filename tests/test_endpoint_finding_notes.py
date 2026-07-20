"""
Tests for CLI-008: endpoint notes/tags and finding notes.

Covers:
  - policy.set_notes / set_tags / add_tags / remove_tags / get_notes_and_tags
  - endpoint CLI: notes set|clear, tags add|remove|set|clear
  - findings_db.update_finding_notes
  - finding CLI: note set|clear + timeline events
  - Endpoint not found / finding not found errors
"""

from __future__ import annotations

import io
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from talos.projects.db import init_project_db
from talos.projects.manager import ProjectManager
import talos.projects.policy as policy_mod
from talos.projects.endpoint_cli import (
    cmd_notes,
    cmd_tags,
    run_endpoint_cli,
)
import talos.findings.db as findings_db
from talos.findings.cli import run_finding_cli, _cmd_note
from talos.findings.model import TIMELINE_ACTOR_ANALYST


PROJECT_ID = "proj-notes-test"
EP_ID = "ep-notes-1"
FINDING_ID = "finding-notes-1"


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    _seed_endpoint(path)
    return path


def _seed_endpoint(db_path: Path) -> None:
    now = "2026-01-01T00:00:00+00:00"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                EP_ID, PROJECT_ID, "GET", "api.example.com",
                "/api/orders", "/api/orders", "application/json", 1,
                "[]", now, now,
            ),
        )


def _project(db_path: Path) -> MagicMock:
    project = MagicMock()
    project.db_path = db_path
    project.id = PROJECT_ID
    return project


def _manager(db_path: Path) -> MagicMock:
    manager = MagicMock(spec=ProjectManager)
    manager.active.return_value = _project(db_path)
    return manager


# ------------------------------------------------------------------ #
# Policy helpers                                                       #
# ------------------------------------------------------------------ #

def test_set_notes_and_get(db_path: Path):
    policy_mod.set_notes(db_path, EP_ID, "Authentication bypass observed.")
    notes, tags = policy_mod.get_notes_and_tags(db_path, EP_ID)
    assert notes == "Authentication bypass observed."
    assert tags == []


def test_tags_add_remove_set_clear(db_path: Path):
    result = policy_mod.add_tags(db_path, EP_ID, ["admin", "critical", "admin"])
    assert result == ["admin", "critical"]

    result = policy_mod.add_tags(db_path, EP_ID, ["pii"])
    assert result == ["admin", "critical", "pii"]

    result = policy_mod.remove_tags(db_path, EP_ID, ["critical"])
    assert result == ["admin", "pii"]

    policy_mod.set_tags(db_path, EP_ID, ["triage", "q2"])
    _, tags = policy_mod.get_notes_and_tags(db_path, EP_ID)
    assert tags == ["triage", "q2"]

    policy_mod.set_tags(db_path, EP_ID, [])
    _, tags = policy_mod.get_notes_and_tags(db_path, EP_ID)
    assert tags == []


def test_get_notes_and_tags_missing_row(db_path: Path):
    notes, tags = policy_mod.get_notes_and_tags(db_path, "missing-ep")
    assert notes == ""
    assert tags == []


# ------------------------------------------------------------------ #
# Endpoint CLI                                                         #
# ------------------------------------------------------------------ #

def test_cmd_notes_set_from_stdin(db_path: Path, capsys: pytest.CaptureFixture[str]):
    args = MagicMock(notes_cmd="set", endpoint_id=EP_ID)
    with patch("sys.stdin", io.StringIO("Line one\nLine two\n")):
        cmd_notes(_project(db_path), args)
    out = capsys.readouterr().out
    assert "Notes set" in out
    notes, _ = policy_mod.get_notes_and_tags(db_path, EP_ID)
    assert notes == "Line one\nLine two"


def test_cmd_notes_set_empty_fails(db_path: Path, capsys: pytest.CaptureFixture[str]):
    args = MagicMock(notes_cmd="set", endpoint_id=EP_ID)
    with patch("sys.stdin", io.StringIO("   \n")):
        with pytest.raises(SystemExit) as exc:
            cmd_notes(_project(db_path), args)
    assert exc.value.code == 1
    assert "empty" in capsys.readouterr().err.lower()


def test_cmd_notes_clear(db_path: Path, capsys: pytest.CaptureFixture[str]):
    policy_mod.set_notes(db_path, EP_ID, "temp")
    args = MagicMock(notes_cmd="clear", endpoint_id=EP_ID)
    cmd_notes(_project(db_path), args)
    assert "Notes cleared" in capsys.readouterr().out
    notes, _ = policy_mod.get_notes_and_tags(db_path, EP_ID)
    assert notes == ""


def test_cmd_notes_unknown_endpoint(db_path: Path, capsys: pytest.CaptureFixture[str]):
    args = MagicMock(notes_cmd="clear", endpoint_id="no-such-ep")
    with pytest.raises(SystemExit) as exc:
        cmd_notes(_project(db_path), args)
    assert exc.value.code == 1
    assert "not found" in capsys.readouterr().err


def test_cmd_tags_add_and_clear(db_path: Path, capsys: pytest.CaptureFixture[str]):
    # New bulk shape: items = [endpoint_id, ...tags] when --tag is omitted (legacy).
    args = MagicMock(
        tags_cmd="add",
        items=[EP_ID, "admin", "critical"],
        tag_flags=None,
        output_format="table",
    )
    cmd_tags(_project(db_path), args)
    out = capsys.readouterr().out
    assert "affected" in out
    _, tags = policy_mod.get_notes_and_tags(db_path, EP_ID)
    assert tags == ["admin", "critical"]

    args = MagicMock(
        tags_cmd="clear",
        endpoint_ids=[EP_ID],
        output_format="table",
    )
    cmd_tags(_project(db_path), args)
    out = capsys.readouterr().out
    assert "tags clear" in out
    _, tags = policy_mod.get_notes_and_tags(db_path, EP_ID)
    assert tags == []


def test_cmd_tags_remove_and_set(db_path: Path, capsys: pytest.CaptureFixture[str]):
    policy_mod.set_tags(db_path, EP_ID, ["a", "b", "c"])
    args = MagicMock(
        tags_cmd="remove",
        items=[EP_ID, "b"],
        tag_flags=None,
        output_format="table",
    )
    cmd_tags(_project(db_path), args)
    _, tags = policy_mod.get_notes_and_tags(db_path, EP_ID)
    assert tags == ["a", "c"]

    args = MagicMock(
        tags_cmd="set",
        items=[EP_ID, "only"],
        tag_flags=None,
        output_format="table",
    )
    cmd_tags(_project(db_path), args)
    _, tags = policy_mod.get_notes_and_tags(db_path, EP_ID)
    assert tags == ["only"]


def test_run_endpoint_cli_tags_dispatch(
    db_path: Path, capsys: pytest.CaptureFixture[str]
):
    run_endpoint_cli(_manager(db_path), ["tags", "add", EP_ID, "admin", "critical"])
    out = capsys.readouterr().out
    assert "tags add" in out
    assert "affected" in out
    _, tags = policy_mod.get_notes_and_tags(db_path, EP_ID)
    assert tags == ["admin", "critical"]


def test_run_endpoint_cli_notes_dispatch(
    db_path: Path, capsys: pytest.CaptureFixture[str]
):
    with patch("sys.stdin", io.StringIO("Authentication bypass observed.\n")):
        run_endpoint_cli(_manager(db_path), ["notes", "set", EP_ID])
    assert "Notes set" in capsys.readouterr().out
    notes, _ = policy_mod.get_notes_and_tags(db_path, EP_ID)
    assert notes == "Authentication bypass observed."


# ------------------------------------------------------------------ #
# Finding notes                                                        #
# ------------------------------------------------------------------ #

def _seed_finding(db_path: Path) -> str:
    return findings_db.create_finding(
        db_path=db_path,
        project_id=PROJECT_ID,
        attack_type="unauth",
        verdict="BYPASS",
        endpoint_id=EP_ID,
        title="Unauth bypass",
        cluster_key=f"UNAUTH:{EP_ID}",
    )


def test_update_finding_notes(db_path: Path):
    fid = _seed_finding(db_path)
    assert findings_db.update_finding_notes(db_path, fid, "Confirmed with customer.")
    finding = findings_db.get_finding(db_path, fid)
    assert finding is not None
    assert finding["notes"] == "Confirmed with customer."


def test_cmd_finding_note_set_and_clear(
    db_path: Path, capsys: pytest.CaptureFixture[str]
):
    fid = _seed_finding(db_path)
    manager = _manager(db_path)

    with patch("sys.stdin", io.StringIO("Confirmed with customer.\n")):
        _cmd_note(manager, ["set", fid])
    out = capsys.readouterr().out
    assert "Notes set" in out

    finding = findings_db.get_finding(db_path, fid)
    assert finding is not None
    assert finding["notes"] == "Confirmed with customer."

    timeline = findings_db.list_timeline(db_path, fid)
    assert any(
        "notes updated" in e["event"].lower() and e["actor"] == TIMELINE_ACTOR_ANALYST
        for e in timeline
    )

    _cmd_note(manager, ["clear", fid])
    out = capsys.readouterr().out
    assert "Notes cleared" in out
    finding = findings_db.get_finding(db_path, fid)
    assert finding is not None
    assert finding["notes"] == ""


def test_cmd_finding_note_missing(db_path: Path, capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exc:
        _cmd_note(_manager(db_path), ["clear", "missing-finding"])
    assert exc.value.code == 1
    assert "not found" in capsys.readouterr().err


def test_run_finding_cli_note_dispatch(
    db_path: Path, capsys: pytest.CaptureFixture[str]
):
    fid = _seed_finding(db_path)
    with patch("sys.stdin", io.StringIO("Piped note.\n")):
        run_finding_cli(_manager(db_path), ["note", "set", fid])
    assert "Notes set" in capsys.readouterr().out
    finding = findings_db.get_finding(db_path, fid)
    assert finding is not None
    assert finding["notes"] == "Piped note."
