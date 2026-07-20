"""
CLI-015 — Confirmation prompt consistency.

Covers:
  - Shared non-interactive policy (require --force, never hang on input)
  - Destructive commands that previously deleted immediately now confirm
  - --force bypass on those commands
"""

from __future__ import annotations

import argparse
import io
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from talos.cli_output import EXIT_CANCELLED, EXIT_USAGE, NONINTERACTIVE_FORCE_REQUIRED
from talos.projects.access import create_module, create_role, set_client_access
from talos.projects.access_cli import cmd_access_delete
from talos.projects.auth import get_auth_config, set_auth_fields
from talos.projects.auth_cli import cmd_auth_clear
from talos.configuration.http_cli import cmd_create as cmd_http_create
from talos.configuration.http_cli import cmd_delete as cmd_http_delete
from talos.configuration.manager import ConfigurationManager
from talos.projects.db import init_project_db


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


@pytest.fixture()
def manager_with_db(db_path: Path, tmp_path: Path) -> MagicMock:
    data_dir = tmp_path / "project_data"
    data_dir.mkdir()
    project = SimpleNamespace(
        db_path=db_path,
        id="test-project",
        data_dir=str(data_dir),
    )
    manager = MagicMock()
    manager.active.return_value = project
    return manager


@pytest.fixture()
def http_manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """
    ProjectManager-like mock with managed-project layout under TALOS_DATA_DIR
    so ConfigurationManager concatenates http.rules correctly.
    """
    data_dir = tmp_path / "talos-data"
    projects = data_dir / "projects"
    project_data = projects / "test-project"
    project_data.mkdir(parents=True)
    new_db = project_data / "talos.db"
    init_project_db(new_db)
    project = SimpleNamespace(
        db_path=new_db,
        id="test-project",
        data_dir=str(project_data),
    )
    manager = MagicMock()
    manager.active.return_value = project
    manager._root = projects
    monkeypatch.setenv("TALOS_DATA_DIR", str(data_dir))
    return manager


def _create_http_rule(manager: MagicMock) -> str:
    """Create a project-layer HTTP rule; return its id."""
    cmd_http_create(
        manager,
        argparse.Namespace(
            name="confirm-test",
            description="",
            direction="request",
            priority=100,
            disabled=False,
            scope=None,
            match_host=[],
            match_path=[],
            match_path_prefix=[],
            match_method=[],
            match_status=[],
            match_content_type=[],
            match_header_exists=[],
            match_endpoint_id=[],
            actions=["header.replace:X-Test=1"],
            global_scope=False,
        ),
    )
    data_dir = Path(manager._root).parent
    cfg = ConfigurationManager(data_dir)
    project = manager.active()
    eff = cfg.load_for_project(project)
    assert eff.http.rules
    return eff.http.rules[0]["id"]


# ------------------------------------------------------------------ #
# HTTP rule delete (confirmation policy)                               #
# ------------------------------------------------------------------ #


def test_http_rule_delete_force_skips_prompt(http_manager: MagicMock) -> None:
    rid = _create_http_rule(http_manager)
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_http_delete(
            http_manager,
            argparse.Namespace(id=rid, force=True, global_scope=False),
        )
    assert f"Deleted HTTP rule: {rid}" in buf.getvalue()
    data_dir = Path(http_manager._root).parent
    cfg = ConfigurationManager(data_dir)
    eff = cfg.load_for_project(http_manager.active())
    assert list(eff.http.rules) == []


def test_http_rule_delete_decline_cancels(http_manager: MagicMock) -> None:
    rid = _create_http_rule(http_manager)
    with (
        patch("talos.cli_output.is_interactive", return_value=True),
        patch("builtins.input", return_value="n"),
        pytest.raises(SystemExit) as exc,
    ):
        cmd_http_delete(
            http_manager,
            argparse.Namespace(id=rid, force=False, global_scope=False),
        )
    assert exc.value.code == EXIT_CANCELLED
    data_dir = Path(http_manager._root).parent
    cfg = ConfigurationManager(data_dir)
    eff = cfg.load_for_project(http_manager.active())
    assert len(eff.http.rules) == 1


def test_http_rule_delete_noninteractive_requires_force(http_manager: MagicMock) -> None:
    rid = _create_http_rule(http_manager)
    err = io.StringIO()
    with (
        patch("talos.cli_output.is_interactive", return_value=False),
        patch(
            "builtins.input",
            side_effect=AssertionError("must not prompt non-interactively"),
        ),
        redirect_stderr(err),
        pytest.raises(SystemExit) as exc,
    ):
        cmd_http_delete(
            http_manager,
            argparse.Namespace(id=rid, force=False, global_scope=False),
        )
    assert exc.value.code == EXIT_USAGE
    assert NONINTERACTIVE_FORCE_REQUIRED in err.getvalue()
    data_dir = Path(http_manager._root).parent
    cfg = ConfigurationManager(data_dir)
    eff = cfg.load_for_project(http_manager.active())
    assert len(eff.http.rules) == 1


# ------------------------------------------------------------------ #
# access delete                                                        #
# ------------------------------------------------------------------ #


def test_access_delete_force(
    manager_with_db: MagicMock, db_path: Path
) -> None:
    create_role(db_path, "admin")
    create_module(db_path, "orders")
    set_client_access(db_path, "admin", "orders", "allow")
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_access_delete(
            manager_with_db,
            argparse.Namespace(role="admin", module="orders", force=True),
        )
    assert "Access mapping deleted" in buf.getvalue()


def test_access_delete_noninteractive_requires_force(
    manager_with_db: MagicMock, db_path: Path
) -> None:
    create_role(db_path, "admin")
    create_module(db_path, "orders")
    set_client_access(db_path, "admin", "orders", "allow")
    err = io.StringIO()
    with (
        patch("talos.cli_output.is_interactive", return_value=False),
        redirect_stderr(err),
        pytest.raises(SystemExit) as exc,
    ):
        cmd_access_delete(
            manager_with_db,
            argparse.Namespace(role="admin", module="orders", force=False),
        )
    assert exc.value.code == EXIT_USAGE
    assert NONINTERACTIVE_FORCE_REQUIRED in err.getvalue()


# ------------------------------------------------------------------ #
# auth clear                                                           #
# ------------------------------------------------------------------ #


def test_auth_clear_force(manager_with_db: MagicMock, db_path: Path) -> None:
    project = manager_with_db.active()
    set_auth_fields(db_path, cookies=["session"], headers=["Authorization"])
    assert get_auth_config(db_path)["cookies"] == ["session"]
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_auth_clear(project, argparse.Namespace(force=True))
    assert "Auth requirements cleared." in buf.getvalue()
    cfg = get_auth_config(db_path)
    assert cfg["cookies"] == []
    assert cfg["headers"] == []


def test_auth_clear_noninteractive_requires_force(
    manager_with_db: MagicMock, db_path: Path
) -> None:
    project = manager_with_db.active()
    set_auth_fields(db_path, cookies=["session"], headers=[])
    err = io.StringIO()
    with (
        patch("talos.cli_output.is_interactive", return_value=False),
        redirect_stderr(err),
        pytest.raises(SystemExit) as exc,
    ):
        cmd_auth_clear(project, argparse.Namespace(force=False))
    assert exc.value.code == EXIT_USAGE
    assert NONINTERACTIVE_FORCE_REQUIRED in err.getvalue()
    assert get_auth_config(db_path)["cookies"] == ["session"]
