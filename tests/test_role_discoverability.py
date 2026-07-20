"""
Tests for CLI-001 — Role UUID discoverability.

Covers:
    - resolve_role / get_role_by_id (name first, then UUID)
    - role list shows UUID + Name + Active
    - role show by name and by UUID
    - auth-config resolves role name to UUID before dispatch
"""

from __future__ import annotations

import argparse
import io
import sqlite3
import uuid
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from talos.projects.access import (
    create_role,
    get_role,
    get_role_by_id,
    list_roles,
    resolve_role,
    set_active_role,
    set_client_access,
    create_module,
)
from talos.projects.access_cli import cmd_role_list, cmd_role_show
from talos.projects.auth_config_cli import _resolve_role_id, cmd_list_flows, cmd_set_provider
from talos.projects.auth_provider import PROVIDER_MANUAL, get_provider
from talos.projects.db import init_project_db


# ------------------------------------------------------------------ #
# Fixtures                                                             #
# ------------------------------------------------------------------ #

@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    """Create a fully-initialised project DB and return its path."""
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


@pytest.fixture
def manager_with_db(db_path: Path) -> MagicMock:
    """ProjectManager mock whose active() returns a project with db_path."""
    project = SimpleNamespace(db_path=db_path, id="test-project")
    manager = MagicMock()
    manager.active.return_value = project
    return manager


# ================================================================== #
# resolve_role                                                         #
# ================================================================== #

class TestResolveRole:
    def test_resolve_by_name(self, db_path: Path) -> None:
        role_id = create_role(db_path, "admin")
        role = resolve_role(db_path, "admin")
        assert role is not None
        assert role["id"] == role_id
        assert role["name"] == "admin"

    def test_resolve_by_uuid(self, db_path: Path) -> None:
        role_id = create_role(db_path, "user")
        role = resolve_role(db_path, role_id)
        assert role is not None
        assert role["id"] == role_id
        assert role["name"] == "user"

    def test_resolve_missing_returns_none(self, db_path: Path) -> None:
        assert resolve_role(db_path, "nope") is None
        assert resolve_role(db_path, str(uuid.uuid4())) is None

    def test_get_role_by_id(self, db_path: Path) -> None:
        role_id = create_role(db_path, "support")
        role = get_role_by_id(db_path, role_id)
        assert role is not None
        assert role["name"] == "support"
        assert get_role_by_id(db_path, str(uuid.uuid4())) is None

    def test_name_preferred_over_uuid_collision(self, db_path: Path) -> None:
        """If a role is named like another role's UUID, name wins."""
        first_id = create_role(db_path, "alpha")
        # Create a second role whose *name* equals first_id (UUID string).
        second_id = str(uuid.uuid4())
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                "INSERT INTO roles (id, name, is_active) VALUES (?, ?, 0)",
                (second_id, first_id),
            )
            conn.commit()
        resolved = resolve_role(db_path, first_id)
        assert resolved is not None
        # Name lookup hits the second role (name == first_id).
        assert resolved["id"] == second_id
        assert resolved["name"] == first_id


# ================================================================== #
# role list / show                                                     #
# ================================================================== #

class TestRoleListShow:
    def test_list_includes_uuid_name_active(
        self, manager_with_db: MagicMock, db_path: Path
    ) -> None:
        admin_id = create_role(db_path, "admin")
        create_role(db_path, "user")
        set_active_role(db_path, "admin")

        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_role_list(manager_with_db, argparse.Namespace())
        out = buf.getvalue()

        assert "UUID" in out
        assert "Name" in out
        assert "Active" in out
        assert admin_id in out
        assert "admin" in out
        assert "user" in out
        # Active marker on admin row
        lines = [ln for ln in out.splitlines() if admin_id in ln]
        assert lines
        assert "*" in lines[0]

    def test_show_by_name(
        self, manager_with_db: MagicMock, db_path: Path
    ) -> None:
        role_id = create_role(db_path, "admin")
        create_module(db_path, "billing")
        set_client_access(db_path, "admin", "billing", "allow")
        set_active_role(db_path, "admin")

        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_role_show(
                manager_with_db, argparse.Namespace(name_or_id="admin")
            )
        out = buf.getvalue()

        assert f"Name            : admin" in out
        assert f"UUID            : {role_id}" in out
        assert "Status          : active" in out
        assert "billing" in out
        assert "Configured auth :" in out
        assert "Flow count      : 0" in out

    def test_show_by_uuid(
        self, manager_with_db: MagicMock, db_path: Path
    ) -> None:
        role_id = create_role(db_path, "guest")
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_role_show(
                manager_with_db, argparse.Namespace(name_or_id=role_id)
            )
        out = buf.getvalue()
        assert "Name            : guest" in out
        assert f"UUID            : {role_id}" in out
        assert "Status          : inactive" in out

    def test_show_missing_exits(
        self, manager_with_db: MagicMock
    ) -> None:
        err = io.StringIO()
        with redirect_stderr(err), pytest.raises(SystemExit) as exc:
            cmd_role_show(
                manager_with_db, argparse.Namespace(name_or_id="missing")
            )
        assert exc.value.code == 1
        assert "not found" in err.getvalue()


# ================================================================== #
# auth-config role resolution                                          #
# ================================================================== #

class TestAuthConfigRoleResolution:
    def test_resolve_role_id_by_name(self, db_path: Path) -> None:
        role_id = create_role(db_path, "analyst")
        assert _resolve_role_id(db_path, "analyst") == role_id

    def test_resolve_role_id_by_uuid(self, db_path: Path) -> None:
        role_id = create_role(db_path, "analyst")
        assert _resolve_role_id(db_path, role_id) == role_id

    def test_resolve_role_id_missing_exits(self, db_path: Path) -> None:
        err = io.StringIO()
        with redirect_stderr(err), pytest.raises(SystemExit) as exc:
            _resolve_role_id(db_path, "ghost")
        assert exc.value.code == 1
        assert "not found" in err.getvalue()

    def test_set_provider_accepts_name(self, db_path: Path) -> None:
        role_id = create_role(db_path, "admin")
        # Simulate dispatch: resolve then call handler with UUID.
        resolved = _resolve_role_id(db_path, "admin")
        assert resolved == role_id
        args = argparse.Namespace(role_id=resolved, provider=PROVIDER_MANUAL)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_set_provider(db_path, args)
        assert get_provider(db_path, role_id) == PROVIDER_MANUAL

    def test_list_flows_after_name_resolve(self, db_path: Path) -> None:
        role_id = create_role(db_path, "user")
        args = argparse.Namespace(role_id=_resolve_role_id(db_path, "user"))
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_list_flows(db_path, args)
        out = buf.getvalue()
        assert role_id in out or "No flows" in out


# ================================================================== #
# list_roles data                                                      #
# ================================================================== #

class TestListRolesData:
    def test_list_roles_includes_ids(self, db_path: Path) -> None:
        a = create_role(db_path, "admin")
        u = create_role(db_path, "user")
        roles = list_roles(db_path)
        by_name = {r["name"]: r for r in roles}
        assert by_name["admin"]["id"] == a
        assert by_name["user"]["id"] == u
        assert get_role(db_path, "admin")["id"] == a
