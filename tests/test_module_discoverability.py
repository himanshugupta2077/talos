"""
Tests for CLI-004 — Module name/UUID discoverability.

Covers:
    - resolve_module / get_module_by_id (name first, then UUID)
    - module list shows UUID + Name + Active
    - module show by name and by UUID
    - BAC --module resolves name to UUID via _resolve_module_scope
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
    create_module,
    create_role,
    get_module,
    get_module_by_id,
    list_modules,
    resolve_module,
    set_active_module,
    set_client_access,
)
from talos.projects.access_cli import cmd_module_list, cmd_module_show
from talos.projects.bac.cli import _resolve_module_scope
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
# resolve_module                                                       #
# ================================================================== #

class TestResolveModule:
    def test_resolve_by_name(self, db_path: Path) -> None:
        module_id = create_module(db_path, "payments")
        module = resolve_module(db_path, "payments")
        assert module is not None
        assert module["id"] == module_id
        assert module["name"] == "payments"

    def test_resolve_by_uuid(self, db_path: Path) -> None:
        module_id = create_module(db_path, "billing")
        module = resolve_module(db_path, module_id)
        assert module is not None
        assert module["id"] == module_id
        assert module["name"] == "billing"

    def test_resolve_missing_returns_none(self, db_path: Path) -> None:
        assert resolve_module(db_path, "nope") is None
        assert resolve_module(db_path, str(uuid.uuid4())) is None

    def test_get_module_by_id(self, db_path: Path) -> None:
        module_id = create_module(db_path, "admin")
        module = get_module_by_id(db_path, module_id)
        assert module is not None
        assert module["name"] == "admin"
        assert get_module_by_id(db_path, str(uuid.uuid4())) is None

    def test_name_preferred_over_uuid_collision(self, db_path: Path) -> None:
        """If a module is named like another module's UUID, name wins."""
        first_id = create_module(db_path, "alpha")
        second_id = str(uuid.uuid4())
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                "INSERT INTO modules (id, name, description, is_active) "
                "VALUES (?, ?, '', 0)",
                (second_id, first_id),
            )
            conn.commit()
        resolved = resolve_module(db_path, first_id)
        assert resolved is not None
        assert resolved["id"] == second_id
        assert resolved["name"] == first_id


# ================================================================== #
# module list / show                                                   #
# ================================================================== #

class TestModuleListShow:
    def test_list_includes_uuid_name_active(
        self, manager_with_db: MagicMock, db_path: Path
    ) -> None:
        payments_id = create_module(db_path, "payments")
        create_module(db_path, "billing")
        set_active_module(db_path, "payments")

        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_module_list(manager_with_db, argparse.Namespace())
        out = buf.getvalue()

        assert "UUID" in out
        assert "Name" in out
        assert "Active" in out
        assert payments_id in out
        assert "payments" in out
        assert "billing" in out
        lines = [ln for ln in out.splitlines() if payments_id in ln]
        assert lines
        assert "*" in lines[0]

    def test_show_by_name(
        self, manager_with_db: MagicMock, db_path: Path
    ) -> None:
        module_id = create_module(
            db_path, "payments", description="Payment APIs"
        )
        create_role(db_path, "admin")
        set_client_access(db_path, "admin", "payments", "allow")
        set_active_module(db_path, "payments")

        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_module_show(
                manager_with_db, argparse.Namespace(name_or_id="payments")
            )
        out = buf.getvalue()

        assert "Name            : payments" in out
        assert f"UUID            : {module_id}" in out
        assert "Status          : active" in out
        assert "Payment APIs" in out
        assert "admin" in out

    def test_show_by_uuid(
        self, manager_with_db: MagicMock, db_path: Path
    ) -> None:
        module_id = create_module(db_path, "billing")
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_module_show(
                manager_with_db, argparse.Namespace(name_or_id=module_id)
            )
        out = buf.getvalue()
        assert "Name            : billing" in out
        assert f"UUID            : {module_id}" in out
        assert "Status          : inactive" in out

    def test_show_missing_exits(
        self, manager_with_db: MagicMock
    ) -> None:
        err = io.StringIO()
        with redirect_stderr(err), pytest.raises(SystemExit) as exc:
            cmd_module_show(
                manager_with_db, argparse.Namespace(name_or_id="missing")
            )
        assert exc.value.code == 1
        assert "not found" in err.getvalue()


# ================================================================== #
# BAC --module resolution                                              #
# ================================================================== #

class TestBacModuleResolution:
    def test_resolve_module_scope_by_name(self, db_path: Path) -> None:
        module_id = create_module(db_path, "payments")
        resolved_id, name = _resolve_module_scope(db_path, "payments")
        assert resolved_id == module_id
        assert name == "payments"

    def test_resolve_module_scope_by_uuid(self, db_path: Path) -> None:
        module_id = create_module(db_path, "billing")
        resolved_id, name = _resolve_module_scope(db_path, module_id)
        assert resolved_id == module_id
        assert name == "billing"

    def test_resolve_module_scope_missing_exits(self, db_path: Path) -> None:
        err = io.StringIO()
        with redirect_stderr(err), pytest.raises(SystemExit) as exc:
            _resolve_module_scope(db_path, "ghost")
        assert exc.value.code == 1
        assert "not found" in err.getvalue()


# ================================================================== #
# list_modules data                                                    #
# ================================================================== #

class TestListModulesData:
    def test_list_modules_includes_ids(self, db_path: Path) -> None:
        a = create_module(db_path, "admin")
        p = create_module(db_path, "payments")
        modules = list_modules(db_path)
        by_name = {m["name"]: m for m in modules}
        assert by_name["admin"]["id"] == a
        assert by_name["payments"]["id"] == p
        assert get_module(db_path, "admin")["id"] == a
