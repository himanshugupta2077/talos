"""
Tests for CLI-006 — Complete role & module lifecycle (rename / delete).

Covers:
    - rename_role / rename_module (UUID stable; name uniqueness; global protected)
    - role_dependency_counts / module_dependency_counts
    - delete_role / delete_module cascade + flow reassignment to global
    - CLI handlers: rename, delete --force, abort on confirm refuse, missing
"""

from __future__ import annotations

import argparse
import io
import sqlite3
import uuid
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from talos.projects.access import (
    create_module,
    create_role,
    delete_module,
    delete_role,
    get_active_module,
    get_active_role,
    get_module,
    get_role,
    list_access_map,
    list_modules,
    list_roles,
    module_dependency_counts,
    rename_module,
    rename_role,
    resolve_module,
    resolve_role,
    role_dependency_counts,
    set_active_module,
    set_active_role,
    set_client_access,
)
from talos.projects.access_cli import (
    cmd_module_delete,
    cmd_module_rename,
    cmd_role_delete,
    cmd_role_rename,
)
from talos.projects.auth_provider import set_provider, PROVIDER_MANUAL
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
def manager_with_db(db_path: Path, tmp_path: Path) -> MagicMock:
    """ProjectManager mock with active project (db + data_dir for session files)."""
    data_dir = tmp_path / "project_data"
    data_dir.mkdir()
    project = SimpleNamespace(
        db_path=db_path,
        id="test-project",
        data_dir=str(data_dir),
        auth_session_path=lambda role_id: data_dir / "auth_sessions" / f"{role_id}.txt",
    )
    manager = MagicMock()
    manager.active.return_value = project
    return manager


def _insert_flow(db_path: Path, role_id: str, module_id: str) -> str:
    """Insert a minimal flow row tagged with role_id/module_id; return flow id."""
    flow_id = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO flows (
                id, project_id, captured_at, method, url, host, path,
                query, request_headers, request_cookies, status_code,
                response_headers, content_type, role_id, module_id, tags, source
            ) VALUES (
                ?, 'test-project', '2026-01-01T00:00:00+00:00', 'GET',
                'https://example.com/x', 'example.com', '/x',
                '', '{}', '{}', 200,
                '{}', 'text/plain', ?, ?, '[]', 'proxy_capture'
            )
            """,
            (flow_id, role_id, module_id),
        )
        conn.commit()
    return flow_id


# ================================================================== #
# rename_role                                                          #
# ================================================================== #

class TestRenameRole:
    def test_rename_by_name_keeps_uuid(self, db_path: Path) -> None:
        role_id = create_role(db_path, "adminn")
        result = rename_role(db_path, "adminn", "admin")
        assert result["id"] == role_id
        assert result["old_name"] == "adminn"
        assert result["new_name"] == "admin"
        assert get_role(db_path, "adminn") is None
        assert get_role(db_path, "admin")["id"] == role_id
        assert resolve_role(db_path, role_id)["name"] == "admin"

    def test_rename_by_uuid(self, db_path: Path) -> None:
        role_id = create_role(db_path, "user")
        rename_role(db_path, role_id, "customer")
        assert get_role(db_path, "customer")["id"] == role_id

    def test_rename_global_rejected(self, db_path: Path) -> None:
        with pytest.raises(ValueError, match="global"):
            rename_role(db_path, "global", "something")

    def test_rename_duplicate_rejected(self, db_path: Path) -> None:
        create_role(db_path, "admin")
        create_role(db_path, "user")
        with pytest.raises(ValueError, match="already exists"):
            rename_role(db_path, "user", "admin")

    def test_rename_missing_rejected(self, db_path: Path) -> None:
        with pytest.raises(ValueError, match="not found"):
            rename_role(db_path, "ghost", "admin")

    def test_rename_empty_name_rejected(self, db_path: Path) -> None:
        create_role(db_path, "admin")
        with pytest.raises(ValueError, match="empty"):
            rename_role(db_path, "admin", "  ")

    def test_rename_preserves_access_map(self, db_path: Path) -> None:
        create_role(db_path, "adminn")
        create_module(db_path, "billing")
        set_client_access(db_path, "adminn", "billing", "allow")
        rename_role(db_path, "adminn", "admin")
        entries = list_access_map(db_path)
        assert any(
            e["role"] == "admin" and e["module"] == "billing" for e in entries
        )


# ================================================================== #
# rename_module                                                        #
# ================================================================== #

class TestRenameModule:
    def test_rename_by_name_keeps_uuid(self, db_path: Path) -> None:
        module_id = create_module(db_path, "billin")
        result = rename_module(db_path, "billin", "billing")
        assert result["id"] == module_id
        assert get_module(db_path, "billing")["id"] == module_id

    def test_rename_global_rejected(self, db_path: Path) -> None:
        with pytest.raises(ValueError, match="global"):
            rename_module(db_path, "global", "other")

    def test_rename_duplicate_rejected(self, db_path: Path) -> None:
        create_module(db_path, "a")
        create_module(db_path, "b")
        with pytest.raises(ValueError, match="already exists"):
            rename_module(db_path, "b", "a")


# ================================================================== #
# delete_role                                                          #
# ================================================================== #

class TestDeleteRole:
    def test_delete_unused_role(self, db_path: Path) -> None:
        role_id = create_role(db_path, "adminn")
        result = delete_role(db_path, "adminn")
        assert result["id"] == role_id
        assert result["name"] == "adminn"
        assert get_role(db_path, "adminn") is None
        assert resolve_role(db_path, role_id) is None

    def test_delete_global_rejected(self, db_path: Path) -> None:
        with pytest.raises(ValueError, match="global"):
            delete_role(db_path, "global")

    def test_delete_cascades_access_map(self, db_path: Path) -> None:
        create_role(db_path, "admin")
        create_module(db_path, "billing")
        set_client_access(db_path, "admin", "billing", "allow")
        result = delete_role(db_path, "admin")
        assert result["deleted_access_map"] == 1
        assert list_access_map(db_path) == []

    def test_delete_reassigns_flows_to_global(self, db_path: Path) -> None:
        role_id = create_role(db_path, "admin")
        module_id = create_module(db_path, "billing")
        global_role = get_role(db_path, "global")
        assert global_role is not None
        flow_id = _insert_flow(db_path, role_id, module_id)

        result = delete_role(db_path, "admin")
        assert result["reassigned_flows"] == 1

        with sqlite3.connect(str(db_path)) as conn:
            row = conn.execute(
                "SELECT role_id FROM flows WHERE id = ?", (flow_id,)
            ).fetchone()
        assert row[0] == global_role["id"]

    def test_delete_active_resets_to_global(self, db_path: Path) -> None:
        create_role(db_path, "admin")
        set_active_role(db_path, "admin")
        assert get_active_role(db_path) == "admin"
        result = delete_role(db_path, "admin")
        assert result["was_active"] is True
        assert get_active_role(db_path) == "global"

    def test_delete_cascades_auth_provider(self, db_path: Path) -> None:
        role_id = create_role(db_path, "admin")
        set_provider(db_path, role_id, PROVIDER_MANUAL)
        deps = role_dependency_counts(db_path, role_id)
        assert deps.get("auth_provider", 0) >= 1
        delete_role(db_path, "admin")
        with sqlite3.connect(str(db_path)) as conn:
            n = conn.execute(
                "SELECT COUNT(*) FROM role_auth_provider WHERE role_id = ?",
                (role_id,),
            ).fetchone()[0]
        assert n == 0

    def test_dependency_counts_empty_for_unused(self, db_path: Path) -> None:
        role_id = create_role(db_path, "temp")
        assert role_dependency_counts(db_path, role_id) == {}


# ================================================================== #
# delete_module                                                        #
# ================================================================== #

class TestDeleteModule:
    def test_delete_unused_module(self, db_path: Path) -> None:
        module_id = create_module(db_path, "junk")
        result = delete_module(db_path, "junk")
        assert result["id"] == module_id
        assert get_module(db_path, "junk") is None

    def test_delete_global_rejected(self, db_path: Path) -> None:
        with pytest.raises(ValueError, match="global"):
            delete_module(db_path, "global")

    def test_delete_reassigns_flows(self, db_path: Path) -> None:
        role_id = create_role(db_path, "admin")
        module_id = create_module(db_path, "billing")
        global_mod = get_module(db_path, "global")
        flow_id = _insert_flow(db_path, role_id, module_id)
        result = delete_module(db_path, "billing")
        assert result["reassigned_flows"] == 1
        with sqlite3.connect(str(db_path)) as conn:
            row = conn.execute(
                "SELECT module_id FROM flows WHERE id = ?", (flow_id,)
            ).fetchone()
        assert row[0] == global_mod["id"]

    def test_delete_active_resets_to_global(self, db_path: Path) -> None:
        create_module(db_path, "billing")
        set_active_module(db_path, "billing")
        assert get_active_module(db_path) == "billing"
        delete_module(db_path, "billing")
        assert get_active_module(db_path) == "global"

    def test_dependency_counts_with_access(self, db_path: Path) -> None:
        create_role(db_path, "admin")
        module_id = create_module(db_path, "billing")
        set_client_access(db_path, "admin", "billing", "allow")
        deps = module_dependency_counts(db_path, module_id)
        assert deps.get("access_map") == 1


# ================================================================== #
# CLI handlers                                                         #
# ================================================================== #

class TestRoleCliLifecycle:
    def test_rename_cli(
        self, manager_with_db: MagicMock, db_path: Path
    ) -> None:
        create_role(db_path, "adminn")
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_role_rename(
                manager_with_db,
                argparse.Namespace(name_or_id="adminn", new_name="admin"),
            )
        out = buf.getvalue()
        assert "adminn → admin" in out
        assert get_role(db_path, "admin") is not None

    def test_delete_force(
        self, manager_with_db: MagicMock, db_path: Path
    ) -> None:
        create_role(db_path, "adminn")
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_role_delete(
                manager_with_db,
                argparse.Namespace(name_or_id="adminn", force=True),
            )
        assert "Role deleted: adminn" in buf.getvalue()
        assert get_role(db_path, "adminn") is None

    def test_delete_abort(
        self, manager_with_db: MagicMock, db_path: Path
    ) -> None:
        create_role(db_path, "admin")
        with (
            patch("talos.cli_output.is_interactive", return_value=True),
            patch("builtins.input", return_value="n"),
        ):
            with pytest.raises(SystemExit) as exc:
                cmd_role_delete(
                    manager_with_db,
                    argparse.Namespace(name_or_id="admin", force=False),
                )
        assert exc.value.code == 130  # EXIT_CANCELLED (CLI-012)
        assert get_role(db_path, "admin") is not None

    def test_delete_shows_dependencies(
        self, manager_with_db: MagicMock, db_path: Path
    ) -> None:
        create_role(db_path, "admin")
        create_module(db_path, "billing")
        set_client_access(db_path, "admin", "billing", "allow")
        buf = io.StringIO()
        with (
            redirect_stdout(buf),
            patch("talos.cli_output.is_interactive", return_value=True),
            patch("builtins.input", return_value="n"),
        ):
            with pytest.raises(SystemExit):
                cmd_role_delete(
                    manager_with_db,
                    argparse.Namespace(name_or_id="admin", force=False),
                )
        out = buf.getvalue()
        assert "Access matrix" in out
        assert "Delete anyway" in out or "referenced" in out

    def test_delete_global_cli(
        self, manager_with_db: MagicMock
    ) -> None:
        err = io.StringIO()
        with redirect_stderr(err), pytest.raises(SystemExit) as exc:
            cmd_role_delete(
                manager_with_db,
                argparse.Namespace(name_or_id="global", force=True),
            )
        assert exc.value.code == 1
        assert "global" in err.getvalue()

    def test_delete_missing_cli(
        self, manager_with_db: MagicMock
    ) -> None:
        err = io.StringIO()
        with redirect_stderr(err), pytest.raises(SystemExit) as exc:
            cmd_role_delete(
                manager_with_db,
                argparse.Namespace(name_or_id="nope", force=True),
            )
        assert exc.value.code == 1
        assert "not found" in err.getvalue()

    def test_delete_removes_session_file(
        self, manager_with_db: MagicMock, db_path: Path, tmp_path: Path
    ) -> None:
        role_id = create_role(db_path, "admin")
        project = manager_with_db.active()
        session_path = project.auth_session_path(role_id)
        session_path.parent.mkdir(parents=True, exist_ok=True)
        session_path.write_text("# session\n", encoding="utf-8")
        assert session_path.exists()
        cmd_role_delete(
            manager_with_db,
            argparse.Namespace(name_or_id="admin", force=True),
        )
        assert not session_path.exists()


class TestModuleCliLifecycle:
    def test_rename_cli(
        self, manager_with_db: MagicMock, db_path: Path
    ) -> None:
        create_module(db_path, "billin")
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_module_rename(
                manager_with_db,
                argparse.Namespace(name_or_id="billin", new_name="billing"),
            )
        assert "billin → billing" in buf.getvalue()

    def test_delete_force(
        self, manager_with_db: MagicMock, db_path: Path
    ) -> None:
        create_module(db_path, "old")
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_module_delete(
                manager_with_db,
                argparse.Namespace(name_or_id="old", force=True),
            )
        assert "Module deleted: old" in buf.getvalue()
        assert get_module(db_path, "old") is None

    def test_delete_global_cli(
        self, manager_with_db: MagicMock
    ) -> None:
        err = io.StringIO()
        with redirect_stderr(err), pytest.raises(SystemExit) as exc:
            cmd_module_delete(
                manager_with_db,
                argparse.Namespace(name_or_id="global", force=True),
            )
        assert exc.value.code == 1
        assert "global" in err.getvalue()


class TestSeedIntact:
    def test_list_still_includes_global_after_user_delete(
        self, db_path: Path
    ) -> None:
        create_role(db_path, "temp")
        delete_role(db_path, "temp")
        names = {r["name"] for r in list_roles(db_path)}
        assert "global" in names
        create_module(db_path, "temp-mod")
        delete_module(db_path, "temp-mod")
        mod_names = {m["name"] for m in list_modules(db_path)}
        assert "global" in mod_names
