"""
Tests for CLI-017 — Project lifecycle management.

Covers:
    - ProjectManager.rename (display name only vs slug+directory move)
    - ProjectManager.set_description
    - ProjectManager.delete(purge=False|True)
    - CLI: rename, description show/set, delete --purge confirm policy
    - Collision / missing / empty-name error paths
"""

from __future__ import annotations

import argparse
import io
import json
import sqlite3
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest

from talos.cli_output import EXIT_CANCELLED, EXIT_USAGE, NONINTERACTIVE_FORCE_REQUIRED
from talos.projects.cli import (
    cmd_delete,
    cmd_description,
    cmd_rename,
)
from talos.projects.manager import (
    ProjectAlreadyExists,
    ProjectManager,
    ProjectNotFound,
    TALOS_PROJECT_ENV,
)
from talos.projects.model import ProjectStatus


@pytest.fixture
def projects_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolated projects root; clear TALOS_PROJECT so suite env cannot leak."""
    monkeypatch.delenv(TALOS_PROJECT_ENV, raising=False)
    root = tmp_path / "projects"
    root.mkdir()
    return root


@pytest.fixture
def manager(projects_root: Path) -> ProjectManager:
    return ProjectManager(projects_root)


def _seed(manager: ProjectManager, name: str = "My App", **kwargs) -> str:
    project = manager.create(name=name, **kwargs)
    return project.id


# ================================================================== #
# Manager: rename                                                      #
# ================================================================== #


class TestRename:
    def test_rename_display_name_same_slug(self, manager: ProjectManager) -> None:
        """Names that slug to the same id only update the display name."""
        pid = _seed(manager, "My App")
        data_dir = Path(manager.get(pid).data_dir)
        assert data_dir.is_dir()

        renamed = manager.rename(pid, "my app")
        assert renamed.id == "my-app"
        assert renamed.name == "my app"
        assert Path(renamed.data_dir) == data_dir
        assert data_dir.is_dir()
        assert manager.get("my-app").name == "my app"

    def test_rename_changes_slug_and_moves_directory(
        self, manager: ProjectManager, projects_root: Path
    ) -> None:
        pid = _seed(manager, "Old Name", description="note", scope=["example.com"])
        manager.open(pid)
        old_dir = projects_root / pid
        assert old_dir.is_dir()
        # Marker file so we prove the tree moved, not recreated empty.
        marker = old_dir / "archive" / "marker.txt"
        marker.write_text("keep-me", encoding="utf-8")

        renamed = manager.rename(pid, "New Brand")
        assert renamed.id == "new-brand"
        assert renamed.name == "New Brand"
        assert renamed.description == "note"
        assert renamed.scope == ["example.com"]
        assert renamed.status == ProjectStatus.ACTIVE
        assert not old_dir.exists()
        new_dir = projects_root / "new-brand"
        assert new_dir.is_dir()
        assert (new_dir / "archive" / "marker.txt").read_text(encoding="utf-8") == "keep-me"
        assert Path(renamed.data_dir) == new_dir

        with pytest.raises(ProjectNotFound):
            manager.get(pid)
        assert manager.get("new-brand").id == "new-brand"
        # Registry ACTIVE still points at renamed project.
        assert manager.active() is not None
        assert manager.active().id == "new-brand"

    def test_rename_rewrites_project_id_in_db(
        self, manager: ProjectManager
    ) -> None:
        pid = _seed(manager, "Alpha")
        db_path = manager.get(pid).db_path
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                """
                INSERT INTO flows (
                    id, project_id, captured_at, method, url, host, path,
                    query, request_headers, request_cookies, status_code,
                    response_headers, content_type, role_id, module_id, tags, source
                ) VALUES (
                    'flow-1', ?, '2026-01-01T00:00:00+00:00', 'GET',
                    'https://example.com/', 'example.com', '/',
                    '', '{}', '{}', 200, '{}', 'text/plain',
                    'global', 'global', '[]', 'proxy_capture'
                )
                """,
                (pid,),
            )
            conn.execute(
                """
                INSERT INTO endpoints (
                    id, project_id, method, host, path, normalized_path,
                    first_seen, last_seen
                ) VALUES (
                    'ep-1', ?, 'GET', 'example.com', '/', '/',
                    '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'
                )
                """,
                (pid,),
            )
            conn.commit()

        manager.rename(pid, "Beta")
        new_db = manager.get("beta").db_path
        with sqlite3.connect(str(new_db)) as conn:
            flow_pid = conn.execute(
                "SELECT project_id FROM flows WHERE id = 'flow-1'"
            ).fetchone()[0]
            ep_pid = conn.execute(
                "SELECT project_id FROM endpoints WHERE id = 'ep-1'"
            ).fetchone()[0]
        assert flow_pid == "beta"
        assert ep_pid == "beta"

    def test_rename_collision_rejected(self, manager: ProjectManager) -> None:
        _seed(manager, "Alpha")
        _seed(manager, "Beta")
        with pytest.raises(ProjectAlreadyExists, match="already exists"):
            manager.rename("alpha", "Beta")

    def test_rename_missing_rejected(self, manager: ProjectManager) -> None:
        with pytest.raises(ProjectNotFound):
            manager.rename("ghost", "Real")

    def test_rename_empty_name_rejected(self, manager: ProjectManager) -> None:
        pid = _seed(manager, "Alpha")
        with pytest.raises(ValueError, match="empty"):
            manager.rename(pid, "   ")

    def test_rename_updates_process_override(
        self, projects_root: Path
    ) -> None:
        base = ProjectManager(projects_root)
        pid = _seed(base, "Old")
        bound = ProjectManager(projects_root, project_override=pid)
        assert bound.active() is not None
        assert bound.active().id == pid

        renamed = bound.rename(pid, "Fresh Name")
        assert renamed.id == "fresh-name"
        assert bound.project_override == "fresh-name"
        assert bound.active() is not None
        assert bound.active().id == "fresh-name"


# ================================================================== #
# Manager: description                                                 #
# ================================================================== #


class TestDescription:
    def test_set_description(self, manager: ProjectManager) -> None:
        pid = _seed(manager, "App", description="old")
        updated = manager.set_description(pid, "Production July Assessment")
        assert updated.description == "Production July Assessment"
        assert manager.get(pid).description == "Production July Assessment"

    def test_clear_description(self, manager: ProjectManager) -> None:
        pid = _seed(manager, "App", description="old")
        updated = manager.set_description(pid, "")
        assert updated.description == ""

    def test_set_description_missing(self, manager: ProjectManager) -> None:
        with pytest.raises(ProjectNotFound):
            manager.set_description("ghost", "x")


# ================================================================== #
# Manager: delete / purge                                              #
# ================================================================== #


class TestDeletePurge:
    def test_delete_preserves_disk(self, manager: ProjectManager, projects_root: Path) -> None:
        pid = _seed(manager, "Keep Data")
        data_dir = projects_root / pid
        assert data_dir.is_dir()
        project = manager.delete(pid, purge=False)
        assert project.id == pid
        with pytest.raises(ProjectNotFound):
            manager.get(pid)
        assert data_dir.is_dir()
        assert (data_dir / "talos.db").is_file()

    def test_delete_purge_removes_everything(
        self, manager: ProjectManager, projects_root: Path
    ) -> None:
        pid = _seed(manager, "Wipe Me")
        data_dir = projects_root / pid
        (data_dir / "archive" / "flows-2026-01-01.jsonl").write_text(
            "{}\n", encoding="utf-8"
        )
        assert data_dir.is_dir()

        project = manager.delete(pid, purge=True)
        assert project.id == pid
        with pytest.raises(ProjectNotFound):
            manager.get(pid)
        assert not data_dir.exists()

    def test_delete_purge_missing_dir_ok(
        self, manager: ProjectManager, projects_root: Path
    ) -> None:
        """Registry entry without on-disk dir still purges cleanly."""
        pid = _seed(manager, "Orphan")
        data_dir = projects_root / pid
        # Simulate hand-deleted directory.
        import shutil

        shutil.rmtree(data_dir)
        project = manager.delete(pid, purge=True)
        assert project.id == pid
        assert not data_dir.exists()

    def test_delete_missing(self, manager: ProjectManager) -> None:
        with pytest.raises(ProjectNotFound):
            manager.delete("ghost", purge=True)


# ================================================================== #
# CLI handlers                                                         #
# ================================================================== #


class TestCliRename:
    def test_rename_cli(self, manager: ProjectManager) -> None:
        _seed(manager, "Old")
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_rename(
                manager,
                argparse.Namespace(id="old", new_name="New App"),
            )
        out = buf.getvalue()
        assert "Project renamed." in out
        assert "new-app" in out
        assert manager.get("new-app").name == "New App"

    def test_rename_cli_collision(self, manager: ProjectManager) -> None:
        _seed(manager, "Alpha")
        _seed(manager, "Beta")
        with pytest.raises(SystemExit) as exc:
            cmd_rename(
                manager,
                argparse.Namespace(id="alpha", new_name="Beta"),
            )
        assert exc.value.code == 1


class TestCliDescription:
    def test_description_show(self, manager: ProjectManager) -> None:
        _seed(manager, "App", description="hello world")
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_description(
                manager,
                argparse.Namespace(id="app", text=[]),
            )
        out = buf.getvalue()
        assert "hello world" in out
        assert "Update with:" in out

    def test_description_set(self, manager: ProjectManager) -> None:
        _seed(manager, "App")
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_description(
                manager,
                argparse.Namespace(
                    id="app",
                    text=["Production", "July", "Assessment"],
                ),
            )
        assert manager.get("app").description == "Production July Assessment"
        assert "Production July Assessment" in buf.getvalue()


class TestCliDeletePurge:
    def test_delete_default_preserves_and_hints_purge(
        self, manager: ProjectManager, projects_root: Path
    ) -> None:
        _seed(manager, "Keep")
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_delete(
                manager,
                argparse.Namespace(id="keep", force=True, purge=False),
            )
        out = buf.getvalue()
        assert "Removed:" in out
        assert "Data preserved" in out
        assert "--purge" in out
        assert (projects_root / "keep").is_dir()

    def test_delete_purge_force(
        self, manager: ProjectManager, projects_root: Path
    ) -> None:
        _seed(manager, "Gone")
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_delete(
                manager,
                argparse.Namespace(id="gone", force=True, purge=True),
            )
        out = buf.getvalue()
        assert "Purged:" in out
        assert not (projects_root / "gone").exists()

    def test_delete_purge_interactive_double_confirm(
        self, manager: ProjectManager, projects_root: Path
    ) -> None:
        _seed(manager, "Double")
        answers = iter(["y", "y"])
        buf = io.StringIO()
        with (
            patch("talos.cli_output.is_interactive", return_value=True),
            patch("builtins.input", side_effect=lambda _p: next(answers)),
            redirect_stdout(buf),
        ):
            cmd_delete(
                manager,
                argparse.Namespace(id="double", force=False, purge=True),
            )
        assert "Purged:" in buf.getvalue()
        assert not (projects_root / "double").exists()

    def test_delete_purge_second_confirm_declined(
        self, manager: ProjectManager, projects_root: Path
    ) -> None:
        _seed(manager, "Stay")
        answers = iter(["y", "n"])
        with (
            patch("talos.cli_output.is_interactive", return_value=True),
            patch("builtins.input", side_effect=lambda _p: next(answers)),
            pytest.raises(SystemExit) as exc,
        ):
            cmd_delete(
                manager,
                argparse.Namespace(id="stay", force=False, purge=True),
            )
        assert exc.value.code == EXIT_CANCELLED
        # Still registered — second confirm aborted.
        assert manager.get("stay").id == "stay"
        assert (projects_root / "stay").is_dir()

    def test_delete_purge_noninteractive_requires_force(
        self, manager: ProjectManager, projects_root: Path
    ) -> None:
        _seed(manager, "Ci")
        err = io.StringIO()
        with (
            patch("talos.cli_output.is_interactive", return_value=False),
            patch(
                "builtins.input",
                side_effect=AssertionError("must not prompt"),
            ),
            redirect_stderr(err),
            pytest.raises(SystemExit) as exc,
        ):
            cmd_delete(
                manager,
                argparse.Namespace(id="ci", force=False, purge=True),
            )
        assert exc.value.code == EXIT_USAGE
        assert NONINTERACTIVE_FORCE_REQUIRED in err.getvalue()
        assert manager.get("ci").id == "ci"
        assert (projects_root / "ci").is_dir()


# ================================================================== #
# Registry JSON shape after rename                                     #
# ================================================================== #


def test_registry_rekeyed_after_rename(
    manager: ProjectManager, projects_root: Path
) -> None:
    _seed(manager, "Before")
    manager.rename("before", "After")
    raw = json.loads((projects_root / "registry.json").read_text(encoding="utf-8"))
    assert "before" not in raw
    assert "after" in raw
    assert raw["after"]["id"] == "after"
    assert raw["after"]["name"] == "After"
    assert raw["after"]["data_dir"].endswith("after")
