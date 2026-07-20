"""
Tests for CLI-013: process-scoped project context override.

Covers:
  - ProjectManager.active() prefers constructor override over registry ACTIVE
  - TALOS_PROJECT env is honored when no constructor override is given
  - Constructor override wins over TALOS_PROJECT
  - Override does not rewrite registry ACTIVE status
  - Unknown override id raises ProjectNotFound
  - Root CLI: --project and --project= forms; missing value → exit 2
  - Root CLI: unknown project → exit 1
  - Concurrent binds: two managers with different overrides stay independent
  - Endpoint list works with override while registry has no ACTIVE project
  - End-to-end simulation: create → --project / TALOS_PROJECT actions →
    second project isolation → open + override still independent
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from talos.__main__ import _make_manager, _split_global_args, main
from talos.config import TalosConfig
from talos.projects.db import init_project_db
from talos.projects.endpoint_cli import run_endpoint_cli
from talos.projects.manager import (
    ProjectManager,
    ProjectNotFound,
    TALOS_PROJECT_ENV,
)
from talos.projects.model import ProjectStatus


@pytest.fixture
def projects_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolated projects root; clear TALOS_PROJECT so tests do not leak env."""
    monkeypatch.delenv(TALOS_PROJECT_ENV, raising=False)
    root = tmp_path / "projects"
    root.mkdir()
    return root


def _create_inactive(manager: ProjectManager, name: str) -> str:
    project = manager.create(name=name, scope=["example.com"])
    assert project.status == ProjectStatus.INACTIVE
    return project.id


class TestProjectManagerOverride:
    def test_constructor_override_without_registry_active(
        self, projects_root: Path
    ) -> None:
        manager = ProjectManager(projects_root)
        pid = _create_inactive(manager, "Alpha App")
        assert manager.active() is None

        bound = ProjectManager(projects_root, project_override=pid)
        active = bound.active()
        assert active is not None
        assert active.id == pid
        # Registry still has no ACTIVE project.
        assert ProjectManager(projects_root).active() is None

    def test_override_does_not_mutate_registry_active(
        self, projects_root: Path
    ) -> None:
        manager = ProjectManager(projects_root)
        a = _create_inactive(manager, "Project A")
        b = _create_inactive(manager, "Project B")
        manager.open(a)
        assert manager.active() is not None
        assert manager.active().id == a

        other = ProjectManager(projects_root, project_override=b)
        assert other.active() is not None
        assert other.active().id == b

        # Original registry ACTIVE remains A.
        assert ProjectManager(projects_root).active().id == a
        still = ProjectManager(projects_root).get(a)
        assert still.status == ProjectStatus.ACTIVE
        assert ProjectManager(projects_root).get(b).status == ProjectStatus.INACTIVE

    def test_env_override(self, projects_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        manager = ProjectManager(projects_root)
        pid = _create_inactive(manager, "Env Project")
        monkeypatch.setenv(TALOS_PROJECT_ENV, pid)

        bound = ProjectManager(projects_root)
        assert bound.project_override == pid
        assert bound.active() is not None
        assert bound.active().id == pid

    def test_constructor_wins_over_env(
        self, projects_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        manager = ProjectManager(projects_root)
        a = _create_inactive(manager, "Env Winner")
        b = _create_inactive(manager, "Ctor Winner")
        monkeypatch.setenv(TALOS_PROJECT_ENV, a)

        bound = ProjectManager(projects_root, project_override=b)
        assert bound.project_override == b
        assert bound.active().id == b

    def test_unknown_override_raises(self, projects_root: Path) -> None:
        bound = ProjectManager(projects_root, project_override="does-not-exist")
        with pytest.raises(ProjectNotFound, match="does-not-exist"):
            bound.active()

    def test_concurrent_managers_independent(self, projects_root: Path) -> None:
        base = ProjectManager(projects_root)
        a = _create_inactive(base, "Script A")
        b = _create_inactive(base, "Script B")

        ma = ProjectManager(projects_root, project_override=a)
        mb = ProjectManager(projects_root, project_override=b)
        assert ma.active().id == a
        assert mb.active().id == b
        assert ProjectManager(projects_root).active() is None


class TestSplitGlobalArgs:
    def test_project_flag_space_form(self) -> None:
        project, rest = _split_global_args(["--project", "pentest", "endpoint", "list"])
        assert project == "pentest"
        assert rest == ["endpoint", "list"]

    def test_project_flag_equals_form(self) -> None:
        project, rest = _split_global_args(["--project=pentest", "endpoint", "list"])
        assert project == "pentest"
        assert rest == ["endpoint", "list"]

    def test_no_global_flags(self) -> None:
        project, rest = _split_global_args(["endpoint", "list"])
        assert project is None
        assert rest == ["endpoint", "list"]

    def test_help_only(self) -> None:
        project, rest = _split_global_args(["--help"])
        assert project is None
        assert rest == ["--help"]

    def test_project_then_help(self) -> None:
        project, rest = _split_global_args(["--project", "x", "--help"])
        assert project == "x"
        assert rest == ["--help"]

    def test_missing_project_value_exits_usage(self) -> None:
        with pytest.raises(SystemExit) as exc:
            _split_global_args(["--project"])
        assert exc.value.code == 2

    def test_empty_equals_value_exits_usage(self) -> None:
        with pytest.raises(SystemExit) as exc:
            _split_global_args(["--project="])
        assert exc.value.code == 2


class TestMakeManager:
    def test_exports_talos_project_env(
        self, projects_root: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv(TALOS_PROJECT_ENV, raising=False)
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        # Point projects under config.projects_dir
        config = TalosConfig(data_dir=data_dir)
        # Create project in the config projects dir
        mgr = ProjectManager(config.projects_dir)
        pid = _create_inactive(mgr, "Export Env")

        made = _make_manager(config, pid)
        assert os.environ.get(TALOS_PROJECT_ENV) == pid
        assert made.active().id == pid

    def test_unknown_project_exits_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(TALOS_PROJECT_ENV, raising=False)
        config = TalosConfig(data_dir=tmp_path / "data")
        config.projects_dir.mkdir(parents=True)
        with pytest.raises(SystemExit) as exc:
            _make_manager(config, "missing-project")
        assert exc.value.code == 1


class TestMainIntegration:
    def test_main_endpoint_list_with_project_flag(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.delenv(TALOS_PROJECT_ENV, raising=False)
        data_dir = tmp_path / "talos-data"
        monkeypatch.setenv("TALOS_DATA_DIR", str(data_dir))

        config = TalosConfig.from_env()
        mgr = ProjectManager(config.projects_dir)
        pid = _create_inactive(mgr, "Main Flag")
        # Ensure schema + empty endpoint inventory is readable
        init_project_db(mgr.get(pid).db_path)

        main(["--project", pid, "endpoint", "list"])
        captured = capsys.readouterr()
        assert "Error:" not in captured.err
        # Command must succeed without open; empty inventory is fine.
        # Registry ACTIVE must remain unset (status still inactive).
        assert ProjectManager(config.projects_dir).get(pid).status == ProjectStatus.INACTIVE
        # Clear process env export from --project so a clean manager sees registry only.
        monkeypatch.delenv(TALOS_PROJECT_ENV, raising=False)
        assert ProjectManager(config.projects_dir).active() is None

    def test_main_status_with_env_override(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        data_dir = tmp_path / "talos-data"
        monkeypatch.setenv("TALOS_DATA_DIR", str(data_dir))
        config = TalosConfig.from_env()
        mgr = ProjectManager(config.projects_dir)
        pid = _create_inactive(mgr, "Status Env")
        monkeypatch.setenv(TALOS_PROJECT_ENV, pid)

        main(["project", "status"])
        out = capsys.readouterr().out
        assert "process override" in out
        assert pid in out

    def test_run_endpoint_cli_with_override_manager(
        self,
        projects_root: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        base = ProjectManager(projects_root)
        pid = _create_inactive(base, "Endpoint Override")
        manager = ProjectManager(projects_root, project_override=pid)
        run_endpoint_cli(manager, ["list"])
        out = capsys.readouterr().out
        # Empty project: still prints a summary line without precondition error.
        assert "Error:" not in out


class TestEndToEndSimulation:
    """
    Walk a realistic automation path with zero `project open`:

      create → --project actions → TALOS_PROJECT actions →
      second project in parallel → verify registry never flipped ACTIVE

    Mirrors how CI / concurrent scripts should use CLI-013.
    """

    def test_full_lifecycle_without_project_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        data_dir = tmp_path / "sim-data"
        monkeypatch.setenv("TALOS_DATA_DIR", str(data_dir))
        monkeypatch.delenv(TALOS_PROJECT_ENV, raising=False)

        def run_ok(argv: list[str]) -> str:
            """Invoke main; fail test if stderr has Error: or exit is raised."""
            main(argv)
            captured = capsys.readouterr()
            assert "Error:" not in captured.err, (
                f"command {argv!r} failed:\n{captured.err}"
            )
            return captured.out

        def registry_active_id() -> str | None:
            """Read registry ACTIVE without inheriting process TALOS_PROJECT."""
            monkeypatch.delenv(TALOS_PROJECT_ENV, raising=False)
            active = ProjectManager(TalosConfig.from_env().projects_dir).active()
            return active.id if active else None

        # ------------------------------------------------------------------ #
        # 1. Create project A (no open)
        # ------------------------------------------------------------------ #
        out = run_ok([
            "project", "create", "Sim Alpha",
            "--scope", "api.alpha.example.com",
            "-d", "CLI-013 simulation project A",
        ])
        assert "Project created" in out or "created" in out.lower()
        assert "sim-alpha" in out
        assert registry_active_id() is None

        # ------------------------------------------------------------------ #
        # 2. Status via --project (registry still inactive)
        # ------------------------------------------------------------------ #
        out = run_ok(["--project", "sim-alpha", "project", "status"])
        assert "process override" in out
        assert "sim-alpha" in out
        assert "api.alpha.example.com" in out
        assert registry_active_id() is None
        # --project exports TALOS_PROJECT; clear so later registry checks stay pure.
        monkeypatch.delenv(TALOS_PROJECT_ENV, raising=False)

        # ------------------------------------------------------------------ #
        # 3. Mutating commands without open: roles, modules, http rules, access
        # ------------------------------------------------------------------ #
        out = run_ok(["--project", "sim-alpha", "role", "create", "admin"])
        assert "admin" in out.lower() or "Role" in out

        out = run_ok(["--project", "sim-alpha", "role", "create", "user"])
        assert "user" in out.lower() or "Role" in out

        out = run_ok(["--project", "sim-alpha", "module", "create", "billing"])
        assert "billing" in out.lower() or "Module" in out

        out = run_ok(["--project", "sim-alpha", "role", "list"])
        assert "admin" in out
        assert "user" in out

        out = run_ok(["--project", "sim-alpha", "module", "list"])
        assert "billing" in out

        out = run_ok([
            "--project", "sim-alpha",
            "access", "client", "set", "admin", "billing", "allow",
        ])
        assert "Error:" not in out

        out = run_ok(["--project", "sim-alpha", "access", "show"])
        assert "admin" in out
        assert "billing" in out

        out = run_ok([
            "--project", "sim-alpha",
            "config", "http", "create",
            "--name", "sim-alpha-header",
            "--action", "header.replace:X-Sim-Test=alpha",
        ])
        assert "Error:" not in out

        out = run_ok(["--project", "sim-alpha", "config", "http", "list"])
        assert "X-Sim-Test" in out or "sim-alpha-header" in out or "alpha" in out

        out = run_ok(["--project", "sim-alpha", "endpoint", "list"])
        # Empty capture surface is fine; must not precondition-fail.
        assert "Error:" not in out

        out = run_ok(["--project", "sim-alpha", "finding", "list"])
        assert "Error:" not in out

        assert registry_active_id() is None
        monkeypatch.delenv(TALOS_PROJECT_ENV, raising=False)

        # ------------------------------------------------------------------ #
        # 4. Same project via TALOS_PROJECT env (no --project flag)
        # ------------------------------------------------------------------ #
        monkeypatch.setenv(TALOS_PROJECT_ENV, "sim-alpha")
        out = run_ok(["role", "list"])
        assert "admin" in out
        out = run_ok(["project", "status"])
        assert "process override" in out
        assert "sim-alpha" in out
        monkeypatch.delenv(TALOS_PROJECT_ENV, raising=False)
        assert registry_active_id() is None

        # ------------------------------------------------------------------ #
        # 5. Second project B — parallel automation without touching A's data
        # ------------------------------------------------------------------ #
        out = run_ok([
            "project", "create", "Sim Beta",
            "--scope", "api.beta.example.com",
        ])
        assert "sim-beta" in out

        out = run_ok(["--project", "sim-beta", "role", "create", "operator"])
        assert "operator" in out.lower() or "Role" in out

        out = run_ok(["--project", "sim-beta", "role", "list"])
        assert "operator" in out
        # Beta must not see Alpha's roles
        assert "admin" not in out

        out = run_ok(["--project", "sim-alpha", "role", "list"])
        assert "admin" in out
        assert "operator" not in out

        assert registry_active_id() is None
        monkeypatch.delenv(TALOS_PROJECT_ENV, raising=False)

        # ------------------------------------------------------------------ #
        # 6. Interactive open still works; override still wins over ACTIVE
        # ------------------------------------------------------------------ #
        out = run_ok(["project", "open", "sim-alpha"])
        assert "opened" in out.lower() or "ACTIVE" in out or "sim-alpha" in out
        assert registry_active_id() == "sim-alpha"

        # Override to beta while alpha is registry-ACTIVE
        out = run_ok(["--project", "sim-beta", "role", "list"])
        assert "operator" in out
        assert "admin" not in out

        # Registry ACTIVE remains alpha (override did not steal it)
        monkeypatch.delenv(TALOS_PROJECT_ENV, raising=False)
        assert registry_active_id() == "sim-alpha"

        out = run_ok(["project", "status"])
        assert "sim-alpha" in out
        assert "process override" not in out

        # Persist check: alpha still has its HTTP rule; beta never got it
        out = run_ok(["--project", "sim-alpha", "config", "http", "list"])
        assert "X-Sim-Test" in out or "sim-alpha-header" in out or "alpha" in out.lower()
        out = run_ok(["--project", "sim-beta", "config", "http", "list"])
        # Beta rules list should not include Alpha's header rule
        assert "X-Sim-Test" not in out
        assert "sim-alpha-header" not in out
