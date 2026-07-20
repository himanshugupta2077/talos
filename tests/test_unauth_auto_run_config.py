"""
Tests for CLI-005 — Unauth auto-run config surface.

Covers:
    - get_unauth_auto_run / set_unauth_auto_run defaults and persistence
    - talos attack unauth config show
    - talos attack unauth config --auto-run on|off
"""

from __future__ import annotations

import argparse
import io
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from talos.projects.attack_config import (
    get_unauth_auto_run,
    set_unauth_auto_run,
)
from talos.projects.db import init_project_db
from talos.projects.unauth.cli import cmd_unauth_config


# ------------------------------------------------------------------ #
# Fixtures                                                             #
# ------------------------------------------------------------------ #

@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


@pytest.fixture
def manager_with_db(db_path: Path) -> MagicMock:
    project = SimpleNamespace(db_path=db_path, id="test-project")
    manager = MagicMock()
    manager.active.return_value = project
    return manager


# ================================================================== #
# attack_config helpers                                                #
# ================================================================== #

class TestUnauthAutoRunHelpers:
    def test_default_is_off(self, db_path: Path) -> None:
        assert get_unauth_auto_run(db_path) is False

    def test_set_on_and_off(self, db_path: Path) -> None:
        set_unauth_auto_run(db_path, True)
        assert get_unauth_auto_run(db_path) is True
        set_unauth_auto_run(db_path, False)
        assert get_unauth_auto_run(db_path) is False

    def test_upsert_is_idempotent(self, db_path: Path) -> None:
        set_unauth_auto_run(db_path, True)
        set_unauth_auto_run(db_path, True)
        assert get_unauth_auto_run(db_path) is True


# ================================================================== #
# CLI handlers                                                         #
# ================================================================== #

class TestUnauthConfigCli:
    def test_show_default_disabled(
        self, manager_with_db: MagicMock, db_path: Path
    ) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_unauth_config(
                manager_with_db,
                argparse.Namespace(auto_run=None, config_action="show"),
            )
        out = buf.getvalue()
        assert "Auto Run : Disabled" in out
        assert get_unauth_auto_run(db_path) is False

    def test_enable_auto_run(
        self, manager_with_db: MagicMock, db_path: Path
    ) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_unauth_config(
                manager_with_db,
                argparse.Namespace(auto_run="on", config_action=None),
            )
        out = buf.getvalue()
        assert "Auto Run set to: Enabled" in out
        assert "Auto Run : Enabled" in out
        assert get_unauth_auto_run(db_path) is True

    def test_disable_auto_run(
        self, manager_with_db: MagicMock, db_path: Path
    ) -> None:
        set_unauth_auto_run(db_path, True)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_unauth_config(
                manager_with_db,
                argparse.Namespace(auto_run="off", config_action=None),
            )
        out = buf.getvalue()
        assert "Auto Run set to: Disabled" in out
        assert "Auto Run : Disabled" in out
        assert get_unauth_auto_run(db_path) is False

    def test_show_after_enable(
        self, manager_with_db: MagicMock, db_path: Path
    ) -> None:
        set_unauth_auto_run(db_path, True)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_unauth_config(
                manager_with_db,
                argparse.Namespace(auto_run=None, config_action="show"),
            )
        assert "Auto Run : Enabled" in buf.getvalue()
