"""
CLI-021: Session recovery commands.

Covers:
    - talos auth-config clear-session <role>  → clear_manual_session_config
    - talos auth-config reset-health <role>   → reset_suspicion
    - Role existence checks
    - Idempotent recovery when already clear / already zero
    - Talos Helper documents both commands
"""

from __future__ import annotations

import argparse
import io
import re
import uuid
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from talos.__main__ import _print_usage
from talos.projects.auth import (
    get_suspicion_state,
    increment_suspicion,
    reset_suspicion,
)
from talos.projects.auth_config_cli import cmd_clear_session, cmd_reset_health
from talos.projects.auth_provider import (
    clear_manual_session_config,
    get_manual_session_config,
    set_manual_session_config,
)
from talos.projects.db import init_project_db


# ------------------------------------------------------------------ #
# Fixtures                                                             #
# ------------------------------------------------------------------ #


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


@pytest.fixture
def db_with_role(db_path: Path) -> tuple[Path, str]:
    import sqlite3

    role_id = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO roles (id, name, is_active) VALUES (?, 'admin', 0)",
            (role_id,),
        )
        conn.commit()
    return db_path, role_id


# ------------------------------------------------------------------ #
# clear-session                                                        #
# ------------------------------------------------------------------ #


class TestClearSession:
    def test_clears_manual_session_config(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        set_manual_session_config(
            db_path,
            role_id,
            headers={"Authorization": "Bearer x"},
            cookies={"session": "abc"},
            expires_at=None,
            ttl_seconds=3600,
        )
        assert get_manual_session_config(db_path, role_id) is not None

        args = argparse.Namespace(role_id=role_id)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_clear_session(db_path, args)

        assert buf.getvalue().strip() == "Session cleared."
        assert get_manual_session_config(db_path, role_id) is None

    def test_idempotent_when_no_session(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        assert get_manual_session_config(db_path, role_id) is None

        args = argparse.Namespace(role_id=role_id)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_clear_session(db_path, args)

        assert buf.getvalue().strip() == "Session cleared."
        assert get_manual_session_config(db_path, role_id) is None

    def test_missing_role_exits(self, db_path: Path) -> None:
        args = argparse.Namespace(role_id=str(uuid.uuid4()))
        with pytest.raises(SystemExit) as exc:
            cmd_clear_session(db_path, args)
        assert exc.value.code == 1


# ------------------------------------------------------------------ #
# reset-health                                                         #
# ------------------------------------------------------------------ #


class TestResetHealth:
    def test_resets_suspicion_counter(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        increment_suspicion(db_path, role_id)
        increment_suspicion(db_path, role_id)
        increment_suspicion(db_path, role_id)
        assert get_suspicion_state(db_path, role_id)["suspicion_count"] == 3

        args = argparse.Namespace(role_id=role_id)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_reset_health(db_path, args)

        assert buf.getvalue().strip() == "Health suspicion reset."
        state = get_suspicion_state(db_path, role_id)
        assert state["suspicion_count"] == 0
        assert state["last_checked_at"] is not None

    def test_idempotent_when_already_zero(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        # No prior suspicion row / zero count
        assert get_suspicion_state(db_path, role_id)["suspicion_count"] == 0

        args = argparse.Namespace(role_id=role_id)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_reset_health(db_path, args)

        assert buf.getvalue().strip() == "Health suspicion reset."
        assert get_suspicion_state(db_path, role_id)["suspicion_count"] == 0

    def test_missing_role_exits(self, db_path: Path) -> None:
        args = argparse.Namespace(role_id=str(uuid.uuid4()))
        with pytest.raises(SystemExit) as exc:
            cmd_reset_health(db_path, args)
        assert exc.value.code == 1


# ------------------------------------------------------------------ #
# Backend API parity (CLI wires existing functions)                    #
# ------------------------------------------------------------------ #


class TestBackendApis:
    def test_clear_manual_session_config_api(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        set_manual_session_config(
            db_path,
            role_id,
            headers={"X-Token": "t"},
            cookies={},
            expires_at=None,
            ttl_seconds=60,
        )
        clear_manual_session_config(db_path, role_id)
        assert get_manual_session_config(db_path, role_id) is None

    def test_reset_suspicion_api(self, db_with_role: tuple) -> None:
        db_path, role_id = db_with_role
        increment_suspicion(db_path, role_id)
        reset_suspicion(db_path, role_id)
        assert get_suspicion_state(db_path, role_id)["suspicion_count"] == 0


# ------------------------------------------------------------------ #
# Talos Helper                                                         #
# ------------------------------------------------------------------ #


def test_talos_helper_documents_session_recovery() -> None:
    """Root help must list clear-session and reset-health under auth-config."""
    out = io.StringIO()
    with redirect_stdout(out):
        _print_usage()
    text = out.getvalue()
    assert re.search(r"^\s+clear-session\s+", text, re.M)
    assert re.search(r"^\s+reset-health\s+", text, re.M)
    assert "auth-config" in text
