"""
CLI-019 — Input Validation flag consistency.

--ignore-cache means re-run analysis (ignore completed cache).
--force means confirmation bypass on destructive commands (clear-cache).

Phase shortcuts previously used --force for re-analysis; they now use
--ignore-cache as the primary flag, with --force kept only as a
backwards-compatible alias for ignore-cache on those phase commands.
"""

from __future__ import annotations

import io
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from talos.cli_output import EXIT_USAGE, NONINTERACTIVE_FORCE_REQUIRED
from talos.input_validation.cli import run_input_validation_cli
from talos.input_validation.config import IVConfig, save_config
from talos.projects.db import init_project_db
from talos.__main__ import _print_usage


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


@pytest.fixture()
def manager_enabled(db_path: Path) -> MagicMock:
    """Active project with IV enabled."""
    save_config(db_path, IVConfig(enabled=True))
    project = SimpleNamespace(db_path=db_path, id="test-project")
    manager = MagicMock()
    manager.active.return_value = project
    return manager


def _run_iv(manager: MagicMock, argv: list[str]) -> str:
    """Run IV CLI; return combined stdout."""
    out = io.StringIO()
    with redirect_stdout(out):
        run_input_validation_cli(manager, argv)
    return out.getvalue()


# ------------------------------------------------------------------ #
# Phase shortcuts: --ignore-cache primary, --force alias               #
# ------------------------------------------------------------------ #


class TestPhaseIgnoreCacheFlag:
    def test_phase_ignore_cache_passes_true(
        self, manager_enabled: MagicMock
    ) -> None:
        with (
            patch(
                "talos.input_validation.engine.verify_auth_for_iv_scan",
                return_value=[],
            ),
            patch(
                "talos.input_validation.engine.schedule_project",
                return_value=3,
            ) as sched,
        ):
            text = _run_iv(manager_enabled, ["baseline", "--ignore-cache"])
        sched.assert_called_once()
        assert sched.call_args.kwargs.get("ignore_cache") is True
        assert "Enqueued 3" in text

    def test_phase_force_alias_still_sets_ignore_cache(
        self, manager_enabled: MagicMock
    ) -> None:
        """Backwards-compatible: --force on phase cmd still re-runs."""
        with (
            patch(
                "talos.input_validation.engine.verify_auth_for_iv_scan",
                return_value=[],
            ),
            patch(
                "talos.input_validation.engine.schedule_project",
                return_value=1,
            ) as sched,
        ):
            _run_iv(manager_enabled, ["identifier", "--force"])
        assert sched.call_args.kwargs.get("ignore_cache") is True

    def test_phase_without_flag_does_not_ignore_cache(
        self, manager_enabled: MagicMock
    ) -> None:
        with (
            patch(
                "talos.input_validation.engine.verify_auth_for_iv_scan",
                return_value=[],
            ),
            patch(
                "talos.input_validation.engine.schedule_project",
                return_value=0,
            ) as sched,
        ):
            text = _run_iv(manager_enabled, ["characters"])
        assert sched.call_args.kwargs.get("ignore_cache") is False
        assert "Use --ignore-cache to re-run" in text
        assert "/ --force" not in text


# ------------------------------------------------------------------ #
# run: --ignore-cache only (not --force)                               #
# ------------------------------------------------------------------ #


class TestRunIgnoreCacheFlag:
    def test_run_ignore_cache(
        self, manager_enabled: MagicMock
    ) -> None:
        with (
            patch(
                "talos.input_validation.engine.verify_auth_for_iv_scan",
                return_value=[],
            ),
            patch(
                "talos.input_validation.engine.schedule_project",
                return_value=2,
            ) as sched,
        ):
            _run_iv(manager_enabled, ["run", "--ignore-cache"])
        assert sched.call_args.kwargs.get("ignore_cache") is True

    def test_run_does_not_accept_force_as_reanalysis(
        self, manager_enabled: MagicMock
    ) -> None:
        """run never had --force for re-analysis; keep it that way."""
        err = io.StringIO()
        with (
            redirect_stderr(err),
            pytest.raises(SystemExit) as exc,
        ):
            run_input_validation_cli(manager_enabled, ["run", "--force"])
        assert exc.value.code == 2  # argparse usage error


# ------------------------------------------------------------------ #
# clear-cache: --force is confirmation bypass only                     #
# ------------------------------------------------------------------ #


class TestClearCacheForceIsConfirm:
    def test_clear_cache_force_skips_prompt(
        self, manager_enabled: MagicMock, db_path: Path
    ) -> None:
        with (
            patch(
                "talos.input_validation.db.clear_all_iv_cache",
                return_value=(0, 0),
            ) as clear,
            patch("talos.cli_output.is_interactive", return_value=True),
            patch(
                "builtins.input",
                side_effect=AssertionError("must not prompt with --force"),
            ),
        ):
            text = _run_iv(manager_enabled, ["clear-cache", "--force"])
        clear.assert_called_once_with(db_path)
        assert "Cache cleared" in text

    def test_clear_cache_noninteractive_requires_force(
        self, manager_enabled: MagicMock
    ) -> None:
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
            run_input_validation_cli(manager_enabled, ["clear-cache"])
        assert exc.value.code == EXIT_USAGE
        assert NONINTERACTIVE_FORCE_REQUIRED in err.getvalue()

    def test_clear_cache_does_not_use_ignore_cache_for_confirm(
        self, manager_enabled: MagicMock
    ) -> None:
        """--ignore-cache is not a confirmation bypass on clear-cache."""
        err = io.StringIO()
        with (
            redirect_stderr(err),
            pytest.raises(SystemExit) as exc,
        ):
            run_input_validation_cli(
                manager_enabled, ["clear-cache", "--ignore-cache"]
            )
        assert exc.value.code == 2  # argparse unknown option


# ------------------------------------------------------------------ #
# Talos Helper (root --help)                                           #
# ------------------------------------------------------------------ #


def test_talos_helper_phase_shortcuts_document_ignore_cache() -> None:
    out = io.StringIO()
    with redirect_stdout(out):
        _print_usage()
    text = out.getvalue()
    assert "input-validation" in text
    assert "--ignore-cache" in text
    # Phase line must not advertise --force for re-analysis
    assert "Phase shortcuts (--host/--endpoint/--parameter/--force)" not in text
    assert (
        "Phase shortcuts (--host/--endpoint/--parameter/\n"
        "                    --ignore-cache)"
        in text
        or "--ignore-cache)" in text
    )
    # clear-cache still documents --force as confirmation bypass
    assert "clear-cache" in text
    assert "[--force]" in text
