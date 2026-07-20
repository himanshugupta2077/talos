"""
Tests for talos.cli_output — shared CLI formatting, exit codes, and
machine-readable output (CLI-011/012/014).
"""

from __future__ import annotations

import argparse
import json
from enum import Enum
from pathlib import Path

import pytest

from talos.cli_output import (
    EXIT_CANCELLED,
    EXIT_FAILURE,
    EXIT_OK,
    EXIT_PRECONDITION,
    EXIT_USAGE,
    NONINTERACTIVE_FORCE_REQUIRED,
    OUTPUT_FORMAT_JSON,
    OUTPUT_FORMAT_TABLE,
    OUTPUT_FORMATS,
    add_force_argument,
    add_format_argument,
    cli_cancelled,
    cli_error,
    cli_exit,
    cli_info,
    cli_json,
    cli_precondition_error,
    cli_success,
    cli_usage_error,
    cli_warning,
    confirm_or_exit,
    confirm_or_force,
    get_output_format,
    is_interactive,
    json_ready,
    wants_json,
)


def _force_interactive(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make confirm helpers treat stdin as a TTY."""
    monkeypatch.setattr("talos.cli_output.is_interactive", lambda: True)


def _force_noninteractive(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make confirm helpers treat stdin as non-interactive (CI / pipe)."""
    monkeypatch.setattr("talos.cli_output.is_interactive", lambda: False)


def test_exit_code_constants() -> None:
    assert EXIT_OK == 0
    assert EXIT_FAILURE == 1
    assert EXIT_USAGE == 2
    assert EXIT_PRECONDITION == 3
    assert EXIT_CANCELLED == 130


def test_cli_success_summary_only(capsys: pytest.CaptureFixture[str]) -> None:
    cli_success('Created role "admin"')
    out = capsys.readouterr().out
    assert out == 'Created role "admin"\n'


def test_cli_success_with_fields(capsys: pytest.CaptureFixture[str]) -> None:
    cli_success('Created role "admin"', {"UUID": "7f42-abcd", "Name": "admin"})
    out = capsys.readouterr().out
    assert out == (
        'Created role "admin"\n'
        "\n"
        "UUID:\n"
        "7f42-abcd\n"
        "Name:\n"
        "admin\n"
    )


def test_cli_info(capsys: pytest.CaptureFixture[str]) -> None:
    cli_info("No projects registered.")
    assert capsys.readouterr().out == "No projects registered.\n"


def test_cli_warning_format(capsys: pytest.CaptureFixture[str]) -> None:
    cli_warning("No endpoints matched.")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Warning:\n\nNo endpoints matched.\n"


def test_cli_error_format_and_exit(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli_error("Endpoint not found.")
    assert exc.value.code == EXIT_FAILURE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Error:\n\nEndpoint not found.\n"


def test_cli_error_no_exit(capsys: pytest.CaptureFixture[str]) -> None:
    cli_error("Soft failure.", exit_code=None)
    assert capsys.readouterr().err == "Error:\n\nSoft failure.\n"


def test_cli_error_custom_exit_code() -> None:
    with pytest.raises(SystemExit) as exc:
        cli_error("Nope.", exit_code=EXIT_USAGE)
    assert exc.value.code == EXIT_USAGE


def test_cli_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        cli_usage_error("Unknown command: 'foo'.")
    assert exc.value.code == EXIT_USAGE


def test_cli_precondition_error() -> None:
    with pytest.raises(SystemExit) as exc:
        cli_precondition_error("No active project.")
    assert exc.value.code == EXIT_PRECONDITION


def test_cli_cancelled_print_only(capsys: pytest.CaptureFixture[str]) -> None:
    cli_cancelled()
    assert capsys.readouterr().out == "Cancelled.\n"


def test_cli_cancelled_exits() -> None:
    with pytest.raises(SystemExit) as exc:
        cli_cancelled(exit=True)
    assert exc.value.code == EXIT_CANCELLED


def test_cli_exit() -> None:
    with pytest.raises(SystemExit) as exc:
        cli_exit(EXIT_OK)
    assert exc.value.code == EXIT_OK


def test_confirm_or_force_force_skips_prompt(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def _should_not_call(_prompt: str) -> str:
        raise AssertionError("input() must not be called when force=True")

    monkeypatch.setattr("builtins.input", _should_not_call)
    # force=True must work even when non-interactive
    _force_noninteractive(monkeypatch)
    assert confirm_or_force("Delete everything?", force=True) is True
    assert capsys.readouterr().out == ""


def test_confirm_or_force_yes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _force_interactive(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda _p: "y")
    assert confirm_or_force("Proceed?") is True
    assert capsys.readouterr().out == ""


def test_confirm_or_force_no_prints_cancelled(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _force_interactive(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda _p: "n")
    assert confirm_or_force("Proceed?") is False
    assert capsys.readouterr().out == "Cancelled.\n"


def test_confirm_or_force_empty_defaults_to_no(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _force_interactive(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda _p: "")
    assert confirm_or_force("Proceed?") is False
    assert capsys.readouterr().out == "Cancelled.\n"


def test_confirm_or_force_appends_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_interactive(monkeypatch)
    seen: list[str] = []

    def _capture(prompt: str) -> str:
        seen.append(prompt)
        return "y"

    monkeypatch.setattr("builtins.input", _capture)
    confirm_or_force("Delete role 'admin'?")
    assert seen == ["Delete role 'admin'? [y/N] "]


def test_confirm_or_force_noninteractive_requires_force(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI-015: non-interactive without --force must error, never hang on input()."""
    _force_noninteractive(monkeypatch)

    def _should_not_call(_prompt: str) -> str:
        raise AssertionError("input() must not be called when non-interactive")

    monkeypatch.setattr("builtins.input", _should_not_call)
    with pytest.raises(SystemExit) as exc:
        confirm_or_force("Delete mutation?")
    assert exc.value.code == EXIT_USAGE
    err = capsys.readouterr().err
    assert "Error:" in err
    assert NONINTERACTIVE_FORCE_REQUIRED in err


def test_confirm_or_force_noninteractive_force_ok(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_noninteractive(monkeypatch)
    monkeypatch.setattr(
        "builtins.input",
        lambda _p: (_ for _ in ()).throw(AssertionError("no prompt")),
    )
    assert confirm_or_force("Delete?", force=True) is True


def test_confirm_or_exit_cancels_with_130(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _force_interactive(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda _p: "n")
    with pytest.raises(SystemExit) as exc:
        confirm_or_exit("Delete role 'admin'?")
    assert exc.value.code == EXIT_CANCELLED
    assert capsys.readouterr().out == "Cancelled.\n"


def test_confirm_or_exit_force_returns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "builtins.input",
        lambda _p: (_ for _ in ()).throw(AssertionError("no prompt")),
    )
    confirm_or_exit("Delete?", force=True)


def test_confirm_or_exit_noninteractive_requires_force(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _force_noninteractive(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        confirm_or_exit("Delete project?")
    assert exc.value.code == EXIT_USAGE
    assert NONINTERACTIVE_FORCE_REQUIRED in capsys.readouterr().err


def test_add_force_argument_defaults_false() -> None:
    parser = argparse.ArgumentParser()
    add_force_argument(parser)
    args = parser.parse_args([])
    assert args.force is False
    args_f = parser.parse_args(["--force"])
    assert args_f.force is True


def test_is_interactive_reflects_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    assert is_interactive() is True
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert is_interactive() is False


# ------------------------------------------------------------------ #
# Machine-readable output (CLI-014)                                    #
# ------------------------------------------------------------------ #


def test_output_format_constants() -> None:
    assert OUTPUT_FORMAT_TABLE == "table"
    assert OUTPUT_FORMAT_JSON == "json"
    assert OUTPUT_FORMATS == ("table", "json")


def test_add_format_argument_defaults_to_table() -> None:
    parser = argparse.ArgumentParser()
    add_format_argument(parser)
    args = parser.parse_args([])
    assert args.output_format == OUTPUT_FORMAT_TABLE
    assert wants_json(args) is False
    assert get_output_format(args) == OUTPUT_FORMAT_TABLE


def test_add_format_argument_json() -> None:
    parser = argparse.ArgumentParser()
    add_format_argument(parser)
    args = parser.parse_args(["--format", "json"])
    assert args.output_format == OUTPUT_FORMAT_JSON
    assert wants_json(args) is True


def test_wants_json_none_is_table() -> None:
    assert wants_json(None) is False
    assert get_output_format(None) == OUTPUT_FORMAT_TABLE


def test_cli_json_list(capsys: pytest.CaptureFixture[str]) -> None:
    cli_json([{"id": "a", "method": "GET", "path": "/users"}])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data == [{"id": "a", "method": "GET", "path": "/users"}]


def test_cli_json_empty_list(capsys: pytest.CaptureFixture[str]) -> None:
    cli_json([])
    assert json.loads(capsys.readouterr().out) == []


def test_cli_json_null(capsys: pytest.CaptureFixture[str]) -> None:
    cli_json(None)
    assert json.loads(capsys.readouterr().out) is None


def test_json_ready_path_and_enum() -> None:
    class Sample(Enum):
        ACTIVE = "active"

    ready = json_ready({"path": Path("/tmp/x"), "status": Sample.ACTIVE, "tags": {"a"}})
    assert ready["path"] == "/tmp/x"
    assert ready["status"] == "active"
    assert ready["tags"] == ["a"]
