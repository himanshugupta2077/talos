"""
Module: talos.cli_output

Purpose:
    Shared helpers for consistent CLI output and exit codes across all
    Talos commands. User-facing messages and process termination should go
    through this module instead of ad-hoc print() / sys.exit() calls.

Dependencies: argparse, dataclasses, json, sys
Data flow:
    CLI handlers → cli_* helpers → stdout / stderr → optional sys.exit
Side effects:
    - Writes to stdout or stderr.
    - cli_error / cli_exit / cli_cancelled(exit=True) may terminate the process.

Exit code policy (CLI-012)
--------------------------
| Code | Constant            | Meaning                                      |
|------|---------------------|----------------------------------------------|
| 0    | EXIT_OK             | Success (including intentional no-ops)       |
| 1    | EXIT_FAILURE        | General failure (not found, operation fail)  |
| 2    | EXIT_USAGE          | Invalid arguments / unknown subcommand       |
| 3    | EXIT_PRECONDITION   | Preconditions not met (no project, auth, …)  |
| 130  | EXIT_CANCELLED      | User declined an interactive confirmation    |

130 matches the conventional shell status for SIGINT (128+2) so scripts can
treat interactive abort as non-success without conflating it with hard errors.

Machine-readable output (CLI-014)
---------------------------------
List, show, and status commands accept::

    --format table|json

Default is ``table`` (human-readable, backward compatible). ``--format json``
writes a single JSON document to stdout (indent=2). Empty lists emit ``[]``.
Errors and warnings stay on stderr in the human shapes below — only the
successful data payload is JSON.

Standard human output formats
-----------------------------
Success (stdout)::

    Created role "admin"

    UUID:
    7f42...

Warning (stderr)::

    Warning:

    No endpoints matched.

Error (stderr)::

    Error:

    Endpoint not found.

Cancellation (stdout)::

    Cancelled.

Confirmation policy (CLI-015)
-----------------------------
Destructive and capacity-sensitive commands share one rule:

* Interactive TTY → ``confirm_or_exit`` prompts ``[y/N]``; decline → 130.
* Non-interactive (CI, pipes) → require ``--force`` or exit **2** with::

      Error:

      Operation requires --force in non-interactive mode.

* ``--force`` always skips the prompt. Use ``add_force_argument(parser)``.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from collections.abc import Mapping
from enum import Enum
from pathlib import Path
from typing import Any, NoReturn, TextIO

# ------------------------------------------------------------------ #
# Exit codes (single source of truth — CLI-012)                        #
# ------------------------------------------------------------------ #

EXIT_OK: int = 0
"""Command succeeded (including intentional empty/no-op outcomes)."""

EXIT_FAILURE: int = 1
"""General failure: resource not found, operation failed, empty attack queue
when the run should have produced work for reasons other than preconditions."""

EXIT_USAGE: int = 2
"""Invalid arguments, unknown subcommand, mutually exclusive flags, missing
required operands. Aligns with many Unix tools' usage-error convention."""

EXIT_PRECONDITION: int = 3
"""Required environment or setup is missing: no project bound, auth not
ready, mandatory config absent, policy blocks the action."""

EXIT_CANCELLED: int = 130
"""User declined a confirmation prompt (not a hard error)."""


# ------------------------------------------------------------------ #
# Output formats (CLI-014)                                             #
# ------------------------------------------------------------------ #

OUTPUT_FORMAT_TABLE: str = "table"
"""Human-readable tables / labeled blocks (default)."""

OUTPUT_FORMAT_JSON: str = "json"
"""Machine-readable JSON document on stdout."""

OUTPUT_FORMATS: tuple[str, ...] = (OUTPUT_FORMAT_TABLE, OUTPUT_FORMAT_JSON)
"""Allowed values for --format."""


# ------------------------------------------------------------------ #
# Windows / locale-safe stdio                                          #
# ------------------------------------------------------------------ #
#
# Windows consoles default to cp1252. print() of arrows (→), box drawing,
# check marks, or captured target text then raises UnicodeEncodeError.
# Reconfigure streams to UTF-8 once at process start; write helpers still
# fall back to replacement so a hostile/wrapped stream cannot crash the CLI.

_WINDOWS_CONSOLE_UTF8: int = 65001
"""Windows code page for UTF-8 (chcp 65001)."""


def _reconfigure_utf8(stream: Any) -> None:
    """
    Purpose:
        Point a text stream at UTF-8 with replacement errors when the
        runtime supports TextIO.reconfigure (Python 3.7+).
    Input:
        stream — sys.stdout / sys.stderr, or None.
    Output: None.
    Side effects: May change the stream encoding. Never raises.
    """
    if stream is None:
        return
    reconfigure = getattr(stream, "reconfigure", None)
    if not callable(reconfigure):
        return
    try:
        reconfigure(encoding="utf-8", errors="replace")
    except (OSError, ValueError, AttributeError, TypeError):
        return


def _enable_windows_utf8_console() -> None:
    """
    Purpose:
        Ask the Windows console to interpret our UTF-8 bytes as UTF-8
        so arrows render instead of mojibake after reconfigure.
    Input: None.
    Output: None.
    Side effects: May call SetConsoleCP / SetConsoleOutputCP. Never raises.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleOutputCP(_WINDOWS_CONSOLE_UTF8)
        kernel32.SetConsoleCP(_WINDOWS_CONSOLE_UTF8)
    except Exception:
        return


def configure_stdio() -> None:
    """
    Purpose:
        Make stdout/stderr UTF-8 so Windows cp1252 consoles do not crash
        on schema arrows, help text, or captured target Unicode.
    Input: None.
    Output: None.
    Side effects:
        Reconfigures sys.stdout and sys.stderr when possible. On Windows,
        may switch the console code page to UTF-8. Safe to call more than
        once.
    """
    _enable_windows_utf8_console()
    _reconfigure_utf8(sys.stdout)
    _reconfigure_utf8(sys.stderr)


def _cli_write(text: str, *, file: TextIO | Any) -> None:
    """
    Purpose:
        Write text to a stream without raising UnicodeEncodeError.
    Input:
        text — already-formatted payload, including any trailing newline.
        file — destination stream (stdout or stderr).
    Output: None.
    Side effects: Writes to file. Falls back to the binary buffer or
        replacement characters when the stream encoding cannot represent
        a character.
    """
    try:
        file.write(text)
        return
    except UnicodeEncodeError:
        pass
    buffer = getattr(file, "buffer", None)
    if buffer is not None:
        try:
            buffer.write(text.encode("utf-8", errors="replace"))
            return
        except (AttributeError, OSError, ValueError, TypeError):
            pass
    encoding = getattr(file, "encoding", None) or "ascii"
    file.write(text.encode(encoding, errors="replace").decode(encoding, errors="replace"))


def _cli_print(
    *args: object,
    sep: str = " ",
    end: str = "\n",
    file: TextIO | Any | None = None,
) -> None:
    """
    Purpose:
        print() replacement used by cli_* helpers. Configures UTF-8 stdio
        then writes without raising UnicodeEncodeError.
    Input:
        args — values joined with sep (same as print).
        sep / end / file — print() counterparts.
    Output: None.
    Side effects: May reconfigure stdio; writes to file (default stdout).
    """
    configure_stdio()
    stream = sys.stdout if file is None else file
    _cli_write(sep.join(str(item) for item in args) + end, file=stream)


def add_format_argument(
    parser: argparse.ArgumentParser,
    *,
    default: str = OUTPUT_FORMAT_TABLE,
) -> argparse.Action:
    """
    Purpose:
        Attach the shared ``--format {table,json}`` flag to a list/show/status
        subcommand parser. Default is table (backward compatible).
    Input:
        parser  — argparse parser for the subcommand.
        default — format when the flag is omitted (must be in OUTPUT_FORMATS).
    Output:
        The Action object returned by add_argument.
    Side effects: Mutates parser.
    """
    return parser.add_argument(
        "--format",
        dest="output_format",
        choices=list(OUTPUT_FORMATS),
        default=default,
        metavar="FMT",
        help=(
            "Output format: 'table' (default, human-readable) or "
            "'json' (machine-readable for scripts / jq)."
        ),
    )


def get_output_format(args: argparse.Namespace | None) -> str:
    """
    Purpose:
        Resolve the effective output format from a parsed namespace.
    Input:
        args — parsed argparse namespace (may lack output_format).
    Output:
        OUTPUT_FORMAT_TABLE or OUTPUT_FORMAT_JSON.
    Side effects: None.
    """
    if args is None:
        return OUTPUT_FORMAT_TABLE
    value = getattr(args, "output_format", OUTPUT_FORMAT_TABLE)
    if value in OUTPUT_FORMATS:
        return value
    return OUTPUT_FORMAT_TABLE


def wants_json(args: argparse.Namespace | None) -> bool:
    """
    Purpose:
        True when the operator requested ``--format json``.
    Input:
        args — parsed namespace (or None → table).
    Output: bool.
    Side effects: None.
    """
    return get_output_format(args) == OUTPUT_FORMAT_JSON


def json_ready(value: Any) -> Any:
    """
    Purpose:
        Convert common Python values into JSON-serializable forms.
        Handles Path, Enum, dataclass, sets, tuples, and nested containers.
        Unknown types fall back to str().
    Input:
        value — arbitrary object from CLI handlers / DB rows.
    Output:
        A structure safe for json.dumps.
    Side effects: None.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return json_ready(dataclasses.asdict(value))
    if isinstance(value, Mapping):
        return {str(k): json_ready(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_ready(item) for item in value]
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return json_ready(value.to_dict())
    return str(value)


def cli_json(data: Any) -> None:
    """
    Purpose:
        Print a single JSON document to stdout for automation (CLI-014).
        Uses indent=2 for readability; trailing newline for shell friendliness.
    Input:
        data — list, dict, or other value (passed through json_ready).
    Output: None.
    Side effects: Writes to stdout.
    """
    _cli_print(json.dumps(json_ready(data), indent=2, ensure_ascii=False))


def cli_exit(code: int = EXIT_OK) -> NoReturn:
    """
    Purpose:
        Terminate the process with a documented exit code.
    Input:
        code — One of EXIT_* constants (default EXIT_OK).
    Output: Never returns.
    Side effects: Calls sys.exit(code).
    """
    sys.exit(code)


def cli_success(
    message: str,
    fields: Mapping[str, Any] | None = None,
) -> None:
    """
    Purpose:
        Print a success summary to stdout, optionally followed by labeled fields.
    Input:
        message — One-line (or multi-line) success summary.
        fields  — Optional ordered map of label → value printed as::

                      Label:
                      value
    Output: None
    Side effects: Writes to stdout. Does not exit (success is EXIT_OK by default).
    """
    _cli_print(message)
    if not fields:
        return
    _cli_print()
    for key, value in fields.items():
        _cli_print(f"{key}:")
        _cli_print(value)


def cli_info(message: str) -> None:
    """
    Purpose:
        Print a neutral informational message to stdout (not success/error).
    Input:
        message — Text to print (may be multi-line).
    Output: None
    Side effects: Writes to stdout.
    """
    _cli_print(message)


def cli_warning(message: str) -> None:
    """
    Purpose:
        Print a standardized warning block to stderr.
    Input:
        message — Warning body (may be multi-line).
    Output: None
    Side effects: Writes to stderr. Does not change the process exit code.
    """
    _cli_print(f"Warning:\n\n{message}", file=sys.stderr)


def cli_error(
    message: str,
    *,
    exit_code: int | None = EXIT_FAILURE,
) -> None:
    """
    Purpose:
        Print a standardized error block to stderr and optionally exit.
    Input:
        message   — Error body (may be multi-line). Prefer a full sentence
                    or clear phrase; do not prefix with "Error:" yourself.
        exit_code — If not None (default EXIT_FAILURE / 1), call sys.exit
                    after printing. Pass exit_code=None to print only and
                    return (caller exits later, e.g. after printing usage).
    Output: None (does not return when exit_code is set).
    Side effects: Writes to stderr; may terminate the process.
    """
    _cli_print(f"Error:\n\n{message}", file=sys.stderr)
    if exit_code is not None:
        sys.exit(exit_code)


def cli_usage_error(message: str) -> NoReturn:
    """
    Purpose:
        Report invalid arguments / unknown subcommand and exit EXIT_USAGE (2).
    Input:
        message — Usage problem description (no "Error:" prefix).
    Output: Never returns.
    """
    cli_error(message, exit_code=EXIT_USAGE)
    raise SystemExit(EXIT_USAGE)  # unreachable; satisfies NoReturn type checkers


def cli_precondition_error(message: str) -> NoReturn:
    """
    Purpose:
        Report a failed precondition and exit EXIT_PRECONDITION (3).
        Use for missing project bind, auth not ready, mandatory setup
        incomplete, policy blocks, etc.
    Input:
        message — What is missing / blocked and how to fix it.
    Output: Never returns.
    """
    cli_error(message, exit_code=EXIT_PRECONDITION)
    raise SystemExit(EXIT_PRECONDITION)  # unreachable; satisfies NoReturn


def cli_cancelled(*, exit: bool = False) -> None:
    """
    Purpose:
        Print the standard cancellation notice used when the user declines
        a confirmation prompt.
    Input:
        exit — If True, terminate with EXIT_CANCELLED (130) after printing.
    Output: None (does not return when exit=True).
    Side effects: Writes "Cancelled." to stdout; may sys.exit(130).
    """
    _cli_print("Cancelled.")
    if exit:
        sys.exit(EXIT_CANCELLED)


# ------------------------------------------------------------------ #
# Confirmation policy (CLI-015)                                        #
# ------------------------------------------------------------------ #
#
# Standard policy for destructive / capacity-sensitive operations:
#
#   Interactive terminal (stdin is a TTY)
#       → prompt with [y/N]; decline → Cancelled. (exit 130 via confirm_or_exit)
#
#   Non-interactive terminal (CI, pipes, redirected stdin)
#       → require --force; otherwise error and exit EXIT_USAGE (2):
#         "Operation requires --force in non-interactive mode."
#
#   --force always skips the prompt (interactive or not).
#
# All destructive commands must go through confirm_or_force / confirm_or_exit
# and expose --force via add_force_argument (or equivalent).


NONINTERACTIVE_FORCE_REQUIRED: str = (
    "Operation requires --force in non-interactive mode."
)
"""Error body when a confirmable action runs without --force and stdin is not a TTY."""


def is_interactive() -> bool:
    """
    Purpose:
        Detect whether stdin is an interactive terminal (safe to prompt).
        Non-interactive contexts (CI, pipes, ``< /dev/null``) return False
        so confirmation helpers can require ``--force`` instead of hanging
        on ``input()``.
    Input: None.
    Output: True when ``sys.stdin.isatty()`` is True.
    Side effects: None.
    """
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError, OSError):
        return False


def add_force_argument(
    parser: argparse.ArgumentParser,
    *,
    help: str = (
        "Skip confirmation prompt (required in non-interactive mode)."
    ),
) -> argparse.Action:
    """
    Purpose:
        Attach the shared ``--force`` flag used by destructive commands
        (CLI-015). Interactive runs may omit it and answer ``[y/N]``;
        non-interactive runs must pass ``--force``.
    Input:
        parser — argparse parser for the subcommand.
        help   — help text (default documents non-interactive requirement).
    Output:
        The Action object returned by add_argument.
    Side effects: Mutates parser.
    """
    return parser.add_argument(
        "--force",
        action="store_true",
        help=help,
    )


def confirm_or_force(prompt: str, *, force: bool = False) -> bool:
    """
    Purpose:
        Shared yes/no confirmation for destructive or risky operations
        (CLI-015).

        Policy:
          * force=True → return True immediately (no prompt).
          * Non-interactive (stdin not a TTY) and force=False → print the
            standard Error block and exit EXIT_USAGE (2). Never blocks on
            input() in CI or pipes.
          * Interactive → prompt with ``[y/N]``; yes → True; decline →
            print Cancelled. and return False.

        Callers that should abort the process on decline must exit
        EXIT_CANCELLED (130) when this returns False (or use confirm_or_exit).
    Input:
        prompt — Question text without a trailing [y/N] suffix (appended here).
        force  — If True, bypass interactive confirmation.
    Output:
        True if confirmed (or force); False if the user declined.
        Does not return when non-interactive without force (exits 2).
    Side effects:
        May read from stdin; may write Cancelled. to stdout; may exit 2.
    """
    if force:
        return True
    if not is_interactive():
        cli_error(NONINTERACTIVE_FORCE_REQUIRED, exit_code=EXIT_USAGE)
        raise SystemExit(EXIT_USAGE)  # unreachable; satisfies type checkers
    answer = input(f"{prompt.rstrip()} [y/N] ").strip().lower()
    if answer in ("y", "yes"):
        return True
    cli_cancelled()
    return False


def confirm_or_exit(prompt: str, *, force: bool = False) -> None:
    """
    Purpose:
        Like confirm_or_force, but exits EXIT_CANCELLED (130) if the user
        declines. Returns only when confirmed or force=True.
        Non-interactive without force exits EXIT_USAGE (2) via confirm_or_force.
    Input:
        prompt — Question without [y/N] suffix.
        force  — Skip prompt when True (required when stdin is not a TTY).
    Output: None (or never returns on cancel / non-interactive error).
    Side effects: May prompt; may print Cancelled. and exit 130; may exit 2.
    """
    if not confirm_or_force(prompt, force=force):
        sys.exit(EXIT_CANCELLED)
