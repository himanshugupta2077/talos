"""
Module: talos.projects.outscope_cli

Purpose:
    CLI for out-of-scope Basic Scope prefixes (same model as in-scope):

        talos project outscope add <prefix>
        talos project outscope remove <prefix>
        talos project outscope list [--format table|json]
        talos project outscope clear [--force]
        talos project outscope import <file>

    Compatibility: `outscope add domain <value>` still accepted and routed
    through the same prefix path (the literal token "domain" is optional legacy).

Dependencies: argparse, sys, pathlib, talos.projects.outscope, manager
Data flow:
    CLI args → active project → outscope CRUD → SQLite
Side effects:
    Mutates out_of_scope_domains; notifies proxy config change.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from talos.cli_output import (
    add_force_argument,
    add_format_argument,
    cli_error,
    cli_json,
    cli_precondition_error,
    confirm_or_exit,
    wants_json,
)
from talos.projects.manager import ProjectManager, NO_ACTIVE_PROJECT_HINT
from talos.projects.outscope import (
    add_prefix,
    add_prefixes_atomic,
    clear_prefixes,
    list_prefixes,
    remove_prefix,
)
from talos.projects.scope_io import ScopeImportError, parse_scope_file
from talos.proxy.scope import ScopeParseError


def _require_active(manager: ProjectManager):
    project = manager.active()
    if project is None:
        cli_precondition_error(NO_ACTIVE_PROJECT_HINT)
    return project


def _notify(project_id: str, reason: str) -> None:
    from talos.proxy.runtime.events import notify_proxy_config_changed

    notify_proxy_config_changed(project_id, reason)


def cmd_add(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Add one out-of-scope Basic Scope prefix."""
    project = _require_active(manager)
    prefix = args.prefix
    try:
        inserted = add_prefix(project.db_path, project.id, prefix)
    except ScopeParseError as exc:
        cli_error(str(exc))

    display = prefix.strip()
    if inserted:
        print(f"Added out-of-scope prefix: {display}")
        _notify(project.id, f"outscope add {display}")
    else:
        print(f"Already present: {display}")


def cmd_list(manager: ProjectManager, args: argparse.Namespace) -> None:
    """List out-of-scope prefixes for the active project."""
    project = _require_active(manager)
    entries = list_prefixes(project.db_path)

    if wants_json(args):
        cli_json(entries)
        return

    if not entries:
        print("No out-of-scope prefixes configured.")
        return

    print(f"{len(entries)} out-of-scope prefix(es):\n")
    for entry in entries:
        print(f"  {entry['prefix']:<50}  added {entry['created_at']}")


def cmd_remove(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Remove one out-of-scope prefix."""
    project = _require_active(manager)
    prefix = args.prefix
    removed = remove_prefix(project.db_path, project.id, prefix)
    display = prefix.strip()
    if removed:
        print(f"Removed out-of-scope prefix: {display}")
        _notify(project.id, f"outscope remove {display}")
    else:
        cli_error(f"Out-of-scope prefix not found: {display!r}")


def cmd_clear(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Clear all out-of-scope prefixes."""
    project = _require_active(manager)
    entries = list_prefixes(project.db_path)
    if not entries:
        print("Out-of-scope list is already empty.")
        return

    confirm_or_exit(
        f"Clear all {len(entries)} out-of-scope prefix(es) for project '{project.id}'?",
        force=bool(getattr(args, "force", False)),
    )
    n = clear_prefixes(project.db_path, project.id)
    print(f"Cleared {n} out-of-scope prefix(es) for '{project.id}'.")
    _notify(project.id, "outscope clear")


def cmd_import(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Atomically import out-of-scope prefixes from a UTF-8 text file."""
    project = _require_active(manager)
    path = Path(args.file)
    if not path.is_file():
        cli_error(f"Import file not found: {path}")

    try:
        prefixes = parse_scope_file(path)
    except ScopeImportError as exc:
        cli_error(str(exc))
    except OSError as exc:
        cli_error(f"Failed to read import file: {exc}")
    except UnicodeError as exc:
        cli_error(f"Import file must be UTF-8 text: {exc}")

    if not prefixes:
        print("No out-of-scope prefixes found in file (empty or comments only).")
        return

    if getattr(args, "replace", False):
        clear_prefixes(project.db_path, project.id)

    try:
        inserted, skipped = add_prefixes_atomic(
            project.db_path, project.id, prefixes
        )
    except ScopeParseError as exc:
        cli_error(str(exc))

    print(
        f"Out-of-scope imported {len(prefixes)} prefix(es) from {path.name}: "
        f"{inserted} added, {skipped} already present."
    )
    for p in prefixes:
        print(f"  {p}")
    _notify(project.id, f"outscope import {path.name}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="talos project outscope",
        description=(
            "Manage out-of-scope URL-prefix exclusions for the active project. "
            "Uses the same Basic Scope model as in-scope. "
            "Out-of-scope rules override in-scope rules."
        ),
    )
    sub = parser.add_subparsers(dest="command", metavar="command", required=True)

    p_add = sub.add_parser("add", help="Add an out-of-scope URL/host prefix.")
    p_add.add_argument(
        "prefix",
        help=(
            "Basic Scope prefix to exclude, e.g. analytics.example.com, "
            "example.com/logout, example.com:9000, http://10.10.10.25:8081"
        ),
    )

    p_list = sub.add_parser("list", help="List out-of-scope prefixes.")
    add_format_argument(p_list)

    p_remove = sub.add_parser("remove", help="Remove an out-of-scope prefix.")
    p_remove.add_argument("prefix", help="Exact prefix to remove.")

    p_clear = sub.add_parser("clear", help="Remove all out-of-scope prefixes.")
    add_force_argument(p_clear)

    p_import = sub.add_parser(
        "import",
        help="Import out-of-scope prefixes from a UTF-8 text file.",
    )
    p_import.add_argument("file", help="Path to text file (one prefix per line).")
    p_import.add_argument(
        "--replace",
        action="store_true",
        help="Clear existing out-of-scope entries before import.",
    )

    return parser


_COMMAND_MAP = {
    "add": cmd_add,
    "list": cmd_list,
    "remove": cmd_remove,
    "clear": cmd_clear,
    "import": cmd_import,
}


def run_outscope_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse and dispatch outscope commands.
        Compatibility: if argv is `add domain <value>` or `remove domain <value>`,
        rewrite to `add <value>` / `remove <value>`.
    """
    # Legacy: outscope add domain X  /  outscope remove domain X
    if (
        len(argv) >= 3
        and argv[0] in ("add", "remove")
        and argv[1] == "domain"
    ):
        argv = [argv[0], argv[2], *argv[3:]]

    parser = build_parser()
    args = parser.parse_args(argv)
    handler = _COMMAND_MAP.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    handler(manager, args)
