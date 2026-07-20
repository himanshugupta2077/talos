"""
Module: talos.projects.scope_cli

Purpose:
    CLI for Basic Scope in-scope management:

        talos project scope add <prefix>
        talos project scope remove <prefix>
        talos project scope list [--format table|json]
        talos project scope clear [--force]
        talos project scope import <file>

    Compatibility surface (routed from projects.cli):

        talos project scope <id> [PATTERN ...]
            — display or replace entire list (legacy).

    Requires a bound project for add/remove/list/clear/import
    (registry ACTIVE, --project, or TALOS_PROJECT), except the legacy
    `scope <id> ...` form which takes an explicit project id.

Dependencies: argparse, sys, pathlib, talos.projects.manager, scope_io, proxy.scope
Data flow:
    CLI args → ProjectManager scope methods → registry.json
Side effects:
    Registry writes; proxy config change notifications on mutation.
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
    cli_usage_error,
    confirm_or_exit,
    wants_json,
)
from talos.projects.manager import ProjectManager, ProjectNotFound, NO_ACTIVE_PROJECT_HINT
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
    """Add one Basic Scope prefix to the active project's allow list."""
    project = _require_active(manager)
    try:
        project, inserted = manager.add_scope_prefix(project.id, args.prefix)
    except ScopeParseError as exc:
        cli_error(str(exc))
    except ProjectNotFound as exc:
        cli_error(str(exc))

    if inserted:
        print(f"Added in-scope prefix: {args.prefix.strip()}")
        _notify(project.id, f"scope add {args.prefix.strip()}")
    else:
        print(f"Already present: {args.prefix.strip()}")


def cmd_remove(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Remove one Basic Scope prefix from the active project."""
    project = _require_active(manager)
    try:
        project, removed = manager.remove_scope_prefix(project.id, args.prefix)
    except ProjectNotFound as exc:
        cli_error(str(exc))

    if removed:
        print(f"Removed in-scope prefix: {args.prefix.strip()}")
        _notify(project.id, f"scope remove {args.prefix.strip()}")
    else:
        cli_error(f"In-scope prefix not found: {args.prefix.strip()!r}")


def cmd_list(manager: ProjectManager, args: argparse.Namespace) -> None:
    """List in-scope prefixes for the active project."""
    project = _require_active(manager)
    entries = list(project.scope or [])

    if wants_json(args):
        cli_json(entries)
        return

    if not entries:
        print("No in-scope prefixes configured.")
        print(
            "Hint: talos project scope add <prefix>  "
            "(e.g. example.com or http://example.com:8000)"
        )
        return

    print(f"{len(entries)} in-scope prefix(es):\n")
    for prefix in entries:
        print(f"  {prefix}")


def cmd_clear(manager: ProjectManager, args: argparse.Namespace) -> None:
    """Clear all in-scope prefixes (destructive; requires confirm/--force)."""
    project = _require_active(manager)
    count = len(project.scope or [])
    if count == 0:
        print("In-scope list is already empty.")
        return

    confirm_or_exit(
        f"Clear all {count} in-scope prefix(es) for project '{project.id}'?",
        force=bool(getattr(args, "force", False)),
    )
    try:
        project = manager.clear_scope(project.id)
    except ProjectNotFound as exc:
        cli_error(str(exc))
    print(f"Cleared in-scope list for '{project.id}'.")
    _notify(project.id, "scope clear")


def cmd_import(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Atomically import Basic Scope prefixes from a UTF-8 text file.
    Invalid lines reject the entire import (no partial mutation).
    """
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
        print("No scope prefixes found in file (empty or comments only).")
        return

    try:
        project, added, skipped = manager.import_scope_prefixes(
            project.id,
            prefixes,
            replace=bool(getattr(args, "replace", False)),
        )
    except ScopeParseError as exc:
        cli_error(str(exc))
    except ProjectNotFound as exc:
        cli_error(str(exc))

    mode = "replaced with" if getattr(args, "replace", False) else "imported"
    print(
        f"Scope {mode} {len(prefixes)} prefix(es) from {path.name}: "
        f"{added} added, {skipped} already present."
    )
    for p in prefixes:
        print(f"  {p}")
    _notify(project.id, f"scope import {path.name}")


def build_parser() -> argparse.ArgumentParser:
    """
    Purpose:
        Construct parser for `talos project scope` resource subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="talos project scope",
        description=(
            "Manage Basic Scope (URL-prefix) allow list for the active project. "
            "One entry is one complete prefix (host, host:port, scheme://host, "
            "optional path). Omitted protocol matches HTTP and HTTPS. "
            "Omitted port matches any port; a specified port matches only that port. "
            "Subdomains are not implied."
        ),
    )
    sub = parser.add_subparsers(dest="command", metavar="command", required=True)

    p_add = sub.add_parser(
        "add",
        help="Add one URL/host prefix to in-scope.",
    )
    p_add.add_argument(
        "prefix",
        help=(
            "Basic Scope prefix, e.g. example.com, example.com:8000, "
            "http://example.com/api/, https://10.10.10.25:8443/admin/"
        ),
    )

    p_remove = sub.add_parser("remove", help="Remove one in-scope prefix.")
    p_remove.add_argument("prefix", help="Exact prefix to remove.")

    p_list = sub.add_parser("list", help="List in-scope prefixes.")
    add_format_argument(p_list)

    p_clear = sub.add_parser("clear", help="Remove all in-scope prefixes.")
    add_force_argument(p_clear)

    p_import = sub.add_parser(
        "import",
        help="Import prefixes from a UTF-8 text file (one prefix per line).",
    )
    p_import.add_argument(
        "file",
        help="Path to text file. # comments and blank lines ignored. Atomic validate.",
    )
    p_import.add_argument(
        "--replace",
        action="store_true",
        help="Replace the entire scope list with the file contents.",
    )

    return parser


_COMMAND_MAP = {
    "add": cmd_add,
    "remove": cmd_remove,
    "list": cmd_list,
    "clear": cmd_clear,
    "import": cmd_import,
}


def run_scope_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Dispatch `talos project scope <subcommand> ...`.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = _COMMAND_MAP.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    handler(manager, args)
