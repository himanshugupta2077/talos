"""
Module: talos.projects.cli

Purpose:
    Command-line interface for project management operations.
    Entry point for: create, open, close, delete, list, scope commands.

Dependencies: argparse, talos.projects.manager, talos.config
Data flow:
    CLI args → ProjectManager → stdout (human-readable output)
Side effects:
    - All state changes are delegated to ProjectManager.
    - Prints structured output to stdout.
    - Exits with code 1 on error.
"""

import argparse
import sys
from pathlib import Path

from talos.projects.manager import (
    ProjectManager,
    ProjectError,
    ProjectNotFound,
    ProjectAlreadyExists,
    NoActiveProject,
)
from talos.projects.model import Project, ProjectStatus, ScopeConstraints
from talos.projects.outscope_cli import run_outscope_cli


# ------------------------------------------------------------------ #
# Formatting helpers                                                   #
# ------------------------------------------------------------------ #

def _fmt_project(project: Project, label: str = "") -> str:
    """
    Purpose: Render a single project as a human-readable block.
    Input:   project — Project instance; label — optional prefix tag.
    Output:  Multi-line string.
    Side effects: None.
    """
    status_tag = "[ACTIVE]" if project.status == ProjectStatus.ACTIVE else "[inactive]"
    prefix = f"  {label}" if label else ""
    scope_display = ", ".join(project.scope) if project.scope else "(none)"
    c = project.constraints
    return (
        f"{prefix}{status_tag} {project.name} ({project.id})\n"
        f"    Created         : {project.created_at}\n"
        f"    Scope           : {scope_display}\n"
        f"    Store bodies    : {c.store_bodies}\n"
        f"    Max body size   : {c.max_body_size:,} bytes\n"
        f"    DB              : {project.db_path}\n"
        f"    Note            : {project.description or '—'}"
    )


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def cmd_create(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose: Create a new project.
    Input:   manager, args with: name, description, scope (optional list).
    Side effects: Prints confirmation; exits 1 on failure.
    """
    scope = args.scope or []
    try:
        project = manager.create(
            name=args.name,
            description=args.description or "",
            scope=scope,
        )
        print(f"Project created.\n{_fmt_project(project)}")
    except ProjectAlreadyExists as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def cmd_open(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose: Open (activate) a project.
    Input:   manager, args with: id.
    Side effects: Prints confirmation; exits 1 on failure.
    """
    try:
        project = manager.open(args.id)
        print(f"Project opened.\n{_fmt_project(project)}")
    except ProjectNotFound as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def cmd_close(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose: Close the active project.
    Side effects: Prints confirmation or info if none active.
    """
    closed = manager.close()
    if closed:
        print(f"Project closed: {closed.name} ({closed.id})")
    else:
        print("No active project to close.")


def cmd_delete(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose: Remove a project from the registry (data preserved on disk).
    Input:   manager, args with: id, force (bool).
    Side effects: Prompts for confirmation unless --force; exits 1 on abort/error.
    """
    if not args.force:
        confirm = input(
            f"Remove project '{args.id}' from registry? Data on disk will NOT be deleted. [y/N] "
        ).strip().lower()
        if confirm != "y":
            print("Aborted.")
            sys.exit(0)

    try:
        project = manager.delete(args.id)
        print(f"Removed: {project.name} ({project.id})\nData preserved at: {project.data_dir}")
    except ProjectNotFound as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def cmd_list(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose: List all registered projects.
    Side effects: Prints project list to stdout.
    """
    projects = manager.list_all()
    if not projects:
        print("No projects registered. Use 'talos project create <name>'.")
        return

    active = manager.active()
    print(f"{len(projects)} project(s):\n")
    for project in projects:
        print(_fmt_project(project))
        print()


def cmd_scope(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose: Set or display scope for a project.
    Input:   manager, args with: id, patterns (list, optional).
    Side effects:
        - If patterns provided: updates scope, prints confirmation.
        - If no patterns: prints current scope.
    """
    try:
        project = manager.get(args.id)
    except ProjectNotFound as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.patterns:
        project = manager.set_scope(args.id, args.patterns)
        print(f"Scope updated for '{project.id}':")
        for pattern in project.scope:
            print(f"  {pattern}")
    else:
        if project.scope:
            print(f"Scope for '{project.id}':")
            for pattern in project.scope:
                print(f"  {pattern}")
        else:
            print(f"No scope set for '{project.id}'. Use: talos project scope {project.id} <host> [<host>...]")


def cmd_constraints(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Get or set capture constraints for a project.
        If options provided: applies changes and prints updated constraints.
        If no options: prints current constraints.
    Input:
        manager — ProjectManager instance.
        args    — parsed args: id, store_bodies (bool|None), max_body_size (int|None).
    Side effects:
        - Writes registry if any change is requested.
        - Prints result to stdout.
    """
    try:
        project = manager.get(args.id)
    except ProjectNotFound as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Determine whether any change was requested.
    changing = (args.store_bodies is not None) or (args.max_body_size is not None)

    if changing:
        current = project.constraints
        new_constraints = ScopeConstraints(
            capture_in_scope_only=True,  # always enforced; not user-configurable
            store_bodies=args.store_bodies if args.store_bodies is not None else current.store_bodies,
            max_body_size=args.max_body_size if args.max_body_size is not None else current.max_body_size,
        )
        project = manager.set_constraints(args.id, new_constraints)
        print(f"Constraints updated for '{project.id}':")
    else:
        print(f"Constraints for '{project.id}':")

    c = project.constraints
    print(f"  capture_in_scope_only : {c.capture_in_scope_only}")
    print(f"  store_bodies          : {c.store_bodies}")
    print(f"  max_body_size         : {c.max_body_size:,} bytes")


def cmd_status(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose: Show current active project (quick status check).
    Side effects: Prints active project or 'none'.
    """
    active = manager.active()
    if active:
        print(f"Active project:\n{_fmt_project(active)}")
    else:
        print("No active project. Use 'talos project open <id>'.")


# ------------------------------------------------------------------ #
# Parser construction                                                  #
# ------------------------------------------------------------------ #

def build_parser() -> argparse.ArgumentParser:
    """
    Purpose: Construct the full argument parser for 'talos project' subcommands.
    Output:  Configured ArgumentParser.
    Side effects: None.
    """
    parser = argparse.ArgumentParser(
        prog="talos project",
        description="Manage Talos projects. A project is the root isolation unit.",
    )
    sub = parser.add_subparsers(dest="command", metavar="command", required=True)

    # create
    p_create = sub.add_parser("create", help="Create a new project.")
    p_create.add_argument("name", help="Human-readable project name.")
    p_create.add_argument("-d", "--description", default="", help="Optional description.")
    p_create.add_argument(
        "-s", "--scope", nargs="*", metavar="HOST",
        help="Initial scope patterns (host or URL prefix). Can be set later with 'scope'.",
    )

    # open
    p_open = sub.add_parser("open", help="Open (activate) a project.")
    p_open.add_argument("id", help="Project id (slug).")

    # close
    sub.add_parser("close", help="Close the currently active project.")

    # delete
    p_delete = sub.add_parser("delete", help="Remove a project from the registry (data preserved).")
    p_delete.add_argument("id", help="Project id (slug).")
    p_delete.add_argument("--force", action="store_true", help="Skip confirmation prompt.")

    # list
    sub.add_parser("list", help="List all projects.")

    # scope
    p_scope = sub.add_parser("scope", help="Get or set scope for a project.")
    p_scope.add_argument("id", help="Project id (slug).")
    p_scope.add_argument(
        "patterns", nargs="*", metavar="PATTERN",
        help="Scope patterns to set. Omit to display current scope.",
    )

    # constraints
    p_constraints = sub.add_parser(
        "constraints",
        help="Get or set capture constraints for a project.",
    )
    p_constraints.add_argument("id", help="Project id (slug).")
    p_constraints.add_argument(
        "--store-bodies",
        dest="store_bodies",
        type=lambda v: v.lower() in ("1", "true", "yes"),
        default=None,
        metavar="BOOL",
        help="Store request/response bodies (true|false).",
    )
    p_constraints.add_argument(
        "--max-body-size",
        dest="max_body_size",
        type=int,
        default=None,
        metavar="BYTES",
        help="Maximum body size in bytes before truncation.",
    )

    # status
    sub.add_parser("status", help="Show the currently active project.")

    # outscope — delegates to its own sub-parser via run_outscope_cli
    sub.add_parser("outscope", help="Manage the out-of-scope domain list.",
                   add_help=False)

    return parser


_COMMAND_MAP = {
    "create": cmd_create,
    "open": cmd_open,
    "close": cmd_close,
    "delete": cmd_delete,
    "list": cmd_list,
    "scope": cmd_scope,
    "constraints": cmd_constraints,
    "status": cmd_status,
}


def run_project_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse argv and dispatch to the appropriate project command handler.
    Input:
        manager — ProjectManager instance.
        argv    — list of CLI arguments (excluding the top-level 'talos' token).
    Side effects:
        Delegates to command handlers; may exit with sys.exit().
    """
    # Delegate outscope subcommand directly — it has its own sub-parser.
    if argv and argv[0] == "outscope":
        run_outscope_cli(manager, argv[1:])
        return

    parser = build_parser()
    args = parser.parse_args(argv)

    handler = _COMMAND_MAP.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    handler(manager, args)
