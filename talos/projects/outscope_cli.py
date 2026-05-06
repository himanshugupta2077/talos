"""
Module: talos.projects.outscope_cli

Purpose:
    Command-line interface for managing the per-project out-of-scope domain list.
    Entry point for: talos project outscope add|list|remove

    All subcommands require an active project.

Dependencies: argparse, sys, talos.projects.outscope, talos.projects.manager
Data flow:
    CLI args → active project lookup → outscope CRUD → stdout
Side effects:
    - State changes delegated to talos.projects.outscope.
    - Prints structured output to stdout.
    - Exits with code 1 on error.
"""

import argparse
import sys

from talos.projects.manager import ProjectManager, NoActiveProject
from talos.projects.outscope import add_domain, list_domains, remove_domain


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def cmd_add(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Add a domain to the out-of-scope list for the active project.
        'type' positional must be 'domain' (extensibility placeholder).
    Input:
        manager — ProjectManager instance.
        args    — parsed args: type (must be 'domain'), value (domain string).
    Side effects:
        Prints confirmation or 'already present' notice; exits 1 on error.
    """
    if args.type != "domain":
        print(f"Error: unknown type '{args.type}'. Only 'domain' is supported.", file=sys.stderr)
        sys.exit(1)

    project = _require_active(manager)
    inserted = add_domain(project.db_path, project.id, args.value)

    if inserted:
        print(f"Added out-of-scope domain: {args.value.strip().lower()}")
    else:
        print(f"Already present: {args.value.strip().lower()}")


def cmd_list(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose:
        List all out-of-scope domains for the active project.
    Side effects:
        Prints domain list to stdout.
    """
    project = _require_active(manager)
    entries = list_domains(project.db_path)

    if not entries:
        print("No out-of-scope domains configured.")
        return

    print(f"{len(entries)} out-of-scope domain(s):\n")
    for entry in entries:
        print(f"  {entry['domain']:<50}  added {entry['created_at']}")


def cmd_remove(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Remove a domain from the out-of-scope list for the active project.
        'type' positional must be 'domain'.
    Input:
        manager — ProjectManager instance.
        args    — parsed args: type (must be 'domain'), value (domain string).
    Side effects:
        Prints confirmation or 'not found' notice; exits 1 on error.
    """
    if args.type != "domain":
        print(f"Error: unknown type '{args.type}'. Only 'domain' is supported.", file=sys.stderr)
        sys.exit(1)

    project = _require_active(manager)
    removed = remove_domain(project.db_path, project.id, args.value)

    if removed:
        print(f"Removed out-of-scope domain: {args.value.strip().lower()}")
    else:
        print(f"Not found: {args.value.strip().lower()}")


# ------------------------------------------------------------------ #
# Helper                                                               #
# ------------------------------------------------------------------ #

def _require_active(manager: ProjectManager):
    """
    Purpose:
        Retrieve the active project or exit with a clear error.
    Output:
        Active Project instance.
    Side effects:
        Exits with code 1 if no project is active.
    """
    project = manager.active()
    if project is None:
        print(
            "Error: no active project. Run 'talos project open <id>' first.",
            file=sys.stderr,
        )
        sys.exit(1)
    return project


# ------------------------------------------------------------------ #
# Parser construction                                                  #
# ------------------------------------------------------------------ #

def build_parser() -> argparse.ArgumentParser:
    """
    Purpose:
        Construct the argument parser for 'talos project outscope' subcommands.
    Output:
        Configured ArgumentParser.
    Side effects: None.
    """
    parser = argparse.ArgumentParser(
        prog="talos project outscope",
        description="Manage the out-of-scope domain list for the active project.",
    )
    sub = parser.add_subparsers(dest="command", metavar="command", required=True)

    # add domain <value>
    p_add = sub.add_parser("add", help="Add an entry to the out-of-scope list.")
    p_add.add_argument(
        "type",
        choices=["domain"],
        help="Entry type. Currently only 'domain' is supported.",
    )
    p_add.add_argument("value", help="Domain to block (e.g. api.stripe.com).")

    # list
    sub.add_parser("list", help="List all out-of-scope entries.")

    # remove domain <value>
    p_remove = sub.add_parser("remove", help="Remove an entry from the out-of-scope list.")
    p_remove.add_argument(
        "type",
        choices=["domain"],
        help="Entry type. Currently only 'domain' is supported.",
    )
    p_remove.add_argument("value", help="Domain to unblock (e.g. api.stripe.com).")

    return parser


_COMMAND_MAP = {
    "add": cmd_add,
    "list": cmd_list,
    "remove": cmd_remove,
}


def run_outscope_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse argv and dispatch to the appropriate outscope command handler.
    Input:
        manager — ProjectManager instance.
        argv    — list of CLI arguments after 'talos project outscope'.
    Side effects:
        Delegates to command handlers; may exit via sys.exit().
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    handler = _COMMAND_MAP.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    handler(manager, args)
