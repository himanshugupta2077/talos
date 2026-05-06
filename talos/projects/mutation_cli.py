"""
Module: talos.projects.mutation_cli

Purpose:
    Command-line interface for managing per-project request mutations.
    Entry point for: talos mutation add|list|delete

    All subcommands require an active project.

Dependencies: argparse, sys, talos.projects.mutation, talos.projects.manager
Data flow:
    CLI args → active project lookup → mutation CRUD → stdout
Side effects:
    - State changes delegated to talos.projects.mutation.
    - Prints structured output to stdout.
    - Exits with code 1 on error.
"""

import argparse
import sys

from talos.projects.manager import ProjectManager
from talos.projects.mutation import add_mutation, delete_mutation, list_mutations


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def cmd_add(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Add a new request mutation to the active project.
        'mutation_type' positional must be 'header'.
    Input:
        manager — ProjectManager instance.
        args    — parsed args: mutation_type, key, value.
    Side effects:
        Prints the assigned mutation ID on success; exits 1 on error.
    """
    project = _require_active(manager)

    try:
        mutation_id = add_mutation(project.db_path, args.mutation_type, args.key, args.value)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Mutation added: {mutation_id}")
    print(f"  type : {args.mutation_type}")
    print(f"  key  : {args.key}")
    print(f"  value: {args.value}")


def cmd_list(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose:
        List all request mutations for the active project.
    Side effects:
        Prints mutation list to stdout.
    """
    project = _require_active(manager)
    mutations = list_mutations(project.db_path)

    if not mutations:
        print("No request mutations configured.")
        return

    print(f"{len(mutations)} mutation(s):\n")
    for m in mutations:
        status = "enabled" if m["enabled"] else "disabled"
        print(f"  {m['id']}  [{status}]")
        print(f"    type : {m['type']}")
        print(f"    key  : {m['key']}")
        print(f"    value: {m['value']}")
        print()


def cmd_delete(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Delete a request mutation by ID from the active project.
    Input:
        manager — ProjectManager instance.
        args    — parsed args: id (mutation UUID string).
    Side effects:
        Prints confirmation or 'not found' notice; exits 1 on error.
    """
    project = _require_active(manager)
    removed = delete_mutation(project.db_path, args.id)

    if removed:
        print(f"Deleted mutation: {args.id}")
    else:
        print(f"Not found: {args.id}", file=sys.stderr)
        sys.exit(1)


# ------------------------------------------------------------------ #
# Entry point                                                          #
# ------------------------------------------------------------------ #

def run_mutation_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse and dispatch 'talos mutation' subcommands.
    Input:
        manager — ProjectManager instance.
        argv    — argument list after 'mutation' (e.g. ['add', 'header', ...]).
    Side effects:
        Dispatches to the appropriate command handler.
    """
    parser = argparse.ArgumentParser(
        prog="talos mutation",
        description="Manage per-project request mutations.",
    )
    sub = parser.add_subparsers(dest="subcommand")

    # add
    p_add = sub.add_parser("add", help="Add a new request mutation.")
    p_add.add_argument(
        "mutation_type",
        metavar="TYPE",
        help="Mutation type. Only 'header' is supported.",
    )
    p_add.add_argument("key", metavar="KEY", help="Header name.")
    p_add.add_argument("value", metavar="VALUE", help="Header value.")

    # list
    sub.add_parser("list", help="List all request mutations.")

    # delete
    p_delete = sub.add_parser("delete", help="Delete a mutation by ID.")
    p_delete.add_argument("id", metavar="ID", help="Mutation UUID to delete.")

    args = parser.parse_args(argv)

    if args.subcommand is None:
        parser.print_help()
        sys.exit(0)

    if args.subcommand == "add":
        cmd_add(manager, args)
    elif args.subcommand == "list":
        cmd_list(manager, args)
    elif args.subcommand == "delete":
        cmd_delete(manager, args)
    else:
        parser.print_help()
        sys.exit(1)


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
