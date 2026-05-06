"""
Module: talos.projects.endpoint_cli

Purpose:
    Command-line interface for endpoint annotation management.

    Commands:
        talos endpoint mark   <endpoint_id> (--logout | --dangerous | --safe)
        talos endpoint unmark <endpoint_id> (--logout | --dangerous)
        talos endpoint show   <endpoint_id>

    'mark' adds a safety tag to an endpoint or, with --safe, clears all tags.
    'unmark' removes a specific tag.
    'show' displays the endpoint record and its current annotations.

    Tag semantics:
        logout    → never replay (any mode — manual or auto).
        dangerous → skip in automated replay; manual replay is still allowed.
        safe      → (--mark --safe only) clears both tags; restores default.

Dependencies: argparse, sys, talos.projects.manager,
              talos.projects.annotations, talos.replay.db
Data flow:
    CLI args → active project DB → annotations module → stdout
Side effects:
    - 'mark' and 'unmark' write to endpoint_annotations table.
    - 'show' is read-only.
    - All commands require an active project.
    - Exits 1 if no active project or endpoint not found.
"""

import argparse
import sys

from talos.projects.manager import ProjectManager
import talos.projects.annotations as annotations_mod
import talos.replay.db as replay_db


# ------------------------------------------------------------------ #
# CLI entry point                                                      #
# ------------------------------------------------------------------ #

def run_endpoint_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse endpoint subcommand arguments and dispatch to the handler.
    Input:
        manager — ProjectManager instance carrying the projects root path.
        argv    — argument list after 'endpoint'.
    Side effects:
        Dispatches to cmd_endpoint_mark, cmd_endpoint_unmark, or cmd_endpoint_show.
        Prints usage and exits 1 for unrecognised subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="talos endpoint",
        description="Manage endpoint safety annotations.",
    )
    sub = parser.add_subparsers(dest="endpoint_cmd", metavar="<command>")
    sub.required = True

    # talos endpoint mark <id> (--logout | --dangerous | --safe)
    p_mark = sub.add_parser(
        "mark",
        help="Add a safety annotation to an endpoint.",
    )
    p_mark.add_argument("endpoint_id", help="UUID of the endpoint to annotate.")
    group_mark = p_mark.add_mutually_exclusive_group(required=True)
    group_mark.add_argument(
        "--logout",
        action="store_true",
        help="Tag as logout endpoint — never replayed in any mode.",
    )
    group_mark.add_argument(
        "--dangerous",
        action="store_true",
        help="Tag as dangerous — skipped in automated replay; manual is still allowed.",
    )
    group_mark.add_argument(
        "--safe",
        action="store_true",
        help="Clear all annotations — restore default safe state.",
    )

    # talos endpoint unmark <id> (--logout | --dangerous)
    p_unmark = sub.add_parser(
        "unmark",
        help="Remove an annotation tag from an endpoint.",
    )
    p_unmark.add_argument("endpoint_id", help="UUID of the endpoint.")
    group_unmark = p_unmark.add_mutually_exclusive_group(required=True)
    group_unmark.add_argument(
        "--logout",
        action="store_true",
        help="Remove the logout tag.",
    )
    group_unmark.add_argument(
        "--dangerous",
        action="store_true",
        help="Remove the dangerous tag.",
    )

    # talos endpoint show <id>
    p_show = sub.add_parser(
        "show",
        help="Display endpoint details and current annotations.",
    )
    p_show.add_argument("endpoint_id", help="UUID of the endpoint to display.")

    args = parser.parse_args(argv)

    project = manager.active()
    if project is None:
        print(
            "Error: No active project. Run 'talos project open <id>' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.endpoint_cmd == "mark":
        cmd_endpoint_mark(project, args)
    elif args.endpoint_cmd == "unmark":
        cmd_endpoint_unmark(project, args)
    elif args.endpoint_cmd == "show":
        cmd_endpoint_show(project, args)


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def cmd_endpoint_mark(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Add a safety annotation to an endpoint, or clear all annotations (--safe).
    Input:
        project — active Project instance.
        args    — parsed args: endpoint_id (str), logout/dangerous/safe (bool).
    Side effects:
        Writes to endpoint_annotations table.
        Exits 1 if the endpoint does not exist.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    endpoint_id = args.endpoint_id

    endpoint = replay_db.get_endpoint_by_id(db_path, endpoint_id)
    if endpoint is None:
        print(f"Error: Endpoint '{endpoint_id}' not found.", file=sys.stderr)
        sys.exit(1)

    ep_label = f"{endpoint['method']} {endpoint['host']}{endpoint['normalized_path']}"

    if args.safe:
        annotations_mod.clear_annotations(db_path, endpoint_id)
        print(f"Cleared all annotations on {ep_label}")
    elif args.logout:
        annotations_mod.add_annotation(db_path, endpoint_id, "logout")
        print(f"Marked {ep_label} as logout")
    elif args.dangerous:
        annotations_mod.add_annotation(db_path, endpoint_id, "dangerous")
        print(f"Marked {ep_label} as dangerous")


def cmd_endpoint_unmark(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Remove a specific annotation tag from an endpoint.
    Input:
        project — active Project instance.
        args    — parsed args: endpoint_id (str), logout/dangerous (bool).
    Side effects:
        Deletes tag row from endpoint_annotations. No-op if tag is not present.
        Exits 1 if the endpoint does not exist.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    endpoint_id = args.endpoint_id

    endpoint = replay_db.get_endpoint_by_id(db_path, endpoint_id)
    if endpoint is None:
        print(f"Error: Endpoint '{endpoint_id}' not found.", file=sys.stderr)
        sys.exit(1)

    ep_label = f"{endpoint['method']} {endpoint['host']}{endpoint['normalized_path']}"

    if args.logout:
        annotations_mod.remove_annotation(db_path, endpoint_id, "logout")
        print(f"Removed logout annotation from {ep_label}")
    elif args.dangerous:
        annotations_mod.remove_annotation(db_path, endpoint_id, "dangerous")
        print(f"Removed dangerous annotation from {ep_label}")


def cmd_endpoint_show(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Display the endpoint record and its current annotation tags.
    Input:
        project — active Project instance.
        args    — parsed args: endpoint_id (str).
    Side effects:
        Reads endpoint + annotations from DB; prints to stdout.
        Exits 1 if the endpoint does not exist.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    endpoint_id = args.endpoint_id

    endpoint = replay_db.get_endpoint_by_id(db_path, endpoint_id)
    if endpoint is None:
        print(f"Error: Endpoint '{endpoint_id}' not found.", file=sys.stderr)
        sys.exit(1)

    tags = annotations_mod.get_annotations(db_path, endpoint_id)
    ep_label = f"{endpoint['method']} {endpoint['host']}{endpoint['normalized_path']}"
    tag_str = ", ".join(sorted(tags)) if tags else "none"

    print(
        f"Endpoint : {endpoint_id}\n"
        f"  {ep_label}\n\n"
        f"Annotations: {tag_str}"
    )
