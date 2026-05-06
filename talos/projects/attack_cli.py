"""
Module: talos.projects.attack_cli

Purpose:
    Command-line interface for managing per-attack configuration.
    Entry point for: talos attack unauth exclude add|remove|list

    Exclusions work at two granularities:
      host-level  : talos attack unauth exclude add api.internal.example.com
      host+path   : talos attack unauth exclude add test.com/api/v1
                    (excludes all endpoints whose path starts with /api/v1 on test.com)

    All subcommands require an active project.

Dependencies: argparse, sys, talos.projects.attack_config, talos.scheduler.db,
              talos.projects.manager
Data flow:
    CLI args → active project lookup → attack_config / scheduler CRUD → stdout
Side effects:
    - add: inserts into attack_host_exclusions; cancels pending/running auth_test jobs.
    - remove: deletes from attack_host_exclusions.
    - list: read-only.
"""

import argparse
import sys

from talos.projects.attack_config import (
    add_unauth_exclusion,
    remove_unauth_exclusion,
    list_unauth_excluded_hosts,
)
from talos.projects.manager import ProjectManager, NoActiveProject
from talos.scheduler import db as sched_db


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _require_active(manager: ProjectManager):
    """
    Purpose: Return the active project or exit with an error message.
    Side effects: May call sys.exit(1).
    """
    try:
        return manager.get_active()
    except NoActiveProject:
        print("Error: no active project. Run 'talos project open <id>' first.", file=sys.stderr)
        sys.exit(1)


def _parse_target(raw: str) -> tuple[str, str]:
    """
    Purpose:
        Split a user-supplied target string into (host, path).

        Examples:
          'api.internal.example.com'  → ('api.internal.example.com', '')
          'test.com/api/v1'           → ('test.com', '/api/v1')
          'test.com/fdfd/fd/'         → ('test.com', '/fdfd/fd')   # trailing slash stripped

    Input:  raw — string typed by the user.
    Output: (host, path) both lowercased; path is '' or starts with '/'.
    """
    raw = raw.strip().lower()
    # Strip any scheme the user may have typed (http:// / https://)
    for scheme in ("https://", "http://"):
        if raw.startswith(scheme):
            raw = raw[len(scheme):]
            break
    if "/" in raw:
        host, rest = raw.split("/", 1)
        path = "/" + rest.rstrip("/")
        if path == "/":
            path = ""
    else:
        host = raw
        path = ""
    return host, path


def _fmt_target(host: str, path: str) -> str:
    """Return a human-readable target label."""
    return host + path if path else host


# ------------------------------------------------------------------ #
# unauth exclude subcommands                                           #
# ------------------------------------------------------------------ #

def cmd_unauth_exclude_add(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Add a host (or host+path prefix) to the unauth attack exclusion list.
        Cancels any pending/running auth_test scheduler jobs for that exclusion.
    """
    project = _require_active(manager)
    host, path = _parse_target(args.target)

    inserted = add_unauth_exclusion(project.db_path, host, path)
    label = _fmt_target(host, path)

    if not inserted:
        print(f"Already excluded: {label}")
        return

    print(f"Excluded from unauth testing: {label}")

    cancelled = sched_db.cancel_auth_test_jobs_for_host(project.db_path, host, path)
    if cancelled:
        print(f"Cancelled {cancelled} pending/running auth_test job(s) for this exclusion.")


def cmd_unauth_exclude_remove(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Remove a host (or host+path prefix) from the unauth attack exclusion list.
    """
    project = _require_active(manager)
    host, path = _parse_target(args.target)
    label = _fmt_target(host, path)

    removed = remove_unauth_exclusion(project.db_path, host, path)

    if removed:
        print(f"Removed exclusion: {label}")
    else:
        print(f"Not found: {label}", file=sys.stderr)
        sys.exit(1)


def cmd_unauth_exclude_list(manager: ProjectManager, _args: argparse.Namespace) -> None:
    """
    Purpose:
        List all entries excluded from unauth attack testing.
    Side effects:
        Prints exclusion list to stdout.
    """
    project = _require_active(manager)
    entries = list_unauth_excluded_hosts(project.db_path)

    if not entries:
        print("No exclusions for unauth testing.")
        return

    print(f"{len(entries)} exclusion(s):\n")
    for e in entries:
        label = _fmt_target(e["host"], e["path"])
        scope = "(host+path)" if e["path"] else "(host-level)"
        print(f"  {label:<70}  {scope}  added {e['created_at']}")


# ------------------------------------------------------------------ #
# Parser construction                                                  #
# ------------------------------------------------------------------ #

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="talos attack",
        description="Manage attack module configuration.",
    )
    sub = parser.add_subparsers(dest="attack_type", metavar="<attack>")
    sub.required = True

    # ---- unauth ---- #
    unauth_p = sub.add_parser("unauth", help="Unauthenticated execution attack settings.")
    unauth_sub = unauth_p.add_subparsers(dest="unauth_cmd", metavar="<command>")
    unauth_sub.required = True

    exclude_p = unauth_sub.add_parser("exclude", help="Manage per-host/path exclusions.")
    excl_sub = exclude_p.add_subparsers(dest="excl_cmd", metavar="<subcommand>")
    excl_sub.required = True

    add_p = excl_sub.add_parser(
        "add",
        help="Exclude a host or host+path prefix from unauth testing.",
        description=(
            "Exclude a host or host+path prefix.\n"
            "Examples:\n"
            "  talos attack unauth exclude add api.internal.example.com\n"
            "  talos attack unauth exclude add test.com/api/v1\n"
            "  talos attack unauth exclude add test.com/fdfd/fd/"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_p.add_argument(
        "target",
        help="Host (e.g. api.example.com) or host+path (e.g. test.com/api/v1).",
    )

    rem_p = excl_sub.add_parser(
        "remove",
        help="Remove a host or host+path exclusion.",
    )
    rem_p.add_argument(
        "target",
        help="Same format as 'add' — host or host+path.",
    )

    excl_sub.add_parser("list", help="List all exclusions.")

    return parser


# ------------------------------------------------------------------ #
# Entry point                                                          #
# ------------------------------------------------------------------ #

def run_attack_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse argv and dispatch to the appropriate attack subcommand handler.
    Input:
        manager — ProjectManager instance (already constructed in __main__).
        argv    — Argument list after the 'attack' token has been consumed.
    Side effects:
        Delegates to subcommand handler; may sys.exit().
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.attack_type == "unauth":
        if args.unauth_cmd == "exclude":
            if args.excl_cmd == "add":
                cmd_unauth_exclude_add(manager, args)
            elif args.excl_cmd == "remove":
                cmd_unauth_exclude_remove(manager, args)
            elif args.excl_cmd == "list":
                cmd_unauth_exclude_list(manager, args)
