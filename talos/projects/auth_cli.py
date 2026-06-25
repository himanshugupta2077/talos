"""
Module: talos.projects.auth_cli

Purpose:
    Command-line interface for auth configuration and auth-bypass testing.

    Auth config commands:
        talos auth set   --cookie <name> ... --header <name> ...
        talos auth unset --cookie <name> ... --header <name> ...
        talos auth show
        talos auth clear
        talos auth test  <endpoint_id>

    'set' and 'unset' manage the per-project auth requirements stored in
    auth_config (cookie and header artifact names that constitute authentication).
    'set' is additive; 'unset' removes specific entries.

    'test' runs a Type 2 replay on the best qualifying flow for an endpoint:
    strips configured auth fields, replays, diffs, and outputs the verdict
    (SECURE | BYPASS | UNKNOWN).

    Role-based session management has moved to 'talos auth-config'.

Dependencies: argparse, asyncio, sys,
              talos.projects.manager, talos.projects.auth,
              talos.replay.auth_strip, talos.replay.db
Data flow:
    CLI args → active project DB → auth functions / auth_strip → stdout
Side effects:
    - 'set' / 'unset' / 'clear' write to auth_config table.
    - 'test' sends outbound HTTP, writes replay flow + diff + auth_test_result.
    - All commands require an active project.
    - Exits 1 on hard errors (no active project, missing config, flow not found).
"""

import argparse
import asyncio
import sys
import uuid

from talos.projects.manager import ProjectManager
from talos.projects.auth import (
    get_auth_config,
    set_auth_fields,
    unset_auth_fields,
    clear_auth_config,
)
from talos.replay import db as replay_db
from talos.replay.auth_strip import AuthTestOutcome, run_auth_bypass_test
from talos.scheduler import db as sched_db
from talos.scheduler.job import AUTH_TEST, PRIORITY_MANUAL


# ------------------------------------------------------------------ #
# CLI entry point                                                      #
# ------------------------------------------------------------------ #

def run_auth_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse auth subcommand arguments and dispatch to the appropriate handler.
    Input:
        manager — ProjectManager instance.
        argv    — argument list after 'auth' (e.g. ['set', '--cookie', 'sessionid']).
    Side effects:
        Dispatches to cmd_auth_set/unset/show/clear/test.
        Prints usage and exits 1 for unrecognised subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="talos auth",
        description=(
            "Define required auth artifacts and run auth-bypass tests.\n\n"
            "For role-based session management: talos auth-config"
        ),
    )
    sub = parser.add_subparsers(dest="auth_cmd", metavar="<command>")
    sub.required = True

    # talos auth set --cookie <name> ... --header <name> ...
    p_set = sub.add_parser(
        "set",
        help="Add cookie/header artifact names to the auth requirements (additive).",
    )
    p_set.add_argument(
        "--cookie",
        dest="cookies",
        action="append",
        default=[],
        metavar="NAME",
        help="Cookie name that carries auth (repeatable).",
    )
    p_set.add_argument(
        "--header",
        dest="headers",
        action="append",
        default=[],
        metavar="NAME",
        help="Header name that carries auth (repeatable).",
    )

    # talos auth unset --cookie <name> ... --header <name> ...
    p_unset = sub.add_parser(
        "unset",
        help="Remove specific cookie/header artifact names from the auth requirements.",
    )
    p_unset.add_argument(
        "--cookie",
        dest="cookies",
        action="append",
        default=[],
        metavar="NAME",
        help="Cookie name to remove (repeatable).",
    )
    p_unset.add_argument(
        "--header",
        dest="headers",
        action="append",
        default=[],
        metavar="NAME",
        help="Header name to remove (repeatable).",
    )

    # talos auth show
    sub.add_parser("show", help="Display the current auth requirements.")

    # talos auth clear
    sub.add_parser("clear", help="Remove all auth requirement entries.")

    # talos auth test <endpoint_id>
    p_test = sub.add_parser(
        "test",
        help="Run an auth-bypass test on the best flow for an endpoint.",
    )
    p_test.add_argument("endpoint_id", help="UUID of the endpoint to test.")
    p_test.add_argument(
        "--right-now",
        action="store_true",
        help="Run the auth test immediately instead of enqueuing it.",
    )

    args = parser.parse_args(argv)

    project = manager.active()
    if project is None:
        print(
            "Error: No active project. Run 'talos project open <id>' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.auth_cmd == "set":
        cmd_auth_set(project, args)
    elif args.auth_cmd == "unset":
        cmd_auth_unset(project, args)
    elif args.auth_cmd == "show":
        cmd_auth_show(project)
    elif args.auth_cmd == "clear":
        cmd_auth_clear(project)
    elif args.auth_cmd == "test":
        cmd_auth_test(project, args)


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def cmd_auth_set(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Add cookie and/or header names to the project's auth requirements.
        Additive — existing entries are preserved.
    Input:
        project — active Project instance.
        args    — parsed args with: cookies (list[str]), headers (list[str]).
    Side effects:
        Writes to auth_config table; prints confirmation to stdout.
        Exits 1 if no names were provided.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    cookies: list[str] = args.cookies
    headers: list[str] = args.headers

    if not cookies and not headers:
        print(
            "Error: Provide at least one --cookie or --header name.",
            file=sys.stderr,
        )
        sys.exit(1)

    set_auth_fields(db_path, cookies, headers)

    print("Auth requirements updated.")
    if cookies:
        print(f"  cookies : {', '.join(cookies)}")
    if headers:
        print(f"  headers : {', '.join(headers)}")
    print("Run 'talos auth show' to see the full config.")


def cmd_auth_unset(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Remove specific cookie and/or header names from the auth requirements.
    Input:
        project — active Project instance.
        args    — parsed args with: cookies (list[str]), headers (list[str]).
    Side effects:
        Deletes matching rows from auth_config; prints confirmation.
        Exits 1 if no names were provided.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    cookies: list[str] = args.cookies
    headers: list[str] = args.headers

    if not cookies and not headers:
        print(
            "Error: Provide at least one --cookie or --header name to remove.",
            file=sys.stderr,
        )
        sys.exit(1)

    unset_auth_fields(db_path, cookies, headers)

    print("Auth requirements updated.")
    if cookies:
        print(f"  removed cookies : {', '.join(cookies)}")
    if headers:
        print(f"  removed headers : {', '.join(headers)}")


def cmd_auth_show(project: object) -> None:
    """
    Purpose:
        Display the current auth requirements for the active project.
    Input:
        project — active Project instance.
    Side effects:
        Prints auth config to stdout.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    config = get_auth_config(db_path)

    if not config["cookies"] and not config["headers"]:
        print("Auth requirements: (empty)")
        print("Use 'talos auth set --cookie <name>' or '--header <name>' to configure.")
        return

    print("Required Auth Artifacts:")
    for name in config["cookies"]:
        print(f"  cookie : {name}")
    for name in config["headers"]:
        print(f"  header : {name}")


def cmd_auth_clear(project: object) -> None:
    """
    Purpose:
        Remove all auth requirement entries for the active project.
    Input:
        project — active Project instance.
    Side effects:
        Deletes all rows from auth_config; prints confirmation.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    clear_auth_config(db_path)
    print("Auth requirements cleared.")


def cmd_auth_test(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Run an auth-bypass test on the best qualifying flow for an endpoint.
        By default enqueues the job for the scheduler.  With --right-now the
        test is executed immediately in-process.
    Input:
        project — active Project instance.
        args    — parsed args with: endpoint_id (str), right_now (bool).
    Side effects:
        --right-now: Sends HTTP request; writes replay flow, diff, auth_test_result.
        default: Inserts one scheduler job; prints job ID to stdout.
        Exits 1 if endpoint not found.
    """
    db_path = project.db_path   # type: ignore[attr-defined]
    project_id = project.id     # type: ignore[attr-defined]
    endpoint_id = args.endpoint_id

    endpoint = replay_db.get_endpoint_by_id(db_path, endpoint_id)
    if endpoint is None:
        print(f"Error: Endpoint '{endpoint_id}' not found.", file=sys.stderr)
        sys.exit(1)

    if not args.right_now:
        job_id = str(uuid.uuid4())
        sched_db.enqueue_job(
            db_path=db_path,
            job_id=job_id,
            job_type=AUTH_TEST,
            project_id=project_id,
            endpoint_id=endpoint_id,
            priority=PRIORITY_MANUAL,
        )
        print(f"Job enqueued: {job_id}")
        return

    ep_label = (
        f"{endpoint['method']} {endpoint['host']}{endpoint['normalized_path']}"
    )
    print(f"Auth bypass test: {ep_label}")

    outcome: AuthTestOutcome = asyncio.run(
        run_auth_bypass_test(endpoint_id, db_path, project_id)
    )

    if outcome.failure_reason == "no_qualifying_flow":
        print(
            f"Error: Endpoint '{endpoint_id}' has no 200 OK proxy_capture flow.",
            file=sys.stderr,
        )
        sys.exit(1)

    if outcome.failure_reason == "auth_config_empty":
        print(
            "Error: Auth requirements empty. "
            "Run 'talos auth set --cookie <name>' or '--header <name>' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    if outcome.failure_reason in ("endpoint_annotated_logout", "endpoint_annotated_dangerous"):
        print(
            f"Error: Endpoint '{endpoint_id}' is annotated "
            f"({outcome.failure_reason}) — auth test blocked.",
            file=sys.stderr,
        )
        sys.exit(1)

    _print_auth_outcome(outcome)


# ------------------------------------------------------------------ #
# Output formatting                                                    #
# ------------------------------------------------------------------ #

def _print_auth_outcome(outcome: AuthTestOutcome) -> None:
    """
    Purpose:
        Print a human-readable auth-bypass test result to stdout.
    Input:   outcome — AuthTestOutcome instance.
    Side effects: Writes to stdout.
    """
    print(
        f"  original flow   : {outcome.original_flow_id}\n"
        f"  replay flow     : {outcome.replayed_flow_id or '—'}\n"
        f"  original status : {outcome.original_status or '—'}\n"
        f"  replay status   : {outcome.replay_status or '—'}\n"
        f"  diff verdict    : {outcome.diff_verdict or '—'}\n"
        f"  auth verdict    : {outcome.auth_verdict}"
    )
    if outcome.failure_reason:
        print(f"  note            : {outcome.failure_reason}")
