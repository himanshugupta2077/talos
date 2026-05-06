"""
Module: talos.replay.cli

Purpose:
    Command-line interface for the replay engine.
    Entry point for:
        talos replay flow <flow_id>
        talos replay endpoint <endpoint_id>

    Both commands require an active project.  The active project supplies
    the database path and project_id used for storing the replay result.

Dependencies: argparse, asyncio, sys, talos.projects.manager, talos.replay.engine,
              talos.replay.db
Data flow:
    CLI args → active project DB → engine (async) → ReplayOutcome → stdout
Side effects:
    - Sends an outbound HTTP request.
    - Writes one replay flow to the project SQLite database.
    - Prints outcome to stdout.
    - Exits with code 1 on hard errors (no active project, flow/endpoint not found).
"""

import argparse
import asyncio
import sys
import uuid

from talos.projects.manager import ProjectManager
from talos.replay import db as replay_db
from talos.replay.engine import replay_endpoint, replay_flow
from talos.scheduler import db as sched_db
from talos.scheduler.job import PRIORITY_MANUAL, REPLAY_ENDPOINT, REPLAY_FLOW


# ------------------------------------------------------------------ #
# CLI entry point                                                      #
# ------------------------------------------------------------------ #

def run_replay_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse replay subcommand arguments and dispatch to the appropriate handler.
    Input:
        manager — ProjectManager instance carrying the projects root path.
        argv    — argument list after 'replay' (e.g. ['flow', '<id>']).
    Side effects:
        Delegates to cmd_replay_flow or cmd_replay_endpoint.
        Prints usage and exits 1 for unrecognised subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="talos replay",
        description="Replay stored HTTP flows against the target.",
    )
    sub = parser.add_subparsers(dest="replay_cmd", metavar="<command>")
    sub.required = True

    # talos replay flow <flow_id>
    p_flow = sub.add_parser("flow", help="Replay a specific flow by its UUID.")
    p_flow.add_argument("flow_id", help="UUID of the flow to replay.")
    p_flow.add_argument(
        "--right-now",
        action="store_true",
        help="Run the replay immediately instead of enqueuing it (debug/manual override).",
    )

    # talos replay endpoint <endpoint_id>
    p_ep = sub.add_parser(
        "endpoint",
        help="Replay the best qualifying flow for an endpoint.",
    )
    p_ep.add_argument("endpoint_id", help="UUID of the endpoint to replay.")
    p_ep.add_argument(
        "--right-now",
        action="store_true",
        help="Run the replay immediately instead of enqueuing it (debug/manual override).",
    )

    args = parser.parse_args(argv)

    project = manager.active()
    if project is None:
        print(
            "Error: No active project. Run 'talos project open <id>' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.replay_cmd == "flow":
        cmd_replay_flow(project, args)
    elif args.replay_cmd == "endpoint":
        cmd_replay_endpoint(project, args)


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def cmd_replay_flow(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Replay a specific flow by its UUID.
        By default enqueues the job for the scheduler.  With --right-now the
        replay is executed immediately in-process.
    Input:
        project — active Project instance.
        args    — parsed args with: flow_id (str), right_now (bool).
    Side effects:
        --right-now: Sends HTTP request; stores result; prints outcome to stdout.
        default: Inserts one scheduler job; prints job ID to stdout.
        Exits 1 if the flow is not found (--right-now only).
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    project_id = project.id    # type: ignore[attr-defined]
    flow_id = args.flow_id

    if not args.right_now:
        job_id = str(uuid.uuid4())
        sched_db.enqueue_job(
            db_path=db_path,
            job_id=job_id,
            job_type=REPLAY_FLOW,
            project_id=project_id,
            flow_id=flow_id,
            priority=PRIORITY_MANUAL,
        )
        print(f"Job enqueued: {job_id}")
        return

    print(f"Replaying flow {flow_id[:8]}…")
    outcome = asyncio.run(
        replay_flow(flow_id, db_path, project_id,
                    source="manual_replay", replay_reason="testing")
    )

    if outcome.failure_reason == "flow_not_found":
        print(f"Error: Flow '{flow_id}' not found.", file=sys.stderr)
        sys.exit(1)

    if outcome.failure_reason == "endpoint_annotated_logout":
        print(
            f"Error: Flow '{flow_id}' belongs to a logout endpoint — replay blocked.",
            file=sys.stderr,
        )
        sys.exit(1)

    _print_outcome(outcome)


def cmd_replay_endpoint(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Replay the best qualifying flow for an endpoint.
        By default enqueues the job for the scheduler.  With --right-now the
        replay is executed immediately in-process.
    Input:
        project — active Project instance.
        args    — parsed args with: endpoint_id (str), right_now (bool).
    Side effects:
        --right-now: Sends HTTP request; stores result; prints outcome to stdout.
        default: Inserts one scheduler job; prints job ID to stdout.
        Exits 1 if the endpoint is not found.
    """
    db_path = project.db_path   # type: ignore[attr-defined]
    project_id = project.id     # type: ignore[attr-defined]
    endpoint_id = args.endpoint_id

    # Validate the endpoint exists before doing anything.
    endpoint = replay_db.get_endpoint_by_id(db_path, endpoint_id)
    if endpoint is None:
        print(f"Error: Endpoint '{endpoint_id}' not found.", file=sys.stderr)
        sys.exit(1)

    if not args.right_now:
        job_id = str(uuid.uuid4())
        sched_db.enqueue_job(
            db_path=db_path,
            job_id=job_id,
            job_type=REPLAY_ENDPOINT,
            project_id=project_id,
            endpoint_id=endpoint_id,
            priority=PRIORITY_MANUAL,
        )
        print(f"Job enqueued: {job_id}")
        return

    ep_label = (
        f"{endpoint['method']} {endpoint['host']}{endpoint['normalized_path']}"
    )
    print(f"Replaying endpoint {ep_label} …")
    outcome = asyncio.run(
        replay_endpoint(endpoint_id, db_path, project_id,
                        source="manual_replay", replay_reason="testing")
    )

    if outcome.failure_reason == "no_qualifying_flow":
        print(
            f"Error: Endpoint '{endpoint_id}' has no 200 OK proxy_capture flow "
            "to replay.",
            file=sys.stderr,
        )
        sys.exit(1)

    if outcome.failure_reason == "endpoint_annotated_logout":
        print(
            f"Error: Endpoint '{endpoint_id}' is tagged logout — replay blocked.",
            file=sys.stderr,
        )
        sys.exit(1)

    if outcome.failure_reason == "endpoint_annotated_dangerous":
        print(
            f"Error: Endpoint '{endpoint_id}' is tagged dangerous — "
            "blocked in automated replay. Use 'talos replay flow <id>' to override.",
            file=sys.stderr,
        )
        sys.exit(1)

    _print_outcome(outcome)


# ------------------------------------------------------------------ #
# Output formatting                                                    #
# ------------------------------------------------------------------ #

def _print_outcome(outcome: object) -> None:
    """
    Purpose:
        Print a human-readable summary of a ReplayOutcome to stdout.
    Input:   outcome — ReplayOutcome instance.
    Side effects: Writes to stdout.
    """
    from talos.replay.engine import ReplayOutcome  # local import avoids circularity

    assert isinstance(outcome, ReplayOutcome)

    if outcome.success:
        print(
            f"  original : {outcome.original_flow_id}\n"
            f"  replayed : {outcome.replayed_flow_id}\n"
            f"  status   : {outcome.status_code}\n"
            f"  verdict  : {outcome.verdict}\n"
            f"  result   : OK"
        )
    else:
        print(
            f"  original : {outcome.original_flow_id}\n"
            f"  replayed : {outcome.replayed_flow_id or '—'}\n"
            f"  status   : {outcome.status_code or '—'}\n"
            f"  verdict  : {outcome.verdict or '—'}\n"
            f"  result   : FAILED — {outcome.failure_reason}"
        )
