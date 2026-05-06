"""
Module: talos.scheduler.cli

Purpose:
    Command-line interface for the replay scheduler.
    Entry points:
        talos scheduler status                              — show queue depth by status + metrics
        talos scheduler config [--min-delay N] [--max-delay N] [--max-queue-size N]
        talos scheduler enqueue flow <flow_id>              — queue a flow replay job
        talos scheduler enqueue endpoint <endpoint_id>      — queue an endpoint replay/auth job
        talos scheduler clear                               — remove all pending jobs

    The scheduler itself is not user-started — it runs automatically as a daemon
    thread when the proxy starts.  This CLI manages its configuration and queue.

    All commands require an active project.

Dependencies: argparse, sys, uuid
              talos.projects.manager, talos.scheduler.db, talos.scheduler.job
Data flow:
    CLI args → active project → scheduler DB operations → stdout
Side effects:
    - config: writes to scheduler_config table; reads back and displays.
    - enqueue: inserts one row into scheduler_jobs (with dedup + overflow checks).
    - clear: deletes pending rows from scheduler_jobs.
    - status: read-only display.
"""

import argparse
import sys
import uuid

from talos.projects.manager import ProjectManager
from talos.scheduler import db as sched_db
from talos.scheduler.job import (
    AUTH_TEST,
    PRIORITY_AUTO,
    PRIORITY_MANUAL,
    REPLAY_ENDPOINT,
    REPLAY_FLOW,
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_RUNNING,
    STATUS_SKIPPED,
)


# ------------------------------------------------------------------ #
# CLI entry point                                                      #
# ------------------------------------------------------------------ #

def run_scheduler_cli(
    manager: ProjectManager,
    argv: list[str],
) -> None:
    """
    Purpose:
        Parse scheduler subcommand arguments and dispatch to the handler.
    Input:
        manager — ProjectManager instance.
        argv    — Argument list after 'scheduler'.
    Side effects:
        Delegates entirely to subcommand handlers.
    """
    parser = argparse.ArgumentParser(
        prog="talos scheduler",
        description="Control the replay scheduler.",
    )
    sub = parser.add_subparsers(dest="sched_cmd", metavar="<command>")
    sub.required = True

    # talos scheduler status
    sub.add_parser("status", help="Show queue depth by status and execution metrics.")

    # talos scheduler config
    p_config = sub.add_parser(
        "config",
        help="Read or update scheduler config (min-delay, max-delay, max-queue-size).",
    )
    p_config.add_argument(
        "--min-delay",
        type=float,
        metavar="SECONDS",
        help="Minimum seconds to wait between jobs.",
    )
    p_config.add_argument(
        "--max-delay",
        type=float,
        metavar="SECONDS",
        help="Maximum seconds to wait between jobs.",
    )
    p_config.add_argument(
        "--max-queue-size",
        type=int,
        metavar="N",
        help="Maximum active (pending + running) jobs allowed.",
    )

    # talos scheduler enqueue <target>
    p_enqueue = sub.add_parser("enqueue", help="Add a job to the scheduler queue.")
    enqueue_sub = p_enqueue.add_subparsers(dest="enqueue_target", metavar="<target>")
    enqueue_sub.required = True

    # talos scheduler enqueue flow <flow_id>
    p_eq_flow = enqueue_sub.add_parser(
        "flow",
        help="Queue an exact replay of a specific flow by UUID.",
    )
    p_eq_flow.add_argument("flow_id", help="UUID of the flow to replay.")
    p_eq_flow.add_argument(
        "--priority",
        type=int,
        default=PRIORITY_MANUAL,
        metavar="N",
        help=(
            f"Execution priority — higher runs first "
            f"(default: {PRIORITY_MANUAL} = manual; auto = {PRIORITY_AUTO})."
        ),
    )
    p_eq_flow.add_argument(
        "--force",
        action="store_true",
        help="Bypass the overflow confirmation prompt and add the job unconditionally.",
    )

    # talos scheduler enqueue endpoint <endpoint_id>
    p_eq_ep = enqueue_sub.add_parser(
        "endpoint",
        help="Queue a replay or auth-bypass test for an endpoint.",
    )
    p_eq_ep.add_argument("endpoint_id", help="UUID of the endpoint to target.")
    p_eq_ep.add_argument(
        "--type",
        dest="job_type",
        choices=["replay", "auth-test"],
        default="replay",
        help=(
            "Job type: 'replay' (exact replay) or 'auth-test' (auth-bypass test). "
            "Default: replay."
        ),
    )
    p_eq_ep.add_argument(
        "--priority",
        type=int,
        default=PRIORITY_MANUAL,
        metavar="N",
        help=(
            f"Execution priority — higher runs first "
            f"(default: {PRIORITY_MANUAL} = manual; auto = {PRIORITY_AUTO})."
        ),
    )
    p_eq_ep.add_argument(
        "--force",
        action="store_true",
        help="Bypass the overflow confirmation prompt and add the job unconditionally.",
    )

    # talos scheduler clear
    p_clear = sub.add_parser(
        "clear",
        help="Remove all pending jobs from the queue (asks for confirmation).",
    )
    p_clear.add_argument(
        "--force",
        action="store_true",
        help="Skip the confirmation prompt.",
    )

    args = parser.parse_args(argv)

    project = manager.active()
    if project is None:
        print(
            "Error: No active project. Run 'talos project open <id>' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.sched_cmd == "status":
        cmd_status(project)
    elif args.sched_cmd == "config":
        cmd_config(project, args)
    elif args.sched_cmd == "enqueue":
        cmd_enqueue(project, args)
    elif args.sched_cmd == "clear":
        cmd_clear(project, args)


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def cmd_status(project: object) -> None:
    """
    Purpose:
        Print the current queue depth by job status, pending job list, execution
        metrics, and current scheduler config.
    Input:   project — Active Project instance.
    Side effects:
        Prints to stdout.
    """
    db_path = project.db_path   # type: ignore[attr-defined]
    project_id = project.id     # type: ignore[attr-defined]

    counts = sched_db.get_queue_status(db_path)
    total = sum(counts.values())

    if not counts:
        print("Scheduler queue is empty.")
    else:
        print(f"Scheduler queue  (total: {total})\n")
        for status_label in (STATUS_PENDING, STATUS_RUNNING, STATUS_DONE, STATUS_FAILED, STATUS_SKIPPED):
            n = counts.get(status_label, 0)
            print(f"  {status_label:<10}  {n}")

    pending_jobs = sched_db.list_pending_jobs(db_path, project_id)
    if pending_jobs:
        print("\nPending jobs (execution order):\n")
        for job in pending_jobs:
            target = job.flow_id or job.endpoint_id or "(unknown)"
            print(
                f"  {job.job_id[:8]}  {job.job_type:<20}  "
                f"target={target[:8]}  priority={job.priority}  "
                f"queued={job.created_at}"
            )

    metrics = sched_db.get_queue_metrics(db_path)
    if metrics["total_jobs"]:
        print("\nExecution metrics:\n")
        avg = metrics["avg_execution_delay_s"]
        last = metrics["last_executed_at"]
        print(f"  jobs executed  : {metrics['total_jobs']}")
        if avg is not None:
            print(f"  avg delay      : {avg:.1f}s")
        else:
            print("  avg delay      : —")
        print(f"  last executed  : {last or '—'}")

    cfg = sched_db.get_scheduler_config(db_path)
    print(
        f"\nScheduler config:\n"
        f"  min-delay      : {cfg['min_delay']}s\n"
        f"  max-delay      : {cfg['max_delay']}s\n"
        f"  max-queue-size : {cfg['max_queue_size']}"
    )


def cmd_config(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Read or update the scheduler config.
        With no flags, display the current config.
        With flags, update the specified fields and display the result.
    Input:
        project — Active Project instance.
        args    — Parsed args: min_delay, max_delay, max_queue_size (all optional).
    Side effects:
        May write to scheduler_config table; prints current config to stdout.
        Exits 1 if the provided values are invalid.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    cfg = sched_db.get_scheduler_config(db_path)

    updated = False
    if args.min_delay is not None:
        if args.min_delay <= 0:
            print("Error: --min-delay must be greater than 0.", file=sys.stderr)
            sys.exit(1)
        cfg["min_delay"] = args.min_delay
        updated = True
    if args.max_delay is not None:
        cfg["max_delay"] = args.max_delay
        updated = True
    if args.max_queue_size is not None:
        if args.max_queue_size < 1:
            print("Error: --max-queue-size must be at least 1.", file=sys.stderr)
            sys.exit(1)
        cfg["max_queue_size"] = args.max_queue_size
        updated = True

    if updated:
        min_d = cfg["min_delay"]
        max_d = cfg["max_delay"]
        if max_d < min_d:
            print(
                f"Error: --max-delay ({max_d}) must be >= --min-delay ({min_d}).",
                file=sys.stderr,
            )
            sys.exit(1)
        sched_db.set_scheduler_config(
            db_path,
            min_delay=min_d,
            max_delay=max_d,
            max_queue_size=cfg["max_queue_size"],
        )
        print("Scheduler config updated.")

    cfg = sched_db.get_scheduler_config(db_path)
    print(
        f"  min-delay      : {cfg['min_delay']}s\n"
        f"  max-delay      : {cfg['max_delay']}s\n"
        f"  max-queue-size : {cfg['max_queue_size']}"
    )


def cmd_enqueue(
    project: object,
    args: argparse.Namespace,
) -> None:
    """
    Purpose:
        Add a single replay job to the scheduler queue.
        Performs two pre-insert checks:
            1. Dedup: abort if an identical pending job already exists.
            2. Overflow: warn with details and ask for confirmation when the
               active job count reaches max_queue_size (read from DB config).
    Input:
        project — Active Project instance.
        args    — Parsed args carrying enqueue_target and job fields.
    Side effects:
        May insert one row into scheduler_jobs.
        Prints confirmation, warning, or error to stdout.
        Exits 1 on unrecoverable error.
    """
    db_path = project.db_path   # type: ignore[attr-defined]
    project_id = project.id     # type: ignore[attr-defined]

    max_queue_size: int = sched_db.get_scheduler_config(db_path)["max_queue_size"]

    # Resolve job identity from the parsed subcommand.
    if args.enqueue_target == "flow":
        flow_id: str = args.flow_id
        endpoint_id = None
        job_type = REPLAY_FLOW
        target_label = f"flow {flow_id[:8]}"
    else:  # endpoint
        endpoint_id = args.endpoint_id
        flow_id = None
        job_type = AUTH_TEST if args.job_type == "auth-test" else REPLAY_ENDPOINT
        target_label = f"endpoint {endpoint_id[:8]}"

    priority: int = args.priority

    # --- Dedup check -------------------------------------------------------
    # Prevent identical pending jobs from accumulating before the scheduler
    # has consumed the first one.
    if sched_db.has_pending_duplicate(
        db_path, job_type, endpoint_id=endpoint_id, flow_id=flow_id
    ):
        print(
            f"Skipped: a pending {job_type} job for {target_label} "
            "already exists in the queue.\n"
            "Use 'talos scheduler status' to view queued jobs."
        )
        return

    # --- Overflow check ----------------------------------------------------
    # When the active queue is at or above the limit, inform the user with
    # full context and ask for confirmation.  --force bypasses this prompt.
    if not args.force:
        active = sched_db.count_active_jobs(db_path)
        if active >= max_queue_size:
            print(
                f"Warning: Queue is at capacity ({active}/{max_queue_size} active jobs).\n"
                f"\n"
                f"  Type     : {job_type}\n"
                f"  Target   : {target_label}\n"
                f"  Priority : {priority}\n"
                f"\n"
                "Adding more jobs at this point increases detection risk and may\n"
                "overload the target.  Run 'talos scheduler status' to review\n"
                "what is already queued.\n"
                "\n"
                "Re-run with --force to add the job without this prompt.\n",
            )
            confirm = input("Proceed? [y/N] ").strip().lower()
            if confirm != "y":
                print("Cancelled.")
                return

    # --- Insert ------------------------------------------------------------
    job_id = str(uuid.uuid4())
    job = sched_db.enqueue_job(
        db_path=db_path,
        job_id=job_id,
        job_type=job_type,
        project_id=project_id,
        endpoint_id=endpoint_id,
        flow_id=flow_id,
        priority=priority,
    )

    print(
        f"Enqueued:\n"
        f"  Job      : {job.job_id}\n"
        f"  Type     : {job.job_type}\n"
        f"  Target   : {target_label}\n"
        f"  Priority : {job.priority}"
    )


def cmd_clear(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Remove all pending jobs from the queue.
        Running, done, failed, and skipped jobs are never affected.
        Requires confirmation unless --force is passed.
    Input:
        project — Active Project instance.
        args    — Parsed args with force (bool).
    Side effects:
        Deletes rows from scheduler_jobs; prints count to stdout.
    """
    db_path = project.db_path  # type: ignore[attr-defined]

    # Count only pending — running jobs are mid-execution and out of scope.
    counts = sched_db.get_queue_status(db_path)
    pending_count = counts.get(STATUS_PENDING, 0)

    if pending_count == 0:
        print("Queue is already empty — no pending jobs to remove.")
        return

    if not args.force:
        print(
            f"This will remove {pending_count} pending job(s) from the queue.\n"
            "Running and completed jobs are not affected."
        )
        confirm = input("Confirm clear? [y/N] ").strip().lower()
        if confirm != "y":
            print("Cancelled.")
            return

    removed = sched_db.clear_pending_jobs(db_path)
    print(f"Cleared {removed} pending job(s) from the queue.")
