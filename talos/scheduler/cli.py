"""
Module: talos.scheduler.cli

Purpose:
    Command-line interface for the replay scheduler.
    Entry points:
        talos scheduler status                              — show queue depth by status + metrics
        talos scheduler config [--min-delay N] [--max-delay N] [--max-queue-size N]
        talos scheduler enqueue flow <flow_id>              — queue a flow replay job
        talos scheduler enqueue endpoint <endpoint_id>      — queue an endpoint replay/auth job
        talos scheduler jobs list [--status] [--type] [--limit]
        talos scheduler jobs show <job_id>
        talos scheduler cancel <job_id>                     — cancel one pending/paused job
        talos scheduler prune --status <done|failed|…>      — delete terminal history
        talos scheduler clear                               — remove all pending jobs
        talos scheduler pause                               — pause execution (all pending → paused)
        talos scheduler resume                              — validate sessions and resume execution

    Process lifecycle (standalone daemon, independent of the proxy)::

        talos scheduler start
        talos scheduler stop
        talos scheduler status   — process runtime + queue metrics

    Queue/control commands require a bound project. ``stop`` does not.


Dependencies: argparse, json, sys, uuid
              talos.cli_output, talos.projects.manager, talos.scheduler.db,
              talos.scheduler.job
Data flow:
    CLI args → bound project → scheduler DB operations → stdout
Side effects:
    - config: writes to scheduler_config table; reads back and displays.
    - enqueue: inserts one row into scheduler_jobs (with dedup + overflow checks).
    - jobs list/show: read-only inventory / detail.
    - cancel: marks one pending/paused job cancelled.
    - prune: deletes terminal-status history for one status.
    - clear: deletes pending rows from scheduler_jobs.
    - status: read-only display.
    - pause: sets scheduler state to PAUSED and marks all pending jobs paused.
    - resume: validates sessions, resumes paused jobs, sets state to RUNNING.
"""
from talos.cli_output import (
    add_force_argument,
    add_format_argument,
    cli_error,
    cli_success,
    cli_warning,
    cli_json,
    cli_usage_error,
    cli_precondition_error,
    confirm_or_exit,
    wants_json,
)

import argparse
import json
import sys
import uuid

from talos.projects.manager import ProjectManager
from talos.scheduler import db as sched_db
from talos.scheduler.db import (
    CANCELLABLE_STATUSES,
    PRUNEABLE_STATUSES,
    SCHED_STATE_RUNNING,
    SCHED_STATE_PAUSED,
    SCHED_STATE_WAITING_FOR_SESSION,
)
from talos.scheduler.job import (
    AUTH_TEST,
    JOB_TYPES,
    PRIORITY_AUTO,
    PRIORITY_MANUAL,
    REPLAY_ENDPOINT,
    REPLAY_FLOW,
    STATUS_CANCELLED,
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_PAUSED,
    STATUS_PENDING,
    STATUS_RUNNING,
    STATUS_SKIPPED,
)


# All lifecycle statuses for filters and status display.
_ALL_JOB_STATUSES: tuple[str, ...] = (
    STATUS_PENDING,
    STATUS_RUNNING,
    STATUS_PAUSED,
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_SKIPPED,
    STATUS_CANCELLED,
)

_DEFAULT_JOBS_LIMIT: int = 50
_MAX_JOBS_LIMIT: int = 1000


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

    # talos scheduler start / stop (process lifecycle)
    sub.add_parser(
        "start",
        help="Start the managed scheduler process for the bound project.",
    )
    sub.add_parser(
        "stop",
        help="Gracefully stop the managed scheduler process.",
    )

    # talos scheduler status — process runtime + queue metrics
    p_status = sub.add_parser(
        "status",
        help="Show scheduler process runtime and queue depth / metrics.",
    )
    add_format_argument(p_status)

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
    add_force_argument(
        p_eq_flow,
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
    add_force_argument(
        p_eq_ep,
        help="Bypass the overflow confirmation prompt and add the job unconditionally.",
    )

    # talos scheduler jobs list|show
    p_jobs = sub.add_parser(
        "jobs",
        help="List or inspect individual scheduler jobs.",
    )
    jobs_sub = p_jobs.add_subparsers(dest="jobs_cmd", metavar="<action>")
    jobs_sub.required = True

    p_jobs_list = jobs_sub.add_parser(
        "list",
        help="List jobs with optional status/type filters.",
    )
    p_jobs_list.add_argument(
        "--status",
        choices=list(_ALL_JOB_STATUSES),
        default=None,
        metavar="STATUS",
        help=(
            "Filter by status: pending, running, paused, done, failed, "
            "skipped, cancelled."
        ),
    )
    p_jobs_list.add_argument(
        "--type",
        dest="filter_type",
        default=None,
        metavar="TYPE",
        help=(
            "Filter by job type (exact, e.g. bac_session_swap) or family prefix "
            "(replay, bac, iv, unauth_attack)."
        ),
    )
    p_jobs_list.add_argument(
        "--limit",
        type=int,
        default=_DEFAULT_JOBS_LIMIT,
        metavar="N",
        help=f"Maximum rows to show (default {_DEFAULT_JOBS_LIMIT}, max {_MAX_JOBS_LIMIT}).",
    )
    add_format_argument(p_jobs_list)

    p_jobs_show = jobs_sub.add_parser(
        "show",
        help="Show full detail for one job (UUID or unique prefix).",
    )
    p_jobs_show.add_argument(
        "job_id",
        help="Job UUID or unique prefix.",
    )
    add_format_argument(p_jobs_show)

    # talos scheduler cancel <job_id>
    p_cancel = sub.add_parser(
        "cancel",
        help="Cancel one pending or paused job by UUID (or unique prefix).",
    )
    p_cancel.add_argument(
        "job_id",
        help="Job UUID or unique prefix.",
    )

    # talos scheduler prune --status …
    p_prune = sub.add_parser(
        "prune",
        help="Delete terminal job history for one status (done/failed/skipped/cancelled).",
    )
    p_prune.add_argument(
        "--status",
        required=True,
        choices=sorted(PRUNEABLE_STATUSES),
        metavar="STATUS",
        help="Terminal status to delete: done, failed, skipped, or cancelled.",
    )
    add_force_argument(p_prune)

    # talos scheduler clear
    p_clear = sub.add_parser(
        "clear",
        help="Remove all pending jobs from the queue (asks for confirmation).",
    )
    add_force_argument(p_clear)

    # talos scheduler pause
    sub.add_parser(
        "pause",
        help=(
            "Pause scheduler execution.  All pending jobs are moved to 'paused' "
            "state and no new jobs are executed until 'talos scheduler resume' is run."
        ),
    )

    # talos scheduler resume
    sub.add_parser(
        "resume",
        help=(
            "Validate active sessions and resume execution.  Paused jobs are "
            "returned to 'pending' and the scheduler loop restarts."
        ),
    )

    args = parser.parse_args(argv)

    # Process stop does not require an active project.
    if args.sched_cmd == "stop":
        cmd_process_stop()
        return
    if args.sched_cmd == "start":
        project = manager.active()
        if project is None:
            cli_precondition_error(
                "No active project. Run 'talos project open <id>', "
                "or pass --project <id> / set TALOS_PROJECT."
            )
        cmd_process_start(project)
        return

    project = manager.active()
    if project is None:
        cli_precondition_error("No active project. Run 'talos project open <id>', or pass --project <id> / set TALOS_PROJECT.")

    if args.sched_cmd == "status":
        cmd_status(project, args)
    elif args.sched_cmd == "config":
        cmd_config(project, args)
    elif args.sched_cmd == "enqueue":
        cmd_enqueue(project, args)
    elif args.sched_cmd == "jobs":
        if args.jobs_cmd == "list":
            cmd_jobs_list(project, args)
        elif args.jobs_cmd == "show":
            cmd_jobs_show(project, args)
        else:
            cli_usage_error(f"Unknown jobs action '{args.jobs_cmd}'.")
    elif args.sched_cmd == "cancel":
        cmd_cancel(project, args)
    elif args.sched_cmd == "prune":
        cmd_prune(project, args)
    elif args.sched_cmd == "clear":
        cmd_clear(project, args)
    elif args.sched_cmd == "pause":
        cmd_pause(project)
    elif args.sched_cmd == "resume":
        cmd_resume(project)


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

def _resolve_job(project: object, job_id: str):
    """
    Purpose:
        Resolve a job by full UUID or unique prefix; exit on not found / ambiguous.
    Input:
        project — Active Project instance.
        job_id  — UUID or prefix from the CLI.
    Output:
        ReplayJob on success.
    Side effects:
        Exits 1 (not found) or 2 (ambiguous prefix).
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    project_id = project.id    # type: ignore[attr-defined]
    try:
        job = sched_db.get_job(db_path, project_id, job_id)
    except ValueError as exc:
        cli_usage_error(str(exc))
    if job is None:
        cli_error(f"Job '{job_id}' not found.")
    return job


def _job_to_dict(job) -> dict:
    """
    Purpose:
        Serialize a ReplayJob for JSON output (no Path objects).
    Input:
        job — ReplayJob instance.
    Output:
        Plain dict suitable for cli_json.
    Side effects: None.
    """
    meta_obj = None
    if job.meta:
        try:
            meta_obj = json.loads(job.meta)
        except (ValueError, TypeError):
            meta_obj = job.meta
    return {
        "job_id": job.job_id,
        "status": job.status,
        "job_type": job.job_type,
        "priority": job.priority,
        "endpoint_id": job.endpoint_id,
        "flow_id": job.flow_id,
        "created_at": job.created_at,
        "scheduled_at": job.scheduled_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "failure_reason": job.failure_reason,
        "replayed_flow_id": job.replayed_flow_id,
        "verdict": job.verdict,
        "meta": meta_obj,
        "project_id": job.project_id,
    }


def _format_created(iso: str | None) -> str:
    """Shorten ISO timestamps for table columns (date + time to minutes)."""
    if not iso:
        return "—"
    # 2024-01-15T12:34:56.789012+00:00 → 2024-01-15 12:34
    cleaned = iso.replace("T", " ")
    if len(cleaned) >= 16:
        return cleaned[:16]
    return cleaned


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def cmd_status(project: object, args: argparse.Namespace | None = None) -> None:
    """
    Purpose:
        Print managed process runtime, scheduler DB state, queue depth,
        pending jobs, metrics, and config.
    Input:
        project — Active Project instance.
        args    — optional namespace with output_format (CLI-014).
    Side effects:
        Prints to stdout (table or JSON).
    """
    from talos.config import TalosConfig
    from talos.scheduler.runtime import SchedulerRuntimeManager

    db_path = project.db_path   # type: ignore[attr-defined]
    project_id = project.id     # type: ignore[attr-defined]

    proc = SchedulerRuntimeManager(data_dir=TalosConfig.from_env().data_dir).status()

    # Scheduler execution state (DB).
    sched_state = sched_db.get_scheduler_state(db_path)
    state_label = {
        SCHED_STATE_RUNNING: "Running",
        SCHED_STATE_PAUSED: "Paused",
        SCHED_STATE_WAITING_FOR_SESSION: "Waiting for session",
    }.get(sched_state, sched_state)

    counts = sched_db.get_queue_status(db_path)
    total = sum(counts.values())
    pending_jobs = sched_db.list_pending_jobs(db_path, project_id)
    metrics = sched_db.get_queue_metrics(db_path)
    cfg = sched_db.get_scheduler_config(db_path)

    if wants_json(args):
        cli_json({
            "process": proc.to_dict(),
            "state": sched_state,
            "state_label": state_label,
            "queue": {
                "total": total,
                "by_status": dict(counts),
            },
            "pending_jobs": [
                {
                    "job_id": job.job_id,
                    "job_type": job.job_type,
                    "flow_id": job.flow_id,
                    "endpoint_id": job.endpoint_id,
                    "priority": job.priority,
                    "created_at": job.created_at,
                }
                for job in pending_jobs
            ],
            "metrics": metrics,
            "config": cfg,
        })
        return

    print(f"Process state    : {proc.state.value}")
    print(f"  PID            : {proc.pid if proc.pid is not None else '-'}")
    print(f"  Project        : {proc.project_id or '-'}")
    if proc.validation_deferred:
        print("  Validation     : deferred (lifecycle lock busy)")
    print(f"  Log            : {proc.log_path or '-'}")
    print(f"Queue/DB state   : {state_label}\n")

    if not counts:
        print("Scheduler queue is empty.")
    else:
        print(f"Scheduler queue  (total: {total})\n")
        for status_label in _ALL_JOB_STATUSES:
            n = counts.get(status_label, 0)
            print(f"  {status_label:<20}  {n}")

    if pending_jobs:
        print("\nPending jobs (execution order):\n")
        for job in pending_jobs:
            target = job.flow_id or job.endpoint_id or "(unknown)"
            print(
                f"  {job.job_id[:8]}  {job.job_type:<20}  "
                f"target={target[:8]}  priority={job.priority}  "
                f"queued={job.created_at}"
            )

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

    print(
        f"\nScheduler config:\n"
        f"  min-delay      : {cfg['min_delay']}s\n"
        f"  max-delay      : {cfg['max_delay']}s\n"
        f"  max-queue-size : {cfg['max_queue_size']}"
    )
    print(
        "\nTip: use 'talos scheduler jobs list' for full inventory, "
        "'jobs show <id>' for detail."
    )


def cmd_jobs_list(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        List scheduler jobs with optional status / type / limit filters.
    Input:
        project — Active Project instance.
        args    — status, filter_type, limit, output_format.
    Side effects:
        Prints table or JSON to stdout.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    project_id = project.id    # type: ignore[attr-defined]

    limit = args.limit
    if limit < 1:
        cli_usage_error("--limit must be at least 1.")
    if limit > _MAX_JOBS_LIMIT:
        cli_usage_error(f"--limit must be at most {_MAX_JOBS_LIMIT}.")

    filter_type = args.filter_type
    if filter_type is not None:
        filter_type = filter_type.strip()
        if not filter_type:
            cli_usage_error("--type must not be empty.")
        # Soft validation: warn only if it cannot match any known type family.
        known = set(JOB_TYPES)
        exact_ok = filter_type in known
        family_ok = any(
            t == filter_type or t.startswith(filter_type + "_")
            for t in known
        )
        if not exact_ok and not family_ok:
            cli_warning(
                f"Unknown job type '{filter_type}'. "
                f"Known types include: {', '.join(JOB_TYPES[:6])}, …"
            )

    jobs = sched_db.list_jobs(
        db_path,
        project_id,
        status=args.status,
        job_type=filter_type,
        limit=limit,
    )

    if wants_json(args):
        cli_json([_job_to_dict(j) for j in jobs])
        return

    if not jobs:
        filters = []
        if args.status:
            filters.append(f"status={args.status}")
        if filter_type:
            filters.append(f"type={filter_type}")
        suffix = f" ({', '.join(filters)})" if filters else ""
        print(f"No scheduler jobs{suffix}.")
        return

    header = (
        f"{'UUID':36}  {'Status':10}  {'Type':22}  {'Created':16}"
    )
    print(header)
    print("-" * len(header))
    for job in jobs:
        print(
            f"{job.job_id:36}  {job.status:10}  {job.job_type:22}  "
            f"{_format_created(job.created_at):16}"
        )


def cmd_jobs_show(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Display full detail for one scheduler job.
    Input:
        project — Active Project instance.
        args    — job_id, output_format.
    Side effects:
        Prints labeled block or JSON; exits 1 if not found.
    """
    job = _resolve_job(project, args.job_id)

    if wants_json(args):
        cli_json(_job_to_dict(job))
        return

    meta_display = "—"
    if job.meta:
        try:
            meta_display = json.dumps(json.loads(job.meta), indent=2, ensure_ascii=False)
        except (ValueError, TypeError):
            meta_display = job.meta

    print(f"Job: {job.job_id}")
    print(f"  Status:          {job.status}")
    print(f"  Type:            {job.job_type}")
    print(f"  Priority:        {job.priority}")
    print(f"  Endpoint:        {job.endpoint_id or '—'}")
    print(f"  Flow:            {job.flow_id or '—'}")
    print(f"  Created:         {job.created_at}")
    print(f"  Scheduled:       {job.scheduled_at or '—'}")
    print(f"  Started:         {job.started_at or '—'}")
    print(f"  Finished:        {job.finished_at or '—'}")
    print(f"  Failure reason:  {job.failure_reason or '—'}")
    print(f"  Replayed flow:   {job.replayed_flow_id or '—'}")
    print(f"  Verdict:         {job.verdict or '—'}")
    # Retry count is not tracked in the current schema; surface explicitly.
    print(f"  Retry count:     — (not tracked)")
    print(f"  Parameters:")
    if meta_display == "—":
        print("    —")
    else:
        for line in meta_display.splitlines():
            print(f"    {line}")


def cmd_cancel(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Cancel one pending or paused job (status → cancelled).
        Running jobs cannot be cancelled mid-execution; terminal jobs are
        already finished — use prune to remove history.
    Input:
        project — Active Project instance.
        args    — job_id.
    Side effects:
        May update one scheduler_jobs row; prints result; exits 1 on failure.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    job = _resolve_job(project, args.job_id)

    if job.status not in CANCELLABLE_STATUSES:
        if job.status == STATUS_RUNNING:
            # Intruder: request cooperative cancel via session control_flag.
            if job.job_type == "intruder_session":
                import json as _json
                from talos.intruder import db as intruder_db

                meta = {}
                if job.meta:
                    try:
                        meta = _json.loads(job.meta) if isinstance(job.meta, str) else dict(job.meta)
                    except Exception:  # noqa: BLE001
                        meta = {}
                session_id = meta.get("session_id")
                if session_id:
                    intruder_db.set_control_flag(db_path, session_id, "cancel")
                    cli_success(
                        "Cancel requested for running Intruder session "
                        "(cooperative; job will finish current attempt).",
                        {
                            "Job": job.job_id,
                            "Session": session_id,
                            "Type": job.job_type,
                            "Control flag": "cancel",
                        },
                    )
                    return
            cli_error(
                f"Job '{job.job_id}' is running and cannot be cancelled mid-execution. "
                "Pause the scheduler if you need to stop the queue, or wait for "
                "this job to finish."
            )
        if job.status in PRUNEABLE_STATUSES:
            cli_error(
                f"Job '{job.job_id}' has status '{job.status}' and cannot be cancelled. "
                "Only pending or paused jobs can be cancelled. "
                f"Use 'talos scheduler prune --status {job.status}' to remove history."
            )
        cli_error(
            f"Job '{job.job_id}' has status '{job.status}' and cannot be cancelled. "
            "Only pending or paused jobs can be cancelled."
        )

    previous = sched_db.cancel_job(db_path, job.job_id)
    if previous is None:
        # Race: status changed between resolve and cancel.
        cli_error(
            f"Could not cancel job '{job.job_id}' — it is no longer pending or paused."
        )

    cli_success(
        "Cancelled.",
        {
            "Job": job.job_id,
            "Previous status": previous,
            "Type": job.job_type,
        },
    )


def cmd_prune(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Delete terminal job history for one status bucket.
        Requires --status (done|failed|skipped|cancelled) and confirmation
        unless --force is passed (CLI-015).
    Input:
        project — Active Project instance.
        args    — status, force.
    Side effects:
        May delete rows from scheduler_jobs; prints count.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    status: str = args.status

    if status not in PRUNEABLE_STATUSES:
        allowed = ", ".join(sorted(PRUNEABLE_STATUSES))
        cli_usage_error(f"--status must be one of: {allowed}.")

    count = sched_db.count_jobs_by_status(db_path, status)
    if count == 0:
        print(f"No jobs with status '{status}' to prune.")
        return

    if not args.force:
        print(
            f"This will permanently delete {count} job(s) with status '{status}'.\n"
            "Active queue jobs (pending/running/paused) are not affected."
        )
        confirm_or_exit("Confirm prune?")

    removed = sched_db.prune_jobs(db_path, status)
    print(f"Pruned {removed} job(s) with status '{status}'.")


def cmd_pause(project: object) -> None:
    """
    Purpose:
        Pause the scheduler.  All pending jobs are moved to 'paused' state and
        no new jobs are executed.  Useful when the tester wants to update
        session artifacts proactively before expiry.
    Input:   project — Active Project instance.
    Side effects:
        Sets scheduler state to PAUSED; marks all pending jobs paused.
        Prints confirmation to stdout.
    """
    db_path = project.db_path  # type: ignore[attr-defined]

    paused = sched_db.pause_pending_jobs(db_path)
    sched_db.set_scheduler_state(db_path, SCHED_STATE_PAUSED, reason="manual pause")

    print("Scheduler paused.")
    print(f"  Pending jobs paused : {paused}")
    print("\nTo resume, run:")
    print("  talos scheduler resume")


def _roles_requiring_session_validation(db_path, project_id: str) -> set:
    """
    Purpose:
        Determine which roles actually need a valid MANUAL session before the
        scheduler can safely resume.  Only BAC job types consult
        session_health/MANUAL-provider gating during execution (see
        ReplayScheduler._execute_bac_job) — replay, auth-bypass, input-
        validation, and unauth-attack jobs never require role authentication
        to run.  In particular, unauth attacks are explicitly unauthenticated
        by design, so a pending/paused unauth_attack job must never block
        (or be blocked by) session validation for any role.
    Input:
        db_path    — Path to the project's talos.db.
        project_id — Active project identifier.
    Output:
        Set of role_id strings referenced by any PENDING or PAUSED BAC job's
        meta.attacker_role_id.
    Side effects: None (read-only).
    """
    from talos.scheduler.job import BAC_JOB_TYPES

    required: set = set()
    for status in (STATUS_PENDING, STATUS_PAUSED):
        for job in sched_db.list_jobs_by_status(db_path, project_id, status, limit=10_000):
            if job.job_type not in BAC_JOB_TYPES:
                continue
            if not job.meta:
                continue
            try:
                meta = json.loads(job.meta)
            except (ValueError, TypeError):
                continue
            role_id = meta.get("attacker_role_id")
            if role_id:
                required.add(role_id)
    return required


def cmd_resume(project: object) -> None:
    """
    Purpose:
        Validate active sessions and resume scheduler execution.
        Paused jobs are returned to 'pending' state; the scheduler loop
        restarts from the next DB poll cycle.

        Only roles actually referenced by a pending/paused BAC job are
        validated — BAC is the only attack type whose execution consults
        session_health/MANUAL-provider gating.  Unauthenticated-execution
        (unauth) jobs and any other queued job types never require a role
        session, so they can never block (or be blocked by) resume.

        For each role that needs validation and uses the MANUAL provider,
        the stored session is checked.  If any required session is expired
        or absent, resume is rejected with a clear error message directing
        the tester to 'talos auth-config set-session'.
    Input:   project — Active Project instance.
    Side effects:
        Validates sessions; resumes paused jobs; sets state to RUNNING.
        Prints validation results to stdout.
        Exits 1 if any required session is invalid.
    """
    import sqlite3 as _sqlite3
    from talos.projects.auth_provider import (
        get_provider, get_session_display_state,
        PROVIDER_MANUAL, SESSION_READY, SESSION_EXPIRING,
    )

    db_path = project.db_path  # type: ignore[attr-defined]
    project_id = project.id    # type: ignore[attr-defined]

    required_role_ids = _roles_requiring_session_validation(db_path, project_id)

    print("Validating sessions...\n")

    if not required_role_ids:
        print("  No pending/paused BAC jobs reference a role — nothing to validate.")
        print("  (Unauthenticated-execution and other job types never require a role session.)")
        resumed = sched_db.resume_paused_jobs(db_path)
        sched_db.set_scheduler_state(db_path, SCHED_STATE_RUNNING, reason=None)
        print(f"\nScheduler resumed.")
        print(f"  Jobs returned to pending : {resumed}")
        print(
            "The scheduler process executes jobs when running "
            "(`talos scheduler start` / `talos scheduler status`)."
        )
        _warn_paused_intruder_sessions(db_path, project_id)
        return

    # Only load role names for the roles that actually need validation.
    with _sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = _sqlite3.Row
        placeholders = ",".join("?" for _ in required_role_ids)
        roles = conn.execute(
            f"SELECT r.id, r.name FROM roles r WHERE r.id IN ({placeholders})",
            tuple(required_role_ids),
        ).fetchall()

    invalid_roles: list[str] = []

    for role_row in roles:
        role_id = role_row["id"]
        role_name = role_row["name"]
        provider = get_provider(db_path, role_id)

        if provider != PROVIDER_MANUAL:
            continue

        state = get_session_display_state(db_path, role_id)
        print(f"  {role_name} ({role_id[:8]})")
        print(f"    Provider : MANUAL")
        print(f"    Session  : {state}")

        if state not in (SESSION_READY, SESSION_EXPIRING):
            invalid_roles.append(f"{role_name} ({role_id[:8]})")

    if invalid_roles:
        print("\nResume blocked — the following roles have invalid sessions:")
        for label in invalid_roles:
            print(f"  - {label}")
        print(
            "\nRun 'talos auth-config set-session <role>' to provide "
            "new credentials, then try again."
        )
        sys.exit(1)

    resumed = sched_db.resume_paused_jobs(db_path)
    sched_db.set_scheduler_state(db_path, SCHED_STATE_RUNNING, reason=None)

    print(f"\nScheduler resumed.")
    print(f"  Jobs returned to pending : {resumed}")
    print(
        "The scheduler process executes jobs when running "
        "(`talos scheduler start` / `talos scheduler status`)."
    )


    _warn_paused_intruder_sessions(db_path, project_id)

def cmd_process_start(project: object) -> None:
    """
    Purpose:
        Start the managed standalone scheduler process for the bound project.
    """
    from talos.config import TalosConfig
    from talos.scheduler.runtime import (
        SchedulerAlreadyRunning,
        SchedulerRuntimeManager,
        SchedulerStartError,
    )

    config = TalosConfig.from_env()
    runtime = SchedulerRuntimeManager(data_dir=config.data_dir)
    try:
        info = runtime.start(project=project)  # type: ignore[arg-type]
    except SchedulerAlreadyRunning as exc:
        cli_error(str(exc))
    except SchedulerStartError as exc:
        cli_error(str(exc))
    print(f"Scheduler started (pid={info.pid})")
    print(f"  Project : {info.project_id}")
    print(f"  State   : {info.state.value}")
    print(f"  Log     : {info.log_path}")


def cmd_process_stop() -> None:
    """
    Purpose:
        Gracefully stop the managed scheduler process.
    """
    from talos.config import TalosConfig
    from talos.scheduler.runtime import SchedulerRuntimeManager

    config = TalosConfig.from_env()
    info = SchedulerRuntimeManager(data_dir=config.data_dir).stop()
    print(f"Scheduler stop complete (state={info.state.value}).")


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
            cli_usage_error("--min-delay must be greater than 0.")
        cfg["min_delay"] = args.min_delay
        updated = True
    if args.max_delay is not None:
        cfg["max_delay"] = args.max_delay
        updated = True
    if args.max_queue_size is not None:
        if args.max_queue_size < 1:
            cli_usage_error("--max-queue-size must be at least 1.")
        cfg["max_queue_size"] = args.max_queue_size
        updated = True

    if updated:
        min_d = cfg["min_delay"]
        max_d = cfg["max_delay"]
        if max_d < min_d:
            cli_usage_error(f"--max-delay ({max_d}) must be >= --min-delay ({min_d}).")
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
            "Use 'talos scheduler jobs list --status pending' to view queued jobs."
        )
        return

    # --- Overflow check ----------------------------------------------------
    # When the active queue is at or above the limit, inform the user with
    # full context and ask for confirmation.  --force bypasses this prompt.
    if not args.force:
        active = sched_db.count_active_jobs(db_path)
        if active >= max_queue_size:
            cli_warning(
                f"Queue is at capacity ({active}/{max_queue_size} active jobs).\n"
                f"\n"
                f"  Type     : {job_type}\n"
                f"  Target   : {target_label}\n"
                f"  Priority : {priority}\n"
                f"\n"
                "Adding more jobs at this point increases detection risk and may\n"
                "overload the target.  Run 'talos scheduler jobs list' to review\n"
                "what is already queued.\n"
                "\n"
                "Re-run with --force to add the job without this prompt."
            )
            confirm_or_exit("Proceed?")

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

    cli_success(
        "Enqueued.",
        {
            "Job": job.job_id,
            "Type": job.job_type,
            "Target": target_label,
            "Priority": job.priority,
        },
    )


def cmd_clear(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Remove all pending jobs from the queue.
        Running, done, failed, skipped, and cancelled jobs are never affected.
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
            "Running and completed jobs are not affected.\n"
            "To cancel a single job: talos scheduler cancel <job_id>\n"
            "To delete history:      talos scheduler prune --status done|failed"
        )
        confirm_or_exit("Confirm clear?")

    removed = sched_db.clear_pending_jobs(db_path)
    print(f"Cleared {removed} pending job(s) from the queue.")
