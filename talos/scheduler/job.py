"""
Module: talos.scheduler.job

Purpose:
    Defines the ReplayJob dataclass — the atomic unit of work for the replay
    scheduler — along with the job type, status, and priority constants that
    describe its full lifecycle.

Dependencies: dataclasses, pathlib, typing
Data flow:
    scheduler.db constructs ReplayJob from stored rows and returns them to
    ReplayScheduler for execution.
Side effects:
    None — purely a data definition module.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# ------------------------------------------------------------------ #
# Job type constants                                                   #
# ------------------------------------------------------------------ #

REPLAY_FLOW = "replay_flow"
"""Exact replay of a single, specified flow UUID."""

REPLAY_ENDPOINT = "replay_endpoint"
"""Exact replay using the best qualifying 200 OK flow for an endpoint."""

AUTH_TEST = "auth_test"
"""Auth-bypass test (Type 2 replay, auth stripped) for an endpoint."""

JOB_TYPES: tuple[str, ...] = (REPLAY_FLOW, REPLAY_ENDPOINT, AUTH_TEST)


# ------------------------------------------------------------------ #
# Status constants                                                     #
# ------------------------------------------------------------------ #

STATUS_PENDING = "pending"
"""Job is queued and waiting for the scheduler to pick it up."""

STATUS_RUNNING = "running"
"""Job is currently being executed by the scheduler."""

STATUS_DONE = "done"
"""Job completed — an HTTP response was received and stored."""

STATUS_FAILED = "failed"
"""Job execution failed due to a network or protocol error."""

STATUS_SKIPPED = "skipped"
"""Job was discarded before execution due to a safety annotation or missing data."""


# ------------------------------------------------------------------ #
# Priority levels                                                      #
# ------------------------------------------------------------------ #

PRIORITY_MANUAL = 100
"""Manual jobs enqueued directly by the user via CLI. Processed first."""

PRIORITY_AUTO = 10
"""Automatically enqueued jobs from future attack modules. Lower precedence."""


# ------------------------------------------------------------------ #
# Data type                                                            #
# ------------------------------------------------------------------ #

@dataclass
class ReplayJob:
    """
    Purpose:
        Immutable description of a single scheduled replay operation.
        Constructed on enqueue; read back from the DB when the scheduler
        picks it up for execution.

    Fields:
        job_id           — UUID identifying this job uniquely.
        endpoint_id      — UUID of the target endpoint; None for replay_flow jobs.
        flow_id          — UUID of the target flow; None for replay_endpoint/auth_test jobs.
        job_type         — REPLAY_FLOW | REPLAY_ENDPOINT | AUTH_TEST.
        priority         — Execution order. Higher runs first.
                           PRIORITY_MANUAL (100) > PRIORITY_AUTO (10).
        created_at       — UTC ISO-8601 string captured at enqueue time.
        db_path          — Absolute Path to the project's talos.db.
        project_id       — Project identifier; stamped on stored replay flows.
        status           — Current lifecycle stage; one of the STATUS_* constants.
        started_at       — UTC ISO-8601 when execution began; None until running.
        finished_at      — UTC ISO-8601 of completion; None until done/failed/skipped.
        failure_reason   — Human-readable error description; None on success/skipped.
        replayed_flow_id — UUID of the resulting replay flow stored by the engine;
                           None until the job reaches STATUS_DONE.
        verdict          — Diff or auth verdict from the engine outcome; None until done.
    """

    job_id: str
    endpoint_id: Optional[str]
    flow_id: Optional[str]
    job_type: str
    priority: int
    created_at: str
    db_path: Path
    project_id: str
    status: str = STATUS_PENDING
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    failure_reason: Optional[str] = None
    replayed_flow_id: Optional[str] = None
    verdict: Optional[str] = None
    scheduled_at: Optional[str] = None
