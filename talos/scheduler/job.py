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

# ------------------------------------------------------------------ #
# BAC job type constants                                               #
# ------------------------------------------------------------------ #

BAC_SESSION_SWAP = "bac_session_swap"
"""Direct session swap: replay target-role flow with attacker-role token."""

BAC_METHOD_FUZZ = "bac_method_fuzz"
"""HTTP Method Manipulation: change verb or inject X-HTTP-Method-Override."""

BAC_CONTENT_TYPE = "bac_content_type"
"""Content-Type Confusion: change request Content-Type to bypass parsers."""

BAC_URL_FUZZ = "bac_url_fuzz"
"""URL Manipulation: trailing slash, double slash, dot segments, encoding, case."""

BAC_HEADER_INJECT = "bac_header_inject"
"""Header Manipulation: inject X-Original-URL, X-Forwarded-For, etc."""

BAC_HOST_FUZZ = "bac_host_fuzz"
"""Host Header Changes: replace Host with example.com, localhost, or 127.0.0.1."""

BAC_ROLE_INJECT = "bac_role_inject"
"""Role Parameter Injection: inject isAdmin=true, role=admin, etc."""

BAC_JOB_TYPES: tuple[str, ...] = (
    BAC_SESSION_SWAP,
    BAC_METHOD_FUZZ,
    BAC_CONTENT_TYPE,
    BAC_URL_FUZZ,
    BAC_HEADER_INJECT,
    BAC_HOST_FUZZ,
    BAC_ROLE_INJECT,
)

# ------------------------------------------------------------------ #
# Input Validation job type constants                                  #
# ------------------------------------------------------------------ #

IV_BASELINE = "iv_baseline"
"""Phase 1 — Capture baseline response before any mutation."""

IV_IDENTIFIER = "iv_identifier"
"""Phase 2 — Inject traceable identifier (__TL_xxxxxx__) to detect reflection."""

IV_CHARACTERS = "iv_characters"
"""Phase 3 — Character acceptance testing."""

IV_LENGTH = "iv_length"
"""Phase 4 — Length behaviour (truncation, min/max bounds)."""

IV_TYPES = "iv_types"
"""Phase 5 — Type characterization (verify semantic type hypothesis)."""

IV_TRANSFORMATIONS = "iv_transformations"
"""Phase 6 — Detect input transformations (trim, lowercase, normalization, etc.)."""

IV_REFLECTION = "iv_reflection"
"""Phase 7 — Endpoint-specific reflection analysis (per-endpoint, not cached globally)."""

IV_VALIDATION = "iv_validation"
"""Phase 8 — Validation behaviour and error handling analysis."""

IV_JOB_TYPES: tuple[str, ...] = (
    IV_BASELINE,
    IV_IDENTIFIER,
    IV_CHARACTERS,
    IV_LENGTH,
    IV_TYPES,
    IV_TRANSFORMATIONS,
    IV_REFLECTION,
    IV_VALIDATION,
)

JOB_TYPES: tuple[str, ...] = (REPLAY_FLOW, REPLAY_ENDPOINT, AUTH_TEST) + BAC_JOB_TYPES + IV_JOB_TYPES


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
    meta: Optional[str] = None
    """JSON string carrying attack-type metadata (e.g. attacker_role_id, variant).
    Present on BAC job types; None for all other types."""
