"""
Module: talos.scheduler.scheduler

Purpose:
    ReplayScheduler — infrastructure daemon that drains the scheduler_jobs queue
    and sends replay requests at a controlled, randomised rate.

    Lifecycle mirrors FlowWorker:
        start()  — spawns a daemon thread; returns immediately.
        stop()   — signals the loop to exit after the current job.

    The proxy addon starts the scheduler alongside the worker so both are active
    for the full proxy session.

    Rate control:
        After each executed job the loop sleeps a random duration drawn from
        [min_delay, max_delay] seconds (loaded from scheduler_config in the DB).
        Randomisation avoids periodic patterns that server-side heuristics detect.

    Session Health Engine integration:
        Before each BAC job the scheduler calls session_health.ensure_healthy()
        for the attacker role.  This runs Layer 1 (TTL) and Layer 2 (suspicion
        check) and triggers refresh or validation as needed.
        After each BAC job the scheduler calls session_health.observe_response()
        with the reply status and response data to feed Layer 2 signals.

    Safety pre-check (double layer):
        Before dispatching to the replay engine this layer checks endpoint
        annotations directly so a skippable job is never handed to the engine
        at all.  The engine still has its own guard — this is defence in depth.

    Separation of concerns:
        Proxy     → capture only.
        Worker    → normalise and store.
        Scheduler → decide WHEN to replay.
        Engine    → execute the HTTP request.
        Diff      → evaluate the result.
        Session health → decide whether auth needs refresh.

Design constraints (hard — do not violate):
    - No sleep inside the replay engine.  Delay lives here only.
    - Single-threaded: one job at a time; no parallel execution.
    - No queue writes from this module. DB layer owns persistence.
    - Session health refresh is triggered here, never from the BAC engine.

Dependencies: asyncio, logging, random, threading, time, pathlib
              talos.scheduler.db, talos.scheduler.job
              talos.replay.engine, talos.replay.auth_strip
              talos.projects.annotations, talos.projects.session_health
Data flow:
    TalosAddon.__init__ → ReplayScheduler(project).start()
        → daemon thread: loop: get_next_pending → safety pre-check
               → [BAC] session_health.ensure_healthy
               → mark_running → _execute_job
               → [BAC] session_health.observe_response
               → mark_done/failed/skipped → random sleep
Side effects:
    - Sends outbound HTTP requests (one per job executed).
    - Writes replay flows, diffs, and auth test results to the project DB.
    - Writes job state updates to scheduler_jobs.
    - Writes role_auth_state on session refresh.
    - Logs execution progress.
"""

import asyncio
import logging
import random
import threading
import time
import uuid

import talos.scheduler.db as sched_db
import talos.replay.db as replay_db
from talos.projects.annotations import get_annotations
from talos.projects.attack_config import (
    get_unauth_auto_run,
    get_untested_endpoint_ids,
)
from talos.projects.model import Project
from talos.replay.auth_strip import AuthTestOutcome, run_auth_bypass_test
from talos.replay.engine import ReplayOutcome, replay_endpoint, replay_flow
from talos.scheduler.job import (
    AUTH_TEST,
    BAC_SESSION_SWAP, BAC_METHOD_FUZZ, BAC_CONTENT_TYPE,
    BAC_URL_FUZZ, BAC_HEADER_INJECT, BAC_HOST_FUZZ, BAC_ROLE_INJECT,
    BAC_JOB_TYPES,
    PRIORITY_AUTO,
    REPLAY_ENDPOINT,
    REPLAY_FLOW,
    ReplayJob,
)

_log = logging.getLogger(__name__)

# How long to sleep when the queue is empty before polling again.
_IDLE_POLL_INTERVAL: float = 1.0  # seconds

# Number of idle-poll ticks between auto-enqueue checks.
# At _IDLE_POLL_INTERVAL = 1s this is approximately 30 seconds.
_AUTO_ENQUEUE_INTERVAL: int = 30

# Failure reasons that mean a safety guard fired before any HTTP request was
# sent.  These transition the job to STATUS_SKIPPED, not STATUS_FAILED.
_SKIP_REASONS: frozenset[str] = frozenset({
    "endpoint_annotated_logout",
    "endpoint_annotated_dangerous",
    "flow_not_found",
    "no_qualifying_flow",
    "auth_config_empty",
})


class ReplayScheduler:
    """
    Purpose:
        Consume pending ReplayJobs from the DB queue one at a time, enforcing a
        randomised per-job delay and pre-checking endpoint safety annotations
        before any HTTP request is sent.

    Fields:
        _project     — Active project supplying db_path and project_id.
        _stop_event  — Set to exit the loop cleanly after the current job.
        _thread      — Daemon thread running _run().

    Invariant:
        start() must be called exactly once per session.
        The scheduler is bound to a project for its entire lifetime.
    """

    def __init__(self, project: Project) -> None:
        self._project = project
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="talos-scheduler",
        )

    def start(self) -> None:
        """
        Purpose:
            Start the scheduler daemon thread.  Returns immediately; the loop
            runs in the background until stop() is called.
        Side effects:
            Spawns a daemon thread named 'talos-scheduler'.
        """
        self._thread.start()
        _log.info("ReplayScheduler started for project %s.", self._project.id)

    def stop(self) -> None:
        """
        Purpose:
            Signal the scheduler loop to stop after the current job completes,
            then wait for the thread to exit.
        Side effects:
            Blocks the calling thread until the scheduler thread has exited.
        """
        self._stop_event.set()
        self._thread.join()
        _log.info("ReplayScheduler stopped for project %s.", self._project.id)

    # ------------------------------------------------------------------ #
    # Main loop                                                            #
    # ------------------------------------------------------------------ #

    def _run(self) -> None:
        """
        Purpose:
            Main scheduling loop.  Runs until _stop_event is set.
            On each iteration:
                1. Poll DB for the next pending job.
                2. If empty — idle sleep and retry.
                3. Check endpoint annotations (pre-execution safety layer).
                4. Mark job running; execute it; mark terminal state.
                5. Sleep a randomised delay loaded from scheduler_config.
        Side effects:
            Calls replay engine; writes to DB; logs progress.
        """
        db_path = self._project.db_path
        project_id = self._project.id

        recovered = sched_db.reset_stale_running(db_path)
        if recovered:
            _log.info(
                "[scheduler] Recovered %d stale job(s) → reset to pending.", recovered
            )

        _idle_ticks: int = 0

        while not self._stop_event.is_set():
            job = sched_db.get_next_pending(db_path, project_id)

            if job is None:
                _idle_ticks += 1
                if _idle_ticks >= _AUTO_ENQUEUE_INTERVAL:
                    _idle_ticks = 0
                    self._maybe_auto_enqueue_unauth()
                time.sleep(_IDLE_POLL_INTERVAL)
                continue

            _idle_ticks = 0  # reset on active work

            # --- Safety pre-check (scheduler layer) ---------------------
            skip_reason = self._annotation_pre_check(job)
            if skip_reason is not None:
                sched_db.mark_skipped(db_path, job.job_id, skip_reason)
                _log.info(
                    "[scheduler] SKIPPED job=%s reason=%s",
                    job.job_id[:8],
                    skip_reason,
                )
                continue

            self._execute_job(job)

            if self._stop_event.is_set():
                break

            # Load config fresh each cycle so changes via `talos scheduler config`
            # take effect without restarting the proxy.
            cfg = sched_db.get_scheduler_config(db_path)
            delay = random.uniform(cfg["min_delay"], cfg["max_delay"])
            _log.info("[scheduler] Sleeping %.1fs …", delay)
            time.sleep(delay)

    # ------------------------------------------------------------------ #
    # Auto-enqueue                                                         #
    # ------------------------------------------------------------------ #

    def _maybe_auto_enqueue_unauth(self) -> None:
        """
        Purpose:
            When unauth auto-run is enabled, enqueue AUTH_TEST jobs at
            PRIORITY_AUTO for every endpoint that has no existing result
            and no pending/running job.  Called periodically from the idle
            branch of _run() — never blocks execution of queued jobs.
        Side effects:
            May insert rows into scheduler_jobs.
        """
        db_path = self._project.db_path
        project_id = self._project.id

        try:
            if not get_unauth_auto_run(db_path):
                return
            untested = get_untested_endpoint_ids(db_path, project_id)
            if not untested:
                return
            enqueued = 0
            for eid in untested:
                if sched_db.has_pending_duplicate(db_path, AUTH_TEST, endpoint_id=eid):
                    continue
                sched_db.enqueue_job(
                    db_path=db_path,
                    job_id=str(uuid.uuid4()),
                    job_type=AUTH_TEST,
                    priority=PRIORITY_AUTO,
                    project_id=project_id,
                    endpoint_id=eid,
                )
                enqueued += 1
            if enqueued:
                _log.info("[scheduler] Auto-enqueued %d unauth job(s).", enqueued)
        except Exception as exc:  # noqa: BLE001
            _log.warning("[scheduler] Auto-enqueue unauth error: %s", exc)

    # ------------------------------------------------------------------ #
    # Safety pre-check                                                     #
    # ------------------------------------------------------------------ #

    def _annotation_pre_check(self, job: ReplayJob) -> "str | None":
        """
        Purpose:
            Check endpoint annotations before executing a job.
            - logout    → skip in all modes (all job types).
            - dangerous → skip only for auto jobs (priority < PRIORITY_MANUAL).
        Input:   job — pending ReplayJob.
        Output:  Skip reason string if the job should be skipped; None otherwise.
        Side effects: Reads endpoint_annotations table.
        """
        from talos.scheduler.job import PRIORITY_MANUAL

        # Flow-only jobs may not have an endpoint_id yet.
        if job.endpoint_id is None:
            return None

        tags = get_annotations(self._project.db_path, job.endpoint_id)

        if "logout" in tags:
            return "endpoint_annotated_logout"

        if "dangerous" in tags and job.priority < PRIORITY_MANUAL:
            return "endpoint_annotated_dangerous"

        return None

    # ------------------------------------------------------------------ #
    # Job execution                                                        #
    # ------------------------------------------------------------------ #

    def _execute_job(self, job: ReplayJob) -> None:
        """
        Purpose:
            Execute one replay job end-to-end:
                mark running → dispatch to engine → mark terminal state.
        Input:   job — ReplayJob fetched from the DB.
        Side effects:
            - Marks job running in DB.
            - Calls async replay/auth function via asyncio.run().
            - Marks job done/failed/skipped in DB.
            - Logs result.
        """
        db_path = self._project.db_path
        project_id = self._project.id

        sched_db.mark_running(db_path, job.job_id)

        target = job.flow_id or job.endpoint_id or "(unknown)"
        _log.info(
            "[scheduler] Executing  type=%s  target=%s  job=%s  priority=%d",
            job.job_type,
            target[:8],
            job.job_id[:8],
            job.priority,
        )

        try:
            if job.job_type == REPLAY_FLOW:
                outcome = asyncio.run(
                    replay_flow(
                        flow_id=job.flow_id,  # type: ignore[arg-type]
                        db_path=db_path,
                        project_id=project_id,
                        source="auto_replay",
                        replay_reason="scheduler",
                    )
                )
                self._settle_replay_outcome(job, outcome)

            elif job.job_type == REPLAY_ENDPOINT:
                outcome = asyncio.run(
                    replay_endpoint(
                        endpoint_id=job.endpoint_id,  # type: ignore[arg-type]
                        db_path=db_path,
                        project_id=project_id,
                        source="auto_replay",
                        replay_reason="scheduler",
                    )
                )
                self._settle_replay_outcome(job, outcome)

            elif job.job_type == AUTH_TEST:
                auth_outcome = asyncio.run(
                    run_auth_bypass_test(
                        endpoint_id=job.endpoint_id,  # type: ignore[arg-type]
                        db_path=db_path,
                        project_id=project_id,
                    )
                )
                self._settle_auth_outcome(job, auth_outcome)

            elif job.job_type in BAC_JOB_TYPES:
                self._execute_bac_job(job)

            else:
                _log.error(
                    "Unknown job_type '%s' for job %s — skipping.",
                    job.job_type,
                    job.job_id,
                )
                sched_db.mark_skipped(
                    db_path, job.job_id, f"unknown_job_type:{job.job_type}"
                )

        except Exception as exc:  # noqa: BLE001
            _log.error(
                "Unexpected error executing scheduler job %s: %s", job.job_id, exc
            )
            sched_db.mark_failed(db_path, job.job_id, f"unexpected_error: {exc}")

    def _settle_replay_outcome(self, job: ReplayJob, outcome: ReplayOutcome) -> None:
        """
        Purpose:
            Map a ReplayOutcome to the correct terminal job state and persist it.
        """
        db_path = self._project.db_path

        if outcome.failure_reason in _SKIP_REASONS:
            sched_db.mark_skipped(db_path, job.job_id, outcome.failure_reason)
            _log.info(
                "[scheduler] SKIPPED  job=%s  reason=%s",
                job.job_id[:8],
                outcome.failure_reason,
            )
            return

        if not outcome.success:
            reason = outcome.failure_reason or "unknown_failure"
            sched_db.mark_failed(db_path, job.job_id, reason)
            _log.info(
                "[scheduler] FAILED   job=%s  reason=%s", job.job_id[:8], reason
            )
            return

        sched_db.mark_done(
            db_path,
            job.job_id,
            outcome.replayed_flow_id,
            outcome.verdict,
        )
        _log.info(
            "[scheduler] DONE     job=%s  status=%s  verdict=%s",
            job.job_id[:8],
            outcome.status_code,
            outcome.verdict,
        )

    def _settle_auth_outcome(self, job: ReplayJob, outcome: AuthTestOutcome) -> None:
        """
        Purpose:
            Map an AuthTestOutcome to the correct terminal job state and persist it.
        """
        db_path = self._project.db_path

        if outcome.failure_reason in _SKIP_REASONS:
            sched_db.mark_skipped(db_path, job.job_id, outcome.failure_reason)
            _log.info(
                "[scheduler] SKIPPED  job=%s  reason=%s",
                job.job_id[:8],
                outcome.failure_reason,
            )
            return

        if outcome.failure_reason is not None:
            sched_db.mark_failed(db_path, job.job_id, outcome.failure_reason)
            _log.info(
                "[scheduler] FAILED   job=%s  reason=%s",
                job.job_id[:8],
                outcome.failure_reason,
            )
            return

        sched_db.mark_done(
            db_path,
            job.job_id,
            outcome.replayed_flow_id,
            outcome.auth_verdict,
        )
        _log.info(
            "[scheduler] DONE     job=%s  auth=%s  diff=%s",
            job.job_id[:8],
            outcome.auth_verdict,
            outcome.diff_verdict,
        )

    # ------------------------------------------------------------------ #
    # BAC job execution                                                    #
    # ------------------------------------------------------------------ #

    def _execute_bac_job(self, job: ReplayJob) -> None:
        """
        Purpose:
            Execute a BAC attack job: deserialise meta, ensure session health
            (Layer 1 + 2 gate), call bac.engine, feed response to Layer 2
            observer, settle state.
        Input:   job — ReplayJob with a BAC job type and meta JSON string.
        Side effects:
            - Calls session_health.ensure_healthy before the job.
            - Sends outbound HTTP; writes replay flow + diff + bac_result.
            - Calls session_health.observe_response after the job.
            - Marks job done/failed/skipped.
        """
        import json as _json
        from talos.projects.bac.engine import BacOutcome, execute_bac_job
        from talos.projects.session_health import ensure_healthy, observe_response

        db_path = self._project.db_path
        project_id = self._project.id

        sched_db.mark_running(db_path, job.job_id)

        flow_id = job.flow_id
        if flow_id is None:
            sched_db.mark_skipped(db_path, job.job_id, "bac_job_missing_flow_id")
            return

        meta: dict = {}
        if job.meta:
            try:
                meta = _json.loads(job.meta)
            except (ValueError, TypeError):
                sched_db.mark_failed(db_path, job.job_id, "bac_meta_parse_error")
                return

        attacker_role_id: str = meta.get("attacker_role_id", "")

        # Session Health Engine: Layer 1 (TTL) and Layer 2 (suspicion) gate.
        if attacker_role_id:
            try:
                healthy = ensure_healthy(db_path, attacker_role_id, project_id)
                if not healthy:
                    sched_db.mark_failed(
                        db_path, job.job_id, "session_health_refresh_failed"
                    )
                    _log.warning(
                        "[scheduler] Session health refresh FAILED for role=%s — BAC job skipped.",
                        attacker_role_id[:8],
                    )
                    return
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "[scheduler] Session health check error (non-fatal): %s", exc
                )

        try:
            outcome: BacOutcome = asyncio.run(
                execute_bac_job(
                    flow_id=flow_id,
                    meta=meta,
                    attack_type=job.job_type,
                    db_path=db_path,
                    project_id=project_id,
                )
            )
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "[scheduler] Unexpected error in BAC job %s: %s", job.job_id, exc
            )
            sched_db.mark_failed(db_path, job.job_id, f"unexpected_error: {exc}")
            return

        # Session Health Engine: Layer 2 — feed response signals.
        if attacker_role_id and outcome.replay_status is not None:
            try:
                # Fetch response headers from the replayed flow for header signal checks.
                resp_headers: dict = {}
                resp_body: str = ""
                if outcome.replayed_flow_id:
                    rf = replay_db.get_flow_for_replay(db_path, outcome.replayed_flow_id)
                    if rf:
                        raw_h = rf.get("response_headers", "{}")
                        import json as _j
                        resp_headers = _j.loads(raw_h) if isinstance(raw_h, str) else dict(raw_h)
                        raw_b = rf.get("response_body", b"")
                        resp_body = raw_b.decode("utf-8", errors="replace") if isinstance(raw_b, bytes) else str(raw_b or "")

                threshold_reached = observe_response(
                    db_path,
                    attacker_role_id,
                    outcome.replay_status,
                    resp_headers,
                    resp_body,
                )
                if threshold_reached:
                    _log.info(
                        "[scheduler] Session suspicion threshold reached for role=%s — "
                        "will validate before next BAC job.",
                        attacker_role_id[:8],
                    )
            except Exception as exc:  # noqa: BLE001
                _log.debug("[scheduler] Layer 2 observe error (non-fatal): %s", exc)

        self._settle_bac_outcome(job, outcome)

    def _settle_bac_outcome(self, job: ReplayJob, outcome: "BacOutcome") -> None:
        """
        Purpose:
            Map a BacOutcome to the correct terminal job state and persist it.
        """
        from talos.projects.bac.engine import BacOutcome  # local import avoids circular
        db_path = self._project.db_path

        skip_reasons = _SKIP_REASONS | frozenset({
            "variant_not_applicable",
            "bac_job_missing_flow_id",
        })

        if outcome.failure_reason in skip_reasons:
            sched_db.mark_skipped(db_path, job.job_id, outcome.failure_reason)
            _log.info(
                "[scheduler] SKIPPED  job=%s  reason=%s",
                job.job_id[:8],
                outcome.failure_reason,
            )
            return

        if outcome.failure_reason is not None:
            sched_db.mark_failed(db_path, job.job_id, outcome.failure_reason)
            _log.info(
                "[scheduler] FAILED   job=%s  reason=%s",
                job.job_id[:8],
                outcome.failure_reason,
            )
            return

        sched_db.mark_done(
            db_path,
            job.job_id,
            outcome.replayed_flow_id,
            outcome.bac_verdict,
        )
        _log.info(
            "[scheduler] DONE     job=%s  bac=%s  diff=%s  variant=%s",
            job.job_id[:8],
            outcome.bac_verdict,
            outcome.diff_verdict,
            outcome.variant,
        )

