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
from pathlib import Path

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
from talos.scheduler.db import (
    SCHED_STATE_RUNNING,
    SCHED_STATE_PAUSED,
    SCHED_STATE_WAITING_FOR_SESSION,
)
from talos.scheduler.job import (
    AUTH_TEST,
    AUTH_SESSION_ATTACK,
    AUTH_SESSION_JOB_TYPES,
    BAC_SESSION_SWAP, BAC_METHOD_FUZZ, BAC_CONTENT_TYPE,
    BAC_URL_FUZZ, BAC_HEADER_INJECT, BAC_HOST_FUZZ, BAC_ROLE_INJECT,
    BAC_PARSER_CONFUSE,
    BAC_JOB_TYPES,
    UNAUTH_ATTACK,
    UNAUTH_JOB_TYPES,
    IV_JOB_TYPES,
    INTRUDER_JOB_TYPES,
    INTRUDER_SESSION,
    PRIORITY_AUTO,
    REPLAY_ENDPOINT,
    REPLAY_FLOW,
    ReplayJob,
)

_log = logging.getLogger(__name__)

# How long to sleep when the queue is empty before polling again.
_IDLE_POLL_INTERVAL: float = 1.0  # seconds


# ------------------------------------------------------------------ #
# Auth injection helper for IV scan phases                            #
# ------------------------------------------------------------------ #

def _apply_auth_to_iv_flow(flow: dict, auth_config: dict, auth_state: dict) -> dict:
    """
    Purpose:
        Apply the current auth state to a base flow before IV probe mutations.
        Replaces configured auth headers and cookies with live values from
        role_auth_state so every IV request uses the latest session credentials.

        Must run BEFORE prepare_iv_probe() so probe mutations work on top of
        already-injected auth values.

    Input:
        flow        — original captured flow dict.
        auth_config — {'cookies': list[str], 'headers': list[str]}.
        auth_state  — {artifact_name: value} from role_auth_state.
    Output:
        Modified flow dict with updated request_headers and request_cookies.
    Side effects: None (pure transformation).
    """
    import json as _json

    raw_headers = flow.get("request_headers", "{}")
    headers: dict = _json.loads(raw_headers) if isinstance(raw_headers, str) else dict(raw_headers)

    raw_cookies = flow.get("request_cookies", "{}")
    cookies: dict = _json.loads(raw_cookies) if isinstance(raw_cookies, str) else dict(raw_cookies)

    auth_header_names_lower = {n.lower() for n in auth_config["headers"]}

    # Replace auth headers (case-insensitive removal, then inject).
    headers = {k: v for k, v in headers.items() if k.lower() not in auth_header_names_lower}
    for header_name in auth_config["headers"]:
        if header_name in auth_state:
            headers[header_name] = auth_state[header_name]

    # Replace auth cookies with live values from role_auth_state.
    for cookie_name in auth_config["cookies"]:
        if cookie_name in auth_state:
            cookies[cookie_name] = auth_state[cookie_name]

    # Rebuild Cookie header — remove all existing variants first to prevent
    # duplicate Cookie headers that some proxies join with commas.
    if auth_config["cookies"]:
        for _k in list(headers.keys()):
            if _k.lower() == "cookie":
                del headers[_k]
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if cookie_str:
            headers["Cookie"] = cookie_str

    modified = dict(flow)
    modified["request_headers"] = _json.dumps(headers)
    modified["request_cookies"] = _json.dumps(cookies)
    return modified

# Number of idle-poll ticks between auto-enqueue checks.
# At _IDLE_POLL_INTERVAL = 1s this is approximately 30 seconds.
_AUTO_ENQUEUE_INTERVAL: int = 30

# Failure reasons that mean a safety guard fired before any HTTP request was
# sent.  These transition the job to STATUS_SKIPPED, not STATUS_FAILED.
_SKIP_REASONS: frozenset[str] = frozenset({
    "endpoint_annotated_logout",
    "endpoint_annotated_dangerous",
    "endpoint_excluded",
    "endpoint_not_qualified",
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
                1. Check global scheduler state (paused / waiting_for_session).
                2. Poll DB for the next pending job.
                3. If empty — idle sleep and retry.
                4. Check endpoint annotations (pre-execution safety layer).
                5. Mark job running; execute it; mark terminal state.
                6. Sleep a randomised delay loaded from scheduler_config.

            When the scheduler state is PAUSED or WAITING_FOR_SESSION, the loop
            sleeps the idle interval without consuming jobs.  This preserves the
            queue so execution resumes seamlessly once a session is refreshed.
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
            # Check global scheduler state before polling for work.
            sched_state = sched_db.get_scheduler_state(db_path)
            if sched_state in (SCHED_STATE_PAUSED, SCHED_STATE_WAITING_FOR_SESSION):
                time.sleep(_IDLE_POLL_INTERVAL)
                continue

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
        Side effects: Reads endpoint_policy table (dangerous/logout columns).
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

            elif job.job_type in UNAUTH_JOB_TYPES:
                self._execute_unauth_job(job)

            elif job.job_type in AUTH_SESSION_JOB_TYPES:
                self._execute_auth_session_job(job)

            elif job.job_type in IV_JOB_TYPES:
                self._execute_iv_job(job)

            elif job.job_type in INTRUDER_JOB_TYPES:
                self._execute_intruder_job(job)

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

        # Trigger finding creation for BYPASS verdicts.
        self._maybe_create_finding_auth(job, outcome)

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
                    # Check whether this is a MANUAL provider that needs user input.
                    from talos.projects.auth_provider import (
                        get_provider, PROVIDER_MANUAL,
                    )
                    provider = get_provider(db_path, attacker_role_id)
                    if provider == PROVIDER_MANUAL:
                        # Pause the scheduler and this job — do not fail it.
                        _log.warning(
                            "[scheduler] MANUAL session expired for role=%s — "
                            "pausing scheduler (WAITING_FOR_SESSION).",
                            attacker_role_id[:8],
                        )
                        sched_db.mark_paused(db_path, job.job_id)
                        paused = sched_db.pause_pending_jobs(db_path)
                        sched_db.set_scheduler_state(
                            db_path,
                            SCHED_STATE_WAITING_FOR_SESSION,
                            reason=f"Manual session expired for role {attacker_role_id[:8]}",
                        )
                        _log.warning(
                            "[scheduler] Paused %d pending job(s). "
                            "Run 'talos auth-config set-session %s' then "
                            "'talos scheduler resume' to continue.",
                            paused,
                            attacker_role_id,
                        )
                        return
                    # AUTO provider failure: mark failed as before.
                    sched_db.mark_failed(
                        db_path, job.job_id, "session_health_refresh_failed"
                    )
                    _log.warning(
                        "[scheduler] Session health refresh FAILED for role=%s — BAC job failed.",
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

        # Trigger finding creation for POSSIBLE_BAC verdicts.
        self._maybe_create_finding_bac(job, outcome)

    # ------------------------------------------------------------------ #
    # Unauth job execution                                                 #
    # ------------------------------------------------------------------ #

    def _execute_unauth_job(self, job: ReplayJob) -> None:
        """
        Purpose:
            Execute a UNAUTH_ATTACK job: deserialise meta, call unauth.engine,
            and settle the job state.
        Input:   job — ReplayJob with UNAUTH_ATTACK type and meta JSON string.
        Side effects:
            - Sends outbound HTTP; writes replay flow + diff + unauth_result.
            - Marks job done/failed/skipped.
        """
        import json as _json
        from talos.projects.unauth.engine import UnauthOutcome, execute_unauth_job

        db_path = self._project.db_path
        project_id = self._project.id

        sched_db.mark_running(db_path, job.job_id)

        flow_id = job.flow_id
        if flow_id is None:
            sched_db.mark_skipped(db_path, job.job_id, "unauth_job_missing_flow_id")
            return

        meta: dict = {}
        if job.meta:
            try:
                meta = _json.loads(job.meta)
            except (ValueError, TypeError):
                sched_db.mark_failed(db_path, job.job_id, "unauth_meta_parse_error")
                return

        try:
            outcome: UnauthOutcome = asyncio.run(
                execute_unauth_job(
                    flow_id=flow_id,
                    meta=meta,
                    db_path=db_path,
                    project_id=project_id,
                )
            )
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "[scheduler] Unexpected error in unauth job %s: %s",
                job.job_id[:8],
                exc,
            )
            sched_db.mark_failed(db_path, job.job_id, f"unexpected_error: {exc}")
            return

        self._settle_unauth_outcome(job, outcome)

    def _settle_unauth_outcome(self, job: ReplayJob, outcome: "UnauthOutcome") -> None:
        """
        Purpose:
            Map a UnauthOutcome to the correct terminal job state and persist it.
        """
        db_path = self._project.db_path

        skip_reasons = _SKIP_REASONS | frozenset({
            "request_mutation_not_applicable",
            "unauth_job_missing_flow_id",
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
            outcome.unauth_verdict,
        )
        _log.info(
            "[scheduler] DONE     job=%s  unauth=%s  diff=%s  auth_mut=%s",
            job.job_id[:8],
            outcome.unauth_verdict,
            outcome.diff_verdict,
            outcome.auth_mutation,
        )

        # Trigger finding creation for BYPASS verdicts.
        if outcome.unauth_verdict == "BYPASS":
            self._maybe_create_finding_unauth(job, outcome)

    # ------------------------------------------------------------------ #
    # Auth-session job execution                                           #
    # ------------------------------------------------------------------ #

    def _execute_auth_session_job(self, job: ReplayJob) -> None:
        """
        Purpose:
            Execute an AUTH_SESSION_ATTACK job: deserialise meta, mark
            candidate running, call auth_session.engine, settle job + candidate.
        Input:   job — ReplayJob with AUTH_SESSION_ATTACK type and meta JSON.
        Side effects:
            - Candidate status approved→running→done|failed
            - Outbound HTTP; replay flow + diff + auth_session_results
            - Job done/failed/skipped
            - Findings intentionally deferred to Phase 4
        """
        import json as _json
        from talos.auth_session import db as as_db
        from talos.auth_session.engine import execute_auth_session_job
        from talos.auth_session.models import AuthSessionOutcome

        db_path = self._project.db_path
        project_id = self._project.id

        sched_db.mark_running(db_path, job.job_id)

        flow_id = job.flow_id
        if flow_id is None:
            sched_db.mark_skipped(db_path, job.job_id, "auth_session_job_missing_flow_id")
            return

        meta: dict = {}
        if job.meta:
            try:
                meta = _json.loads(job.meta)
            except (ValueError, TypeError):
                sched_db.mark_failed(db_path, job.job_id, "auth_session_meta_parse_error")
                return

        candidate_id = str(meta.get("candidate_id") or "")
        if candidate_id:
            try:
                as_db.mark_candidate_running(db_path, candidate_id)
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "[scheduler] auth_session mark running failed for %s: %s",
                    candidate_id[:8],
                    exc,
                )

        try:
            outcome: AuthSessionOutcome = asyncio.run(
                execute_auth_session_job(
                    flow_id=flow_id,
                    meta=meta,
                    db_path=db_path,
                    project_id=project_id,
                )
            )
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "[scheduler] Unexpected error in auth_session job %s: %s",
                job.job_id[:8],
                exc,
            )
            if candidate_id:
                try:
                    as_db.mark_candidate_failed(
                        db_path, candidate_id, skip_reason=f"unexpected_error: {exc}"
                    )
                except Exception:  # noqa: BLE001
                    pass
            sched_db.mark_failed(db_path, job.job_id, f"unexpected_error: {exc}")
            return

        self._settle_auth_session_outcome(job, outcome)

    def _settle_auth_session_outcome(
        self, job: ReplayJob, outcome: "AuthSessionOutcome"
    ) -> None:
        """
        Purpose:
            Map AuthSessionOutcome to job terminal state + candidate done/failed.
            On successful WEAK_VALIDATION, create a finding (KD16 settle only).
        """
        from talos.auth_session import db as as_db

        db_path = self._project.db_path
        candidate_id = outcome.candidate_id

        skip_reasons = _SKIP_REASONS | frozenset({
            "auth_session_job_missing_flow_id",
            "candidate_not_found",
            "binding_not_found",
            "mutation_noop_same_token",
            "auth_field_absent",
            "token_not_detectable",
            "auth_session_meta_incomplete",
        })

        if outcome.failure_reason in skip_reasons:
            if candidate_id:
                try:
                    as_db.mark_candidate_failed(
                        db_path,
                        candidate_id,
                        skip_reason=outcome.failure_reason,
                    )
                except Exception as exc:  # noqa: BLE001
                    _log.debug(
                        "[scheduler] auth_session candidate fail mark error: %s", exc
                    )
            sched_db.mark_skipped(db_path, job.job_id, outcome.failure_reason)
            _log.info(
                "[scheduler] SKIPPED  job=%s  reason=%s",
                job.job_id[:8],
                outcome.failure_reason,
            )
            return

        if outcome.failure_reason is not None:
            if candidate_id:
                try:
                    as_db.mark_candidate_failed(
                        db_path,
                        candidate_id,
                        skip_reason=outcome.failure_reason,
                    )
                except Exception as exc:  # noqa: BLE001
                    _log.debug(
                        "[scheduler] auth_session candidate fail mark error: %s", exc
                    )
            sched_db.mark_failed(db_path, job.job_id, outcome.failure_reason)
            _log.info(
                "[scheduler] FAILED   job=%s  reason=%s",
                job.job_id[:8],
                outcome.failure_reason,
            )
            return

        if candidate_id:
            try:
                as_db.mark_candidate_done(db_path, candidate_id)
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "[scheduler] auth_session mark done failed for %s: %s",
                    candidate_id[:8],
                    exc,
                )

        sched_db.mark_done(
            db_path,
            job.job_id,
            outcome.replayed_flow_id,
            outcome.auth_session_verdict,
        )
        _log.info(
            "[scheduler] DONE     job=%s  auth_session=%s  diff=%s  test=%s",
            job.job_id[:8],
            outcome.auth_session_verdict,
            outcome.diff_verdict,
            outcome.test_id,
        )

        self._maybe_create_finding_auth_session(job, outcome)

    def _maybe_create_finding_auth_session(
        self, job: ReplayJob, outcome: "AuthSessionOutcome"
    ) -> None:
        """
        Purpose:
            Create a finding when an auth-session job produces WEAK_VALIDATION.
            Non-fatal — errors are logged and suppressed (KD16 settle path).
        """
        from talos.auth_session.findings_bridge import maybe_create_auth_session_finding

        db_path = self._project.db_path
        project_id = self._project.id

        endpoint_id = outcome.endpoint_id or job.endpoint_id
        risk_hint = None
        mutation_summary = None
        if outcome.candidate_id:
            try:
                from talos.auth_session import db as as_db

                cand = as_db.get_candidate(db_path, outcome.candidate_id)
                if cand is not None:
                    risk_hint = cand.risk_hint
                    mutation_summary = cand.mutation_summary
            except Exception:  # noqa: BLE001
                pass

        try:
            maybe_create_auth_session_finding(
                db_path=db_path,
                project_id=project_id,
                verdict=outcome.auth_session_verdict,
                endpoint_id=endpoint_id,
                original_flow_id=outcome.original_flow_id,
                replayed_flow_id=outcome.replayed_flow_id,
                test_id=outcome.test_id,
                auth_type=outcome.auth_type or "jwt",
                job_id=job.job_id,
                diff_verdict=outcome.diff_verdict,
                risk_hint=risk_hint,
                mutation_summary=mutation_summary,
                candidate_id=outcome.candidate_id,
                binding_id=outcome.binding_id,
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "[findings] Auth-session finding creation error (non-fatal): %s",
                exc,
            )

    def _maybe_create_finding_unauth(
        self, job: ReplayJob, outcome: "UnauthOutcome"
    ) -> None:
        """
        Purpose:
            Create a finding when an unauth job produces a BYPASS verdict.
            Non-fatal — any error is logged and suppressed.
        """
        import json as _json
        from talos.findings.creator import create_finding_from_verdict

        db_path = self._project.db_path
        project_id = self._project.id

        meta: dict = {}
        if job.meta:
            try:
                meta = _json.loads(job.meta)
            except (ValueError, TypeError):
                pass

        endpoint_id = job.endpoint_id
        if endpoint_id is None and outcome.original_flow_id:
            try:
                flow = replay_db.get_flow_for_replay(db_path, outcome.original_flow_id)
                if flow:
                    endpoint_id = flow.get("endpoint_id")
            except Exception:  # noqa: BLE001
                pass

        try:
            create_finding_from_verdict(
                db_path=db_path,
                project_id=project_id,
                attack_module="unauth",
                verdict=outcome.unauth_verdict,
                endpoint_id=endpoint_id,
                original_flow_id=outcome.original_flow_id,
                replayed_flow_id=outcome.replayed_flow_id,
                job_id=job.job_id,
                attack_type=UNAUTH_ATTACK,
                variant=f"{outcome.auth_mutation}+{outcome.request_mutation or 'baseline'}",
                diff_verdict=outcome.diff_verdict,
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning("[findings] Unauth finding creation error (non-fatal): %s", exc)

    # ------------------------------------------------------------------ #
    # Finding creation hooks                                               #
    # ------------------------------------------------------------------ #

    def _maybe_create_finding_bac(self, job: ReplayJob, outcome: "BacOutcome") -> None:
        """
        Purpose:
            Create a finding when a BAC job produces a POSSIBLE_BAC verdict.
            Non-fatal — any error is logged and suppressed so finding creation
            never disrupts the scheduling loop.
        Input:
            job     — completed ReplayJob with BAC type and meta.
            outcome — BacOutcome from the BAC engine.
        Side effects:
            Writes to findings, finding_evidence, finding_timeline tables.
        """
        import json as _json
        from talos.findings.creator import create_finding_from_verdict

        db_path = self._project.db_path
        project_id = self._project.id

        meta: dict = {}
        if job.meta:
            try:
                meta = _json.loads(job.meta)
            except (ValueError, TypeError):
                pass

        # Resolve endpoint_id from the original flow if not on the job.
        endpoint_id = job.endpoint_id
        if endpoint_id is None and outcome.original_flow_id:
            try:
                import talos.replay.db as _rdb
                flow = _rdb.get_flow_for_replay(db_path, outcome.original_flow_id)
                if flow:
                    endpoint_id = flow.get("endpoint_id")
            except Exception:  # noqa: BLE001
                pass

        try:
            create_finding_from_verdict(
                db_path=db_path,
                project_id=project_id,
                attack_module="bac",
                verdict=outcome.bac_verdict,
                endpoint_id=endpoint_id,
                original_flow_id=outcome.original_flow_id,
                replayed_flow_id=outcome.replayed_flow_id,
                job_id=job.job_id,
                attacker_role_id=meta.get("attacker_role_id"),
                target_role_id=meta.get("target_role_id"),
                module_id=meta.get("module_id"),
                attack_type=outcome.attack_type,
                variant=outcome.variant,
                diff_verdict=outcome.diff_verdict,
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning("[findings] BAC finding creation error (non-fatal): %s", exc)

    def _maybe_create_finding_auth(
        self, job: ReplayJob, outcome: "AuthTestOutcome"
    ) -> None:
        """
        Purpose:
            Create a finding when an auth-bypass test produces a BYPASS verdict.
            Non-fatal — any error is logged and suppressed.
        Input:
            job     — completed ReplayJob with AUTH_TEST type.
            outcome — AuthTestOutcome from auth_strip.
        Side effects:
            Writes to findings, finding_evidence, finding_timeline tables.
        """
        from talos.findings.creator import create_finding_from_verdict

        db_path = self._project.db_path
        project_id = self._project.id

        try:
            create_finding_from_verdict(
                db_path=db_path,
                project_id=project_id,
                attack_module="auth_test",
                verdict=outcome.auth_verdict,
                endpoint_id=job.endpoint_id,
                original_flow_id=outcome.original_flow_id,
                replayed_flow_id=outcome.replayed_flow_id,
                job_id=job.job_id,
                diff_verdict=outcome.diff_verdict,
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning("[findings] Auth finding creation error (non-fatal): %s", exc)

    # ------------------------------------------------------------------ #
    # Input Validation job execution                                       #
    # ------------------------------------------------------------------ #

    def _execute_iv_job(self, job: ReplayJob) -> None:
        """
        Purpose:
            Execute one Input Validation probe job.

            Scan phases (baseline, multiprobe, identifier, characters, length,
            types, validation): apply the probe mutation to the base flow, run
            session health check for the role, send via replay_with_mutation,
            and persist the result in iv_probe_results.  Multiprobe stores the
            multi-signal plan under flow_meta.multiprobe (one flow per job).

            Analysis phases (transformations, reflection): consume existing
            iv_probe_results rows for the parameter, run pure analysis, and
            store aggregated conclusions in iv_param_cache / iv_reflection_cache.
            Zero HTTP requests.

        Input:
            job — ReplayJob with an IV job type and meta JSON string.
        Side effects:
            - Scan phases: sends one HTTP request; writes one replay flow.
            - Analysis phases: reads iv_probe_results; writes iv_param_cache
              or iv_reflection_cache.
            - Marks job done/failed/skipped.
        """
        import json as _json
        from talos.projects.db import migrate_project_db
        from talos.input_validation import db as iv_db
        from talos.input_validation.phases import (
            prepare_iv_probe,
            find_best_flow_for_param,
            find_best_flow_for_endpoint,
            analyze_transformations,
            analyze_reflection,
        )
        from talos.scheduler.job import IV_REFLECTION, IV_TRANSFORMATIONS
        from talos.replay.engine import replay_with_mutation
        from talos.projects.session_health import ensure_healthy

        db_path = self._project.db_path
        project_id = self._project.id

        # Ensure schema is at v27 (flow_meta + iv_probe_results) before IV executes.
        migrate_project_db(db_path)

        # Parse job metadata.
        meta: dict = {}
        if job.meta:
            try:
                meta = _json.loads(job.meta)
            except (ValueError, TypeError):
                sched_db.mark_failed(db_path, job.job_id, "iv_meta_parse_error")
                _log.error("[iv] Failed to parse meta for job %s.", job.job_id[:8])
                return

        host: str = meta.get("host", "")
        location: str = meta.get("location", "")
        # Support both old (param_name) and new (parameter_name) meta keys.
        parameter_name: str = meta.get("parameter_name") or meta.get("param_name", "")
        parameter_uuid: str = meta.get("parameter_uuid") or meta.get("param_uuid", "")
        endpoint_id: str = meta.get("endpoint_id", "") or job.endpoint_id or ""
        analysis: str = meta.get("analysis", job.job_type.replace("iv_", ""))

        if not parameter_name or not location:
            sched_db.mark_skipped(db_path, job.job_id, "iv_missing_param_meta")
            _log.warning(
                "[iv] Job %s missing parameter_name or location — skipped.", job.job_id[:8]
            )
            return

        # ── Analysis-only phases (0 HTTP requests) ───────────────────────────
        if job.job_type == IV_REFLECTION:
            self._execute_iv_reflection(
                job, meta, db_path, host, location, parameter_name, parameter_uuid,
                endpoint_id, analyze_reflection, iv_db
            )
            return

        if job.job_type == IV_TRANSFORMATIONS:
            self._execute_iv_transformations(
                job, meta, db_path, host, location, parameter_name, parameter_uuid,
                analyze_transformations, iv_db
            )
            return

        # ── Scan phases — one HTTP request per job ────────────────────────────
        payload: str | None = meta.get("payload")
        # Support both old (payload_class) and new (payload_type) meta keys.
        payload_type: str = meta.get("payload_type") or meta.get("payload_class", "unknown")
        payload_index: int = meta.get("payload_index", 0)

        # Find the best qualifying base flow.
        flow: dict | None = find_best_flow_for_param(db_path, host, location, parameter_name)
        if flow is None:
            iv_db.upsert_probe_result(
                db_path, parameter_uuid, endpoint_id or None, host, location,
                parameter_name, analysis, payload, payload_type, payload_index,
                None, iv_db.STATUS_SKIPPED,
            )
            sched_db.mark_skipped(db_path, job.job_id, "iv_no_qualifying_flow")
            _log.info(
                "[iv] No qualifying flow for %s %s %s — job %s skipped.",
                host, location, parameter_name, job.job_id[:8],
            )
            self._continue_iv_plan_after_job(job, meta, db_path, project_id)
            return

        # Session health check for the role that owns this flow.
        role_id: str = flow.get("role_id", "")
        if role_id:
            try:
                healthy = ensure_healthy(db_path, role_id, project_id)
                if not healthy:
                    iv_db.upsert_probe_result(
                        db_path, parameter_uuid, endpoint_id or None, host, location,
                        parameter_name, analysis, payload, payload_type, payload_index,
                        None, iv_db.STATUS_SKIPPED,
                    )
                    sched_db.mark_failed(
                        db_path, job.job_id, "session_health_refresh_failed"
                    )
                    _log.warning(
                        "[iv] Session health refresh FAILED for role=%s — job skipped.",
                        role_id[:8],
                    )
                    return
            except Exception as exc:  # noqa: BLE001
                _log.warning("[iv] Session health check error (non-fatal): %s", exc)

        # Inject the latest auth state into the base flow before mutation.
        # This ensures every IV probe uses the current session credentials,
        # not the credentials captured in the original flow.
        # Must happen BEFORE prepare_iv_probe so probe mutations are applied
        # on top of the already-injected auth values.
        from talos.projects.auth import get_auth_config as _get_auth_config
        from talos.projects.auth import get_role_auth_state as _get_role_auth_state
        if role_id:
            _auth_cfg = _get_auth_config(db_path)
            if _auth_cfg["cookies"] or _auth_cfg["headers"]:
                _state_info = _get_role_auth_state(db_path, role_id)
                if not _state_info["state"]:
                    # Auth is configured but no active session exists.
                    # Fail the job instead of replaying with stale captured credentials.
                    iv_db.upsert_probe_result(
                        db_path, parameter_uuid, endpoint_id or None, host, location,
                        parameter_name, analysis, payload, payload_type, payload_index,
                        None, iv_db.STATUS_FAILED,
                    )
                    sched_db.mark_failed(db_path, job.job_id, "no_active_auth_state")
                    _log.warning(
                        "[iv] No active auth state for role=%s — job %s failed. "
                        "Run 'talos auth-config refresh <role>'.",
                        role_id[:8], job.job_id[:8],
                    )
                    return
                flow = _apply_auth_to_iv_flow(flow, _auth_cfg, _state_info["state"])

# Transport gate: do not send payloads the HTTP client rejects before
        # the request reaches the application (Illegal header value).
        from talos.input_validation.surface import (
            transport_skip_for_headers,
            transport_skip_for_payload,
        )
        pre_skip = transport_skip_for_payload(location, payload)
        if pre_skip is not None:
            iv_db.upsert_probe_result(
                db_path, parameter_uuid, endpoint_id or None, host, location,
                parameter_name, analysis, payload, payload_type, payload_index,
                None, iv_db.STATUS_SKIPPED,
            )
            sched_db.mark_skipped(db_path, job.job_id, pre_skip.reason)
            _log.info(
                "[iv] SKIP transport %s for %s %s/%s job=%s",
                pre_skip.reason, host, location, parameter_name, job.job_id[:8],
            )
            self._continue_iv_plan_after_job(job, meta, db_path, project_id)
            return

        # Prepare the probe mutation (Module 8: pass payload_type / injection_mode).
        injection_mode = meta.get("injection_mode")
        mutations = prepare_iv_probe(
            analysis,
            flow,
            parameter_name,
            location,
            payload,
            payload_type=payload_type,
            injection_mode=injection_mode if isinstance(injection_mode, str) else None,
        )

        # Post-inject: composed Cookie/header map may still be illegal.
        if location in ("header", "cookie"):
            import json as _json_hdr
            base_headers = flow.get("request_headers") or {}
            if isinstance(base_headers, str):
                try:
                    base_headers = _json_hdr.loads(base_headers)
                except (ValueError, TypeError):
                    base_headers = {}
            effective_headers = dict(base_headers)
            mut_headers = mutations.get("request_headers")
            if isinstance(mut_headers, dict):
                effective_headers = mut_headers
            post_skip = transport_skip_for_headers(location, effective_headers)
            if post_skip is not None:
                iv_db.upsert_probe_result(
                    db_path, parameter_uuid, endpoint_id or None, host, location,
                    parameter_name, analysis, payload, payload_type, payload_index,
                    None, iv_db.STATUS_SKIPPED,
                )
                sched_db.mark_skipped(db_path, job.job_id, post_skip.reason)
                _log.info(
                    "[iv] SKIP transport %s after inject for %s %s/%s job=%s",
                    post_skip.reason, host, location, parameter_name, job.job_id[:8],
                )
                self._continue_iv_plan_after_job(job, meta, db_path, project_id)
                return

        # Build standardized universal flow metadata.
        # source = auto_replay (mechanism); generated_by = input_validation (subsystem).
        flow_meta = {
            "generated_by": "input_validation",
            "analysis": analysis,
            "parameter_uuid": parameter_uuid,
            "parameter_name": parameter_name,
            "payload": payload,
            "payload_type": payload_type,
            "payload_index": payload_index,
            "baseline_flow": flow["id"],
            "mutation": {
                "location": location,
                "host": host,
                "endpoint_id": endpoint_id,
            },
        }
        # Module 4: attach multiprobe plan so evidence is self-describing.
        multiprobe_meta = meta.get("multiprobe")
        if multiprobe_meta:
            flow_meta["multiprobe"] = multiprobe_meta
        elif analysis == "multiprobe" and payload:
            try:
                from talos.input_validation.multiprobe import parse_multiprobe_payload
                plan = parse_multiprobe_payload(payload)
                if plan is not None:
                    flow_meta["multiprobe"] = plan.to_dict()
            except Exception:  # noqa: BLE001
                pass

        # Execute via replay engine with source=auto_replay.
        # generated_by in flow_meta distinguishes IV flows from other auto replays.
        try:
            outcome = asyncio.run(
                replay_with_mutation(
                    original_flow=flow,
                    mutations=mutations,
                    db_path=db_path,
                    project_id=project_id,
                    source="auto_replay",
                    replay_reason="input_validation",
                    flow_meta=flow_meta,
                )
            )
        except Exception as exc:  # noqa: BLE001
            _log.error("[iv] Replay error for job %s: %s", job.job_id[:8], exc)
            iv_db.upsert_probe_result(
                db_path, parameter_uuid, endpoint_id or None, host, location,
                parameter_name, analysis, payload, payload_type, payload_index,
                None, iv_db.STATUS_FAILED,
            )
            sched_db.mark_failed(db_path, job.job_id, f"replay_error: {exc}")
            return

# Persist probe result — only identity fields; HTTP data lives in flows.
        # Client-side "Illegal header value" is not an application rejection:
        # mark skipped with a stable transport reason (defense in depth).
        failure = outcome.failure_reason or ""
        transport_illegal = (
            not outcome.success
            and "Illegal header value" in failure
        )
        if outcome.success:
            probe_status = iv_db.STATUS_COMPLETED
        elif transport_illegal:
            probe_status = iv_db.STATUS_SKIPPED
        else:
            probe_status = iv_db.STATUS_FAILED
        iv_db.upsert_probe_result(
            db_path,
            parameter_uuid,
            endpoint_id or None,
            host,
            location,
            parameter_name,
            analysis,
            payload,
            payload_type,
            payload_index,
            outcome.replayed_flow_id,
            probe_status,
        )

        if outcome.success:
            sched_db.mark_done(
                db_path, job.job_id, outcome.replayed_flow_id, None
            )
            _log.info(
                "[iv] DONE  job=%s  analysis=%s  payload=%r  status=%s  flow=%s",
                job.job_id[:8], analysis,
                payload if payload is not None else "(baseline)",
                outcome.status_code,
                (outcome.replayed_flow_id or "")[:8],
            )
        elif transport_illegal:
            skip_reason = (
                "transport_invalid_cookie"
                if location == "cookie"
                else "transport_invalid_header"
            )
            sched_db.mark_skipped(db_path, job.job_id, skip_reason)
            _log.info(
                "[iv] SKIP transport illegal header value job=%s location=%s",
                job.job_id[:8], location,
            )
        else:
            sched_db.mark_failed(
                db_path, job.job_id, outcome.failure_reason or "replay_failed"
            )

        # Module 5: adaptive planner — next wave after probe settles (ok or fail).
        self._continue_iv_plan_after_job(job, meta, db_path, project_id)

    def _continue_iv_plan_after_job(
        self,
        job: ReplayJob,
        meta: dict,
        db_path: Path,
        project_id: str,
    ) -> None:
        """
        Purpose:
            After any IV job settles, invoke the Module 5 planner to enqueue
            the next adaptive actions for that parameter (or finalize).
        Side effects: May insert scheduler jobs / synthesize profiles.
        """
        try:
            from talos.input_validation.engine import continue_param_plan
            host = meta.get("host", "")
            location = meta.get("location", "")
            parameter_name = meta.get("parameter_name") or meta.get("param_name", "")
            parameter_uuid = meta.get("parameter_uuid") or meta.get("param_uuid", "")
            endpoint_id = meta.get("endpoint_id", "") or job.endpoint_id or ""
            if not parameter_uuid or not parameter_name or not location:
                return
            continue_param_plan(
                db_path,
                project_id,
                host=host,
                location=location,
                parameter_name=parameter_name,
                parameter_uuid=parameter_uuid,
                endpoint_id=endpoint_id,
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning("[iv] planner follow-up failed: %s", exc)

    def _execute_iv_transformations(
        self,
        job: ReplayJob,
        meta: dict,
        db_path: Path,
        host: str,
        location: str,
        parameter_name: str,
        parameter_uuid: str,
        analyze_transformations,
        iv_db,
    ) -> None:
        """
        Purpose:
            Execute a transformations analysis job by consuming existing
            iv_probe_results rows.  Zero HTTP requests.

            Race guard (Module 3): if scan probes for this parameter are still
            pending/running, skip without marking the phase completed so resume
            can re-enqueue analysis after probes finish.  When ready but some
            required analyses are missing, store STATUS_PARTIAL and still
            synthesize a profile offline.
        Side effects:
            Reads iv_probe_results; writes iv_param_cache; optional profile
            synthesis; marks job done/failed/skipped.
        """
        from talos.input_validation.synthesize import (
            analysis_probes_ready,
            synthesize_param_profile,
        )

        readiness = analysis_probes_ready(db_path, parameter_uuid)
        if readiness["wait"]:
            # Do not write STATUS_COMPLETED — phase remains incomplete for resume.
            sched_db.mark_skipped(
                db_path, job.job_id, "iv_probes_still_running"
            )
            _log.info(
                "[iv] Transformations deferred (scan probes still running) job=%s "
                "pending_scan=%s",
                job.job_id[:8], readiness["pending_scan_jobs"],
            )
            return

        probe_records = iv_db.get_probe_results_for_param(db_path, parameter_uuid)
        if not probe_records:
            sched_db.mark_skipped(
                db_path, job.job_id, "iv_no_probe_results_for_analysis"
            )
            _log.info(
                "[iv] No probe results for transformations analysis %s — skipped.",
                job.job_id[:8],
            )
            return

        try:
            result = analyze_transformations(probe_records)
            # Always STATUS_COMPLETED once nothing is waiting — partial is a
            # result flag only so resume does not re-enqueue forever.
            result["partial"] = bool(readiness.get("partial"))
            result["missing_required"] = list(readiness.get("missing_required") or [])
            iv_db.upsert_param_cache(
                db_path, host, location, parameter_name,
                "iv_transformations", iv_db.STATUS_COMPLETED, result,
            )
            # Offline synthesis from whatever probes exist (Module 3).
            try:
                synthesize_param_profile(
                    db_path, parameter_uuid, persist=True, bump_version=True,
                )
            except Exception as synth_exc:  # noqa: BLE001
                _log.warning(
                    "[iv] Profile synthesis after transformations failed: %s",
                    synth_exc,
                )
            sched_db.mark_done(db_path, job.job_id, None, None)
            _log.info(
                "[iv] DONE  transformations  param=%s/%s  host=%s  transforms=%s  "
                "partial=%s",
                location, parameter_name, host,
                result.get("transformations", []),
                result.get("partial"),
            )
            self._continue_iv_plan_after_job(
                job, meta, db_path, self._project.id
            )
        except Exception as exc:  # noqa: BLE001
            _log.error("[iv] Transformations analysis failed for %s: %s", job.job_id[:8], exc)
            iv_db.upsert_param_cache(
                db_path, host, location, parameter_name,
                "iv_transformations", iv_db.STATUS_FAILED, {"error": str(exc)},
            )
            sched_db.mark_failed(db_path, job.job_id, f"analysis_error: {exc}")
            self._continue_iv_plan_after_job(
                job, meta, db_path, self._project.id
            )

    def _execute_iv_reflection(
        self,
        job: ReplayJob,
        meta: dict,
        db_path: Path,
        host: str,
        location: str,
        parameter_name: str,
        parameter_uuid: str,
        endpoint_id: str,
        analyze_reflection,
        iv_db,
    ) -> None:
        """
        Purpose:
            Execute a reflection analysis job by consuming existing
            iv_probe_results rows for this endpoint+parameter.
            Zero HTTP requests.

            Race guard (Module 3): skip while scan probes still run; synthesize
            profile after analysis (partial when required analyses missing).
        Side effects:
            Reads iv_probe_results; writes iv_reflection_cache; optional
            profile synthesis; marks job done/failed/skipped.
        """
        from talos.input_validation.synthesize import (
            analysis_probes_ready,
            synthesize_param_profile,
        )

        if not endpoint_id:
            sched_db.mark_skipped(db_path, job.job_id, "iv_reflection_missing_endpoint")
            return

        readiness = analysis_probes_ready(db_path, parameter_uuid)
        if readiness["wait"]:
            sched_db.mark_skipped(
                db_path, job.job_id, "iv_probes_still_running"
            )
            _log.info(
                "[iv] Reflection deferred (scan probes still running) job=%s "
                "pending_scan=%s",
                job.job_id[:8], readiness["pending_scan_jobs"],
            )
            return

        probe_records = iv_db.get_probe_results_for_endpoint(
            db_path, endpoint_id, parameter_name, location
        )
        if not probe_records:
            # Fall back to all probes for the parameter_uuid.
            probe_records = iv_db.get_probe_results_for_param(db_path, parameter_uuid)

        if not probe_records:
            sched_db.mark_skipped(
                db_path, job.job_id, "iv_no_probe_results_for_analysis"
            )
            _log.info(
                "[iv] No probe results for reflection analysis %s — skipped.",
                job.job_id[:8],
            )
            return

        try:
            result = analyze_reflection(probe_records, parameter_name, endpoint_id)
            result["partial"] = bool(readiness.get("partial"))
            result["missing_required"] = list(readiness.get("missing_required") or [])
            iv_db.upsert_reflection_cache(
                db_path, endpoint_id, parameter_name, location,
                iv_db.STATUS_COMPLETED, result,
            )
            try:
                synthesize_param_profile(
                    db_path, parameter_uuid, persist=True, bump_version=True,
                )
            except Exception as synth_exc:  # noqa: BLE001
                _log.warning(
                    "[iv] Profile synthesis after reflection failed: %s",
                    synth_exc,
                )
            sched_db.mark_done(db_path, job.job_id, None, None)
            _log.info(
                "[iv] DONE  reflection  endpoint=%s  param=%s/%s  reflected=%s  "
                "partial=%s",
                endpoint_id[:8], location, parameter_name, result.get("reflected"),
                result.get("partial"),
            )
            self._continue_iv_plan_after_job(
                job, meta, db_path, self._project.id
            )
        except Exception as exc:  # noqa: BLE001
            _log.error("[iv] Reflection analysis failed for %s: %s", job.job_id[:8], exc)
            iv_db.upsert_reflection_cache(
                db_path, endpoint_id, parameter_name, location,
                iv_db.STATUS_FAILED, {"error": str(exc)},
            )
            sched_db.mark_failed(db_path, job.job_id, f"analysis_error: {exc}")
            self._continue_iv_plan_after_job(
                job, meta, db_path, self._project.id
            )


    # ------------------------------------------------------------------ #
    # Intruder session job execution                                       #
    # ------------------------------------------------------------------ #

    def _execute_intruder_job(self, job: ReplayJob) -> None:
        """
        Purpose:
            Run one time-sliced Intruder session segment inside the scheduler
            worker thread. Maps SegmentOutcome to mark_done/mark_failed and
            enqueues PRIORITY_AUTO continuation when verdict=continue.
        Side effects:
            HTTP via Intruder engine; updates intruder_sessions; scheduler_jobs.
        """
        import json as _json
        from datetime import datetime, timezone

        from talos.intruder.engine import run_session_segment
        from talos.intruder.session import continue_segment_job
        from talos.intruder import db as intruder_db
        from talos.projects.annotations import get_annotations

        db_path = self._project.db_path
        project_id = self._project.id

        meta: dict = {}
        if job.meta:
            try:
                meta = _json.loads(job.meta) if isinstance(job.meta, str) else dict(job.meta)
            except (_json.JSONDecodeError, TypeError, ValueError):
                meta = {}

        session_id = meta.get("session_id")
        segment = int(meta.get("segment") or 1)
        if not session_id:
            sched_db.mark_failed(db_path, job.job_id, "missing_session_id")
            _log.error("[intruder] Job %s missing meta.session_id", job.job_id[:8])
            return

        session = intruder_db.get_session(db_path, session_id)
        if session is None:
            sched_db.mark_failed(db_path, job.job_id, "session_not_found")
            return

        endpoint_id = session.get("endpoint_id") or job.endpoint_id
        if endpoint_id:
            try:
                ann = get_annotations(db_path, endpoint_id)
                if "logout" in ann:
                    sched_db.mark_skipped(db_path, job.job_id, "endpoint_annotated_logout")
                    intruder_db.update_session(
                        db_path,
                        session_id,
                        status="failed",
                        failure_reason="endpoint_annotated_logout",
                        finished_at=datetime.now(timezone.utc).isoformat(),
                        job_id=None,
                    )
                    return
            except Exception as exc:  # noqa: BLE001
                _log.debug("[intruder] annotation check skipped: %s", exc)

        should_stop = self._stop_event.is_set

        try:
            outcome = asyncio.run(
                run_session_segment(
                    session_id,
                    db_path,
                    project_id,
                    job_id=job.job_id,
                    should_stop=should_stop,
                )
            )
        except Exception as exc:  # noqa: BLE001
            _log.error("[intruder] Segment failed job=%s: %s", job.job_id[:8], exc)
            sched_db.mark_failed(db_path, job.job_id, f"intruder_error: {exc}")
            intruder_db.update_session(
                db_path,
                session_id,
                status="failed",
                failure_reason=str(exc),
                job_id=None,
            )
            return

        reason = outcome.reason
        _log.info(
            "[intruder] Segment done job=%s session=%s reason=%s attempts=%d",
            job.job_id[:8],
            session_id[:8],
            reason,
            outcome.attempts_this_segment,
        )

        if reason == "continue":
            sched_db.mark_done(db_path, job.job_id, None, "continue")
            sess = intruder_db.get_session(db_path, session_id)
            prog = dict((sess or {}).get("progress") or {})
            next_seg = int(prog.get("segment") or segment) + 1
            try:
                continue_segment_job(
                    db_path,
                    project_id,
                    session_id,
                    segment=next_seg,
                    endpoint_id=endpoint_id,
                    base_flow_id=(sess or {}).get("base_flow_id"),
                )
            except Exception as exc:  # noqa: BLE001
                _log.error("[intruder] Failed to enqueue continuation: %s", exc)
                intruder_db.update_session(
                    db_path,
                    session_id,
                    status="failed",
                    failure_reason=f"continue_enqueue_failed:{exc}",
                    job_id=None,
                )
            return

        if reason in ("paused", "process_stop"):
            sched_db.mark_done(db_path, job.job_id, None, "paused")
            return

        if reason == "cancelled":
            sched_db.mark_done(db_path, job.job_id, None, "cancelled")
            return

        if reason == "completed":
            sched_db.mark_done(db_path, job.job_id, None, "completed")
            return

        if reason == "failed":
            sched_db.mark_failed(
                db_path, job.job_id, outcome.error or "intruder_failed"
            )
            return

        sched_db.mark_done(db_path, job.job_id, None, reason)
