"""
Module: talos.scheduler.db

Purpose:
    Data access layer for the scheduler_jobs table in the per-project SQLite DB.
    Provides all CRUD operations required by both the scheduler execution loop
    and the CLI management commands:
        enqueue_job            — insert a new pending job.
        has_pending_duplicate  — deduplication check before enqueue.
        count_active_jobs      — overflow check before enqueue.
        get_next_pending       — scheduler poll (highest priority, FIFO within tier).
        mark_running           — claim a job when execution starts.
        mark_done              — record a successful outcome.
        mark_failed            — record an error outcome.
        mark_skipped           — record a safety-annotation skip.
        reset_stale_running    — crash recovery: reset running→pending on startup.
        get_queue_status       — count jobs by status for display.
        list_pending_jobs      — ordered list of pending jobs for display.
        clear_pending_jobs     — bulk-delete pending jobs.

    All functions call migrate_project_db on entry to ensure the
    scheduler_jobs table exists on databases created before v12.

Dependencies: sqlite3, pathlib, datetime, talos.projects.db, talos.scheduler.job
Data flow:
    scheduler.cli → enqueue_job() → DB
    scheduler.scheduler → get_next_pending(), mark_running(), mark_done(),
                          mark_failed(), mark_skipped() → DB
Side effects:
    - All write functions modify the scheduler_jobs table in the project SQLite DB.
    - migrate_project_db is called on every entry to ensure the table exists.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from talos.projects.db import migrate_project_db
from talos.scheduler.job import (

    PRIORITY_AUTO,
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_RUNNING,
    STATUS_SKIPPED,
    ReplayJob,
)


# ------------------------------------------------------------------ #
# Default config values                                                #
# ------------------------------------------------------------------ #

DEFAULT_MIN_DELAY: float = 2.0
"""Default minimum seconds to sleep between executed jobs."""

DEFAULT_MAX_DELAY: float = 6.0
"""Default maximum seconds to sleep between executed jobs."""

DEFAULT_MAX_QUEUE_SIZE: int = 200
"""Default hard ceiling on pending + running jobs."""


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _connect_rw(db_path: Path) -> sqlite3.Connection:
    """
    Purpose: Open a read-write SQLite connection with row_factory set.
    Input:   db_path — absolute Path to the project's talos.db.
    Output:  sqlite3.Connection. Caller is responsible for closing.
    Side effects: Opens a file descriptor.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _row_to_job(row: sqlite3.Row, db_path: Path, project_id: str) -> ReplayJob:
    """
    Purpose:
        Convert a scheduler_jobs DB row to a ReplayJob instance.
    Input:
        row        — sqlite3.Row from the scheduler_jobs table.
        db_path    — Path to the project's talos.db.
        project_id — Project identifier; not stored in the row.
    Output:
        ReplayJob with fields mapped from the row.
    Side effects:
        None.
    """
    return ReplayJob(
        job_id=row["job_id"],
        endpoint_id=row["endpoint_id"],
        flow_id=row["flow_id"],
        job_type=row["job_type"],
        priority=row["priority"],
        created_at=row["created_at"],
        db_path=db_path,
        project_id=project_id,
        status=row["status"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        failure_reason=row["failure_reason"],
        replayed_flow_id=row["replayed_flow_id"],
        verdict=row["verdict"],
        scheduled_at=row["scheduled_at"],
        meta=row["meta"] if "meta" in row.keys() else None,
    )


# ------------------------------------------------------------------ #
# Enqueue                                                              #
# ------------------------------------------------------------------ #

def enqueue_job(
    db_path: Path,
    job_id: str,
    job_type: str,
    project_id: str,
    endpoint_id: Optional[str] = None,
    flow_id: Optional[str] = None,
    priority: int = PRIORITY_AUTO,
    meta: Optional[str] = None,
) -> ReplayJob:
    """
    Purpose:
        Insert a new pending replay job into the scheduler_jobs table.
    Input:
        db_path     — Path to the project's talos.db.
        job_id      — UUID for the new job (caller generates).
        job_type    — REPLAY_FLOW | REPLAY_ENDPOINT | AUTH_TEST | BAC_*.
        project_id  — Project identifier.
        endpoint_id — Target endpoint UUID; None for replay_flow jobs.
        flow_id     — Target flow UUID; None for endpoint/auth jobs.
        priority    — Execution priority; higher runs first.
        meta        — Optional JSON string carrying attack-type metadata.
                      Required for BAC job types; None for all others.
    Output:
        The constructed ReplayJob reflecting what was written to the DB.
    Side effects:
        - Calls migrate_project_db once to ensure the table exists.
        - Inserts one row into scheduler_jobs.
    """
    migrate_project_db(db_path)
    created_at = _now_iso()

    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO scheduler_jobs
                (job_id, endpoint_id, flow_id, job_type, priority,
                 status, created_at, meta)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (job_id, endpoint_id, flow_id, job_type, priority,
             STATUS_PENDING, created_at, meta),
        )
        conn.commit()

    return ReplayJob(
        job_id=job_id,
        endpoint_id=endpoint_id,
        flow_id=flow_id,
        job_type=job_type,
        priority=priority,
        created_at=created_at,
        db_path=db_path,
        project_id=project_id,
        status=STATUS_PENDING,
        meta=meta,
    )


# ------------------------------------------------------------------ #
# Deduplication check                                                  #
# ------------------------------------------------------------------ #

def has_pending_duplicate(
    db_path: Path,
    job_type: str,
    endpoint_id: Optional[str] = None,
    flow_id: Optional[str] = None,
) -> bool:
    """
    Purpose:
        Check whether a pending job with the same identity already exists in
        the queue.  Prevents identical tests from accumulating before the
        scheduler has a chance to execute them.
    Input:
        db_path     — Path to the project's talos.db.
        job_type    — Job type to match (REPLAY_FLOW | REPLAY_ENDPOINT | AUTH_TEST).
        endpoint_id — Endpoint UUID to match; checked when not None.
        flow_id     — Flow UUID to match; checked when not None.
    Output:
        True if a duplicate pending job exists; False otherwise.
    Side effects:
        None (read-only after migration).
    """
    migrate_project_db(db_path)

    with _connect_rw(db_path) as conn:
        if endpoint_id is not None:
            row = conn.execute(
                """
                SELECT 1 FROM scheduler_jobs
                WHERE job_type = ? AND endpoint_id = ? AND status = ?
                LIMIT 1
                """,
                (job_type, endpoint_id, STATUS_PENDING),
            ).fetchone()
        elif flow_id is not None:
            row = conn.execute(
                """
                SELECT 1 FROM scheduler_jobs
                WHERE job_type = ? AND flow_id = ? AND status = ?
                LIMIT 1
                """,
                (job_type, flow_id, STATUS_PENDING),
            ).fetchone()
        else:
            return False

    return row is not None


def has_pending_bac_duplicate(
    db_path: Path,
    job_type: str,
    flow_id: str,
    attacker_role_id: str,
    variant: str,
) -> bool:
    """
    Purpose:
        Check whether a pending or running BAC job with the same identity already
        exists.  BAC jobs are identified by (job_type, flow_id, attacker_role_id,
        variant); using meta JSON fields prevents duplicate attack runs while still
        allowing retries after failure/skipped/done.
    Input:
        db_path          — Path to the project's talos.db.
        job_type         — BAC job type constant (e.g. BAC_SESSION_SWAP).
        flow_id          — Target flow UUID.
        attacker_role_id — UUID of the attacker role stored in meta JSON.
        variant          — Variant name stored in meta JSON.
    Output:
        True if a matching pending/running job exists; False otherwise.
    Side effects:
        None (read-only after migration).
    """
    migrate_project_db(db_path)

    with _connect_rw(db_path) as conn:
        row = conn.execute(
            """
            SELECT 1 FROM scheduler_jobs
            WHERE job_type = ?
              AND flow_id = ?
              AND status IN ('pending', 'running')
              AND json_extract(meta, '$.attacker_role_id') = ?
              AND json_extract(meta, '$.variant') = ?
            LIMIT 1
            """,
            (job_type, flow_id, attacker_role_id, variant),
        ).fetchone()
    return row is not None


# ------------------------------------------------------------------ #
# Queue size query                                                     #
# ------------------------------------------------------------------ #

def count_active_jobs(db_path: Path) -> int:
    """
    Purpose:
        Count pending + running jobs to enforce the max_queue_size limit.
        Both states represent jobs that have not yet been resolved.
    Input:   db_path — Path to the project's talos.db.
    Output:  Number of jobs currently in pending or running state.
    Side effects: None (read-only after migration).
    """
    migrate_project_db(db_path)

    with _connect_rw(db_path) as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) FROM scheduler_jobs
            WHERE status IN (?, ?)
            """,
            (STATUS_PENDING, STATUS_RUNNING),
        ).fetchone()

    return row[0] if row else 0


# ------------------------------------------------------------------ #
# Scheduler polling                                                    #
# ------------------------------------------------------------------ #

def get_next_pending(db_path: Path, project_id: str) -> Optional[ReplayJob]:
    """
    Purpose:
        Fetch the highest-priority pending job without claiming it.
        Ordering: priority DESC (high first), then created_at ASC (FIFO within tier).
        Returns None when the queue contains no pending jobs.
    Input:
        db_path    — Path to the project's talos.db.
        project_id — Project identifier; stamped onto the returned ReplayJob.
    Output:
        The next ReplayJob to execute, or None.
    Side effects:
        None (read-only).
    """
    with _connect_rw(db_path) as conn:
        row = conn.execute(
            """
            SELECT job_id, endpoint_id, flow_id, job_type, priority,
                   status, created_at, scheduled_at, started_at, finished_at,
                   failure_reason, replayed_flow_id, verdict, meta
            FROM scheduler_jobs
            WHERE status = ?
            ORDER BY priority DESC, created_at ASC
            LIMIT 1
            """,
            (STATUS_PENDING,),
        ).fetchone()

    if row is None:
        return None

    return _row_to_job(row, db_path, project_id)


def mark_running(db_path: Path, job_id: str) -> None:
    """
    Purpose:
        Transition a job from pending → running and record the start timestamp.
        Called immediately before execution so the DB reflects the current state
        even if the process crashes mid-execution.
    Input:
        db_path — Path to the project's talos.db.
        job_id  — UUID of the job to claim.
    Side effects:
        Updates one row in scheduler_jobs.
    """
    with _connect_rw(db_path) as conn:
        now = _now_iso()
        conn.execute(
            "UPDATE scheduler_jobs SET status = ?, scheduled_at = ?, started_at = ? WHERE job_id = ?",
            (STATUS_RUNNING, now, now, job_id),
        )
        conn.commit()


def mark_done(
    db_path: Path,
    job_id: str,
    replayed_flow_id: Optional[str],
    verdict: Optional[str],
) -> None:
    """
    Purpose:
        Transition a job from running → done and record the outcome.
    Input:
        db_path          — Path to the project's talos.db.
        job_id           — UUID of the completed job.
        replayed_flow_id — UUID of the replay flow that was stored.
        verdict          — Diff or auth verdict string from the engine.
    Side effects:
        Updates one row in scheduler_jobs.
    """
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            UPDATE scheduler_jobs
            SET status = ?, finished_at = ?, replayed_flow_id = ?, verdict = ?
            WHERE job_id = ?
            """,
            (STATUS_DONE, _now_iso(), replayed_flow_id, verdict, job_id),
        )
        conn.commit()


def mark_failed(db_path: Path, job_id: str, failure_reason: str) -> None:
    """
    Purpose:
        Transition a job from running → failed and record the error.
    Input:
        db_path        — Path to the project's talos.db.
        job_id         — UUID of the failed job.
        failure_reason — Human-readable description of the failure.
    Side effects:
        Updates one row in scheduler_jobs.
    """
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            UPDATE scheduler_jobs
            SET status = ?, finished_at = ?, failure_reason = ?
            WHERE job_id = ?
            """,
            (STATUS_FAILED, _now_iso(), failure_reason, job_id),
        )
        conn.commit()


def mark_skipped(db_path: Path, job_id: str, reason: str) -> None:
    """
    Purpose:
        Transition a job from running → skipped when a safety guard fires
        before any HTTP request is sent (e.g. endpoint annotated logout/dangerous,
        no qualifying flow, auth config empty).
    Input:
        db_path — Path to the project's talos.db.
        job_id  — UUID of the skipped job.
        reason  — Guard label that triggered the skip.
    Side effects:
        Updates one row in scheduler_jobs.
    """
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            UPDATE scheduler_jobs
            SET status = ?, finished_at = ?, failure_reason = ?
            WHERE job_id = ?
            """,
            (STATUS_SKIPPED, _now_iso(), reason, job_id),
        )
        conn.commit()


# ------------------------------------------------------------------ #
# Startup crash recovery                                               #
# ------------------------------------------------------------------ #

def reset_stale_running(db_path: Path) -> int:
    """
    Purpose:
        On scheduler startup, any job left in 'running' state from a previous
        crashed session is reset to 'pending' so it will be retried.
        This prevents jobs from being permanently stuck after a SIGKILL.
    Input:   db_path — Path to the project's talos.db.
    Output:  Number of jobs reset to pending.
    Side effects:
        Updates rows in scheduler_jobs; commits.
    """
    migrate_project_db(db_path)

    with _connect_rw(db_path) as conn:
        cursor = conn.execute(
            "UPDATE scheduler_jobs SET status = ?, started_at = NULL WHERE status = ?",
            (STATUS_PENDING, STATUS_RUNNING),
        )
        conn.commit()
        return cursor.rowcount


# ------------------------------------------------------------------ #
# Status queries                                                       #
# ------------------------------------------------------------------ #

def get_queue_status(db_path: Path) -> dict:
    """
    Purpose:
        Return a count of jobs grouped by status for display.
        Used by 'talos scheduler status'.
    Input:   db_path — Path to the project's talos.db.
    Output:  Dict mapping status string → integer count.
    Side effects: None (read-only after migration).
    """
    migrate_project_db(db_path)

    with _connect_rw(db_path) as conn:
        rows = conn.execute(
            """
            SELECT status, COUNT(*) AS n
            FROM scheduler_jobs
            GROUP BY status
            """,
        ).fetchall()

    return {row["status"]: row["n"] for row in rows}


def list_pending_jobs(db_path: Path, project_id: str) -> list:
    """
    Purpose:
        Return all pending jobs in execution order.
        Used by 'talos scheduler status' to show what is queued next.
    Input:
        db_path    — Path to the project's talos.db.
        project_id — Project identifier for ReplayJob construction.
    Output:
        List of ReplayJob instances ordered by priority DESC, created_at ASC.
    Side effects:
        None (read-only).
    """
    with _connect_rw(db_path) as conn:
        rows = conn.execute(
            """
            SELECT job_id, endpoint_id, flow_id, job_type, priority,
                   status, created_at, scheduled_at, started_at, finished_at,
                   failure_reason, replayed_flow_id, verdict
            FROM scheduler_jobs
            WHERE status = ?
            ORDER BY priority DESC, created_at ASC
            """,
            (STATUS_PENDING,),
        ).fetchall()

    return [_row_to_job(row, db_path, project_id) for row in rows]


# ------------------------------------------------------------------ #
# Queue management                                                     #
# ------------------------------------------------------------------ #

def clear_pending_jobs(db_path: Path) -> int:
    """
    Purpose:
        Remove all pending jobs from the queue.
        Running, done, failed, and skipped jobs are not affected.
    Input:   db_path — Path to the project's talos.db.
    Output:  Number of rows deleted.
    Side effects:
        Deletes rows from scheduler_jobs; commits.
    """
    migrate_project_db(db_path)

    with _connect_rw(db_path) as conn:
        cursor = conn.execute(
            "DELETE FROM scheduler_jobs WHERE status = ?",
            (STATUS_PENDING,),
        )
        conn.commit()
        return cursor.rowcount


# ------------------------------------------------------------------ #
# Scheduler configuration                                              #
# ------------------------------------------------------------------ #

def get_scheduler_config(db_path: Path) -> dict:
    """
    Purpose:
        Read the scheduler configuration from the scheduler_config table.
        Returns hardcoded defaults when the table is empty (fresh DB or
        config was never explicitly set).
    Input:   db_path — Path to the project's talos.db.
    Output:  Dict with keys: min_delay (float), max_delay (float),
             max_queue_size (int).
    Side effects: None (read-only after migration).
    """
    migrate_project_db(db_path)

    with _connect_rw(db_path) as conn:
        row = conn.execute(
            "SELECT min_delay, max_delay, max_queue_size FROM scheduler_config LIMIT 1"
        ).fetchone()

    if row is None:
        return {
            "min_delay": DEFAULT_MIN_DELAY,
            "max_delay": DEFAULT_MAX_DELAY,
            "max_queue_size": DEFAULT_MAX_QUEUE_SIZE,
        }

    return {
        "min_delay": row["min_delay"],
        "max_delay": row["max_delay"],
        "max_queue_size": row["max_queue_size"],
    }


def set_scheduler_config(
    db_path: Path,
    min_delay: float,
    max_delay: float,
    max_queue_size: int,
) -> None:
    """
    Purpose:
        Persist scheduler configuration.  The table holds at most one row;
        this function deletes any existing row then inserts the new values.
    Input:
        db_path        — Path to the project's talos.db.
        min_delay      — Minimum seconds between jobs (must be > 0).
        max_delay      — Maximum seconds between jobs (must be >= min_delay).
        max_queue_size — Maximum pending + running jobs allowed.
    Side effects:
        Deletes the existing config row (if any); inserts the new one; commits.
    """
    migrate_project_db(db_path)

    with _connect_rw(db_path) as conn:
        conn.execute("DELETE FROM scheduler_config")
        conn.execute(
            "INSERT INTO scheduler_config (min_delay, max_delay, max_queue_size) VALUES (?, ?, ?)",
            (min_delay, max_delay, max_queue_size),
        )
        conn.commit()


# ------------------------------------------------------------------ #
# Execution metrics                                                    #
# ------------------------------------------------------------------ #

def get_queue_metrics(db_path: Path) -> dict:
    """
    Purpose:
        Return aggregate execution metrics for display in 'talos scheduler status'.
    Input:   db_path — Path to the project's talos.db.
    Output:  Dict with keys:
                total_jobs              — int, total jobs ever recorded.
                avg_execution_delay_s   — float | None, average seconds from
                                          scheduled_at to finished_at for done jobs.
                last_executed_at        — str | None, ISO-8601 of last finished job.
    Side effects: None (read-only after migration).
    """
    migrate_project_db(db_path)

    with _connect_rw(db_path) as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS total_jobs,
                AVG(
                    (julianday(finished_at) - julianday(scheduled_at)) * 86400.0
                ) AS avg_delay,
                MAX(finished_at) AS last_executed_at
            FROM scheduler_jobs
            WHERE status = 'done'
              AND scheduled_at IS NOT NULL
              AND finished_at  IS NOT NULL
            """
        ).fetchone()

    if row is None:
        return {"total_jobs": 0, "avg_execution_delay_s": None, "last_executed_at": None}

    return {
        "total_jobs": row["total_jobs"],
        "avg_execution_delay_s": row["avg_delay"],
        "last_executed_at": row["last_executed_at"],
    }


# ------------------------------------------------------------------ #
# Host-scoped job cancellation                                         #
# ------------------------------------------------------------------ #

def cancel_auth_test_jobs_for_host(db_path: Path, host: str, path: str = "") -> int:
    """
    Purpose:
        Mark all pending and running AUTH_TEST scheduler jobs for a given host
        (or host+path prefix) as skipped.  Called when an entry is added to the
        unauth exclusion list.

        - path == '' (default) → cancel all jobs for every endpoint on that host.
        - path != ''           → cancel only jobs whose endpoint's normalized_path
                                 equals path OR starts with path + '/'.

    Input:
        db_path — Path to the project's talos.db.
        host    — Hostname to match against the endpoint's host column.
        path    — Optional path prefix.  Empty string means all paths on host.
    Output:
        Number of jobs cancelled (transitioned to skipped).
    Side effects:
        Updates rows in scheduler_jobs; commits.
    """
    migrate_project_db(db_path)
    now = _now_iso()

    with _connect_rw(db_path) as conn:
        if path:
            cursor = conn.execute(
                """
                UPDATE scheduler_jobs
                SET status = ?, finished_at = ?, failure_reason = ?
                WHERE job_type = 'auth_test'
                  AND status IN ('pending', 'running')
                  AND endpoint_id IN (
                      SELECT id FROM endpoints
                      WHERE host = ?
                        AND (normalized_path = ? OR normalized_path LIKE ? || '/%')
                  )
                """,
                (STATUS_SKIPPED, now, "host_excluded", host, path, path),
            )
        else:
            cursor = conn.execute(
                """
                UPDATE scheduler_jobs
                SET status = ?, finished_at = ?, failure_reason = ?
                WHERE job_type = 'auth_test'
                  AND status IN ('pending', 'running')
                  AND endpoint_id IN (
                      SELECT id FROM endpoints WHERE host = ?
                  )
                """,
                (STATUS_SKIPPED, now, "host_excluded", host),
            )
        conn.commit()
        return cursor.rowcount
