"""
Module: talos.ui.api.scheduler

Purpose:
    REST routes for reading and managing the replay scheduler queue.
    The scheduler daemon runs inside the proxy process — these routes
    read/write its state table, not the daemon itself.

Dependencies: fastapi, pydantic, talos.scheduler.db, talos.ui.api._deps
Data flow:
    HTTP GET  → sched_db.get_queue_status / list_pending_jobs / get_scheduler_config → JSON
    HTTP PUT  → sched_db.set_scheduler_config → scheduler_config table
    HTTP DELETE → sched_db.clear_pending_jobs → scheduler_jobs table
Side effects:
    PUT /api/scheduler/config   — writes scheduler_config table.
    DELETE /api/scheduler/queue — deletes pending rows from scheduler_jobs.

Routes:
    GET    /api/scheduler              → queue status + pending jobs + current config
    GET    /api/scheduler/jobs         → jobs filtered by ?status=<status>
    PUT    /api/scheduler/config       → update scheduler config
    DELETE /api/scheduler/queue        → clear all pending jobs
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional

from talos.scheduler import db as sched_db
from talos.ui.api._deps import ActiveProject

router = APIRouter(prefix="/scheduler", tags=["scheduler"])


def _job_to_dict(job) -> dict:
    """
    Purpose:
        Convert a ReplayJob dataclass to a JSON-safe dict.
        Excludes db_path (Path object, not serialisable).
    Side effects: None.
    """
    return {
        "job_id": job.job_id,
        "endpoint_id": job.endpoint_id,
        "flow_id": job.flow_id,
        "job_type": job.job_type,
        "priority": job.priority,
        "status": job.status,
        "created_at": job.created_at,
        "scheduled_at": job.scheduled_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "failure_reason": job.failure_reason,
        "replayed_flow_id": job.replayed_flow_id,
        "verdict": job.verdict,
    }


class _ConfigBody(BaseModel):
    min_delay: Optional[float] = None
    max_delay: Optional[float] = None
    max_queue_size: Optional[int] = None


@router.get("/jobs")
def get_jobs_by_status(
    project: ActiveProject,
    status: str = Query(..., description="Job status: pending|running|done|failed|skipped"),
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict:
    """
    Purpose:
        Return scheduler jobs filtered by a single status value.
        Used by the UI to show per-status detail tables on the scheduler page.
    Input:
        status — one of pending | running | done | failed | skipped.
        limit  — max rows (1–500, default 200).
        offset — row offset for pagination.
    Output:
        Dict: jobs (list of job dicts), total (count for that status).
    Side effects: None.
    Raises:  HTTPException(422) for invalid status values.
    """
    valid = {"pending", "running", "done", "failed", "skipped"}
    if status not in valid:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status '{status}'. Must be one of: {', '.join(sorted(valid))}.",
        )
    jobs = sched_db.list_jobs_by_status(
        project.db_path, project.id, status, limit=limit, offset=offset
    )
    counts = sched_db.get_queue_status(project.db_path)
    return {
        "jobs": [_job_to_dict(j) for j in jobs],
        "total": counts.get(status, 0),
    }


@router.get("")
def get_scheduler_status(project: ActiveProject) -> dict:
    """
    Purpose: Return queue depth by status, pending jobs in order, and current config.
    Output:  Dict: counts (status→int), pending (list of job dicts), config.
    Side effects: None.
    """
    counts = sched_db.get_queue_status(project.db_path)
    pending_jobs = sched_db.list_pending_jobs(project.db_path, project.id)
    config = sched_db.get_scheduler_config(project.db_path)
    return {
        "counts": counts,
        "pending": [_job_to_dict(j) for j in pending_jobs],
        "config": config,
    }


@router.put("/config")
def update_scheduler_config(body: _ConfigBody, project: ActiveProject) -> dict:
    """
    Purpose: Update one or more scheduler config values.
    Input:   body — any combination of min_delay, max_delay, max_queue_size.
             Fields absent (None) are left at their current values.
    Output:  The updated config dict.
    Side effects: Writes scheduler_config table.
    """
    current = sched_db.get_scheduler_config(project.db_path)
    new_min = body.min_delay if body.min_delay is not None else current["min_delay"]
    new_max = body.max_delay if body.max_delay is not None else current["max_delay"]
    new_size = body.max_queue_size if body.max_queue_size is not None else current["max_queue_size"]
    sched_db.set_scheduler_config(project.db_path, new_min, new_max, new_size)
    return sched_db.get_scheduler_config(project.db_path)


@router.delete("/queue")
def clear_queue(project: ActiveProject) -> dict:
    """
    Purpose: Remove all pending jobs from the scheduler queue.
             Running, done, failed, and skipped jobs are unaffected.
    Output:  Dict: cleared (int count of deleted rows).
    Side effects: Deletes rows from scheduler_jobs.
    """
    count = sched_db.clear_pending_jobs(project.db_path)
    return {"cleared": count}
