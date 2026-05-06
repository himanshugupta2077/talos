"""
Module: talos.ui.api.attacks

Purpose:
    REST routes for the attack modules page.
    Currently exposes the Unauthenticated Execution (unauth) attack:
    bulk-enqueue AUTH_TEST jobs, toggle auto-run, surface coverage stats,
    and manage per-host exclusions.

Dependencies:
    fastapi, pydantic, talos.scheduler.db, talos.scheduler.job,
    talos.projects.attack_config, talos.ui.db, talos.ui.api._deps

Data flow:
    GET  /api/attacks/unauth                    → coverage + paginated endpoint list
    POST /api/attacks/unauth/run-untested        → enqueue all untested endpoints
    POST /api/attacks/unauth/{endpoint_id}       → enqueue single endpoint
    GET  /api/attacks/unauth/auto                → {"enabled": bool}
    PUT  /api/attacks/unauth/auto                → toggle auto_run flag
    GET  /api/attacks/unauth/exclusions          → list excluded hosts
    POST /api/attacks/unauth/exclusions          → add host exclusion
    DELETE /api/attacks/unauth/exclusions/{host} → remove host exclusion

Side effects:
    POST routes write rows to scheduler_jobs.
    PUT /api/attacks/unauth/auto writes to attack_config.
    POST/DELETE /api/attacks/unauth/exclusions writes to attack_host_exclusions;
        POST also cancels any pending/running auth_test jobs for the host.
"""

import uuid
from urllib.parse import unquote

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from talos.projects.attack_config import (
    get_unauth_auto_run,
    set_unauth_auto_run,
    get_untested_endpoint_ids,
    add_unauth_exclusion,
    remove_unauth_exclusion,
    list_unauth_excluded_hosts,
)
from talos.scheduler import db as sched_db
from talos.scheduler.job import AUTH_TEST, PRIORITY_MANUAL, PRIORITY_AUTO
from talos.ui import db as idb
from talos.ui.api._deps import ActiveProject

router = APIRouter(prefix="/attacks", tags=["attacks"])


class _AutoRunBody(BaseModel):
    enabled: bool


class _ExclusionBody(BaseModel):
    # Accepts 'host' alone (e.g. 'api.example.com') or
    # 'host' + optional 'path' (e.g. path='/api/v1').
    # The UI may also send a single combined string like 'test.com/api/v1'
    # in the 'host' field — _parse_target handles that.
    host: str
    path: str = ""


def _parse_target(raw_host: str, raw_path: str = "") -> tuple[str, str]:
    """
    Parse a user-supplied target into (host, path).
    Accepts a combined 'host/path' string in raw_host, or separate fields.
    """
    combined = raw_host.strip().lower()
    for scheme in ("https://", "http://"):
        if combined.startswith(scheme):
            combined = combined[len(scheme):]
            break
    if "/" in combined:
        host, rest = combined.split("/", 1)
        path = "/" + rest.rstrip("/")
        if path == "/":
            path = ""
    else:
        host = combined
        path = raw_path.strip().lower() or ""
        if path and not path.startswith("/"):
            path = "/" + path
        path = path.rstrip("/") or ""
    return host, path


class _UnqueueResponse(BaseModel):
    enqueued: int
    skipped: int


@router.get("/unauth")
def get_unauth_status(
    project: ActiveProject,
    offset: int = 0,
    limit: int = 200,
) -> dict:
    """
    Purpose:
        Return aggregate coverage counts and a paginated per-endpoint list
        showing each endpoint's unauth test status and verdict.
    Input:   offset, limit — pagination controls.
    Output:
        Dict with keys:
            coverage  — {total, not_tested, queued, running, bypass, secure, unknown}
            endpoints — list of per-endpoint dicts
            auto_run  — bool
    Side effects: None.
    """
    coverage = idb.get_unauth_coverage(project.db_path)
    endpoints = idb.list_endpoint_unauth_status(
        project.db_path, offset=offset, limit=min(limit, 500)
    )
    auto_run = get_unauth_auto_run(project.db_path)
    return {
        "coverage": coverage,
        "endpoints": endpoints,
        "auto_run": auto_run,
    }


@router.get("/unauth/auto")
def get_unauth_auto(project: ActiveProject) -> dict:
    """
    Purpose: Return the current unauth auto-run setting.
    Output:  {"enabled": bool}
    Side effects: None.
    """
    return {"enabled": get_unauth_auto_run(project.db_path)}


@router.put("/unauth/auto")
def put_unauth_auto(body: _AutoRunBody, project: ActiveProject) -> dict:
    """
    Purpose: Enable or disable unauth auto-run in attack_config.
    Input:   body.enabled — desired state.
    Output:  {"enabled": bool} reflecting new state.
    Side effects: Writes attack_config table.
    """
    set_unauth_auto_run(project.db_path, body.enabled)
    return {"enabled": body.enabled}


@router.post("/unauth/run-untested")
def run_all_untested(project: ActiveProject) -> dict:
    """
    Purpose:
        Enqueue AUTH_TEST jobs at PRIORITY_MANUAL for every endpoint that has
        no existing auth_test_result and no pending/running AUTH_TEST job.
        Duplicate-safe: skips any endpoint already queued via has_pending_duplicate.
    Output:  {"enqueued": int, "skipped": int}
    Side effects: Inserts rows into scheduler_jobs.
    """
    untested_ids = get_untested_endpoint_ids(project.db_path, project.id)
    enqueued = 0
    skipped = 0
    for eid in untested_ids:
        if sched_db.has_pending_duplicate(project.db_path, AUTH_TEST, endpoint_id=eid):
            skipped += 1
            continue
        sched_db.enqueue_job(
            db_path=project.db_path,
            job_id=str(uuid.uuid4()),
            job_type=AUTH_TEST,
            priority=PRIORITY_MANUAL,
            project_id=project.id,
            endpoint_id=eid,
        )
        enqueued += 1
    return {"enqueued": enqueued, "skipped": skipped}


# ------------------------------------------------------------------ #
# Unauth host exclusions  (must be registered before /{endpoint_id}) #
# ------------------------------------------------------------------ #

@router.get("/unauth/exclusions")
def list_exclusions(project: ActiveProject) -> dict:
    """
    Purpose: Return all hosts excluded from unauth testing for the active project.
    Output:  {"exclusions": [{"host": str, "created_at": str}, ...]}
    Side effects: None.
    """
    entries = list_unauth_excluded_hosts(project.db_path)
    return {"exclusions": entries}


@router.post("/unauth/exclusions", status_code=201)
def add_exclusion(body: _ExclusionBody, project: ActiveProject) -> dict:
    """
    Purpose:
        Add a host (or host+path prefix) to the unauth exclusion list and cancel
        any pending/running auth_test jobs for that exclusion.
    Input:   body.host — hostname or combined 'host/path' string.
             body.path — optional separate path (ignored when host contains '/').
    Output:  {"host": str, "path": str, "already_present": bool, "jobs_cancelled": int}
    Side effects:
        Inserts into attack_host_exclusions; may update scheduler_jobs.
    """
    host, path = _parse_target(body.host, body.path)
    if not host:
        raise HTTPException(status_code=422, detail="host must not be empty.")
    inserted = add_unauth_exclusion(project.db_path, host, path)
    cancelled = sched_db.cancel_auth_test_jobs_for_host(project.db_path, host, path) if inserted else 0
    return {"host": host, "path": path, "already_present": not inserted, "jobs_cancelled": cancelled}


@router.delete("/unauth/exclusions/{target:path}")
def remove_exclusion(target: str, project: ActiveProject) -> dict:
    """
    Purpose: Remove a host (or host+path prefix) from the unauth exclusion list.
    Input:   target — URL path segment: host alone or host%2Fpath (slash-encoded).
             The segment is decoded then split on the first '/' to derive host+path.
    Output:  {"host": str, "path": str, "removed": True}
    Side effects: Deletes from attack_host_exclusions.
    Raises:  HTTPException(404) when entry not found.
    """
    host, path = _parse_target(unquote(target))
    removed = remove_unauth_exclusion(project.db_path, host, path)
    if not removed:
        label = host + path if path else host
        raise HTTPException(status_code=404, detail=f"Exclusion not found: {label}")
    return {"host": host, "path": path, "removed": True}


# ------------------------------------------------------------------ #
# Single-endpoint enqueue  (catch-all — must stay last)              #
# ------------------------------------------------------------------ #

@router.post("/unauth/{endpoint_id}")
def run_single_endpoint(endpoint_id: str, project: ActiveProject) -> dict:
    """
    Purpose:
        Enqueue an AUTH_TEST job for a single endpoint at PRIORITY_MANUAL.
        Returns 409 if a pending or running AUTH_TEST job already exists.
    Input:   endpoint_id — UUID of the target endpoint.
    Output:  {"enqueued": 1}
    Side effects: Inserts one row into scheduler_jobs.
    Raises:  HTTPException(409) on duplicate.
    """
    if sched_db.has_pending_duplicate(
        project.db_path, AUTH_TEST, endpoint_id=endpoint_id
    ):
        raise HTTPException(
            status_code=409,
            detail="An auth test job for this endpoint is already pending or running.",
        )
    sched_db.enqueue_job(
        db_path=project.db_path,
        job_id=str(uuid.uuid4()),
        job_type=AUTH_TEST,
        priority=PRIORITY_MANUAL,
        project_id=project.id,
        endpoint_id=endpoint_id,
    )
    return {"enqueued": 1}
