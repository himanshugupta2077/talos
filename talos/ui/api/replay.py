"""
Module: talos.ui.api.replay

Purpose:
    REST routes for triggering flow and endpoint replays from the active project.
    Two execution modes per target:
        enqueue — adds a job to the scheduler queue (default); returns job_id.
        now     — executes the replay immediately in-process; returns full outcome.

    Applies the same annotation guards as the CLI:
        logout    → blocked in all modes.
        dangerous → blocked in enqueue mode (scheduler auto priority); allowed immediately.

Dependencies: fastapi, pydantic, talos.replay.engine, talos.scheduler.db,
              talos.scheduler.job, talos.ui.api._deps
Data flow:
    POST /replay/flow/{id}         → enqueue_job()  → scheduler_jobs table
    POST /replay/flow/{id}/now     → replay_engine.replay_flow() → DB + diff
    POST /replay/endpoint/{id}     → enqueue_job()  → scheduler_jobs table
    POST /replay/endpoint/{id}/now → replay_engine.replay_endpoint() → DB + diff
Side effects:
    enqueue modes  — inserts one row into scheduler_jobs.
    now modes      — sends outbound HTTP request; writes replay flow + diff to DB.

Routes:
    POST /api/replay/flow/{flow_id}          → enqueue flow replay
    POST /api/replay/flow/{flow_id}/now      → immediate flow replay
    POST /api/replay/endpoint/{endpoint_id}  → enqueue endpoint replay
    POST /api/replay/endpoint/{endpoint_id}/now → immediate endpoint replay
"""

import uuid
from dataclasses import asdict

from fastapi import APIRouter, HTTPException

from talos.replay import engine as replay_engine
from talos.scheduler import db as sched_db
from talos.scheduler.job import PRIORITY_MANUAL, REPLAY_ENDPOINT, REPLAY_FLOW
from talos.ui.api._deps import ActiveProject

router = APIRouter(prefix="/replay", tags=["replay"])


def _outcome_to_dict(outcome) -> dict:
    """
    Purpose: Convert a ReplayOutcome dataclass to a JSON-safe dict.
    Side effects: None.
    """
    return {
        "original_flow_id": outcome.original_flow_id,
        "replayed_flow_id": outcome.replayed_flow_id,
        "status_code": outcome.status_code,
        "success": outcome.success,
        "failure_reason": outcome.failure_reason,
        "verdict": outcome.verdict,
    }


# ------------------------------------------------------------------ #
# Flow replay                                                          #
# ------------------------------------------------------------------ #

@router.post("/flow/{flow_id}")
def enqueue_flow_replay(flow_id: str, project: ActiveProject) -> dict:
    """
    Purpose: Add a flow replay job to the scheduler queue.
    Input:   flow_id — UUID of the flow to replay.
    Output:  Dict: job_id, flow_id, status="pending".
    Side effects: Inserts one row into scheduler_jobs.
    """
    job_id = str(uuid.uuid4())
    sched_db.enqueue_job(
        db_path=project.db_path,
        job_id=job_id,
        job_type=REPLAY_FLOW,
        project_id=project.id,
        flow_id=flow_id,
        priority=PRIORITY_MANUAL,
    )
    return {"job_id": job_id, "flow_id": flow_id, "status": "pending"}


@router.post("/flow/{flow_id}/now")
async def replay_flow_now(flow_id: str, project: ActiveProject) -> dict:
    """
    Purpose: Execute a flow replay immediately in-process.
    Input:   flow_id — UUID of the flow to replay.
    Output:  ReplayOutcome dict: original_flow_id, replayed_flow_id, status_code,
             success, failure_reason, verdict.
    Side effects: Sends outbound HTTP request; writes replay flow + diff to DB.
    Raises:  404 if flow not found (via failure_reason in outcome).
    """
    outcome = await replay_engine.replay_flow(
        flow_id=flow_id,
        db_path=project.db_path,
        project_id=project.id,
        source="manual_replay",
        replay_reason="testing",
    )
    if outcome.failure_reason == "flow_not_found":
        raise HTTPException(status_code=404, detail="Flow not found")
    return _outcome_to_dict(outcome)


# ------------------------------------------------------------------ #
# Endpoint replay                                                      #
# ------------------------------------------------------------------ #

@router.post("/endpoint/{endpoint_id}")
def enqueue_endpoint_replay(endpoint_id: str, project: ActiveProject) -> dict:
    """
    Purpose: Add an endpoint replay job to the scheduler queue.
    Input:   endpoint_id — UUID of the endpoint to replay.
    Output:  Dict: job_id, endpoint_id, status="pending".
    Side effects: Inserts one row into scheduler_jobs.
    """
    job_id = str(uuid.uuid4())
    sched_db.enqueue_job(
        db_path=project.db_path,
        job_id=job_id,
        job_type=REPLAY_ENDPOINT,
        project_id=project.id,
        endpoint_id=endpoint_id,
        priority=PRIORITY_MANUAL,
    )
    return {"job_id": job_id, "endpoint_id": endpoint_id, "status": "pending"}


@router.post("/endpoint/{endpoint_id}/now")
async def replay_endpoint_now(endpoint_id: str, project: ActiveProject) -> dict:
    """
    Purpose: Execute an endpoint replay immediately in-process.
             Selects the best qualifying flow (most recent 200 OK proxy_capture).
    Input:   endpoint_id — UUID of the endpoint to replay.
    Output:  ReplayOutcome dict.
    Side effects: Sends outbound HTTP request; writes replay flow + diff to DB.
    Raises:  404 if endpoint not found or has no qualifying flow.
    """
    outcome = await replay_engine.replay_endpoint(
        endpoint_id=endpoint_id,
        db_path=project.db_path,
        project_id=project.id,
        source="manual_replay",
        replay_reason="testing",
    )
    if outcome.failure_reason in ("no_qualifying_flow", "endpoint_annotated_logout"):
        raise HTTPException(status_code=404, detail=outcome.failure_reason)
    return _outcome_to_dict(outcome)
