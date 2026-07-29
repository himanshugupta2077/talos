"""
Module: talos.ai.tools.handlers.replay_send

Purpose:
    Phase D HTTP tools: send.once (ai_send) and replay.flow (enqueue-only).
    Handlers call existing Python APIs only — never subprocess.

Dependencies: talos.send.engine, talos.scheduler.db, scope_policy helpers
Data flow:
    Executor → handler → send_once / enqueue_job → HandlerResult
Side effects:
    HTTP send (send.once); INSERT scheduler_jobs (replay.flow).
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

from talos.ai.models import ExecutionPlan, HandlerResult, ProjectContext
from talos.ai.tools import scope_policy as sp
from talos.scheduler import db as sched_db
from talos.scheduler.job import REPLAY_FLOW
from talos.send.engine import send_once


def handle_send_once(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    """
    Fork parent flow, apply ≤20 edits, send with source=ai_send.
    Non-idempotent: each execute is a new HTTP request.
    """
    parent_flow_id = str(args["parent_flow_id"]).strip()
    edits = args.get("edits") or []
    if not isinstance(edits, list):
        edits = []
    if len(edits) > 20:
        return HandlerResult(
            success=False,
            summary="too many edits",
            error="send.once allows at most 20 edits",
        )

    reason = args.get("reason")
    kwargs = sp.edits_to_send_kwargs(edits)

    try:
        outcome = asyncio.run(
            send_once(
                parent_flow_id,
                ctx.db_path,
                ctx.project_id,
                source="ai_send",
                reason=reason,
                session_id=ctx.session_id,
                **kwargs,
            )
        )
    except Exception as exc:  # noqa: BLE001
        return HandlerResult(
            success=False,
            summary="send failed",
            error=f"{type(exc).__name__}: {exc}",
        )

    data = {
        "execution_flow_id": outcome.execution_flow_id,
        "parent_flow_id": outcome.parent_flow_id,
        "original_flow_id": outcome.original_flow_id,
        "status_code": outcome.status_code,
        "success": outcome.success,
        "failure_reason": outcome.failure_reason,
        "verdict": outcome.verdict,
        "source": outcome.source,
        "edits_applied": len(edits),
        "policy_meta": {
            "effective_url": (plan.policy_meta or {}).get("effective_url"),
            "annotations": (plan.policy_meta or {}).get("annotations"),
        },
    }
    if not outcome.success:
        return HandlerResult(
            success=False,
            summary=outcome.failure_reason or "send failed",
            error=outcome.failure_reason or "send failed",
            data=data,
            citations={
                "parent_flow_id": parent_flow_id,
                "execution_flow_id": outcome.execution_flow_id,
            },
        )

    return HandlerResult(
        success=True,
        summary=(
            f"ai_send status={outcome.status_code} "
            f"flow={outcome.execution_flow_id}"
        ),
        data=data,
        citations={
            "parent_flow_id": parent_flow_id,
            "execution_flow_id": outcome.execution_flow_id,
            "status_code": outcome.status_code,
        },
    )


def handle_replay_flow(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    """
    Enqueue a REPLAY_FLOW job (v1: enqueue only, never right-now).
    Priority: PRIORITY_AI_AUTO unless human-approved dangerous.
    """
    flow_id = str(args["flow_id"]).strip()
    force_dangerous = bool((plan.policy_meta or {}).get("ai_force_dangerous"))
    priority = sp.ai_job_priority(force_dangerous=force_dangerous)
    meta = sp.ai_job_meta(
        session_id=plan.session_id,
        suggestion_id=plan.suggestion_id,
        force_dangerous=force_dangerous,
        extra={"reason": args.get("reason")},
    )

    # Confirm flow still exists (policy already checked; race-safe).
    flow = sp.resolve_flow_target(ctx.db_path, flow_id=flow_id)
    if flow is None:
        return HandlerResult(
            success=False,
            summary="flow not found",
            error=f"Flow not found: {flow_id}",
        )

    job_id = str(uuid.uuid4())
    try:
        job = sched_db.enqueue_job(
            db_path=ctx.db_path,
            job_id=job_id,
            job_type=REPLAY_FLOW,
            project_id=ctx.project_id,
            flow_id=flow_id,
            endpoint_id=flow.get("endpoint_id"),
            priority=priority,
            meta=json.dumps(meta),
        )
    except Exception as exc:  # noqa: BLE001
        return HandlerResult(
            success=False,
            summary="enqueue failed",
            error=f"{type(exc).__name__}: {exc}",
        )

    return HandlerResult(
        success=True,
        summary=f"enqueued replay_flow job={job.job_id} priority={priority}",
        data={
            "job_id": job.job_id,
            "job_type": REPLAY_FLOW,
            "status": job.status,
            "priority": priority,
            "flow_id": flow_id,
            "meta": meta,
        },
        citations={"job_id": job.job_id, "flow_id": flow_id},
    )
