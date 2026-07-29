"""
Module: talos.ai.tools.handlers.inventory

Purpose:
    READ tool handlers: endpoints, flows, findings, IV intel, passive,
    error intel, access coverage, scheduler jobs, intruder.suggest.

Dependencies: existing talos.* Python APIs only (no subprocess).
Data flow:
    Executor → handler.execute → core APIs → HandlerResult
Side effects: None (read-only).
"""

from __future__ import annotations

from typing import Any

from talos.ai.models import ExecutionPlan, HandlerResult, ProjectContext
from talos.findings import db as findings_db
from talos.input_validation.candidates import get_param_intelligence, list_candidates
from talos.projects.access import get_access_coverage
from talos.projects.policy import format_endpoint_list_json, list_endpoints
from talos.replay import db as replay_db
from talos.replay.diff import compute_diff
from talos.scheduler import db as sched_db


def _truncate_list(items: list, limit: int) -> list:
    return items[: max(0, limit)]


def handle_endpoint_list(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    qualified_only = bool(args.get("qualified_only", False))
    limit = int(args.get("limit", 50))
    rows = list_endpoints(
        ctx.db_path,
        ctx.project_id,
        method=args.get("method"),
        host=args.get("host"),
        qualified=True if qualified_only else None,
        search=args.get("search"),
    )
    rows = _truncate_list(rows, limit)
    payload = format_endpoint_list_json(rows)
    return HandlerResult(
        success=True,
        summary=f"{len(rows)} endpoint(s)",
        data=payload if isinstance(payload, dict) else {"endpoints": rows},
        citations={"endpoint_ids": [r.get("id") for r in rows if r.get("id")]},
    )


def handle_endpoint_show(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    endpoint_id = str(args["endpoint_id"]).strip()
    rows = list_endpoints(ctx.db_path, ctx.project_id)
    match = next((r for r in rows if r.get("id") == endpoint_id), None)
    if match is None:
        return HandlerResult(
            success=False,
            summary="endpoint not found",
            error=f"Endpoint not found: {endpoint_id}",
        )
    return HandlerResult(
        success=True,
        summary=f"{match.get('method', '')} {match.get('host', '')}{match.get('normalized_path') or match.get('path', '')}",
        data={"endpoint": match},
        citations={"endpoint_id": endpoint_id},
    )


def _flow_to_safe_dict(flow: dict, *, include_bodies: bool) -> dict[str, Any]:
    """Strip or truncate bodies for observation safety."""
    out = {
        "id": flow.get("id"),
        "method": flow.get("method"),
        "url": flow.get("url"),
        "host": flow.get("host"),
        "path": flow.get("path"),
        "query": flow.get("query"),
        "status_code": flow.get("status_code"),
        "content_type": flow.get("content_type"),
        "endpoint_id": flow.get("endpoint_id"),
        "role_id": flow.get("role_id"),
        "module_id": flow.get("module_id"),
        "source": flow.get("source"),
        "captured_at": flow.get("captured_at"),
        "request_headers": flow.get("request_headers"),
        "response_headers": flow.get("response_headers"),
    }
    if include_bodies:
        req = flow.get("request_body")
        resp = flow.get("response_body")
        # Cap body excerpts at 4096 bytes for observations.
        if isinstance(req, (bytes, bytearray)):
            out["request_body_excerpt"] = bytes(req[:4096]).decode("utf-8", errors="replace")
            out["request_body_truncated"] = len(req) > 4096 or bool(
                flow.get("request_body_truncated")
            )
        elif isinstance(req, str):
            out["request_body_excerpt"] = req[:4096]
            out["request_body_truncated"] = len(req) > 4096
        if isinstance(resp, (bytes, bytearray)):
            out["response_body_excerpt"] = bytes(resp[:4096]).decode(
                "utf-8", errors="replace"
            )
            out["response_body_truncated"] = len(resp) > 4096 or bool(
                flow.get("response_body_truncated")
            )
        elif isinstance(resp, str):
            out["response_body_excerpt"] = resp[:4096]
            out["response_body_truncated"] = len(resp) > 4096
    return out


def handle_flow_show(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    flow_id = str(args["flow_id"]).strip()
    include_bodies = bool(args.get("include_bodies", False))
    flow = replay_db.get_flow_for_replay(ctx.db_path, flow_id)
    if flow is None:
        return HandlerResult(
            success=False,
            summary="flow not found",
            error=f"Flow not found: {flow_id}",
        )
    safe = _flow_to_safe_dict(flow, include_bodies=include_bodies)
    return HandlerResult(
        success=True,
        summary=f"{safe.get('method')} {safe.get('url')} → {safe.get('status_code')}",
        data={"flow": safe},
        citations={"flow_id": flow_id},
    )


def handle_flow_diff(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    flow_a = replay_db.get_flow_for_replay(ctx.db_path, str(args["flow_a"]).strip())
    flow_b = replay_db.get_flow_for_replay(ctx.db_path, str(args["flow_b"]).strip())
    if flow_a is None:
        return HandlerResult(
            success=False,
            summary="flow_a not found",
            error=f"Flow not found: {args['flow_a']}",
        )
    if flow_b is None:
        return HandlerResult(
            success=False,
            summary="flow_b not found",
            error=f"Flow not found: {args['flow_b']}",
        )
    # compute_diff expects original vs replay shape; reuse for any two flows.
    result = compute_diff(flow_a, flow_b)
    data = {
        "verdict": result.verdict,
        "status_changed": result.status_changed,
        "status_diff": result.status_diff,
        "length_diff": result.length_diff,
        "flow_a": flow_a.get("id"),
        "flow_b": flow_b.get("id"),
    }
    return HandlerResult(
        success=True,
        summary=f"diff verdict={result.verdict}",
        data=data,
        citations={"flow_ids": [flow_a.get("id"), flow_b.get("id")]},
    )


def handle_param_intelligence(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    intel = get_param_intelligence(
        ctx.db_path,
        str(args["param_id"]),
        recompute=bool(args.get("recompute", False)),
    )
    if intel is None:
        return HandlerResult(
            success=False,
            summary="parameter not found",
            error=f"Parameter intelligence not found: {args['param_id']}",
        )
    return HandlerResult(
        success=True,
        summary=f"param {intel.get('name')} @ {intel.get('location')}",
        data={"intelligence": intel},
        citations={
            "param_uuid": intel.get("param_uuid"),
            "endpoint_id": intel.get("endpoint_id"),
        },
    )


def handle_iv_candidates(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    limit = int(args.get("limit", 25))
    rows = list_candidates(
        ctx.db_path,
        attack=args.get("attack"),
        min_score=int(args.get("min_score", 0)),
        host=args.get("host"),
        limit=limit,
    )
    return HandlerResult(
        success=True,
        summary=f"{len(rows)} IV candidate(s)",
        data={"candidates": rows},
        citations={
            "param_uuids": [r.get("param_uuid") for r in rows if r.get("param_uuid")]
        },
    )


def handle_finding_list(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    limit = int(args.get("limit", 50))
    rows = findings_db.list_findings(
        ctx.db_path,
        ctx.project_id,
        status=args.get("status"),
    )
    rows = _truncate_list(rows, limit)
    return HandlerResult(
        success=True,
        summary=f"{len(rows)} finding(s)",
        data={"findings": rows},
        citations={"finding_ids": [r.get("id") for r in rows if r.get("id")]},
    )


def handle_finding_show(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    finding_id = str(args["finding_id"]).strip()
    row = findings_db.get_finding(ctx.db_path, finding_id)
    if row is None or row.get("project_id") not in (None, ctx.project_id):
        # Reject cross-project if project_id is set and differs.
        if row is not None and row.get("project_id") and row["project_id"] != ctx.project_id:
            return HandlerResult(
                success=False,
                summary="finding not in pinned project",
                error="Finding does not belong to the pinned project.",
            )
        if row is None:
            return HandlerResult(
                success=False,
                summary="finding not found",
                error=f"Finding not found: {finding_id}",
            )
    evidence = findings_db.list_evidence(ctx.db_path, finding_id)
    return HandlerResult(
        success=True,
        summary=row.get("title") or finding_id,
        data={"finding": row, "evidence": evidence},
        citations={"finding_id": finding_id},
    )


def handle_passive_detections_list(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    from talos.passive import db as passive_db

    limit = int(args.get("limit", 50))
    detections = passive_db.list_detections(
        ctx.db_path,
        project_id=ctx.project_id,
        category=args.get("category"),
        suppressed=args.get("suppressed"),
        limit=limit,
    )
    rows = []
    for d in detections:
        if hasattr(d, "__dataclass_fields__"):
            from dataclasses import asdict

            rows.append(asdict(d))
        elif isinstance(d, dict):
            rows.append(d)
        else:
            rows.append({"id": getattr(d, "id", None), "repr": str(d)})
    return HandlerResult(
        success=True,
        summary=f"{len(rows)} passive detection(s)",
        data={"detections": rows},
        citations={"detection_ids": [r.get("id") for r in rows if r.get("id")]},
    )


def handle_error_intel_list(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    from dataclasses import asdict, is_dataclass

    from talos.error_intel import db as error_db

    limit = int(args.get("limit", 50))
    clusters = error_db.list_clusters(
        ctx.db_path,
        ctx.project_id,
        severity=args.get("severity"),
        category=args.get("category"),
        limit=limit,
    )
    rows = []
    for c in clusters:
        if is_dataclass(c):
            rows.append(asdict(c))
        elif isinstance(c, dict):
            rows.append(c)
        else:
            rows.append({"id": getattr(c, "id", None), "repr": str(c)})
    return HandlerResult(
        success=True,
        summary=f"{len(rows)} error cluster(s)",
        data={"clusters": rows},
        citations={"error_ids": [r.get("id") for r in rows if r.get("id")]},
    )


def handle_access_coverage(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    rows = get_access_coverage(ctx.db_path)
    return HandlerResult(
        success=True,
        summary=f"{len(rows)} access coverage row(s)",
        data={"coverage": rows},
        citations={},
    )


def handle_scheduler_jobs_list(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    limit = int(args.get("limit", 50))
    jobs = sched_db.list_jobs(
        ctx.db_path,
        ctx.project_id,
        status=args.get("status"),
        job_type=args.get("job_type"),
        limit=limit,
    )
    rows = []
    for job in jobs:
        if hasattr(job, "__dict__"):
            rows.append(
                {
                    "id": getattr(job, "id", None),
                    "job_type": getattr(job, "job_type", None),
                    "status": getattr(job, "status", None),
                    "priority": getattr(job, "priority", None),
                    "endpoint_id": getattr(job, "endpoint_id", None),
                    "flow_id": getattr(job, "flow_id", None),
                    "created_at": getattr(job, "created_at", None),
                    "finished_at": getattr(job, "finished_at", None),
                }
            )
        else:
            rows.append(dict(job) if isinstance(job, dict) else {"job": str(job)})
    return HandlerResult(
        success=True,
        summary=f"{len(rows)} job(s)",
        data={"jobs": rows},
        citations={"job_ids": [r.get("id") for r in rows if r.get("id")]},
    )


def handle_scheduler_jobs_show(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    job_id = str(args["job_id"]).strip()
    try:
        job = sched_db.get_job(ctx.db_path, ctx.project_id, job_id)
    except ValueError as exc:
        return HandlerResult(
            success=False,
            summary="ambiguous job id",
            error=str(exc),
        )
    if job is None:
        return HandlerResult(
            success=False,
            summary="job not found",
            error=f"Job not found: {job_id}",
        )
    data = {
        "id": getattr(job, "id", None),
        "job_type": getattr(job, "job_type", None),
        "status": getattr(job, "status", None),
        "priority": getattr(job, "priority", None),
        "endpoint_id": getattr(job, "endpoint_id", None),
        "flow_id": getattr(job, "flow_id", None),
        "created_at": getattr(job, "created_at", None),
        "finished_at": getattr(job, "finished_at", None),
        "error": getattr(job, "error", None),
        "meta": getattr(job, "meta", None),
    }
    return HandlerResult(
        success=True,
        summary=f"job {data['id']} {data['status']}",
        data={"job": data},
        citations={"job_id": data["id"]},
    )


def handle_intruder_suggest(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    from talos.intruder import db as intruder_db
    from talos.intruder.suggest import build_suggestions

    session_id = str(args["session_id"]).strip()
    session = intruder_db.get_session(ctx.db_path, session_id)
    if session is None:
        return HandlerResult(
            success=False,
            summary="intruder session not found",
            error=f"Intruder session not found: {session_id}",
        )
    # Pin check: session must belong to this project when project_id present.
    if session.get("project_id") and session["project_id"] != ctx.project_id:
        return HandlerResult(
            success=False,
            summary="session not in pinned project",
            error="Intruder session does not belong to the pinned project.",
        )
    suggestions = build_suggestions(
        session,
        session.get("config"),
        db_path=ctx.db_path,
        project_id=ctx.project_id,
    )
    return HandlerResult(
        success=True,
        summary=suggestions.get("summary") or "intruder suggestions ready",
        data={"suggestions": suggestions},
        citations={"intruder_session_id": session_id},
    )
