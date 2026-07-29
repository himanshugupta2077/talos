"""
Module: talos.ai.tools.handlers.engines

Purpose:
    Phase D engine orchestration tools (enqueue-only):
    iv.run, iv.synthesize, passive.rescan, attack.unauth.run,
    attack.bac.run, intruder.session.run.

Dependencies: existing engine Python APIs only (no subprocess).
Data flow:
    Executor → handler → schedule/enqueue APIs → HandlerResult
Side effects:
    scheduler_jobs inserts; IV synthesize may write param profiles;
    passive rescan re-runs detectors on stored bodies.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Optional

from talos.ai.models import ExecutionPlan, HandlerResult, ProjectContext
from talos.ai.tools import scope_policy as sp
from talos.scheduler import db as sched_db
from talos.scheduler.job import (
    BAC_JOB_TYPES,
    UNAUTH_ATTACK,
)


# ------------------------------------------------------------------ #
# IV                                                                   #
# ------------------------------------------------------------------ #


def handle_iv_run(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    """Enqueue IV jobs via schedule_* helpers (planner wave)."""
    from talos.input_validation.engine import (
        schedule_endpoint,
        schedule_host,
        schedule_parameter,
        schedule_project,
    )

    scope = str(args.get("scope") or "endpoint").strip()
    phase_filter = args.get("phase_filter")
    ignore_cache = bool(args.get("ignore_cache", False))
    host = args.get("host")
    endpoint_id = args.get("endpoint_id")
    param_name = args.get("param_name")

    try:
        if scope == "project":
            n = schedule_project(
                ctx.db_path,
                ctx.project_id,
                phase_filter=phase_filter,
                ignore_cache=ignore_cache,
            )
        elif scope == "host":
            if not host:
                return HandlerResult(
                    success=False,
                    summary="host required",
                    error="iv.run scope=host requires host",
                )
            n = schedule_host(
                ctx.db_path,
                ctx.project_id,
                str(host),
                phase_filter=phase_filter,
                ignore_cache=ignore_cache,
            )
        elif scope == "parameter":
            if not param_name:
                return HandlerResult(
                    success=False,
                    summary="param_name required",
                    error="iv.run scope=parameter requires param_name",
                )
            n = schedule_parameter(
                ctx.db_path,
                ctx.project_id,
                str(param_name),
                phase_filter=phase_filter,
                ignore_cache=ignore_cache,
            )
        else:  # endpoint
            if not endpoint_id:
                return HandlerResult(
                    success=False,
                    summary="endpoint_id required",
                    error="iv.run scope=endpoint requires endpoint_id",
                )
            n = schedule_endpoint(
                ctx.db_path,
                ctx.project_id,
                str(endpoint_id),
                phase_filter=phase_filter,
                ignore_cache=ignore_cache,
            )
    except Exception as exc:  # noqa: BLE001
        return HandlerResult(
            success=False,
            summary="iv schedule failed",
            error=f"{type(exc).__name__}: {exc}",
        )

    return HandlerResult(
        success=True,
        summary=f"iv.run enqueued={n} scope={scope}",
        data={
            "jobs_enqueued": int(n),
            "scope": scope,
            "host": host,
            "endpoint_id": endpoint_id,
            "param_name": param_name,
            "phase_filter": phase_filter,
            "source": "ai",
            "ai_session_id": plan.session_id,
            "ai_suggestion_id": plan.suggestion_id,
        },
        citations={
            "endpoint_id": endpoint_id,
            "jobs_enqueued": int(n),
        },
    )


def handle_iv_synthesize(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    """Local synthesis from existing probes — no HTTP, no scheduler."""
    from talos.input_validation.synthesize import synthesize_param_profile

    param_uuid = str(args["param_uuid"]).strip()
    persist = bool(args.get("persist", True))
    try:
        profile = synthesize_param_profile(
            ctx.db_path,
            param_uuid,
            persist=persist,
        )
    except Exception as exc:  # noqa: BLE001
        return HandlerResult(
            success=False,
            summary="synthesize failed",
            error=f"{type(exc).__name__}: {exc}",
        )

    if profile is None:
        return HandlerResult(
            success=False,
            summary="no profile",
            error=f"No probes/profile for param_uuid={param_uuid}",
        )

    summary_keys = {
        k: profile.get(k)
        for k in (
            "param_uuid",
            "host",
            "name",
            "location",
            "version",
            "partial",
            "capabilities",
        )
    }
    return HandlerResult(
        success=True,
        summary=f"synthesized param_uuid={param_uuid}",
        data={"profile": summary_keys, "persist": persist},
        citations={"param_uuid": param_uuid},
    )


# ------------------------------------------------------------------ #
# Passive                                                              #
# ------------------------------------------------------------------ #


def handle_passive_rescan(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    """
    Re-run passive detectors on stored bodies (CLI-equivalent of
    `talos passive rescan`). Enqueue-class budget; no new HTTP.
    """
    from talos.passive import db as passive_db
    from talos.passive.cli import (
        _document_id_for_flow,
        _rescan_document,
        _rescan_flow_body,
    )
    from talos.passive.constants import SCANNER_VERSION
    from talos.passive.detectors.orchestrator import DetectorOrchestrator

    flow_id = args.get("flow_id")
    document_id = args.get("document_id")
    do_all = bool(args.get("all", False))
    force = bool(args.get("force", False))

    selected = sum(1 for x in (bool(flow_id), bool(document_id), do_all) if x)
    if selected != 1:
        return HandlerResult(
            success=False,
            summary="bad target",
            error=(
                "passive.rescan requires exactly one of: "
                "flow_id, document_id, all=true"
            ),
        )

    config = passive_db.get_config(ctx.db_path)
    orch = DetectorOrchestrator(config=config)
    scanned = 0
    findings = 0
    try:
        if flow_id:
            fid = str(flow_id).strip()
            doc_id = _document_id_for_flow(ctx.db_path, fid)
            if doc_id:
                n_d, n_f = _rescan_document(
                    ctx.db_path,
                    ctx.project_id,
                    doc_id,
                    preferred_flow_id=fid,
                    config=config,
                    orch=orch,
                    force=force,
                )
                scanned = int(n_d or 0)
                findings = int(n_f or 0)
            else:
                n = _rescan_flow_body(
                    ctx.db_path, ctx.project_id, fid, config, orch
                )
                scanned = int(n or 0)
        elif document_id:
            n_d, n_f = _rescan_document(
                ctx.db_path,
                ctx.project_id,
                str(document_id).strip(),
                preferred_flow_id=None,
                config=config,
                orch=orch,
                force=force,
            )
            scanned = int(n_d or 0)
            findings = int(n_f or 0)
        else:
            docs = passive_db.list_documents(
                ctx.db_path, ctx.project_id, limit=5000
            )
            for doc in docs:
                if getattr(doc, "parent_document_id", None):
                    continue
                if (
                    not force
                    and getattr(doc, "scanner_version", None) == SCANNER_VERSION
                ):
                    continue
                n_d, n_f = _rescan_document(
                    ctx.db_path,
                    ctx.project_id,
                    doc.id,
                    preferred_flow_id=getattr(doc, "first_flow_id", None),
                    config=config,
                    orch=orch,
                    force=force,
                )
                scanned += int(n_d or 0)
                findings += int(n_f or 0)
    except SystemExit as exc:
        return HandlerResult(
            success=False,
            summary="passive rescan failed",
            error=f"rescan aborted: {exc}",
        )
    except Exception as exc:  # noqa: BLE001
        return HandlerResult(
            success=False,
            summary="passive rescan failed",
            error=f"{type(exc).__name__}: {exc}",
        )

    return HandlerResult(
        success=True,
        summary=f"passive.rescan scanned={scanned}",
        data={
            "scanned": scanned,
            "findings_touched": findings,
            "flow_id": flow_id,
            "document_id": document_id,
            "all": do_all,
            "source": "ai",
            "ai_session_id": plan.session_id,
            "ai_suggestion_id": plan.suggestion_id,
        },
        citations={"flow_id": flow_id, "document_id": document_id},
    )


# ------------------------------------------------------------------ #
# Unauth                                                               #
# ------------------------------------------------------------------ #


def handle_attack_unauth_run(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    """Enqueue UNAUTH_ATTACK jobs for one flow/endpoint or a limited scan."""
    from talos.projects.unauth.recipes import UNAUTH_RECIPES

    force_dangerous = bool((plan.policy_meta or {}).get("ai_force_dangerous"))
    priority = sp.ai_job_priority(force_dangerous=force_dangerous)
    technique_filter = args.get("technique")
    limit = int(args.get("limit") or 20)
    flow_id = args.get("flow_id")
    endpoint_id = args.get("endpoint_id")

    recipes = [
        r
        for r in UNAUTH_RECIPES
        if technique_filter is None or r.get("technique") == technique_filter
    ]
    if not recipes:
        return HandlerResult(
            success=False,
            summary="no recipes",
            error=f"No unauth recipes match technique={technique_filter!r}",
        )

    targets: list[dict[str, Any]] = []
    if flow_id:
        flow = sp.resolve_flow_target(ctx.db_path, flow_id=str(flow_id))
        if flow is None:
            return HandlerResult(
                success=False,
                summary="flow not found",
                error=f"Flow not found: {flow_id}",
            )
        targets.append(
            {
                "flow_id": flow.get("id") or flow_id,
                "endpoint_id": flow.get("endpoint_id") or endpoint_id,
            }
        )
    elif endpoint_id:
        from talos.replay import db as replay_db

        best = replay_db.get_best_flow_for_endpoint(ctx.db_path, str(endpoint_id))
        if best is None:
            return HandlerResult(
                success=False,
                summary="no baseline flow",
                error=f"No 2xx proxy_capture flow for endpoint {endpoint_id}",
            )
        targets.append(
            {
                "flow_id": best.get("id"),
                "endpoint_id": endpoint_id,
            }
        )
    else:
        # Limited project scan — prefer qualified endpoints with baselines.
        from talos.projects.policy import list_endpoints
        from talos.replay import db as replay_db

        eps = list_endpoints(ctx.db_path, ctx.project_id, qualified=True) or []
        for ep in eps:
            if len(targets) >= limit:
                break
            eid = ep.get("id") if isinstance(ep, dict) else None
            if not eid:
                continue
            best = replay_db.get_best_flow_for_endpoint(ctx.db_path, eid)
            if best is None:
                continue
            targets.append({"flow_id": best.get("id"), "endpoint_id": eid})

    if not targets:
        return HandlerResult(
            success=False,
            summary="no targets",
            error="No testable flows/endpoints for unauth attack",
        )

    job_ids: list[str] = []
    for t in targets:
        if len(job_ids) >= limit:
            break
        for recipe in recipes:
            if len(job_ids) >= limit:
                break
            meta = sp.ai_job_meta(
                session_id=plan.session_id,
                suggestion_id=plan.suggestion_id,
                force_dangerous=force_dangerous,
                extra={
                    "technique": recipe.get("technique"),
                    "request_mutation": recipe.get("request_mutation"),
                    "request_type": recipe.get("request_type"),
                },
            )
            jid = str(uuid.uuid4())
            sched_db.enqueue_job(
                db_path=ctx.db_path,
                job_id=jid,
                job_type=UNAUTH_ATTACK,
                project_id=ctx.project_id,
                flow_id=t.get("flow_id"),
                endpoint_id=t.get("endpoint_id"),
                priority=priority,
                meta=json.dumps(meta),
            )
            job_ids.append(jid)

    return HandlerResult(
        success=True,
        summary=f"unauth enqueued={len(job_ids)}",
        data={
            "job_ids": job_ids,
            "priority": priority,
            "targets": len(targets),
            "recipes": len(recipes),
        },
        citations={"job_ids": job_ids},
    )


# ------------------------------------------------------------------ #
# BAC                                                                  #
# ------------------------------------------------------------------ #


def handle_attack_bac_run(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    """Enqueue one BAC module's jobs for a flow or limited candidate set."""
    from talos.projects.access import list_roles, resolve_role
    from talos.projects.bac.variants import VARIANTS_BY_ATTACK

    bac_module = str(args["bac_module"]).strip()
    if bac_module not in BAC_JOB_TYPES:
        return HandlerResult(
            success=False,
            summary="bad bac_module",
            error=f"Unknown bac_module: {bac_module}",
        )

    variants = VARIANTS_BY_ATTACK.get(bac_module, [])
    if not variants:
        return HandlerResult(
            success=False,
            summary="no variants",
            error=f"No variants for {bac_module}",
        )

    force_dangerous = bool((plan.policy_meta or {}).get("ai_force_dangerous"))
    priority = sp.ai_job_priority(force_dangerous=force_dangerous)
    limit = int(args.get("limit") or 20)
    flow_id = args.get("flow_id")
    endpoint_id = args.get("endpoint_id")
    attacker_role_name = args.get("attacker_role")

    # Resolve attacker role
    attacker_role_id: Optional[str] = None
    if attacker_role_name:
        role = resolve_role(ctx.db_path, str(attacker_role_name))
        if role is None:
            return HandlerResult(
                success=False,
                summary="role not found",
                error=f"Attacker role not found: {attacker_role_name}",
            )
        attacker_role_id = role.get("id")
    else:
        roles = list_roles(ctx.db_path)
        if roles:
            attacker_role_id = roles[0].get("id")

    if not attacker_role_id:
        return HandlerResult(
            success=False,
            summary="no attacker role",
            error="No attacker role available; create a role or pass attacker_role",
        )

    flows: list[dict[str, Any]] = []
    if flow_id:
        flow = sp.resolve_flow_target(ctx.db_path, flow_id=str(flow_id))
        if flow is None:
            return HandlerResult(
                success=False,
                summary="flow not found",
                error=f"Flow not found: {flow_id}",
            )
        flows.append(flow)
    elif endpoint_id:
        from talos.replay import db as replay_db

        best = replay_db.get_best_flow_for_endpoint(ctx.db_path, str(endpoint_id))
        if best is None:
            return HandlerResult(
                success=False,
                summary="no baseline flow",
                error=f"No baseline flow for endpoint {endpoint_id}",
            )
        flows.append(best)
    else:
        from talos.projects.policy import list_endpoints
        from talos.replay import db as replay_db

        eps = list_endpoints(ctx.db_path, ctx.project_id, qualified=True)
        for ep in eps:
            if len(flows) >= max(1, limit // max(1, len(variants))):
                break
            best = replay_db.get_best_flow_for_endpoint(ctx.db_path, ep.get("id") or "")
            if best is not None:
                flows.append(best)

    if not flows:
        return HandlerResult(
            success=False,
            summary="no targets",
            error="No flows to attack for BAC module",
        )

    job_ids: list[str] = []
    for flow in flows:
        fid = flow.get("id")
        eid = flow.get("endpoint_id") or endpoint_id
        for variant in variants:
            if len(job_ids) >= limit:
                break
            variant_name = variant.get("name") if isinstance(variant, dict) else str(variant)
            meta = sp.ai_job_meta(
                session_id=plan.session_id,
                suggestion_id=plan.suggestion_id,
                force_dangerous=force_dangerous,
                extra={
                    "attacker_role_id": attacker_role_id,
                    "variant": variant_name,
                    "bac_module": bac_module,
                },
            )
            jid = str(uuid.uuid4())
            sched_db.enqueue_job(
                db_path=ctx.db_path,
                job_id=jid,
                job_type=bac_module,
                project_id=ctx.project_id,
                flow_id=fid,
                endpoint_id=eid,
                priority=priority,
                meta=json.dumps(meta),
            )
            job_ids.append(jid)
        if len(job_ids) >= limit:
            break

    return HandlerResult(
        success=True,
        summary=f"bac enqueued={len(job_ids)} module={bac_module}",
        data={
            "job_ids": job_ids,
            "bac_module": bac_module,
            "priority": priority,
            "attacker_role_id": attacker_role_id,
        },
        citations={"job_ids": job_ids, "bac_module": bac_module},
    )


# ------------------------------------------------------------------ #
# Intruder                                                             #
# ------------------------------------------------------------------ #


def handle_intruder_session_run(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    """
    Enqueue one segment for a pre-created intruder session.
    Requires existing session_id (no session create in v1 AI tools).
    Caps estimated payloads against max_payloads / session budget class.
    """
    from talos.intruder import db as intruder_db
    from talos.intruder.config_schema import validate_config
    from talos.intruder.session import enqueue_segment

    session_id = str(args["session_id"]).strip()
    segment = int(args.get("segment") or 0)
    max_payloads = int(args.get("max_payloads") or 200)

    isess = intruder_db.get_session(ctx.db_path, session_id)
    if isess is None:
        return HandlerResult(
            success=False,
            summary="session not found",
            error=f"Intruder session not found: {session_id}",
        )

    cfg = isess.get("config") or {}
    try:
        _norm, estimate = validate_config(cfg, open_generators=False)
    except Exception as exc:  # noqa: BLE001
        return HandlerResult(
            success=False,
            summary="invalid config",
            error=f"Intruder config invalid: {exc}",
        )

    if estimate is not None and int(estimate) > max_payloads:
        return HandlerResult(
            success=False,
            summary="payload cap exceeded",
            error=(
                f"Estimated payloads {estimate} exceeds max_payloads={max_payloads}. "
                "Reduce generators or raise max_payloads (≤200)."
            ),
            data={"estimate": estimate, "max_payloads": max_payloads},
        )

    force_dangerous = bool((plan.policy_meta or {}).get("ai_force_dangerous"))
    priority = sp.ai_job_priority(force_dangerous=force_dangerous)

    try:
        job_id = enqueue_segment(
            ctx.db_path,
            ctx.project_id,
            session_id,
            segment=segment,
            priority=priority,
            endpoint_id=isess.get("endpoint_id"),
            base_flow_id=isess.get("base_flow_id"),
        )
    except Exception as exc:  # noqa: BLE001
        return HandlerResult(
            success=False,
            summary="enqueue failed",
            error=f"{type(exc).__name__}: {exc}",
        )

    # Patch job meta with AI source fields (enqueue_segment uses its own meta).
    try:
        job = sched_db.get_job(ctx.db_path, ctx.project_id, job_id)
        if job is not None:
            existing = {}
            if job.meta:
                try:
                    existing = json.loads(job.meta)
                except json.JSONDecodeError:
                    existing = {}
            existing.update(
                sp.ai_job_meta(
                    session_id=plan.session_id,
                    suggestion_id=plan.suggestion_id,
                    force_dangerous=force_dangerous,
                    extra={
                        "intruder_session_id": session_id,
                        "segment": segment,
                        "estimate": estimate,
                    },
                )
            )
            # Best-effort: re-write meta if DB supports update — fall through if not.
            _patch_job_meta(ctx.db_path, job_id, existing)
    except Exception:  # noqa: BLE001
        pass

    return HandlerResult(
        success=True,
        summary=f"intruder enqueued job={job_id} session={session_id}",
        data={
            "job_id": job_id,
            "session_id": session_id,
            "segment": segment,
            "priority": priority,
            "estimate": estimate,
        },
        citations={"job_id": job_id, "session_id": session_id},
    )


def _patch_job_meta(db_path, job_id: str, meta: dict[str, Any]) -> None:
    """Best-effort UPDATE of scheduler_jobs.meta for AI provenance."""
    import sqlite3

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "UPDATE scheduler_jobs SET meta = ? WHERE job_id = ?",
            (json.dumps(meta), job_id),
        )
        conn.commit()
