"""
Module: talos.ai.tools.handlers.notes_kb

Purpose:
    Phase B notes + PTT handlers; Phase E minimal markdown KB + draft findings.
"""

from __future__ import annotations

from typing import Any

from talos.ai.drafts import store as drafts_store
from talos.ai.kb import store as kb_store
from talos.ai.models import ExecutionPlan, HandlerResult, ProjectContext
from talos.ai.notes import store as notes_store
from talos.ai.workflow import task_tree as ptt


def handle_notes_app_get(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    del args, plan
    snap = notes_store.get_notes(ctx.db_path, ctx.project_id)
    return HandlerResult(
        success=True,
        summary=(
            f"notes revision={snap.revision} "
            f"tainted={bool((snap.doc or {}).get('tainted'))}"
        ),
        data=snap.to_dict(),
        citations={"project_id": ctx.project_id, "revision": snap.revision},
    )


def handle_notes_app_patch(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    del plan
    if_revision = int(args["if_revision"])
    ops = args.get("ops") or []
    try:
        snap = notes_store.patch_notes(
            ctx.db_path,
            ctx.project_id,
            list(ops),
            if_revision=if_revision,
            updated_by="ai",
        )
    except notes_store.NotesRevisionConflict as exc:
        return HandlerResult(
            success=False,
            summary="revision conflict",
            error=str(exc),
            data={"expected": exc.expected, "actual": exc.actual},
        )
    except notes_store.NotesError as exc:
        return HandlerResult(
            success=False,
            summary="notes patch failed",
            error=str(exc),
        )
    return HandlerResult(
        success=True,
        summary=f"notes patched → revision={snap.revision}",
        data=snap.to_dict(),
        citations={"project_id": ctx.project_id, "revision": snap.revision},
    )


def handle_task_tree_list(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    limit = int(args.get("limit", 50))
    status = args.get("status")
    nodes = ptt.list_nodes(
        ctx.db_path,
        ctx.session_id,
        status=status,
        limit=limit,
    )
    payload = [n.to_dict() for n in nodes]
    return HandlerResult(
        success=True,
        summary=f"{len(payload)} task node(s)",
        data={"nodes": payload, "count": len(payload)},
        citations={"session_id": ctx.session_id},
    )


def handle_task_tree_upsert(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    del plan
    try:
        node = ptt.upsert_node(
            ctx.db_path,
            session_id=ctx.session_id,
            project_id=ctx.project_id,
            title=str(args["title"]),
            node_id=args.get("node_id"),
            parent_id=args.get("parent_id"),
            status=str(args.get("status") or "pending"),
            hypothesis=args.get("hypothesis"),
            evidence_refs=args.get("evidence_refs"),
            suggested_tools=args.get("suggested_tools"),
            priority=int(args.get("priority") or 0),
        )
    except ValueError as exc:
        return HandlerResult(
            success=False,
            summary="task_tree upsert failed",
            error=str(exc),
        )
    return HandlerResult(
        success=True,
        summary=f"task node {node.node_id} status={node.status}",
        data={"node": node.to_dict()},
        citations={"node_id": node.node_id, "session_id": ctx.session_id},
    )


# ------------------------------------------------------------------ #
# Phase E: markdown KB (read-only directory)                           #
# ------------------------------------------------------------------ #


def handle_kb_search(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    del plan, ctx
    # Operator-global markdown dir (~/.talos/ai/kb), not project data_dir.
    query = str(args.get("query") or "")
    limit = int(args.get("limit", 10))
    hits = kb_store.search_docs(query, limit=limit)
    kb_path = str(kb_store.kb_dir())
    return HandlerResult(
        success=True,
        summary=f"{len(hits)} KB hit(s) for query={query!r}",
        data={
            "hits": hits,
            "count": len(hits),
            "kb_dir": kb_path,
        },
        citations={"kb_dir": kb_path},
    )


# ------------------------------------------------------------------ #
# Phase E: draft findings                                              #
# ------------------------------------------------------------------ #


def handle_draft_finding_list(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    del plan
    status = args.get("status")
    limit = int(args.get("limit", 50))
    items = drafts_store.list_drafts(
        ctx.db_path,
        ctx.project_id,
        status=status,
        limit=limit,
    )
    payload = [d.to_dict() for d in items]
    return HandlerResult(
        success=True,
        summary=f"{len(payload)} draft finding(s)",
        data={"drafts": payload, "count": len(payload)},
        citations={"project_id": ctx.project_id},
    )


def handle_draft_finding_show(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    del plan
    draft_id = str(args["draft_id"])
    draft = drafts_store.get_draft(ctx.db_path, ctx.project_id, draft_id)
    if draft is None:
        return HandlerResult(
            success=False,
            summary="draft not found",
            error=f"draft not found: {draft_id}",
        )
    return HandlerResult(
        success=True,
        summary=f"draft {draft.id} status={draft.status}",
        data={"draft": draft.to_dict()},
        citations={"draft_id": draft.id},
    )


def handle_draft_finding_create(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    del plan
    try:
        draft = drafts_store.create_draft(
            ctx.db_path,
            ctx.project_id,
            title=str(args["title"]),
            description=str(args["description"]),
            endpoint_id=str(args["endpoint_id"]),
            attack_type=str(args.get("attack_type") or "ai_draft"),
            vulnerability_class=str(args.get("vulnerability_class") or ""),
            evidence_refs=args.get("evidence_refs"),
            confidence=float(args.get("confidence", 0.5)),
            cluster_key=args.get("cluster_key"),
            session_id=ctx.session_id,
        )
    except drafts_store.DraftsError as exc:
        return HandlerResult(
            success=False,
            summary="draft create failed",
            error=str(exc),
        )
    return HandlerResult(
        success=True,
        summary=f"draft created {draft.id}",
        data={"draft": draft.to_dict()},
        citations={"draft_id": draft.id, "endpoint_id": draft.endpoint_id},
    )
