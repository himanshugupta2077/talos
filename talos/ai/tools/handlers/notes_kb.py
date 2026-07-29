"""
Module: talos.ai.tools.handlers.notes_kb

Purpose:
    Phase B tool handlers for structured app notes and PTT.
    KB handlers land in Phase E.
"""

from __future__ import annotations

from typing import Any

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
