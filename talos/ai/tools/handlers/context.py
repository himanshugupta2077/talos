"""
Module: talos.ai.tools.handlers.context

Purpose:
    Role/module READ and MODIFY_CONTEXT (set-active only) tool handlers.
    Create/delete/rename of roles and modules are never exposed as tools.

Dependencies: talos.projects.access
Data flow:
    Executor → set_active_role / set_active_module → project DB
Side effects:
    set_active tools update is_active flags; list/show are read-only.
"""

from __future__ import annotations

from typing import Any

from talos.ai.models import ExecutionPlan, HandlerResult, ProjectContext
from talos.projects.access import (
    get_active_module,
    get_active_role,
    list_modules,
    list_roles,
    resolve_module,
    resolve_role,
    set_active_module,
    set_active_role,
)


def handle_role_list(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    roles = list_roles(ctx.db_path)
    return HandlerResult(
        success=True,
        summary=f"{len(roles)} role(s)",
        data={"roles": roles},
        citations={},
    )


def handle_role_show_active(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    name = get_active_role(ctx.db_path)
    return HandlerResult(
        success=True,
        summary=f"active role: {name}",
        data={"active_role": name},
        citations={},
    )


def handle_module_list(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    modules = list_modules(ctx.db_path)
    return HandlerResult(
        success=True,
        summary=f"{len(modules)} module(s)",
        data={"modules": modules},
        citations={},
    )


def handle_module_show_active(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    name = get_active_module(ctx.db_path)
    return HandlerResult(
        success=True,
        summary=f"active module: {name}",
        data={"active_module": name},
        citations={},
    )


def handle_role_set_active(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    """
    Purpose:
        Activate an existing role by name (or resolve name from UUID input).
        Rejects missing roles — never creates.
    """
    name_or_id = str(args["name"]).strip()
    role = resolve_role(ctx.db_path, name_or_id)
    if role is None:
        return HandlerResult(
            success=False,
            summary="role not found",
            error=f"Role '{name_or_id}' does not exist.",
        )
    old = get_active_role(ctx.db_path)
    new_name = role["name"]
    if old == new_name:
        return HandlerResult(
            success=True,
            summary=f"role already active: {new_name}",
            data={"old": old, "new": new_name, "changed": False},
            citations={"role_id": role["id"]},
        )
    try:
        set_active_role(ctx.db_path, new_name)
    except ValueError as exc:
        return HandlerResult(
            success=False,
            summary="role set failed",
            error=str(exc),
        )
    return HandlerResult(
        success=True,
        summary=f"active role: {old} → {new_name}",
        data={"old": old, "new": new_name, "changed": True},
        citations={"role_id": role["id"]},
    )


def handle_module_set_active(
    args: dict[str, Any],
    ctx: ProjectContext,
    plan: ExecutionPlan,
) -> HandlerResult:
    """
    Purpose:
        Activate an existing module by name (or resolve name from UUID input).
        Rejects missing modules — never creates.
    """
    name_or_id = str(args["name"]).strip()
    module = resolve_module(ctx.db_path, name_or_id)
    if module is None:
        return HandlerResult(
            success=False,
            summary="module not found",
            error=f"Module '{name_or_id}' does not exist.",
        )
    old = get_active_module(ctx.db_path)
    new_name = module["name"]
    if old == new_name:
        return HandlerResult(
            success=True,
            summary=f"module already active: {new_name}",
            data={"old": old, "new": new_name, "changed": False},
            citations={"module_id": module["id"]},
        )
    try:
        set_active_module(ctx.db_path, new_name)
    except ValueError as exc:
        return HandlerResult(
            success=False,
            summary="module set failed",
            error=str(exc),
        )
    return HandlerResult(
        success=True,
        summary=f"active module: {old} → {new_name}",
        data={"old": old, "new": new_name, "changed": True},
        citations={"module_id": module["id"]},
    )
