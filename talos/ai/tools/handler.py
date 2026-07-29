"""
Module: talos.ai.tools.handler

Purpose:
    ToolHandler protocol and HandlerResult re-export. Handlers call existing
    Python APIs only — never subprocess or freeform shell.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from talos.ai.models import ExecutionPlan, HandlerResult, ProjectContext


@runtime_checkable
class ToolHandler(Protocol):
    """
    Sole execution body for a tool. Invoked only by Executor with a sealed plan.
    """

    def execute(
        self,
        args: dict[str, Any],
        ctx: ProjectContext,
        plan: ExecutionPlan,
    ) -> HandlerResult:
        """
        Purpose: Run the tool against the pinned project context.
        Input: schema-normalized args, frozen ProjectContext, sealed plan.
        Output: HandlerResult (success/summary/data/citations).
        Side effects: tool-specific (READ tools should be read-only).
        """
        ...


class CallableHandler:
    """
    Adapter wrapping a plain function as a ToolHandler.
    """

    def __init__(self, fn):
        self._fn = fn

    def execute(
        self,
        args: dict[str, Any],
        ctx: ProjectContext,
        plan: ExecutionPlan,
    ) -> HandlerResult:
        return self._fn(args, ctx, plan)
