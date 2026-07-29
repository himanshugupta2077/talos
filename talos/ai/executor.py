"""
Module: talos.ai.executor

Purpose:
    Sole invoke path for ToolHandlers. Verifies sealed ExecutionPlan tokens,
    enforces project pin, increments budget counters, returns Observations.

Dependencies: uuid, talos.ai.policy tokens, tools registry, workflow session
Data flow:
    ExecutionPlan → verify token → handler.execute → Observation
Side effects:
    Consumes capability token; may UPDATE session usage; handler side effects.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from talos.ai.models import (
    AgentSession,
    ExecutionPlan,
    HandlerResult,
    Observation,
    ProjectContext,
    SessionStatus,
)
from talos.ai.policy import verify_and_consume_token
from talos.ai.tools.registry import ToolRegistry, default_registry
from talos.ai.workflow import budgets as budget_mod
from talos.ai.workflow import session as session_store


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class ExecutorError(Exception):
    """Raised when a plan cannot be executed (token, pin, status)."""


class Executor:
    """
    Invokes ToolHandler.execute only for sealed plans with valid tokens.
    """

    def __init__(self, registry: Optional[ToolRegistry] = None) -> None:
        self._registry = registry

    @property
    def registry(self) -> ToolRegistry:
        return self._registry if self._registry is not None else default_registry()

    def execute(
        self,
        plan: ExecutionPlan,
        session: AgentSession,
        *,
        persist_usage: bool = True,
    ) -> Observation:
        """
        Purpose:
            Execute a sealed plan against the session's frozen project pin.
        Input:
            plan    — from PolicyValidator only.
            session — must be active and match plan.session_id / project pin.
            persist_usage — write budget counters back to DB when True.
        Output:
            Observation (always; success flag mirrors handler).
        Raises:
            ExecutorError on token/pin/status failures (before handler runs).
        """
        if session.session_id != plan.session_id:
            raise ExecutorError("Plan session_id does not match AgentSession.")
        if session.pinned_project_id != plan.project_id:
            raise ExecutorError("Plan project pin does not match AgentSession.")
        if session.status != SessionStatus.ACTIVE:
            raise ExecutorError(
                f"Session is not active (status={session.status.value})."
            )
        if not verify_and_consume_token(plan.plan_id, plan.capability_token):
            raise ExecutorError(
                "Invalid or already-consumed capability token; "
                "re-validate to mint a new ExecutionPlan."
            )

        try:
            policy = self.registry.get_policy(plan.tool_name)
            handler = self.registry._get_handler(plan.tool_name)
        except KeyError as exc:
            raise ExecutorError(f"Tool no longer registered: {plan.tool_name}") from exc

        ctx = session.project_context()
        # Defense in depth: handlers always see frozen db_path from session.
        if ctx.db_path != session.db_path or ctx.project_id != plan.project_id:
            raise ExecutorError("ProjectContext pin integrity check failed.")

        try:
            result: HandlerResult = handler.execute(plan.arguments, ctx, plan)
        except Exception as exc:  # noqa: BLE001 — surface as observation failure
            result = HandlerResult(
                success=False,
                summary="handler exception",
                error=f"{type(exc).__name__}: {exc}",
            )

        budget_mod.apply_tool_call(session.usage, policy.budget_class)
        budget_mod.refresh_wall_clock(session.usage, session.created_at)

        halt = False
        exceeded = budget_mod.first_exceeded(session.budgets, session.usage)
        if exceeded:
            halt = True
            session.status = SessionStatus.HALTED_BUDGET

        if persist_usage:
            session_store.update_session_usage(
                session.db_path,
                session.project_id,
                session.session_id,
                session.usage,
                status=SessionStatus.HALTED_BUDGET if halt else None,
            )

        return Observation(
            observation_id=str(uuid.uuid4()),
            session_id=plan.session_id,
            suggestion_id=plan.suggestion_id,
            plan_id=plan.plan_id,
            tool_name=plan.tool_name,
            result_summary=result.summary if result.success else (result.error or result.summary),
            citations=dict(result.citations or {}),
            untrusted=True,
            created_at=_now_iso(),
            success=bool(result.success),
            data=dict(result.data or {}),
        )
