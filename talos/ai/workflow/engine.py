"""
Module: talos.ai.workflow.engine

Purpose:
    WorkflowEngine façade — the only surface CLI (and later MCP/CP) should
    call for AI session orchestration. Phase A: start/stop/status/resume/
    reset-budget, mode scaffolding, tools list, and validate→execute for
    sealed READ/context tools (approve loop lands in Phase B).

Dependencies: talos.ai.* , talos.projects.manager
Data flow:
    CLI → WorkflowEngine methods → session/audit/policy/executor
Side effects:
    Session rows, audit events, budget updates, handler effects on execute.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Union

from talos.ai import audit
from talos.ai.executor import Executor, ExecutorError
from talos.ai.models import (
    ActionSuggestion,
    AgentSession,
    AutonomyMode,
    DEFAULT_AUTONOMY_MODE,
    EXPERIMENTAL_MODES,
    ExecutionPlan,
    Observation,
    PolicyReject,
    SessionStatus,
    parse_mode,
)
from talos.ai.policy import PolicyValidator
from talos.ai.tools.registry import ToolRegistry, default_registry
from talos.ai.workflow import session as session_store
from talos.projects.manager import (
    NO_ACTIVE_PROJECT_HINT,
    ProjectManager,
    TALOS_PROJECT_ENV,
)


class WorkflowEngineError(Exception):
    """Base engine error with optional exit-code hint for CLI."""

    exit_code: int = 1

    def __init__(self, message: str, *, exit_code: int = 1):
        super().__init__(message)
        self.exit_code = exit_code


class WorkflowEngine:
    """
    Orchestration façade. Owns session lifecycle; does not embed LLM logic.
    """

    def __init__(
        self,
        manager: ProjectManager,
        *,
        registry: Optional[ToolRegistry] = None,
        validator: Optional[PolicyValidator] = None,
        executor: Optional[Executor] = None,
    ) -> None:
        self.manager = manager
        self._registry = registry
        self._validator = validator
        self._executor = executor

    @property
    def registry(self) -> ToolRegistry:
        return self._registry if self._registry is not None else default_registry()

    @property
    def validator(self) -> PolicyValidator:
        if self._validator is None:
            self._validator = PolicyValidator(self.registry)
        return self._validator

    @property
    def executor(self) -> Executor:
        if self._executor is None:
            self._executor = Executor(self.registry)
        return self._executor

    def _require_project(self):
        project = self.manager.active()
        if project is None:
            raise WorkflowEngineError(NO_ACTIVE_PROJECT_HINT, exit_code=3)
        return project

    # ------------------------------------------------------------------ #
    # Session lifecycle                                                    #
    # ------------------------------------------------------------------ #

    def start(
        self,
        goal: str,
        *,
        mode: AutonomyMode | str = DEFAULT_AUTONOMY_MODE,
        force_stop_existing: bool = False,
    ) -> AgentSession:
        """
        Purpose:
            Create an active AI session pinned to the effective project.
        Side effects:
            INSERT ai_sessions; audit session.start; set TALOS_PROJECT env.
        """
        project = self._require_project()
        if isinstance(mode, str):
            mode = parse_mode(mode)

        scope_snapshot = {
            "scope": list(project.scope or []),
            "captured_at": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat(),
        }

        try:
            session = session_store.create_session(
                project.db_path,
                project_id=project.id,
                data_dir=project.data_dir,
                goal=goal or "",
                mode=mode,
                force_stop_existing=force_stop_existing,
                scope_snapshot=scope_snapshot,
            )
        except session_store.ActiveSessionExists as exc:
            raise WorkflowEngineError(str(exc), exit_code=3) from exc

        # Child consistency: pin env to this project for the process.
        os.environ[TALOS_PROJECT_ENV] = project.id

        audit.record_event(
            project.db_path,
            project.id,
            "session.start",
            {
                "session_id": session.session_id,
                "goal": session.goal,
                "mode": session.mode.value,
                "pinned_project_id": session.pinned_project_id,
            },
            session_id=session.session_id,
        )
        return session

    def stop(self, session_id: Optional[str] = None) -> AgentSession:
        project = self._require_project()
        try:
            session = session_store.resolve_session_id(
                project.db_path, project.id, session_id
            )
        except session_store.SessionNotFound as exc:
            raise WorkflowEngineError(str(exc), exit_code=1) from exc

        stopped = session_store.stop_session(
            project.db_path, project.id, session.session_id
        )
        audit.record_event(
            project.db_path,
            project.id,
            "session.stop",
            {"session_id": stopped.session_id, "status": stopped.status.value},
            session_id=stopped.session_id,
        )
        return stopped

    def resume(self, session_id: str) -> AgentSession:
        project = self._require_project()
        try:
            session = session_store.resume_session(
                project.db_path, project.id, session_id
            )
        except session_store.ActiveSessionExists as exc:
            raise WorkflowEngineError(str(exc), exit_code=3) from exc
        except session_store.SessionError as exc:
            raise WorkflowEngineError(str(exc), exit_code=1) from exc

        os.environ[TALOS_PROJECT_ENV] = project.id
        audit.record_event(
            project.db_path,
            project.id,
            "session.resume",
            {"session_id": session.session_id},
            session_id=session.session_id,
        )
        return session

    def reset_budget(self, session_id: Optional[str] = None) -> AgentSession:
        project = self._require_project()
        try:
            session = session_store.resolve_session_id(
                project.db_path, project.id, session_id
            )
        except session_store.SessionNotFound as exc:
            raise WorkflowEngineError(str(exc), exit_code=1) from exc

        updated = session_store.reset_budget(
            project.db_path, project.id, session.session_id
        )
        audit.record_event(
            project.db_path,
            project.id,
            "session.reset_budget",
            {
                "session_id": updated.session_id,
                "status": updated.status.value,
                "usage": updated.usage.to_dict(),
            },
            session_id=updated.session_id,
        )
        return updated

    def status(self, session_id: Optional[str] = None) -> dict[str, Any]:
        """
        Purpose: Build a status payload for the active or named session.
        """
        project = self._require_project()
        try:
            session = session_store.resolve_session_id(
                project.db_path, project.id, session_id
            )
        except session_store.SessionNotFound as exc:
            raise WorkflowEngineError(str(exc), exit_code=1) from exc

        return {
            "session_id": session.session_id,
            "project_id": session.project_id,
            "pinned_project_id": session.pinned_project_id,
            "goal": session.goal,
            "mode": session.mode.value,
            "status": session.status.value,
            "granted_capabilities": sorted(
                c.value for c in session.granted_capabilities
            ),
            "budgets": session.budgets.to_dict(),
            "usage": session.usage.to_dict(),
            "created_at": session.created_at,
            "updated_at": session.updated_at,
            "tools_registered": len(self.registry.names()),
        }

    # ------------------------------------------------------------------ #
    # Mode                                                                 #
    # ------------------------------------------------------------------ #

    def set_mode(
        self,
        mode: AutonomyMode | str,
        *,
        session_id: Optional[str] = None,
        aggressive_ack_phrase: Optional[str] = None,
    ) -> AgentSession:
        """
        Purpose:
            Change session autonomy mode. auto-aggressive requires project
            phrase I_ACCEPT_AUTO_AGGRESSIVE=<project_id> once (or prior ack).
        """
        project = self._require_project()
        if isinstance(mode, str):
            mode = parse_mode(mode)

        try:
            session = session_store.resolve_session_id(
                project.db_path, project.id, session_id
            )
        except session_store.SessionNotFound as exc:
            raise WorkflowEngineError(str(exc), exit_code=1) from exc

        if mode == AutonomyMode.AUTO_AGGRESSIVE:
            if not session_store.has_auto_aggressive_ack(project.db_path, project.id):
                expected = f"I_ACCEPT_AUTO_AGGRESSIVE={project.id}"
                if (aggressive_ack_phrase or "").strip() != expected:
                    raise WorkflowEngineError(
                        "auto-aggressive requires project acknowledgement. "
                        f"Pass --ack '{expected}' (once per project).",
                        exit_code=3,
                    )
                session_store.set_auto_aggressive_ack(
                    project.db_path, project.id, ack_by="operator"
                )

        updated = session_store.update_session_mode(
            project.db_path, project.id, session.session_id, mode
        )
        audit.record_event(
            project.db_path,
            project.id,
            "session.mode_set",
            {
                "session_id": updated.session_id,
                "mode": mode.value,
                "experimental": mode in EXPERIMENTAL_MODES,
            },
            session_id=updated.session_id,
        )
        return updated

    def clear_aggressive_ack(self) -> None:
        project = self._require_project()
        session_store.clear_auto_aggressive_ack(project.db_path, project.id)
        audit.record_event(
            project.db_path,
            project.id,
            "project.clear_aggressive_ack",
            {},
        )

    # ------------------------------------------------------------------ #
    # Tools                                                                #
    # ------------------------------------------------------------------ #

    def list_tools(self) -> list[dict[str, Any]]:
        return [d.to_dict() for d in self.registry.list_tools()]

    # ------------------------------------------------------------------ #
    # Validate → execute (Phase A internal / tests; approve CLI in Phase B)#
    # ------------------------------------------------------------------ #

    def validate_suggestion(
        self,
        suggestion: ActionSuggestion,
        *,
        session_id: Optional[str] = None,
        auto_reads: bool = False,
    ) -> Union[ExecutionPlan, PolicyReject]:
        project = self._require_project()
        try:
            session = session_store.resolve_session_id(
                project.db_path, project.id, session_id or suggestion.session_id
            )
        except session_store.SessionNotFound as exc:
            raise WorkflowEngineError(str(exc), exit_code=1) from exc

        result = self.validator.validate(
            suggestion, session, live=True, auto_reads=auto_reads
        )
        if isinstance(result, PolicyReject):
            audit.record_event(
                project.db_path,
                project.id,
                "policy.reject",
                {
                    "code": result.code,
                    "message": result.message,
                    "tool_name": result.tool_name,
                    "suggestion_id": suggestion.suggestion_id,
                },
                session_id=session.session_id,
            )
        else:
            audit.record_event(
                project.db_path,
                project.id,
                "policy.plan",
                {
                    "plan_id": result.plan_id,
                    "suggestion_id": result.suggestion_id,
                    "tool_name": result.tool_name,
                    "requires_approval": result.requires_approval,
                },
                session_id=session.session_id,
            )
        return result

    def execute_plan(
        self,
        plan: ExecutionPlan,
        *,
        session_id: Optional[str] = None,
    ) -> Observation:
        """
        Purpose:
            Execute a sealed plan. Phase A entry for tests; Phase B wires
            this behind approve after human gate.
        """
        project = self._require_project()
        try:
            session = session_store.resolve_session_id(
                project.db_path,
                project.id,
                session_id or plan.session_id,
            )
        except session_store.SessionNotFound as exc:
            raise WorkflowEngineError(str(exc), exit_code=1) from exc

        if session.mode == AutonomyMode.SUGGEST_ONLY:
            raise WorkflowEngineError(
                "Mode is suggest-only: execution is disabled. "
                "Run 'talos ai mode set step'.",
                exit_code=3,
            )

        try:
            observation = self.executor.execute(plan, session, persist_usage=True)
        except ExecutorError as exc:
            audit.record_event(
                project.db_path,
                project.id,
                "executor.error",
                {
                    "plan_id": plan.plan_id,
                    "error": str(exc),
                    "tool_name": plan.tool_name,
                },
                session_id=session.session_id,
            )
            raise WorkflowEngineError(str(exc), exit_code=1) from exc

        audit.record_event(
            project.db_path,
            project.id,
            "executor.done",
            {
                "plan_id": plan.plan_id,
                "observation_id": observation.observation_id,
                "tool_name": plan.tool_name,
                "success": observation.success,
                "summary": observation.result_summary[:500],
            },
            session_id=session.session_id,
        )
        return observation

    def validate_and_execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        session_id: Optional[str] = None,
        reason: Optional[str] = None,
        auto_reads: bool = True,
    ) -> tuple[ExecutionPlan, Observation]:
        """
        Purpose:
            Convenience for tests and internal Phase A paths: mint an
            in-memory suggestion, validate, execute (skipping human approve
            when plan.requires_approval is False, else still executes for
            test helper — callers must check requires_approval if needed).
        """
        project = self._require_project()
        try:
            session = session_store.resolve_session_id(
                project.db_path, project.id, session_id
            )
        except session_store.SessionNotFound as exc:
            raise WorkflowEngineError(str(exc), exit_code=1) from exc

        suggestion = ActionSuggestion(
            suggestion_id=str(uuid.uuid4()),
            session_id=session.session_id,
            tool_name=tool_name,
            arguments=dict(arguments or {}),
            reason=reason,
            created_at=datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat(),
        )
        plan_or_reject = self.validate_suggestion(
            suggestion, session_id=session.session_id, auto_reads=auto_reads
        )
        if isinstance(plan_or_reject, PolicyReject):
            raise WorkflowEngineError(
                f"Policy rejected: {plan_or_reject.code}: {plan_or_reject.message}",
                exit_code=3,
            )
        observation = self.execute_plan(
            plan_or_reject, session_id=session.session_id
        )
        return plan_or_reject, observation

    def list_audit(
        self,
        *,
        session_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        project = self._require_project()
        return audit.list_events(
            project.db_path,
            project.id,
            session_id=session_id,
            limit=limit,
        )
