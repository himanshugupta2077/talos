"""
Module: talos.ai.workflow.engine

Purpose:
    WorkflowEngine façade — the only surface CLI / MCP / CP should call for
    AI session orchestration. Phase A–C: sessions, tools, notes, suggest →
    immutable suggestions → ExecutionPlan approve/deny, PTT, observations,
    external MCP tool path, LLM or heuristic planner.

Dependencies: talos.ai.* , talos.projects.manager
Data flow:
    CLI/MCP → WorkflowEngine methods → session/audit/policy/executor/planner
Side effects:
    Session rows, audit events, budget updates, notes/plans/obs, handler effects.
"""

from __future__ import annotations

import json
import os
import sqlite3
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
    display_risk_for_capabilities,
    parse_mode,
)
from talos.ai.notes import store as notes_store
from talos.ai.planner.base import PlanRequest, Planner
from talos.ai.planner.factory import build_planner
from talos.ai.policy import PolicyValidator
from talos.ai.tools.registry import ToolRegistry, default_registry
from talos.ai.workflow import budgets as budget_mod
from talos.ai.workflow import observations as obs_store
from talos.ai.workflow import plans as plan_store
from talos.ai.workflow import session as session_store
from talos.ai.workflow import suggestions as suggestion_store
from talos.ai.workflow import task_tree as ptt
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


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


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
        planner: Optional[Planner] = None,
    ) -> None:
        self.manager = manager
        self._registry = registry
        self._validator = validator
        self._executor = executor
        self._planner = planner

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

    @property
    def planner(self) -> Planner:
        """
        Resolve planner from operator AI config (provider=none → heuristic).
        Explicit constructor inject always wins (tests / MCP hosts).
        """
        if self._planner is None:
            self._planner = build_planner(registry=self.registry)
        return self._planner

    def set_planner(self, planner: Planner) -> None:
        """Inject a planner (tests / custom hosts)."""
        self._planner = planner

    def _require_project(self):
        project = self.manager.active()
        if project is None:
            raise WorkflowEngineError(NO_ACTIVE_PROJECT_HINT, exit_code=3)
        return project

    def _require_active_session(
        self, session_id: Optional[str] = None
    ) -> tuple[Any, AgentSession]:
        project = self._require_project()
        try:
            session = session_store.resolve_session_id(
                project.db_path, project.id, session_id
            )
        except session_store.SessionNotFound as exc:
            raise WorkflowEngineError(str(exc), exit_code=1) from exc
        if session.status != SessionStatus.ACTIVE:
            raise WorkflowEngineError(
                f"Session is not active (status={session.status.value}).",
                exit_code=3,
            )
        return project, session

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
            # Halted sessions are not "active"; still allow operator recovery
            # without requiring the UUID when it is the only halted session.
            session = session_store.resolve_session_id(
                project.db_path,
                project.id,
                session_id,
                allow_halted=True,
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
        Falls back to the latest halted_budget session when none is active
        so operators can still inspect budgets after a halt.
        """
        project = self._require_project()
        try:
            session = session_store.resolve_session_id(
                project.db_path,
                project.id,
                session_id,
                allow_halted=True,
            )
        except session_store.SessionNotFound as exc:
            raise WorkflowEngineError(str(exc), exit_code=1) from exc

        pending_plans = plan_store.list_pending_plans(
            project.db_path, session.session_id
        )
        suggestions = suggestion_store.list_suggestions(
            project.db_path, session.session_id, limit=200
        )
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
            "pending_plan_count": len(pending_plans),
            "suggestion_count": len(suggestions),
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
        force: bool = False,
    ) -> Observation:
        """
        Purpose:
            Execute a sealed plan. Plans with requires_approval=True are
            refused unless force=True (Phase B: human approve sets force
            after re-validation). Phase A tests use validate_and_execute.
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

        if plan.requires_approval and not force:
            raise WorkflowEngineError(
                f"Plan {plan.plan_id} requires approval before execute "
                f"(tool={plan.tool_name}). Phase B: talos ai approve <plan_id>.",
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
        force: bool = True,
    ) -> tuple[ExecutionPlan, Observation]:
        """
        Purpose:
            Test/internal helper: mint an in-memory suggestion, validate,
            and execute. Default force=True bypasses the approval gate so
            Phase A unit tests can exercise handlers; production paths
            must use validate → approve → execute_plan(force=True) only
            after an operator decision (Phase B).
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
            plan_or_reject,
            session_id=session.session_id,
            force=force,
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

    # ------------------------------------------------------------------ #
    # Phase B — suggest / approve / deny / pending / notes                 #
    # ------------------------------------------------------------------ #

    def _gather_inventory_signals(self, db_path, project_id: str) -> dict[str, Any]:
        """Cheap counts for the offline heuristic planner (fail soft)."""
        signals: dict[str, Any] = {
            "endpoint_count": 0,
            "iv_candidate_count": 0,
            "passive_detection_count": 0,
            "finding_count": 0,
            "error_cluster_count": 0,
            "open_job_count": 0,
        }
        try:
            with sqlite3.connect(str(db_path)) as conn:
                def _count(sql: str, params: tuple = ()) -> int:
                    try:
                        row = conn.execute(sql, params).fetchone()
                        return int(row[0]) if row and row[0] is not None else 0
                    except sqlite3.Error:
                        return 0

                signals["endpoint_count"] = _count(
                    "SELECT COUNT(*) FROM endpoints WHERE project_id = ?",
                    (project_id,),
                )
                signals["finding_count"] = _count(
                    "SELECT COUNT(*) FROM findings WHERE project_id = ?",
                    (project_id,),
                )
                signals["passive_detection_count"] = _count(
                    "SELECT COUNT(*) FROM passive_detections WHERE project_id = ?",
                    (project_id,),
                )
                signals["error_cluster_count"] = _count(
                    "SELECT COUNT(*) FROM error_clusters WHERE project_id = ?",
                    (project_id,),
                )
                signals["open_job_count"] = _count(
                    "SELECT COUNT(*) FROM scheduler_jobs WHERE project_id = ? "
                    "AND status IN ('pending', 'running', 'queued')",
                    (project_id,),
                )
                # IV candidates live in param profiles / cache — best-effort.
                signals["iv_candidate_count"] = _count(
                    "SELECT COUNT(*) FROM iv_param_profiles WHERE project_id = ?",
                    (project_id,),
                )
        except Exception:  # noqa: BLE001 — planner still works without signals
            pass
        return signals

    def _build_plan_request(
        self,
        session: AgentSession,
        *,
        max_suggestions: int = 5,
    ) -> PlanRequest:
        notes_snap = notes_store.get_notes(session.db_path, session.project_id)
        notes_pack = notes_store.pack_for_planner(notes_snap)
        frontier = ptt.frontier(session.db_path, session.session_id)
        recent = obs_store.list_observations(
            session.db_path, session.session_id, limit=10
        )
        recent_packed = obs_store.pack_for_planner(recent)
        specs = [self.registry.get_spec(n) for n in self.registry.names()]
        budget_mod.refresh_wall_clock(session.usage, session.created_at)
        return PlanRequest(
            session_id=session.session_id,
            goal=session.goal,
            mode=session.mode.value,
            granted_capabilities=session.granted_capabilities,
            tool_descriptors=specs,
            notes_pack=notes_pack,
            kb_hits=[],
            ptt_frontier=frontier,
            budgets_summary={
                "limits": session.budgets.to_dict(),
                "usage": session.usage.to_dict(),
            },
            recent_observations=recent_packed,
            max_suggestions=max_suggestions,
            inventory_signals=self._gather_inventory_signals(
                session.db_path, session.project_id
            ),
        )

    def _persist_plan_from_validate(
        self,
        db_path,
        plan: ExecutionPlan,
        *,
        status: str = plan_store.PlanStatus.PENDING_APPROVAL.value,
    ) -> None:
        plan_store.insert_plan(db_path, plan, status=status)

    def _execute_and_record(
        self,
        project,
        session: AgentSession,
        plan: ExecutionPlan,
        *,
        force: bool = True,
    ) -> Observation:
        """Execute sealed plan, persist observation + plan terminal status."""
        plan_store.set_plan_status(
            project.db_path,
            plan.plan_id,
            plan_store.PlanStatus.EXECUTING.value,
            decided=False,
        )
        try:
            observation = self.execute_plan(
                plan, session_id=session.session_id, force=force
            )
        except WorkflowEngineError:
            plan_store.set_plan_status(
                project.db_path,
                plan.plan_id,
                plan_store.PlanStatus.FAILED.value,
                failure_reason="executor error",
            )
            raise

        terminal = (
            plan_store.PlanStatus.EXECUTED.value
            if observation.success
            else plan_store.PlanStatus.FAILED.value
        )
        plan_store.set_plan_status(
            project.db_path,
            plan.plan_id,
            terminal,
            failure_reason=None if observation.success else observation.result_summary,
        )
        obs_store.insert_observation(project.db_path, observation)
        return observation

    def suggest(
        self,
        *,
        session_id: Optional[str] = None,
        auto_reads: bool = False,
        max_suggestions: int = 5,
    ) -> dict[str, Any]:
        """
        Purpose:
            One planner turn → immutable suggestions; validate into plans
            when mode allows; optional auto-execute READ tools with --auto-reads.
        """
        project, session = self._require_active_session(session_id)

        exceeded = budget_mod.first_exceeded(
            session.budgets, session.usage, started_at_iso=session.created_at
        )
        if exceeded:
            session_store.update_session_usage(
                project.db_path,
                project.id,
                session.session_id,
                session.usage,
                status=SessionStatus.HALTED_BUDGET,
            )
            raise WorkflowEngineError(
                f"Budget exceeded ({exceeded}); session halted. "
                "Run 'talos ai reset-budget'.",
                exit_code=3,
            )

        if auto_reads and session.mode == AutonomyMode.SUGGEST_ONLY:
            raise WorkflowEngineError(
                "--auto-reads is not available in suggest-only mode. "
                "Run 'talos ai mode set step' first.",
                exit_code=3,
            )

        request = self._build_plan_request(
            session, max_suggestions=max(1, min(int(max_suggestions or 5), 10))
        )
        planner = self.planner
        raw_suggestions = list(planner.plan(request) or [])

        # Account LLM tokens when the planner reports usage (LLMPlanner).
        llm_tokens_added = self._apply_planner_token_usage(session, planner)
        if llm_tokens_added:
            budget_mod.refresh_wall_clock(session.usage, session.created_at)
            halt_tokens = budget_mod.first_exceeded(session.budgets, session.usage)
            session_store.update_session_usage(
                project.db_path,
                project.id,
                session.session_id,
                session.usage,
                status=SessionStatus.HALTED_BUDGET if halt_tokens else None,
            )
            if halt_tokens:
                session = session_store.get_session(
                    project.db_path, project.id, session.session_id
                )

        # Ensure session_id + created_at on every suggestion.
        suggestions: list[ActionSuggestion] = []
        for s in raw_suggestions:
            suggestions.append(
                ActionSuggestion(
                    suggestion_id=s.suggestion_id or str(uuid.uuid4()),
                    session_id=session.session_id,
                    tool_name=s.tool_name,
                    arguments=dict(s.arguments or {}),
                    reason=s.reason,
                    cli_preview=s.cli_preview,
                    created_at=s.created_at or _now_iso(),
                    display_risk=s.display_risk,
                )
            )

        suggestion_store.record_suggestions(project.db_path, suggestions)

        planner_source = getattr(planner, "last_source", None)
        planner_error = getattr(planner, "last_error", None)

        if suggestions:
            session.usage.steps += 1
            budget_mod.refresh_wall_clock(session.usage, session.created_at)
            halt = budget_mod.first_exceeded(session.budgets, session.usage)
            session_store.update_session_usage(
                project.db_path,
                project.id,
                session.session_id,
                session.usage,
                status=SessionStatus.HALTED_BUDGET if halt else None,
            )
            if halt:
                # Still return recorded suggestions; further suggest/approve blocked.
                pass

        audit.record_event(
            project.db_path,
            project.id,
            "planner.suggest",
            {
                "session_id": session.session_id,
                "count": len(suggestions),
                "tools": [s.tool_name for s in suggestions],
                "auto_reads": auto_reads,
                "mode": session.mode.value,
                "planner_source": planner_source,
                "planner_error": planner_error,
                "llm_tokens_added": llm_tokens_added,
            },
            session_id=session.session_id,
        )

        plans_out: list[dict[str, Any]] = []
        observations_out: list[dict[str, Any]] = []
        rejects: list[dict[str, Any]] = []

        # Reload session after step budget update.
        session = session_store.get_session(
            project.db_path, project.id, session.session_id
        )

        for s in suggestions:
            if session.mode == AutonomyMode.SUGGEST_ONLY:
                # Record suggestions only; no ExecutionPlan (execute hard-off).
                continue

            if session.status != SessionStatus.ACTIVE:
                rejects.append(
                    {
                        "suggestion_id": s.suggestion_id,
                        "code": "session_not_active",
                        "message": f"status={session.status.value}",
                    }
                )
                continue

            result = self.validator.validate(
                s, session, live=True, auto_reads=auto_reads
            )
            if isinstance(result, PolicyReject):
                plan_store.insert_rejected_plan(
                    project.db_path,
                    plan_id=str(uuid.uuid4()),
                    suggestion_id=s.suggestion_id,
                    session_id=session.session_id,
                    tool_name=s.tool_name,
                    arguments=s.arguments,
                    reason=f"{result.code}: {result.message}",
                )
                rejects.append(
                    {
                        "suggestion_id": s.suggestion_id,
                        "code": result.code,
                        "message": result.message,
                        "tool_name": s.tool_name,
                    }
                )
                audit.record_event(
                    project.db_path,
                    project.id,
                    "policy.reject",
                    {
                        "code": result.code,
                        "message": result.message,
                        "tool_name": result.tool_name,
                        "suggestion_id": s.suggestion_id,
                    },
                    session_id=session.session_id,
                )
                continue

            # Persist pending (or will auto-exec).
            status = plan_store.PlanStatus.PENDING_APPROVAL.value
            self._persist_plan_from_validate(
                project.db_path, result, status=status
            )
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

            auto_exec = not result.requires_approval
            if auto_exec:
                plan_store.set_plan_status(
                    project.db_path,
                    result.plan_id,
                    plan_store.PlanStatus.AUTHORIZED.value,
                )
                try:
                    obs = self._execute_and_record(
                        project, session, result, force=True
                    )
                    observations_out.append(
                        {
                            "observation_id": obs.observation_id,
                            "plan_id": obs.plan_id,
                            "tool_name": obs.tool_name,
                            "success": obs.success,
                            "summary": obs.result_summary,
                        }
                    )
                    session = session_store.get_session(
                        project.db_path, project.id, session.session_id
                    )
                except WorkflowEngineError as exc:
                    rejects.append(
                        {
                            "suggestion_id": s.suggestion_id,
                            "plan_id": result.plan_id,
                            "code": "execute_failed",
                            "message": str(exc),
                        }
                    )
            else:
                plans_out.append(
                    {
                        "plan_id": result.plan_id,
                        "suggestion_id": result.suggestion_id,
                        "tool_name": result.tool_name,
                        "arguments": result.arguments,
                        "requires_approval": result.requires_approval,
                        "status": status,
                        "cli_preview": s.cli_preview,
                        "reason": s.reason,
                    }
                )

        return {
            "session_id": session.session_id,
            "mode": session.mode.value,
            "suggestions": [
                {
                    "suggestion_id": s.suggestion_id,
                    "tool_name": s.tool_name,
                    "arguments": s.arguments,
                    "reason": s.reason,
                    "cli_preview": s.cli_preview,
                    "display_risk": s.display_risk,
                    "created_at": s.created_at,
                }
                for s in suggestions
            ],
            "pending_plans": plans_out,
            "auto_executed": observations_out,
            "rejects": rejects,
            "suggestion_count": len(suggestions),
            "pending_plan_count": len(plans_out),
            "auto_executed_count": len(observations_out),
            "planner_source": planner_source,
            "planner_error": planner_error,
            "llm_tokens_added": llm_tokens_added,
        }

    def _apply_planner_token_usage(
        self, session: AgentSession, planner: Planner
    ) -> int:
        """
        Increment session.usage.llm_tokens from planner.last_usage when present.
        Returns tokens added (0 if none).
        """
        usage = getattr(planner, "last_usage", None)
        if not isinstance(usage, dict) or not usage:
            return 0
        total = usage.get("total_tokens")
        try:
            tokens = int(total or 0)
        except (TypeError, ValueError):
            tokens = 0
        if tokens <= 0:
            return 0
        session.usage.llm_tokens += tokens
        return tokens

    def external_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        session_id: Optional[str] = None,
        reason: str = "external tools/call",
    ) -> dict[str, Any]:
        """
        Purpose:
            MCP / external client tool path. Always goes through:
            record immutable ActionSuggestion → PolicyValidator → optional
            Executor. Never bypasses approval for step mode tools that need it.

        Output status values:
            executed | needs_approval | rejected | error
        """
        project, session = self._require_active_session(session_id)

        exceeded = budget_mod.first_exceeded(
            session.budgets, session.usage, started_at_iso=session.created_at
        )
        if exceeded:
            session_store.update_session_usage(
                project.db_path,
                project.id,
                session.session_id,
                session.usage,
                status=SessionStatus.HALTED_BUDGET,
            )
            return {
                "status": "rejected",
                "code": "budget_exceeded",
                "message": f"Budget exceeded ({exceeded}); session halted.",
                "session_id": session.session_id,
            }

        tool_name = (tool_name or "").strip()
        if not tool_name:
            return {
                "status": "error",
                "code": "missing_tool_name",
                "message": "tool_name is required",
                "session_id": session.session_id,
            }

        display_risk = "read"
        try:
            policy = self.registry.get_policy(tool_name)
            display_risk = display_risk_for_capabilities(policy.capabilities)
        except KeyError:
            pass

        suggestion = ActionSuggestion(
            suggestion_id=str(uuid.uuid4()),
            session_id=session.session_id,
            tool_name=tool_name,
            arguments=dict(arguments or {}),
            reason=reason,
            cli_preview=f"# {tool_name} {arguments!r}"[:500],
            created_at=_now_iso(),
            display_risk=display_risk,
        )
        suggestion_store.record_suggestions(project.db_path, [suggestion])
        audit.record_event(
            project.db_path,
            project.id,
            "mcp.tool_call",
            {
                "suggestion_id": suggestion.suggestion_id,
                "tool_name": tool_name,
                "mode": session.mode.value,
            },
            session_id=session.session_id,
        )

        if session.mode == AutonomyMode.SUGGEST_ONLY:
            return {
                "status": "needs_approval",
                "code": "suggest_only",
                "message": (
                    "Mode is suggest-only: suggestion recorded but not executable. "
                    "Run 'talos ai mode set step' then approve after re-suggest, "
                    "or use step mode for MCP execute path."
                ),
                "suggestion_id": suggestion.suggestion_id,
                "tool_name": tool_name,
                "arguments": suggestion.arguments,
                "session_id": session.session_id,
                "mode": session.mode.value,
            }

        result = self.validator.validate(
            suggestion, session, live=True, auto_reads=False
        )
        if isinstance(result, PolicyReject):
            plan_store.insert_rejected_plan(
                project.db_path,
                plan_id=str(uuid.uuid4()),
                suggestion_id=suggestion.suggestion_id,
                session_id=session.session_id,
                tool_name=tool_name,
                arguments=suggestion.arguments,
                reason=f"{result.code}: {result.message}",
            )
            audit.record_event(
                project.db_path,
                project.id,
                "policy.reject",
                {
                    "code": result.code,
                    "message": result.message,
                    "tool_name": tool_name,
                    "suggestion_id": suggestion.suggestion_id,
                    "source": "mcp",
                },
                session_id=session.session_id,
            )
            return {
                "status": "rejected",
                "code": result.code,
                "message": result.message,
                "suggestion_id": suggestion.suggestion_id,
                "tool_name": tool_name,
                "session_id": session.session_id,
            }

        # Prefer needs_approval over silent pending queues for step mode.
        if result.requires_approval:
            plan_store.insert_plan(
                project.db_path,
                result,
                status=plan_store.PlanStatus.PENDING_APPROVAL.value,
            )
            audit.record_event(
                project.db_path,
                project.id,
                "policy.plan",
                {
                    "plan_id": result.plan_id,
                    "suggestion_id": result.suggestion_id,
                    "tool_name": result.tool_name,
                    "requires_approval": True,
                    "source": "mcp",
                },
                session_id=session.session_id,
            )
            return {
                "status": "needs_approval",
                "code": "needs_approval",
                "message": (
                    f"Tool '{tool_name}' requires operator approval. "
                    f"Run: talos ai approve {result.plan_id}"
                ),
                "suggestion_id": suggestion.suggestion_id,
                "plan_id": result.plan_id,
                "tool_name": tool_name,
                "arguments": result.arguments,
                "session_id": session.session_id,
                "mode": session.mode.value,
            }

        # Auto-authorize path (experimental auto-* modes when caps allow).
        plan_store.insert_plan(
            project.db_path,
            result,
            status=plan_store.PlanStatus.AUTHORIZED.value,
        )
        try:
            observation = self._execute_and_record(
                project, session, result, force=True
            )
        except WorkflowEngineError as exc:
            return {
                "status": "error",
                "code": "execute_failed",
                "message": str(exc),
                "suggestion_id": suggestion.suggestion_id,
                "plan_id": result.plan_id,
                "tool_name": tool_name,
                "session_id": session.session_id,
            }

        return {
            "status": "executed",
            "suggestion_id": suggestion.suggestion_id,
            "plan_id": result.plan_id,
            "tool_name": tool_name,
            "arguments": result.arguments,
            "observation": {
                "observation_id": observation.observation_id,
                "success": observation.success,
                "summary": observation.result_summary,
                "citations": observation.citations,
                "data": observation.data,
            },
            "session_id": session.session_id,
            "mode": session.mode.value,
        }

    def approve(
        self,
        target_id: str,
        *,
        session_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Purpose:
            Approve a *pending* ExecutionPlan (or resolve suggestion_id → latest
            pending plan), re-validate, execute, record observation.

            Terminal plans (executed/denied/failed/…) cannot be re-approved —
            operator must run a new suggest turn (avoids silent re-execution).
        """
        project, session = self._require_active_session(session_id)

        if session.mode == AutonomyMode.SUGGEST_ONLY:
            raise WorkflowEngineError(
                "Mode is suggest-only: approve/execute is disabled. "
                "Run 'talos ai mode set step'.",
                exit_code=3,
            )

        exceeded = budget_mod.first_exceeded(
            session.budgets, session.usage, started_at_iso=session.created_at
        )
        if exceeded:
            # Persist halt so status matches budgets.
            session_store.update_session_usage(
                project.db_path,
                project.id,
                session.session_id,
                session.usage,
                status=SessionStatus.HALTED_BUDGET,
            )
            raise WorkflowEngineError(
                f"Budget exceeded ({exceeded}); cannot approve. "
                "Run 'talos ai reset-budget'.",
                exit_code=3,
            )

        target_id = (target_id or "").strip()
        if not target_id:
            raise WorkflowEngineError("plan_id or suggestion_id required", exit_code=2)

        plan_row = plan_store.get_plan_row(project.db_path, target_id)
        suggestion_id: Optional[str] = None
        resolved_via_plan = False

        if plan_row is not None:
            resolved_via_plan = True
            if plan_row.get("session_id") != session.session_id:
                raise WorkflowEngineError(
                    "Plan does not belong to the active session.",
                    exit_code=1,
                )
            status = plan_row.get("status") or ""
            if status in plan_store.TERMINAL_PLAN_STATUSES:
                raise WorkflowEngineError(
                    f"Plan is already terminal (status={status}); "
                    "run 'talos ai suggest' for a new proposal. "
                    "Re-approve of executed/denied plans is not allowed.",
                    exit_code=3,
                )
            if status not in (
                plan_store.PlanStatus.PENDING_APPROVAL.value,
                plan_store.PlanStatus.AUTHORIZED.value,
            ):
                raise WorkflowEngineError(
                    f"Plan status '{status}' cannot be approved "
                    f"(need pending_approval).",
                    exit_code=3,
                )
            suggestion_id = plan_row.get("suggestion_id")
        else:
            # Treat as suggestion_id → latest pending plan only.
            suggestion = suggestion_store.get_suggestion(
                project.db_path, target_id, session_id=session.session_id
            )
            if suggestion is None:
                raise WorkflowEngineError(
                    f"No plan or suggestion found for id: {target_id}",
                    exit_code=1,
                )
            suggestion_id = suggestion.suggestion_id
            plan_row = plan_store.latest_pending_for_suggestion(
                project.db_path, suggestion_id
            )
            if plan_row is None:
                raise WorkflowEngineError(
                    f"No pending plan for suggestion {suggestion_id}. "
                    "It may already be executed, denied, or never validated "
                    "(suggest-only records suggestions without plans). "
                    "Run 'talos ai suggest' again if you need a new plan.",
                    exit_code=3,
                )

        if suggestion_id is None:
            raise WorkflowEngineError(
                f"Cannot resolve suggestion for {target_id}", exit_code=1
            )

        suggestion = suggestion_store.get_suggestion(
            project.db_path, suggestion_id, session_id=session.session_id
        )
        if suggestion is None:
            raise WorkflowEngineError(
                f"Suggestion not found: {suggestion_id}", exit_code=1
            )

        # Re-validate always (live policy) — mints a new sealed plan + token.
        result = self.validator.validate(
            suggestion, session, live=True, auto_reads=False
        )
        if isinstance(result, PolicyReject):
            if plan_row is not None and plan_row.get("status") == (
                plan_store.PlanStatus.PENDING_APPROVAL.value
            ):
                plan_store.set_plan_status(
                    project.db_path,
                    plan_row["id"],
                    plan_store.PlanStatus.REJECTED.value,
                    failure_reason=f"{result.code}: {result.message}",
                )
            audit.record_event(
                project.db_path,
                project.id,
                "policy.reject",
                {
                    "code": result.code,
                    "message": result.message,
                    "suggestion_id": suggestion_id,
                    "on": "approve",
                    "resolved_via_plan": resolved_via_plan,
                },
                session_id=session.session_id,
            )
            raise WorkflowEngineError(
                f"Policy rejected on approve: {result.code}: {result.message}",
                exit_code=3,
            )

        # Supersede old pending/authorized plan if revalidation minted a new id.
        if plan_row is not None and plan_row["id"] != result.plan_id:
            if plan_row.get("status") in (
                plan_store.PlanStatus.PENDING_APPROVAL.value,
                plan_store.PlanStatus.AUTHORIZED.value,
            ):
                plan_store.set_plan_status(
                    project.db_path,
                    plan_row["id"],
                    plan_store.PlanStatus.SUPERSEDED.value,
                    failure_reason="revalidated on approve",
                )

        existing_new = plan_store.get_plan_row(project.db_path, result.plan_id)
        if existing_new is None:
            plan_store.insert_plan(
                project.db_path,
                result,
                status=plan_store.PlanStatus.AUTHORIZED.value,
            )
        else:
            plan_store.set_plan_status(
                project.db_path,
                result.plan_id,
                plan_store.PlanStatus.AUTHORIZED.value,
            )

        audit.record_event(
            project.db_path,
            project.id,
            "plan.approve",
            {
                "plan_id": result.plan_id,
                "suggestion_id": suggestion_id,
                "tool_name": result.tool_name,
                "superseded": plan_row["id"]
                if plan_row is not None and plan_row["id"] != result.plan_id
                else None,
            },
            session_id=session.session_id,
        )

        observation = self._execute_and_record(
            project, session, result, force=True
        )
        return {
            "plan_id": result.plan_id,
            "suggestion_id": suggestion_id,
            "tool_name": result.tool_name,
            "arguments": result.arguments,
            "observation": {
                "observation_id": observation.observation_id,
                "success": observation.success,
                "summary": observation.result_summary,
                "citations": observation.citations,
                "data": observation.data,
            },
            "session_id": session.session_id,
        }

    def deny(
        self,
        target_id: str,
        *,
        session_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> dict[str, Any]:
        """Deny a plan_id or all non-terminal plans for a suggestion_id."""
        project, session = self._require_active_session(session_id)
        target_id = (target_id or "").strip()
        if not target_id:
            raise WorkflowEngineError("plan_id or suggestion_id required", exit_code=2)

        reason_text = (reason or "denied by operator").strip()
        plan_row = plan_store.get_plan_row(project.db_path, target_id)
        denied_ids: list[str] = []

        if plan_row is not None:
            if plan_row.get("session_id") != session.session_id:
                raise WorkflowEngineError(
                    "Plan does not belong to the active session.", exit_code=1
                )
            if plan_row.get("status") in plan_store.TERMINAL_PLAN_STATUSES:
                raise WorkflowEngineError(
                    f"Plan already terminal ({plan_row.get('status')}).",
                    exit_code=1,
                )
            plan_store.set_plan_status(
                project.db_path,
                plan_row["id"],
                plan_store.PlanStatus.DENIED.value,
                failure_reason=reason_text,
            )
            denied_ids.append(plan_row["id"])
        else:
            suggestion = suggestion_store.get_suggestion(
                project.db_path, target_id, session_id=session.session_id
            )
            if suggestion is None:
                raise WorkflowEngineError(
                    f"No plan or suggestion found for id: {target_id}",
                    exit_code=1,
                )
            n = plan_store.deny_plans_for_suggestion(
                project.db_path, suggestion.suggestion_id, reason=reason_text
            )
            if n == 0:
                # No plans yet (e.g. suggest-only) — still audit the deny intent.
                pass
            else:
                rows = plan_store.list_plans(
                    project.db_path, session.session_id, limit=200
                )
                denied_ids = [
                    r["id"]
                    for r in rows
                    if r.get("suggestion_id") == suggestion.suggestion_id
                    and r.get("status") == plan_store.PlanStatus.DENIED.value
                ]

        audit.record_event(
            project.db_path,
            project.id,
            "plan.deny",
            {
                "target_id": target_id,
                "denied_plan_ids": denied_ids,
                "reason": reason_text,
            },
            session_id=session.session_id,
        )
        return {
            "target_id": target_id,
            "denied_plan_ids": denied_ids,
            "reason": reason_text,
            "session_id": session.session_id,
        }

    def pending(
        self, *, session_id: Optional[str] = None
    ) -> dict[str, Any]:
        """List suggestions + plans awaiting approval."""
        project, session = self._require_active_session(session_id)
        suggestions = suggestion_store.list_suggestions(
            project.db_path, session.session_id, limit=100
        )
        pending_plans = plan_store.list_pending_plans(
            project.db_path, session.session_id
        )
        return {
            "session_id": session.session_id,
            "mode": session.mode.value,
            "suggestions": [
                {
                    "suggestion_id": s.suggestion_id,
                    "tool_name": s.tool_name,
                    "arguments": s.arguments,
                    "reason": s.reason,
                    "cli_preview": s.cli_preview,
                    "created_at": s.created_at,
                }
                for s in suggestions
            ],
            "pending_plans": [
                plan_store.plan_row_to_public(r) for r in pending_plans
            ],
            "suggestion_count": len(suggestions),
            "pending_plan_count": len(pending_plans),
        }

    def show_plan(
        self, plan_id: str, *, session_id: Optional[str] = None
    ) -> dict[str, Any]:
        """Show ExecutionPlan vs linked immutable suggestion."""
        project = self._require_project()
        try:
            session = session_store.resolve_session_id(
                project.db_path, project.id, session_id
            )
        except session_store.SessionNotFound as exc:
            raise WorkflowEngineError(str(exc), exit_code=1) from exc

        row = plan_store.get_plan_row(project.db_path, plan_id)
        if row is None or row.get("session_id") != session.session_id:
            raise WorkflowEngineError(f"Plan not found: {plan_id}", exit_code=1)

        suggestion = suggestion_store.get_suggestion(
            project.db_path,
            row["suggestion_id"],
            session_id=session.session_id,
        )
        public = plan_store.plan_row_to_public(row)
        return {
            "plan": public,
            "suggestion": {
                "suggestion_id": suggestion.suggestion_id,
                "tool_name": suggestion.tool_name,
                "arguments": suggestion.arguments,
                "reason": suggestion.reason,
                "cli_preview": suggestion.cli_preview,
                "created_at": suggestion.created_at,
            }
            if suggestion
            else None,
            "args_differ": (
                json.dumps(public.get("arguments") or {}, sort_keys=True)
                != json.dumps(
                    (suggestion.arguments if suggestion else {}) or {},
                    sort_keys=True,
                )
            ),
        }

    # ---- Notes operator CLI surface ----

    def notes_show(self) -> dict[str, Any]:
        project = self._require_project()
        snap = notes_store.get_notes(project.db_path, project.id)
        return snap.to_dict()

    def notes_export(self) -> dict[str, Any]:
        return self.notes_show()

    def notes_replace(
        self,
        doc: dict[str, Any],
        *,
        if_revision: Optional[int] = None,
        updated_by: str = "operator",
    ) -> dict[str, Any]:
        project = self._require_project()
        try:
            snap = notes_store.replace_notes(
                project.db_path,
                project.id,
                doc,
                if_revision=if_revision,
                updated_by=updated_by,
            )
        except notes_store.NotesRevisionConflict as exc:
            raise WorkflowEngineError(str(exc), exit_code=3) from exc
        except notes_store.NotesError as exc:
            raise WorkflowEngineError(str(exc), exit_code=1) from exc
        audit.record_event(
            project.db_path,
            project.id,
            "notes.replace",
            {"revision": snap.revision, "updated_by": updated_by},
        )
        return snap.to_dict()

