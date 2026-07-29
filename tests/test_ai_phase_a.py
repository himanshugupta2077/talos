"""
Tests for Talos AI Layer — Phase A foundation.

Covers:
    - Schema v49 tables (ai_sessions, ai_audit_events, ai_project_prefs)
    - Session pin, one-active-per-project, start/stop/resume/reset-budget
    - Capability grants by mode (suggest-only empty; step full)
    - ToolRegistry has no public call()/execute()
    - PolicyValidator → sealed ExecutionPlan → Executor for READ tools
    - role.set_active exists-only (no create)
    - suggest-only hard-rejects validate/execute
"""

from __future__ import annotations

import inspect
import json
import sqlite3
import uuid
from pathlib import Path

import pytest

from talos.ai.executor import Executor, ExecutorError
from talos.ai.models import (
    ActionSuggestion,
    AutonomyMode,
    BudgetLimits,
    Capability,
    ExecutionPlan,
    PolicyReject,
    SessionStatus,
    grants_for_mode,
)
from talos.ai.policy import reset_token_store_for_tests
from talos.ai.tools.registry import (
    ToolRegistry,
    default_registry,
    reset_default_registry_for_tests,
)
from talos.ai.workflow.engine import WorkflowEngine, WorkflowEngineError
from talos.ai.workflow import session as session_store
from talos.projects.access import create_role, get_active_role
from talos.projects.db import SCHEMA_VERSION, get_schema_version
from talos.projects.manager import ProjectManager, TALOS_PROJECT_ENV


@pytest.fixture(autouse=True)
def _clean_ai_singletons() -> None:
    reset_token_store_for_tests()
    reset_default_registry_for_tests()
    yield
    reset_token_store_for_tests()
    reset_default_registry_for_tests()


@pytest.fixture
def projects_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.delenv(TALOS_PROJECT_ENV, raising=False)
    root = tmp_path / "projects"
    root.mkdir()
    return root


@pytest.fixture
def manager(projects_root: Path) -> ProjectManager:
    return ProjectManager(projects_root)


@pytest.fixture
def project(manager: ProjectManager):
    p = manager.create(name="AI Test App", scope=["example.com"])
    manager.open(p.id)
    return manager.get(p.id)


@pytest.fixture
def engine(manager: ProjectManager, project) -> WorkflowEngine:
    return WorkflowEngine(manager)


# ================================================================== #
# Schema                                                               #
# ================================================================== #


class TestSchemaV49:
    def test_schema_version_is_at_least_49(self) -> None:
        # Phase B bumped SCHEMA_VERSION to 51; Phase A tables still required.
        assert SCHEMA_VERSION >= 49

    def test_fresh_db_has_ai_tables(self, project) -> None:
        assert get_schema_version(project.db_path) == SCHEMA_VERSION
        with sqlite3.connect(str(project.db_path)) as conn:
            tables = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        assert "ai_sessions" in tables
        assert "ai_audit_events" in tables
        assert "ai_project_prefs" in tables


# ================================================================== #
# Capabilities                                                         #
# ================================================================== #


class TestCapabilities:
    def test_suggest_only_grants_nothing(self) -> None:
        assert grants_for_mode(AutonomyMode.SUGGEST_ONLY) == frozenset()

    def test_step_grants_read_and_modify_context(self) -> None:
        caps = grants_for_mode(AutonomyMode.STEP)
        assert Capability.READ_ENDPOINTS in caps
        assert Capability.READ_CONTEXT in caps
        assert Capability.MODIFY_CONTEXT in caps
        assert Capability.SEND_REQUEST in caps


# ================================================================== #
# Session lifecycle                                                    #
# ================================================================== #


class TestSessionLifecycle:
    def test_start_pins_project(self, engine: WorkflowEngine, project) -> None:
        session = engine.start("map the app", mode=AutonomyMode.SUGGEST_ONLY)
        assert session.status == SessionStatus.ACTIVE
        assert session.pinned_project_id == project.id
        assert session.project_id == project.id
        assert Path(session.data_dir) == Path(project.data_dir)
        assert session.db_path == project.db_path
        assert session.goal == "map the app"

    def test_one_active_per_project(self, engine: WorkflowEngine) -> None:
        engine.start("first")
        with pytest.raises(WorkflowEngineError) as exc:
            engine.start("second")
        assert exc.value.exit_code == 3

    def test_force_stop_existing(self, engine: WorkflowEngine) -> None:
        first = engine.start("first")
        second = engine.start("second", force_stop_existing=True)
        assert second.session_id != first.session_id
        reloaded = session_store.get_session(
            first.db_path, first.project_id, first.session_id
        )
        assert reloaded.status == SessionStatus.STOPPED

    def test_stop_and_resume(self, engine: WorkflowEngine) -> None:
        session = engine.start("goal")
        stopped = engine.stop(session.session_id)
        assert stopped.status == SessionStatus.STOPPED
        resumed = engine.resume(session.session_id)
        assert resumed.status == SessionStatus.ACTIVE
        assert resumed.pinned_project_id == session.pinned_project_id

    def test_reset_budget(self, engine: WorkflowEngine, project) -> None:
        session = engine.start("goal", mode=AutonomyMode.STEP)
        # Manually bump usage.
        session.usage.tool_calls = 10
        session_store.update_session_usage(
            project.db_path, project.id, session.session_id, session.usage
        )
        reset = engine.reset_budget(session.session_id)
        assert reset.usage.tool_calls == 0

    def test_status_payload(self, engine: WorkflowEngine) -> None:
        engine.start("goal", mode=AutonomyMode.STEP)
        payload = engine.status()
        assert payload["status"] == "active"
        assert payload["mode"] == "step"
        assert "read_endpoints" in payload["granted_capabilities"]
        assert payload["tools_registered"] >= 1

    def test_audit_on_start(self, engine: WorkflowEngine) -> None:
        session = engine.start("audited")
        events = engine.list_audit(session_id=session.session_id)
        types = [e["event_type"] for e in events]
        assert "session.start" in types


# ================================================================== #
# Tool registry                                                        #
# ================================================================== #


class TestToolRegistry:
    def test_no_public_call_or_execute(self) -> None:
        reg = default_registry()
        public = [n for n in dir(reg) if not n.startswith("_")]
        assert "call" not in public
        assert "execute" not in public
        # Source-level: class body must not define call/execute as public.
        src = inspect.getsource(ToolRegistry)
        assert "def call(" not in src
        assert "def execute(" not in src

    def test_list_tools_includes_phase_a(self, engine: WorkflowEngine) -> None:
        names = {t["name"] for t in engine.list_tools()}
        assert "endpoint.list" in names
        assert "role.set_active" in names
        assert "module.set_active" in names
        assert "role.list" in names
        assert "iv.candidates" in names
        # Phase D registers HTTP tools (still present alongside Phase A READ tools).
        assert "send.once" in names

    def test_unknown_tool_get_spec_raises(self) -> None:
        reg = default_registry()
        with pytest.raises(KeyError):
            reg.get_spec("project.delete")


# ================================================================== #
# Policy + Executor                                                    #
# ================================================================== #


class TestValidateExecute:
    def test_suggest_only_rejects_validate(self, engine: WorkflowEngine) -> None:
        session = engine.start("recon", mode=AutonomyMode.SUGGEST_ONLY)
        suggestion = ActionSuggestion(
            suggestion_id=str(uuid.uuid4()),
            session_id=session.session_id,
            tool_name="role.list",
            arguments={},
            created_at=session.created_at,
        )
        result = engine.validate_suggestion(suggestion)
        assert isinstance(result, PolicyReject)
        assert result.code == "suggest_only"

    def test_unknown_tool_rejected(self, engine: WorkflowEngine) -> None:
        session = engine.start("recon", mode=AutonomyMode.STEP)
        suggestion = ActionSuggestion(
            suggestion_id=str(uuid.uuid4()),
            session_id=session.session_id,
            tool_name="project.delete",
            arguments={},
            created_at=session.created_at,
        )
        result = engine.validate_suggestion(suggestion)
        assert isinstance(result, PolicyReject)
        assert result.code == "unknown_tool"

    def test_schema_invalid_rejected(self, engine: WorkflowEngine) -> None:
        session = engine.start("recon", mode=AutonomyMode.STEP)
        suggestion = ActionSuggestion(
            suggestion_id=str(uuid.uuid4()),
            session_id=session.session_id,
            tool_name="endpoint.show",
            arguments={},  # missing endpoint_id
            created_at=session.created_at,
        )
        result = engine.validate_suggestion(suggestion)
        assert isinstance(result, PolicyReject)
        assert result.code == "schema_invalid"

    def test_forbidden_project_arg_rejected(self, engine: WorkflowEngine) -> None:
        session = engine.start("recon", mode=AutonomyMode.STEP)
        suggestion = ActionSuggestion(
            suggestion_id=str(uuid.uuid4()),
            session_id=session.session_id,
            tool_name="role.list",
            arguments={"project_id": "other-project"},
            created_at=session.created_at,
        )
        result = engine.validate_suggestion(suggestion)
        assert isinstance(result, PolicyReject)
        assert result.code == "schema_invalid"

    def test_validate_execute_role_list(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("recon", mode=AutonomyMode.STEP)
        plan, observation = engine.validate_and_execute(
            "role.list",
            {},
            session_id=session.session_id,
            auto_reads=True,
        )
        assert isinstance(plan, ExecutionPlan)
        assert plan.project_id == project.id
        assert plan.tool_name == "role.list"
        assert observation.success is True
        assert "roles" in observation.data
        # Seeded global role present.
        names = {r["name"] for r in observation.data["roles"]}
        assert "global" in names

        # Token is single-use.
        with pytest.raises(ExecutorError):
            Executor().execute(plan, session, persist_usage=False)

    def test_validate_execute_endpoint_list_empty(
        self, engine: WorkflowEngine
    ) -> None:
        engine.start("recon", mode=AutonomyMode.STEP)
        plan, observation = engine.validate_and_execute(
            "endpoint.list",
            {"limit": 10},
            auto_reads=True,
        )
        assert plan.tool_name == "endpoint.list"
        assert observation.success is True

    def test_role_set_active_exists_only(
        self, engine: WorkflowEngine, project
    ) -> None:
        engine.start("recon", mode=AutonomyMode.STEP)
        create_role(project.db_path, "admin")
        assert get_active_role(project.db_path) == "global"

        plan, observation = engine.validate_and_execute(
            "role.set_active",
            {"name": "admin"},
            auto_reads=False,
        )
        assert observation.success is True
        assert get_active_role(project.db_path) == "admin"
        assert observation.data.get("old") == "global"
        assert observation.data.get("new") == "admin"

        # Missing role fails in handler (after policy allows).
        _, obs2 = engine.validate_and_execute(
            "role.set_active",
            {"name": "does-not-exist"},
        )
        assert obs2.success is False
        assert "does not exist" in (obs2.result_summary or "")

    def test_execution_plan_not_forgable(self, engine: WorkflowEngine, project) -> None:
        session = engine.start("recon", mode=AutonomyMode.STEP)
        forged = ExecutionPlan(
            plan_id=str(uuid.uuid4()),
            suggestion_id=str(uuid.uuid4()),
            session_id=session.session_id,
            tool_name="role.list",
            arguments={},
            required_capabilities=frozenset({Capability.READ_CONTEXT}),
            project_id=project.id,
            capability_token="forged-token",
            created_at=session.created_at,
        )
        with pytest.raises(ExecutorError):
            Executor().execute(forged, session, persist_usage=False)

    def test_budget_increments_on_execute(self, engine: WorkflowEngine, project) -> None:
        session = engine.start("recon", mode=AutonomyMode.STEP)
        engine.validate_and_execute("role.list", {}, session_id=session.session_id)
        reloaded = session_store.get_session(
            project.db_path, project.id, session.session_id
        )
        assert reloaded.usage.tool_calls == 1


# ================================================================== #
# Mode + prefs                                                         #
# ================================================================== #


class TestModeAndPrefs:
    def test_mode_set_step(self, engine: WorkflowEngine) -> None:
        session = engine.start("g", mode=AutonomyMode.SUGGEST_ONLY)
        updated = engine.set_mode(AutonomyMode.STEP, session_id=session.session_id)
        assert updated.mode == AutonomyMode.STEP
        assert Capability.READ_ENDPOINTS in updated.granted_capabilities

    def test_auto_aggressive_requires_ack(self, engine: WorkflowEngine, project) -> None:
        engine.start("g", mode=AutonomyMode.STEP)
        with pytest.raises(WorkflowEngineError) as exc:
            engine.set_mode(AutonomyMode.AUTO_AGGRESSIVE)
        assert exc.value.exit_code == 3

        engine.set_mode(
            AutonomyMode.AUTO_AGGRESSIVE,
            aggressive_ack_phrase=f"I_ACCEPT_AUTO_AGGRESSIVE={project.id}",
        )
        prefs = session_store.get_project_prefs(project.db_path, project.id)
        assert prefs["auto_aggressive_ack_at"] is not None

        engine.clear_aggressive_ack()
        prefs2 = session_store.get_project_prefs(project.db_path, project.id)
        assert prefs2["auto_aggressive_ack_at"] is None


# ================================================================== #
# Approval gate + budgets + CLI safety                                 #
# ================================================================== #


class TestApprovalGate:
    def test_execute_plan_blocks_pending_approval(
        self, engine: WorkflowEngine
    ) -> None:
        """MODIFY_CONTEXT plans require approval; execute_plan without force fails."""
        session = engine.start("recon", mode=AutonomyMode.STEP)
        suggestion = ActionSuggestion(
            suggestion_id=str(uuid.uuid4()),
            session_id=session.session_id,
            tool_name="role.set_active",
            arguments={"name": "global"},
            created_at=session.created_at,
        )
        plan = engine.validate_suggestion(suggestion, auto_reads=False)
        assert isinstance(plan, ExecutionPlan)
        assert plan.requires_approval is True
        with pytest.raises(WorkflowEngineError) as exc:
            engine.execute_plan(plan, force=False)
        assert exc.value.exit_code == 3
        assert "requires approval" in str(exc.value).lower()

    def test_auto_reads_read_tool_no_approval_needed(
        self, engine: WorkflowEngine
    ) -> None:
        """READ tools with auto_reads skip the approval flag."""
        session = engine.start("recon", mode=AutonomyMode.STEP)
        suggestion = ActionSuggestion(
            suggestion_id=str(uuid.uuid4()),
            session_id=session.session_id,
            tool_name="role.list",
            arguments={},
            created_at=session.created_at,
        )
        plan = engine.validate_suggestion(suggestion, auto_reads=True)
        assert isinstance(plan, ExecutionPlan)
        assert plan.requires_approval is False
        obs = engine.execute_plan(plan, force=False)
        assert obs.success is True


class TestBudgetHalt:
    def test_tool_call_budget_halts_session(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("recon", mode=AutonomyMode.STEP)
        tight = BudgetLimits(max_tool_calls=1)
        with sqlite3.connect(str(project.db_path)) as conn:
            conn.execute(
                "UPDATE ai_sessions SET budgets_json = ? WHERE id = ?",
                (json.dumps(tight.to_dict()), session.session_id),
            )
            conn.commit()

        reloaded = session_store.get_session(
            project.db_path, project.id, session.session_id
        )
        assert reloaded.budgets.max_tool_calls == 1

        engine.validate_and_execute(
            "role.list", {}, session_id=session.session_id, force=True
        )
        after = session_store.get_session(
            project.db_path, project.id, session.session_id
        )
        assert after.usage.tool_calls == 1
        assert after.status == SessionStatus.HALTED_BUDGET

        with pytest.raises(WorkflowEngineError):
            engine.validate_and_execute(
                "role.list", {}, session_id=session.session_id, force=True
            )


class TestCliSafety:
    def test_experimental_start_requires_force_noninteractive(
        self, manager: ProjectManager, project, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """auto-* on start must not succeed silently without --force in non-TTY."""
        import io
        from contextlib import redirect_stderr, redirect_stdout

        from talos.ai.cli import run_ai_cli

        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        out, err = io.StringIO(), io.StringIO()
        with pytest.raises(SystemExit) as exc:
            with redirect_stdout(out), redirect_stderr(err):
                run_ai_cli(manager, ["start", "--mode", "auto-low", "--goal", "x"])
        assert exc.value.code == 2
        combined = (err.getvalue() + out.getvalue()).lower()
        assert "force" in combined

    def test_force_stop_existing_no_prompt_when_none(
        self, manager: ProjectManager, project, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--force-stop-existing with no active session should not require --force."""
        import io
        from contextlib import redirect_stderr, redirect_stdout

        from talos.ai.cli import run_ai_cli

        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            run_ai_cli(
                manager,
                [
                    "start",
                    "--goal",
                    "only",
                    "--force-stop-existing",
                    "--format",
                    "json",
                ],
            )
        assert '"session_id"' in out.getvalue()
        assert "Error" not in err.getvalue()
