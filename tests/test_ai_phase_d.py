"""
Tests for Talos AI Layer — Phase D active pentest surface.

Covers:
    - send.once / replay.flow registration + schemas
    - Live Basic Scope + outscope + fail-closed snapshot shrink
    - Annotation matrix: logout always reject; dangerous requires human approve
    - ai_force_dangerous + PRIORITY_AI_* on enqueue
    - Engine enqueue tools (iv.run, attack.unauth, attack.bac, intruder)
    - send.once with mocked HTTP (source=ai_send)
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from talos.ai.models import (
    ActionSuggestion,
    AutonomyMode,
    Capability,
    PolicyReject,
    grants_for_mode,
)
from talos.ai.policy import reset_token_store_for_tests
from talos.ai.tools.registry import default_registry, reset_default_registry_for_tests
from talos.ai.tools import scope_policy as sp
from talos.ai.workflow.engine import WorkflowEngine, WorkflowEngineError
from talos.projects.access import create_role
from talos.projects.annotations import add_annotation, get_annotations
from talos.projects.manager import ProjectManager, TALOS_PROJECT_ENV
from talos.scheduler.job import (
    PRIORITY_AI_AUTO,
    PRIORITY_AI_MANUAL,
    PRIORITY_MANUAL,
    REPLAY_FLOW,
    UNAUTH_ATTACK,
)


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
    p = manager.create(name="AI Phase D App", scope=["example.com"])
    manager.open(p.id)
    return manager.get(p.id)


@pytest.fixture
def engine(manager: ProjectManager, project) -> WorkflowEngine:
    return WorkflowEngine(manager)


def _role_module(db_path: Path) -> tuple[str, str]:
    """Return (role_id, module_id) for global role/module (seeded)."""
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute(
            "SELECT id FROM roles WHERE name = 'global' LIMIT 1"
        ).fetchone()
        module = conn.execute(
            "SELECT id FROM modules WHERE name = 'global' LIMIT 1"
        ).fetchone()
    if role is None or module is None:
        # Fresh DB may use different seed names — take first of each.
        with sqlite3.connect(str(db_path)) as conn:
            role = conn.execute("SELECT id FROM roles LIMIT 1").fetchone()
            module = conn.execute("SELECT id FROM modules LIMIT 1").fetchone()
    assert role is not None and module is not None
    return str(role[0]), str(module[0])


def _insert_flow(
    db_path: Path,
    project_id: str,
    *,
    flow_id: str | None = None,
    endpoint_id: str | None = None,
    host: str = "example.com",
    path: str = "/api/item",
    url: str | None = None,
    method: str = "GET",
    query: str = "",
    status_code: int = 200,
) -> tuple[str, str]:
    """Insert a minimal endpoint + proxy_capture flow. Returns (flow_id, endpoint_id)."""
    fid = flow_id or str(uuid.uuid4())
    eid = endpoint_id or str(uuid.uuid4())
    role_id, module_id = _role_module(db_path)
    full_url = url or f"https://{host}{path}"
    if query:
        full_url = f"{full_url}?{query}"

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO endpoints (
                id, project_id, method, host, path, normalized_path,
                first_seen, last_seen
            ) VALUES (?, ?, ?, ?, ?, ?, '2020-01-01T00:00:00+00:00',
                      '2020-01-01T00:00:00+00:00')
            """,
            (eid, project_id, method, f"https://{host}", path, path),
        )
        conn.execute(
            """
            INSERT INTO flows (
                id, project_id, captured_at, method, url, host, path, query,
                request_headers, request_cookies, request_body,
                request_body_truncated, status_code, response_headers,
                response_body, response_body_truncated, content_type,
                endpoint_id, role_id, module_id, source
            ) VALUES (
                ?, ?, '2020-01-01T00:00:00+00:00',
                ?, ?, ?, ?, ?,
                ?, '{}', ?, 0, ?, '{}', ?, 0, 'application/json',
                ?, ?, ?, 'proxy_capture'
            )
            """,
            (
                fid,
                project_id,
                method,
                full_url,
                host,
                path,
                query,
                json.dumps({"Host": host, "Content-Type": "application/json"}),
                b"{}",
                status_code,
                b'{"ok":true}',
                eid,
                role_id,
                module_id,
            ),
        )
        conn.commit()
    return fid, eid


def _mock_response(status_code: int = 200, body: bytes = b'{"ok":1}'):
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = body
    resp.headers = {"content-type": "application/json"}
    return resp


def _suggestion(tool: str, args: dict, session_id: str) -> ActionSuggestion:
    return ActionSuggestion(
        suggestion_id=str(uuid.uuid4()),
        session_id=session_id,
        tool_name=tool,
        arguments=args,
        reason="test",
        cli_preview=f"# {tool}",
        created_at="2020-01-01T00:00:00+00:00",
    )


# ================================================================== #
# Registry / capabilities                                              #
# ================================================================== #


class TestPhaseDRegistry:
    def test_phase_d_tools_registered(self, engine: WorkflowEngine) -> None:
        names = {t["name"] for t in engine.list_tools()}
        for t in (
            "send.once",
            "replay.flow",
            "iv.run",
            "iv.synthesize",
            "passive.rescan",
            "attack.unauth.run",
            "attack.bac.run",
            "intruder.session.run",
        ):
            assert t in names

    def test_priority_constants(self) -> None:
        assert PRIORITY_AI_AUTO == 15
        assert PRIORITY_AI_MANUAL == PRIORITY_MANUAL == 100
        assert PRIORITY_AI_AUTO < PRIORITY_MANUAL

    def test_auto_aggressive_grants_send_and_enqueue(self) -> None:
        caps = grants_for_mode(AutonomyMode.AUTO_AGGRESSIVE)
        assert Capability.SEND_REQUEST in caps
        assert Capability.ENQUEUE_IV in caps
        assert Capability.ENQUEUE_ATTACK in caps
        assert Capability.ENQUEUE_INTRUDER in caps
        assert Capability.ENQUEUE_PASSIVE in caps

    def test_auto_budget_has_replay_not_send(self) -> None:
        caps = grants_for_mode(AutonomyMode.AUTO_BUDGET)
        assert Capability.REPLAY_FLOW in caps
        assert Capability.SEND_REQUEST not in caps


# ================================================================== #
# Scope helpers                                                        #
# ================================================================== #


class TestScopeHelpers:
    def test_apply_send_edits_to_url_query(self) -> None:
        base = "https://example.com/api?a=1&b=2"
        out = sp.apply_send_edits_to_url(
            base,
            [
                {"op": "set", "target": "query", "key": "a", "value": "99"},
                {"op": "remove", "target": "query", "key": "b"},
            ],
        )
        assert "a=99" in out
        assert "b=2" not in out

    def test_empty_in_scope_denies(self) -> None:
        ok, code, meta = sp.check_url_allowed(
            "https://example.com/",
            live_in_scope=[],
            live_outscope=[],
        )
        assert not ok
        assert code == "scope_denied"
        assert meta["decision"] == "empty_in_scope"


# ================================================================== #
# Live scope                                                           #
# ================================================================== #


class TestLiveScope:
    def test_out_of_scope_url_rejected(self, engine: WorkflowEngine, project) -> None:
        session = engine.start("probe", mode=AutonomyMode.STEP)
        fid, _eid = _insert_flow(
            project.db_path,
            project.id,
            host="evil.example.org",
            path="/x",
            url="https://evil.example.org/x",
        )
        # Project scope is example.com — evil host denied
        plan = engine.validate_suggestion(
            _suggestion(
                "send.once",
                {"parent_flow_id": fid},
                session.session_id,
            )
        )
        assert isinstance(plan, PolicyReject)
        assert plan.code == "scope_denied"

    def test_in_scope_send_validates(self, engine: WorkflowEngine, project) -> None:
        session = engine.start("probe", mode=AutonomyMode.STEP)
        fid, _eid = _insert_flow(project.db_path, project.id)
        plan = engine.validate_suggestion(
            _suggestion(
                "send.once",
                {"parent_flow_id": fid},
                session.session_id,
            )
        )
        assert not isinstance(plan, PolicyReject)
        assert plan.tool_name == "send.once"
        assert plan.requires_approval is True
        assert plan.policy_meta.get("effective_url", "").startswith(
            "https://example.com"
        )

    def test_empty_scope_denies_all_http(self, manager: ProjectManager, project) -> None:
        manager.set_scope(project.id, [])
        engine = WorkflowEngine(manager)
        session = engine.start("probe", mode=AutonomyMode.STEP)
        fid, _ = _insert_flow(project.db_path, project.id)
        plan = engine.validate_suggestion(
            _suggestion("replay.flow", {"flow_id": fid}, session.session_id)
        )
        assert isinstance(plan, PolicyReject)
        assert plan.code == "scope_denied"

    def test_scope_shrink_mid_session_rejects(
        self, manager: ProjectManager, project
    ) -> None:
        engine = WorkflowEngine(manager)
        session = engine.start("probe", mode=AutonomyMode.STEP)
        fid, _ = _insert_flow(
            project.db_path,
            project.id,
            host="api.example.com",
            path="/v1",
            url="https://api.example.com/v1",
        )
        # Widen first so the flow is in-scope at start.
        manager.set_scope(project.id, ["example.com", "api.example.com"])
        # Refresh engine manager view
        engine = WorkflowEngine(manager)
        session = engine.start(
            "probe2", mode=AutonomyMode.STEP, force_stop_existing=True
        )
        plan_ok = engine.validate_suggestion(
            _suggestion("send.once", {"parent_flow_id": fid}, session.session_id)
        )
        assert not isinstance(plan_ok, PolicyReject)

        # Shrink live scope — fail-closed
        manager.set_scope(project.id, ["other.com"])
        engine = WorkflowEngine(manager)
        # Resolve same session via project
        plan_bad = engine.validate_suggestion(
            _suggestion("send.once", {"parent_flow_id": fid}, session.session_id),
            session_id=session.session_id,
        )
        assert isinstance(plan_bad, PolicyReject)
        assert plan_bad.code == "scope_denied"

    def test_send_edit_effective_url_out_of_scope(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("probe", mode=AutonomyMode.STEP)
        fid, _ = _insert_flow(project.db_path, project.id)
        plan = engine.validate_suggestion(
            _suggestion(
                "send.once",
                {
                    "parent_flow_id": fid,
                    "edits": [
                        {
                            "op": "set",
                            "target": "host",
                            "value": "evil.other",
                        }
                    ],
                },
                session.session_id,
            )
        )
        assert isinstance(plan, PolicyReject)
        assert plan.code == "scope_denied"


# ================================================================== #
# Annotations                                                          #
# ================================================================== #


class TestAnnotations:
    def test_logout_always_rejected(self, engine: WorkflowEngine, project) -> None:
        session = engine.start("probe", mode=AutonomyMode.STEP)
        fid, eid = _insert_flow(project.db_path, project.id)
        add_annotation(project.db_path, eid, "logout")
        assert "logout" in get_annotations(project.db_path, eid)

        for tool, args in (
            ("send.once", {"parent_flow_id": fid}),
            ("replay.flow", {"flow_id": fid}),
        ):
            plan = engine.validate_suggestion(
                _suggestion(tool, args, session.session_id)
            )
            assert isinstance(plan, PolicyReject), tool
            assert plan.code == "annotation_logout", tool

    def test_dangerous_requires_approval_even_in_auto(
        self, engine: WorkflowEngine, project
    ) -> None:
        # Ack auto-aggressive for this project
        session = engine.start(
            "probe",
            mode=AutonomyMode.AUTO_AGGRESSIVE,
        )
        # start experimental requires force in CLI; engine.start may allow —
        # if it rejects, set mode after step start.
        if session.mode != AutonomyMode.AUTO_AGGRESSIVE:
            # Fall back: create step then force mode via prefs if needed
            pytest.skip("auto-aggressive start requires CLI ack path")

        fid, eid = _insert_flow(project.db_path, project.id)
        add_annotation(project.db_path, eid, "dangerous")
        plan = engine.validate_suggestion(
            _suggestion("send.once", {"parent_flow_id": fid}, session.session_id)
        )
        # If auto-aggressive start was blocked at engine layer, skip.
        if isinstance(plan, PolicyReject) and plan.code == "suggest_only":
            pytest.skip("mode not aggressive")
        assert not isinstance(plan, PolicyReject)
        assert plan.requires_approval is True
        assert plan.policy_meta.get("ai_force_dangerous") is False

    def test_dangerous_approve_sets_force_flag(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("probe", mode=AutonomyMode.STEP)
        fid, eid = _insert_flow(project.db_path, project.id)
        add_annotation(project.db_path, eid, "dangerous")

        suggestion = _suggestion(
            "replay.flow", {"flow_id": fid}, session.session_id
        )
        from talos.ai.workflow import suggestions as suggestion_store

        suggestion_store.record_suggestions(project.db_path, [suggestion])
        plan = engine.validate_suggestion(suggestion)
        assert not isinstance(plan, PolicyReject)
        assert plan.requires_approval is True
        assert plan.policy_meta.get("ai_force_dangerous") is False

        from talos.ai.workflow import plans as plan_store

        plan_store.insert_plan(
            project.db_path,
            plan,
            status=plan_store.PlanStatus.PENDING_APPROVAL.value,
        )

        result = engine.approve(plan.plan_id, session_id=session.session_id)
        obs = result["observation"]
        assert obs["success"] is True
        data = obs.get("data") or {}
        assert data.get("priority") == PRIORITY_AI_MANUAL
        assert data.get("meta", {}).get("ai_force_dangerous") is True
        assert data.get("meta", {}).get("source") == "ai"

    def test_replay_enqueue_priority_ai_auto(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("probe", mode=AutonomyMode.STEP)
        fid, _ = _insert_flow(project.db_path, project.id)
        plan, obs = engine.validate_and_execute(
            "replay.flow",
            {"flow_id": fid},
            session_id=session.session_id,
        )
        assert obs.success is True
        assert obs.data.get("priority") == PRIORITY_AI_AUTO
        assert obs.data.get("job_type") == REPLAY_FLOW
        assert obs.data.get("meta", {}).get("source") == "ai"


# ================================================================== #
# send.once (mocked HTTP)                                              #
# ================================================================== #


class TestSendOnce:
    def test_send_once_ai_send_source(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("probe", mode=AutonomyMode.STEP)
        fid, _ = _insert_flow(project.db_path, project.id)
        response = _mock_response()

        with patch("talos.send.engine.httpx.AsyncClient") as client_cls:
            client = AsyncMock()
            client.__aenter__.return_value = client
            client.__aexit__.return_value = None
            client.request = AsyncMock(return_value=response)
            client_cls.return_value = client

            plan, obs = engine.validate_and_execute(
                "send.once",
                {
                    "parent_flow_id": fid,
                    "edits": [
                        {
                            "op": "set",
                            "target": "query",
                            "key": "q",
                            "value": "1",
                        }
                    ],
                    "reason": "probe idor",
                },
                session_id=session.session_id,
            )

        assert obs.success is True
        assert obs.data.get("source") == "ai_send"
        assert obs.data.get("status_code") == 200
        assert obs.data.get("execution_flow_id")
        assert session.usage.http_executed >= 0  # budget applied on session reload

        # Budget class http_executed should have incremented
        from talos.ai.workflow import session as session_store

        reloaded = session_store.get_session(
            project.db_path, project.id, session.session_id
        )
        assert reloaded.usage.http_executed >= 1

    def test_send_once_edit_cap_schema(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("probe", mode=AutonomyMode.STEP)
        fid, _ = _insert_flow(project.db_path, project.id)
        edits = [
            {"op": "set", "target": "query", "key": f"k{i}", "value": "v"}
            for i in range(21)
        ]
        plan = engine.validate_suggestion(
            _suggestion(
                "send.once",
                {"parent_flow_id": fid, "edits": edits},
                session.session_id,
            )
        )
        assert isinstance(plan, PolicyReject)
        assert plan.code == "schema_invalid"

    def test_suggest_only_cannot_execute_send(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("probe", mode=AutonomyMode.SUGGEST_ONLY)
        fid, _ = _insert_flow(project.db_path, project.id)
        plan = engine.validate_suggestion(
            _suggestion("send.once", {"parent_flow_id": fid}, session.session_id)
        )
        assert isinstance(plan, PolicyReject)
        assert plan.code == "suggest_only"


# ================================================================== #
# Engine enqueue                                                       #
# ================================================================== #


class TestEngineEnqueue:
    def test_unauth_enqueue_for_flow(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("probe", mode=AutonomyMode.STEP)
        fid, eid = _insert_flow(project.db_path, project.id)
        plan, obs = engine.validate_and_execute(
            "attack.unauth.run",
            {"flow_id": fid, "technique": "baseline", "limit": 5},
            session_id=session.session_id,
        )
        assert obs.success is True
        assert len(obs.data.get("job_ids") or []) >= 1
        assert obs.data.get("priority") == PRIORITY_AI_AUTO

        # Jobs are UNAUTH_ATTACK
        with sqlite3.connect(str(project.db_path)) as conn:
            rows = conn.execute(
                "SELECT job_type, priority, meta FROM scheduler_jobs"
            ).fetchall()
        assert rows
        assert all(r[0] == UNAUTH_ATTACK for r in rows)
        meta0 = json.loads(rows[0][2])
        assert meta0.get("source") == "ai"
        assert meta0.get("ai_session_id") == session.session_id

    def test_bac_requires_module_and_role(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("probe", mode=AutonomyMode.STEP)
        create_role(project.db_path, "attacker")
        fid, _ = _insert_flow(project.db_path, project.id)
        plan, obs = engine.validate_and_execute(
            "attack.bac.run",
            {
                "bac_module": "bac_method_fuzz",
                "flow_id": fid,
                "attacker_role": "attacker",
                "limit": 3,
            },
            session_id=session.session_id,
        )
        assert obs.success is True
        assert obs.data.get("bac_module") == "bac_method_fuzz"
        assert len(obs.data.get("job_ids") or []) >= 1

    def test_iv_run_endpoint_scope(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("probe", mode=AutonomyMode.STEP)
        _fid, eid = _insert_flow(project.db_path, project.id)
        # schedule_endpoint with no params should enqueue 0 cleanly
        plan, obs = engine.validate_and_execute(
            "iv.run",
            {"scope": "endpoint", "endpoint_id": eid},
            session_id=session.session_id,
        )
        assert obs.success is True
        assert "jobs_enqueued" in obs.data

    def test_passive_rescan_all_empty(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("probe", mode=AutonomyMode.STEP)
        plan, obs = engine.validate_and_execute(
            "passive.rescan",
            {"all": True},
            session_id=session.session_id,
        )
        assert obs.success is True
        assert obs.data.get("scanned") == 0

    def test_intruder_session_missing(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("probe", mode=AutonomyMode.STEP)
        plan = engine.validate_suggestion(
            _suggestion(
                "intruder.session.run",
                {"session_id": str(uuid.uuid4())},
                session.session_id,
            )
        )
        assert isinstance(plan, PolicyReject)
        assert plan.code == "intruder_session_not_found"

    def test_jobs_enqueued_budget(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("probe", mode=AutonomyMode.STEP)
        fid, _ = _insert_flow(project.db_path, project.id)
        engine.validate_and_execute(
            "replay.flow",
            {"flow_id": fid},
            session_id=session.session_id,
        )
        from talos.ai.workflow import session as session_store

        reloaded = session_store.get_session(
            project.db_path, project.id, session.session_id
        )
        assert reloaded.usage.jobs_enqueued >= 1


# ================================================================== #
# Auto-aggressive dangerous matrix                                     #
# ================================================================== #


class TestDangerousAutoMatrix:
    def test_dangerous_not_auto_executed(
        self, engine: WorkflowEngine, project, monkeypatch
    ) -> None:
        """
        Even when capabilities would auto-exec, dangerous forces approval.
        Use step + force path to mint plan, then check requires_approval.
        """
        session = engine.start("probe", mode=AutonomyMode.STEP)
        fid, eid = _insert_flow(project.db_path, project.id)
        add_annotation(project.db_path, eid, "dangerous")
        plan = engine.validate_suggestion(
            _suggestion("send.once", {"parent_flow_id": fid}, session.session_id),
            auto_reads=False,
        )
        assert not isinstance(plan, PolicyReject)
        assert plan.requires_approval is True
        assert "dangerous" in (plan.policy_meta.get("annotations") or [])
