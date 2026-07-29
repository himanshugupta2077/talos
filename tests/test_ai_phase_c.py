"""
Tests for Talos AI Layer — Phase C (stdio MCP + LLM providers, no redaction).

Covers:
    - AI config load/save/set/unset
    - Provider factory (none / ollama / openai-compatible / anthropic)
    - LLMPlanner parse + heuristic fallback
    - MCP tools/list descriptors
    - MCP tools/call sealed path (suggest-only, needs_approval, execute)
    - No talos/ai/redaction.py module
    - Registry still has no call()/execute()
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any, Optional
from unittest.mock import MagicMock

import pytest

from talos.ai.llm.base import ChatMessage, CompleteResult, Role
from talos.ai.llm.config import (
    AiConfig,
    apply_config_set,
    load_ai_config,
    save_ai_config,
    unset_ai_config_keys,
)
from talos.ai.llm.factory import build_provider
from talos.ai.llm.none import NoneProvider
from talos.ai.mcp.server import McpServer, run_stdio_server
from talos.ai.models import AutonomyMode
from talos.ai.planner.base import PlanRequest
from talos.ai.planner.factory import build_planner
from talos.ai.planner.heuristic import HeuristicPlanner
from talos.ai.planner.llm_planner import LLMPlanner, _extract_json_suggestions
from talos.ai.policy import reset_token_store_for_tests
from talos.ai.tools.registry import default_registry, reset_default_registry_for_tests
from talos.ai.workflow.engine import WorkflowEngine, WorkflowEngineError
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
    p = manager.create(name="AI Phase C App", scope=["example.com"])
    manager.open(p.id)
    return manager.get(p.id)


@pytest.fixture
def engine(manager: ProjectManager, project) -> WorkflowEngine:
    return WorkflowEngine(manager)


@pytest.fixture
def ai_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    data = tmp_path / "talos-data"
    data.mkdir()
    monkeypatch.setenv("TALOS_DATA_DIR", str(data))
    return data


# ================================================================== #
# Config                                                               #
# ================================================================== #


class TestAiConfig:
    def test_default_provider_none(self, ai_data_dir: Path) -> None:
        cfg = load_ai_config(ai_data_dir)
        assert cfg.normalized_provider() == "none"
        assert cfg.fallback_to_heuristic is True

    def test_save_and_load(self, ai_data_dir: Path) -> None:
        cfg = AiConfig(provider="ollama", model="llama3.2", base_url="http://127.0.0.1:11434")
        path = save_ai_config(cfg, ai_data_dir)
        assert path.exists()
        loaded = load_ai_config(ai_data_dir)
        assert loaded.normalized_provider() == "ollama"
        assert loaded.model == "llama3.2"

    def test_set_and_unset(self, ai_data_dir: Path) -> None:
        cfg = load_ai_config(ai_data_dir)
        cfg = apply_config_set(cfg, "provider", "anthropic")
        cfg = apply_config_set(cfg, "model", "claude-3-5-haiku-latest")
        save_ai_config(cfg, ai_data_dir)
        loaded = load_ai_config(ai_data_dir)
        assert loaded.normalized_provider() == "anthropic"
        loaded = unset_ai_config_keys(loaded, ["provider", "model"])
        assert loaded.normalized_provider() == "none"
        assert loaded.model == ""

    def test_openai_alias(self) -> None:
        cfg = apply_config_set(AiConfig(), "provider", "openai")
        assert cfg.normalized_provider() == "openai-compatible"

    def test_api_key_from_env(
        self, ai_data_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TALOS_AI_API_KEY", "sk-test-123")
        cfg = load_ai_config(ai_data_dir)
        assert cfg.resolve_api_key() == "sk-test-123"
        pub = cfg.to_public_dict()
        assert pub["api_key_configured"] is True
        assert pub.get("api_key") in ("", "***") or "api_key" in pub


# ================================================================== #
# Providers                                                            #
# ================================================================== #


class TestProviders:
    def test_build_none(self) -> None:
        p = build_provider(AiConfig(provider="none"))
        assert isinstance(p, NoneProvider)
        result = p.complete([ChatMessage(role=Role.USER, content="hi")])
        assert result.error

    def test_build_ollama_defaults(self) -> None:
        p = build_provider(AiConfig(provider="ollama"))
        assert p.name == "ollama"

    def test_build_openai_compat(self) -> None:
        p = build_provider(AiConfig(provider="openai-compatible", model="gpt-4o-mini"))
        assert p.name == "openai-compatible"

    def test_build_anthropic(self) -> None:
        p = build_provider(AiConfig(provider="anthropic"))
        assert p.name == "anthropic"

    def test_no_redaction_module(self) -> None:
        import importlib.util

        assert importlib.util.find_spec("talos.ai.redaction") is None


# ================================================================== #
# LLM Planner                                                          #
# ================================================================== #


class FakeProvider:
    name = "fake"

    def __init__(self, result: CompleteResult) -> None:
        self._result = result
        self.calls = 0

    def complete(
        self,
        messages: list[ChatMessage],
        *,
        tools: Optional[list[dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> CompleteResult:
        self.calls += 1
        return self._result


class TestLLMPlanner:
    def test_extract_json_array(self) -> None:
        text = '[{"tool_name":"endpoint.list","arguments":{"limit":10},"reason":"map"}]'
        items = _extract_json_suggestions(text)
        assert len(items) == 1
        assert items[0]["tool_name"] == "endpoint.list"

    def test_extract_fenced_json(self) -> None:
        text = '```json\n[{"tool_name":"role.list","arguments":{},"reason":"roles"}]\n```'
        items = _extract_json_suggestions(text)
        assert items[0]["tool_name"] == "role.list"

    def test_llm_plan_parses_tool_calls(self) -> None:
        result = CompleteResult(
            text="",
            tool_calls=[
                {
                    "name": "endpoint.list",
                    "arguments": {"limit": 25},
                }
            ],
            raw_usage={"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
        )
        planner = LLMPlanner(
            config=AiConfig(provider="openai-compatible", fallback_to_heuristic=False),
            provider=FakeProvider(result),
        )
        req = PlanRequest(
            session_id="s1",
            goal="Map endpoints",
            mode="step",
            granted_capabilities=frozenset(),
            tool_descriptors=[default_registry().get_spec("endpoint.list")],
            max_suggestions=3,
        )
        suggestions = planner.plan(req)
        assert len(suggestions) == 1
        assert suggestions[0].tool_name == "endpoint.list"
        assert planner.last_source == "llm"
        assert planner.last_usage.get("total_tokens") == 120

    def test_fallback_on_provider_error(self) -> None:
        from talos.ai.llm.base import ProviderError

        class Boom:
            name = "boom"

            def complete(self, *a, **k):
                raise ProviderError("down", retryable=True)

        planner = LLMPlanner(
            config=AiConfig(provider="ollama", fallback_to_heuristic=True),
            provider=Boom(),  # type: ignore[arg-type]
        )
        req = PlanRequest(
            session_id="s1",
            goal="Map endpoints",
            mode="step",
            granted_capabilities=frozenset(),
            tool_descriptors=[
                default_registry().get_spec(n) for n in default_registry().names()
            ],
            max_suggestions=3,
            inventory_signals={"endpoint_count": 0},
        )
        suggestions = planner.plan(req)
        assert suggestions
        assert planner.last_source == "heuristic"

    def test_build_planner_none_is_heuristic(self, ai_data_dir: Path) -> None:
        save_ai_config(AiConfig(provider="none"), ai_data_dir)
        # factory loads from env TALOS_DATA_DIR set by fixture
        planner = build_planner(load_ai_config(ai_data_dir))
        assert isinstance(planner, HeuristicPlanner)


# ================================================================== #
# Engine external_tool_call + MCP                                      #
# ================================================================== #


class TestExternalToolCall:
    def test_suggest_only_records_without_execute(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("mcp test", mode=AutonomyMode.SUGGEST_ONLY)
        out = engine.external_tool_call(
            "endpoint.list",
            {"limit": 10},
            session_id=session.session_id,
        )
        assert out["status"] == "needs_approval"
        assert out["code"] == "suggest_only"
        assert out["suggestion_id"]
        # No pending plan in suggest-only
        pending = engine.pending(session_id=session.session_id)
        assert pending["pending_plan_count"] == 0

    def test_step_needs_approval(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("mcp step", mode=AutonomyMode.STEP)
        out = engine.external_tool_call(
            "endpoint.list",
            {"limit": 10},
            session_id=session.session_id,
        )
        assert out["status"] == "needs_approval"
        assert out["code"] == "needs_approval"
        assert out["plan_id"]
        # Operator can approve
        result = engine.approve(out["plan_id"], session_id=session.session_id)
        assert result["tool_name"] == "endpoint.list"
        assert result["observation"]["success"] is True

    def test_unknown_tool_rejected(self, engine: WorkflowEngine, project) -> None:
        session = engine.start("mcp bad", mode=AutonomyMode.STEP)
        out = engine.external_tool_call(
            "project.delete",
            {},
            session_id=session.session_id,
        )
        assert out["status"] == "rejected"
        assert out["code"] == "unknown_tool"

    def test_pin_frozen_session(self, engine: WorkflowEngine, project) -> None:
        session = engine.start("pin", mode=AutonomyMode.STEP)
        assert session.pinned_project_id == project.id
        out = engine.external_tool_call(
            "endpoint.list", {}, session_id=session.session_id
        )
        assert out["session_id"] == session.session_id


class TestMcpServer:
    def test_tools_list_specs_only(self, engine: WorkflowEngine, project) -> None:
        engine.start("mcp list", mode=AutonomyMode.STEP)
        server = McpServer(engine)
        resp = server.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        )
        assert resp is not None
        tools = resp["result"]["tools"]
        assert len(tools) >= 20
        names = {t["name"] for t in tools}
        assert "endpoint.list" in names
        # No policy authority knobs on MCP list surface
        sample = tools[0]
        assert "inputSchema" in sample
        assert "requires_approval" not in sample
        assert "capabilities" not in sample

    def test_initialize(self, engine: WorkflowEngine, project) -> None:
        engine.start("init", mode=AutonomyMode.SUGGEST_ONLY)
        server = McpServer(engine)
        resp = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"},
                },
            }
        )
        assert resp["result"]["serverInfo"]["name"] == "talos-ai"
        assert "tools" in resp["result"]["capabilities"]

    def test_tools_call_suggest_only(self, engine: WorkflowEngine, project) -> None:
        engine.start("mcp call so", mode=AutonomyMode.SUGGEST_ONLY)
        server = McpServer(engine)
        resp = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "endpoint.list",
                    "arguments": {"limit": 5},
                },
            }
        )
        assert resp is not None
        assert resp["result"]["isError"] is False
        payload = json.loads(resp["result"]["content"][0]["text"])
        assert payload["status"] == "needs_approval"
        assert payload["code"] == "suggest_only"

    def test_tools_call_step_then_approve(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("mcp call step", mode=AutonomyMode.STEP)
        server = McpServer(engine, session_id=session.session_id)
        resp = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "role.list",
                    "arguments": {},
                },
            }
        )
        payload = json.loads(resp["result"]["content"][0]["text"])
        assert payload["status"] == "needs_approval"
        plan_id = payload["plan_id"]
        approved = engine.approve(plan_id)
        assert approved["observation"]["success"] is True

    def test_stdio_roundtrip(self, engine: WorkflowEngine, project) -> None:
        engine.start("stdio", mode=AutonomyMode.STEP)
        lines = [
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "t", "version": "0"},
                    },
                }
            ),
            json.dumps(
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
            ),
        ]
        stdin = io.StringIO("\n".join(lines) + "\n")
        stdout = io.StringIO()
        rc = run_stdio_server(engine, stdin=stdin, stdout=stdout)
        assert rc == 0
        out_lines = [ln for ln in stdout.getvalue().splitlines() if ln.strip()]
        assert len(out_lines) == 2
        r1 = json.loads(out_lines[0])
        r2 = json.loads(out_lines[1])
        assert r1["result"]["serverInfo"]["name"] == "talos-ai"
        assert len(r2["result"]["tools"]) >= 20

    def test_cannot_bypass_via_unknown_method(
        self, engine: WorkflowEngine, project
    ) -> None:
        engine.start("bad method", mode=AutonomyMode.STEP)
        server = McpServer(engine)
        resp = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/execute_raw",
                "params": {},
            }
        )
        assert "error" in resp
        assert resp["error"]["code"] == -32601


class TestRegistryStillSealed:
    def test_no_call_or_execute(self) -> None:
        reg = default_registry()
        assert not hasattr(reg, "call") or not callable(getattr(reg, "call", None))
        # Explicit public API
        assert hasattr(reg, "list_tools")
        assert hasattr(reg, "get_spec")
        public = [n for n in dir(reg) if not n.startswith("_")]
        assert "call" not in public
        assert "execute" not in public


class TestSuggestUsesConfiguredPlanner:
    def test_suggest_with_fake_llm(
        self, engine: WorkflowEngine, project
    ) -> None:
        result = CompleteResult(
            text=json.dumps(
                [
                    {
                        "tool_name": "notes.app.get",
                        "arguments": {},
                        "reason": "load notes",
                    }
                ]
            ),
            raw_usage={"total_tokens": 50},
        )
        planner = LLMPlanner(
            config=AiConfig(
                provider="openai-compatible", fallback_to_heuristic=False
            ),
            provider=FakeProvider(result),
        )
        engine.set_planner(planner)
        session = engine.start("llm suggest", mode=AutonomyMode.STEP)
        out = engine.suggest(session_id=session.session_id, max_suggestions=3)
        assert out["suggestion_count"] >= 1
        assert out["planner_source"] == "llm"
        assert out["llm_tokens_added"] == 50
        tools = {s["tool_name"] for s in out["suggestions"]}
        assert "notes.app.get" in tools

        # Budget usage persisted
        status = engine.status(session.session_id)
        assert status["usage"]["llm_tokens"] >= 50
