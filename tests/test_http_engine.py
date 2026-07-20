"""
Tests for the HTTP Manipulation Engine.

Covers:
    - Rule matching (host/path/method/status/headers)
    - Header / cookie / query / body / status actions
    - Priority ordering
    - Master switch (http.enabled)
    - Layer concatenation (global + project rules both apply)
    - CLI create / list / enable compact actions
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import yaml

from talos.configuration.http_engine import HTTPManipulationEngine
from talos.configuration.http_rules import (
    HttpRuleError,
    normalize_rule,
    parse_action_cli,
    rule_matches,
)
from talos.configuration.manager import ConfigurationManager
from talos.configuration.http_cli import cmd_create, cmd_list, run_http_cli
from talos.projects.db import init_project_db


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "talos-data"
    d.mkdir()
    (d / "projects").mkdir()
    return d


@pytest.fixture
def project_dir(data_dir: Path) -> Path:
    pdir = data_dir / "projects" / "demo"
    pdir.mkdir()
    init_project_db(pdir / "talos.db")
    return pdir


def _manager_with_project(data_dir: Path, project_dir: Path) -> MagicMock:
    project = SimpleNamespace(
        id="demo",
        data_dir=str(project_dir),
        db_path=project_dir / "talos.db",
        constraints=SimpleNamespace(store_bodies=True, max_body_size=1024 * 1024),
    )
    manager = MagicMock()
    manager.active.return_value = project
    manager._root = data_dir / "projects"
    return manager


# ================================================================== #
# Matching                                                             #
# ================================================================== #


class TestRuleMatching:
    def test_empty_match_always(self) -> None:
        rule = normalize_rule({"name": "all", "direction": "request", "actions": []})
        assert rule_matches(rule, direction="request", method="GET", host="h", path="/")

    def test_host_and_path(self) -> None:
        rule = normalize_rule(
            {
                "name": "api",
                "match": {"host": "api.example.com", "path": "/v1/*"},
                "actions": [],
            }
        )
        assert rule_matches(
            rule,
            direction="request",
            host="api.example.com",
            path="/v1/users",
            method="GET",
        )
        assert not rule_matches(
            rule,
            direction="request",
            host="api.example.com",
            path="/v2/users",
            method="GET",
        )
        assert not rule_matches(
            rule,
            direction="request",
            host="other.com",
            path="/v1/users",
            method="GET",
        )

    def test_direction_filter(self) -> None:
        rule = normalize_rule(
            {"name": "resp", "direction": "response", "actions": []}
        )
        assert not rule_matches(rule, direction="request", host="h", path="/")
        assert rule_matches(rule, direction="response", host="h", path="/", status_code=200)

    def test_disabled_never_matches(self) -> None:
        rule = normalize_rule(
            {"name": "off", "enabled": False, "actions": []}
        )
        assert not rule_matches(rule, direction="request", host="h", path="/")


# ================================================================== #
# Engine actions                                                       #
# ================================================================== #


class TestEngineActions:
    def test_header_pipeline(self) -> None:
        rules = [
            normalize_rule(
                {
                    "name": "headers",
                    "priority": 10,
                    "actions": [
                        {"op": "header.remove", "name": "X-Drop"},
                        {"op": "header.replace", "name": "User-Agent", "value": "Talos"},
                        {"op": "header.add", "name": "X-Add", "value": "1"},
                        {"op": "header.add", "name": "User-Agent", "value": "should-not-win"},
                        {"op": "header.rename", "from": "X-Old", "to": "X-New"},
                    ],
                }
            )
        ]
        headers = {
            "X-Drop": "gone",
            "User-Agent": "browser",
            "X-Old": "v",
        }
        engine = HTTPManipulationEngine(rules, enabled=True)
        stats = engine.apply_request(
            method="GET",
            url="https://example.com/",
            headers=headers,
            host="example.com",
            path="/",
        )
        assert stats["actions_run"] == 5
        assert "X-Drop" not in headers
        assert headers["User-Agent"] == "Talos"
        assert headers["X-Add"] == "1"
        assert "X-Old" not in headers
        assert headers["X-New"] == "v"

    def test_priority_order(self) -> None:
        rules = [
            normalize_rule(
                {
                    "name": "late",
                    "priority": 200,
                    "actions": [
                        {"op": "header.replace", "name": "X-Order", "value": "second"},
                    ],
                }
            ),
            normalize_rule(
                {
                    "name": "early",
                    "priority": 50,
                    "actions": [
                        {"op": "header.replace", "name": "X-Order", "value": "first"},
                    ],
                }
            ),
        ]
        # Engine does not re-sort; callers pass sorted rules (manager does).
        from talos.configuration.http_rules import sort_rules

        engine = HTTPManipulationEngine(sort_rules(rules), enabled=True)
        headers: dict[str, str] = {}
        engine.apply_request(
            method="GET", url="https://h/", headers=headers, host="h", path="/"
        )
        assert headers["X-Order"] == "second"

    def test_query_and_method(self) -> None:
        rules = [
            normalize_rule(
                {
                    "name": "q",
                    "actions": [
                        {"op": "query.replace", "name": "debug", "value": "1"},
                        {"op": "method.replace", "value": "POST"},
                    ],
                }
            )
        ]
        engine = HTTPManipulationEngine(rules)
        state = {"url": "https://example.com/path?a=1", "method": "GET"}

        def set_url(u: str) -> None:
            state["url"] = u

        def set_method(m: str) -> None:
            state["method"] = m

        engine.apply_request(
            method=state["method"],
            url=state["url"],
            headers={},
            set_url=set_url,
            set_method=set_method,
            host="example.com",
            path="/path",
        )
        assert state["method"] == "POST"
        assert "debug=1" in state["url"]

    def test_body_regex_and_status(self) -> None:
        rules = [
            normalize_rule(
                {
                    "name": "body",
                    "direction": "response",
                    "actions": [
                        {"op": "body.regex_replace", "pattern": "secret", "replacement": "REDACTED"},
                        {"op": "status.override", "value": 200},
                        {"op": "header.remove", "name": "Content-Security-Policy"},
                    ],
                }
            )
        ]
        engine = HTTPManipulationEngine(rules)
        body = {"data": b"token=secret&x=1"}
        status = {"code": 403}
        headers = {"Content-Security-Policy": "default-src 'none'"}

        engine.apply_response(
            method="GET",
            url="https://h/",
            status_code=status["code"],
            headers=headers,
            get_body=lambda: body["data"],
            set_body=lambda v: body.__setitem__("data", v),
            set_status=lambda c: status.__setitem__("code", c),
            host="h",
            path="/",
        )
        assert b"REDACTED" in body["data"]
        assert status["code"] == 200
        assert "Content-Security-Policy" not in headers

    def test_master_switch_off(self) -> None:
        rules = [
            normalize_rule(
                {
                    "name": "x",
                    "actions": [{"op": "header.replace", "name": "X", "value": "1"}],
                }
            )
        ]
        engine = HTTPManipulationEngine(rules, enabled=False)
        headers: dict[str, str] = {}
        stats = engine.apply_request(
            method="GET", url="https://h/", headers=headers, host="h", path="/"
        )
        assert stats["actions_run"] == 0
        assert headers == {}

    def test_default_no_rules(self) -> None:
        engine = HTTPManipulationEngine([], enabled=True)
        headers = {"If-None-Match": "abc"}
        engine.apply_request(
            method="GET", url="https://h/", headers=headers, host="h", path="/"
        )
        assert headers["If-None-Match"] == "abc"


# ================================================================== #
# Compact action parser                                                #
# ================================================================== #


class TestActionCli:
    def test_parse_specs(self) -> None:
        assert parse_action_cli("header.remove:If-None-Match")["op"] == "header.remove"
        assert parse_action_cli("header.replace:UA=Talos")["value"] == "Talos"
        assert parse_action_cli("header.rename:A->B")["to"] == "B"
        assert parse_action_cli("delay:250")["ms"] == 250
        assert parse_action_cli("drop")["op"] == "drop"
        with pytest.raises(HttpRuleError):
            parse_action_cli("header.unknown:x")


# ================================================================== #
# Layered config + CLI                                                 #
# ================================================================== #


class TestHttpConfigLayers:
    def test_default_empty_rules(self, data_dir: Path) -> None:
        mgr = ConfigurationManager(data_dir)
        eff = mgr.load()
        assert eff.http.enabled is True
        assert list(eff.http.rules) == []

    def test_global_and_project_concat(
        self, data_dir: Path, project_dir: Path
    ) -> None:
        mgr = ConfigurationManager(data_dir)
        mgr.set_value(
            "http.rules",
            [
                {
                    "id": "11111111-1111-1111-1111-111111111111",
                    "name": "global-rule",
                    "priority": 50,
                    "direction": "request",
                    "enabled": True,
                    "match": {},
                    "actions": [{"op": "header.replace", "name": "X-G", "value": "1"}],
                }
            ],
            global_scope=True,
        )
        mgr.set_value(
            "http.rules",
            [
                {
                    "id": "22222222-2222-2222-2222-222222222222",
                    "name": "project-rule",
                    "priority": 10,
                    "direction": "request",
                    "enabled": True,
                    "match": {},
                    "actions": [{"op": "header.replace", "name": "X-P", "value": "2"}],
                }
            ],
            global_scope=False,
            project_data_dir=project_dir,
            project_db_path=project_dir / "talos.db",
        )
        eff = mgr.load(project_data_dir=project_dir)
        assert len(eff.http.rules) == 2
        # Lower priority first
        assert eff.http.rules[0]["name"] == "project-rule"
        assert eff.http.rules[1]["name"] == "global-rule"
        assert eff.http.rules[0]["source"] == "project"
        assert eff.http.rules[1]["source"] == "global"

        engine = HTTPManipulationEngine.from_http_section(eff.http)
        headers: dict[str, str] = {}
        engine.apply_request(
            method="GET", url="https://h/", headers=headers, host="h", path="/"
        )
        assert headers["X-P"] == "2"
        assert headers["X-G"] == "1"

    def test_cli_create_and_list(
        self, data_dir: Path, project_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TALOS_DATA_DIR", str(data_dir))
        manager = _manager_with_project(data_dir, project_dir)
        cmd_create(
            manager,
            SimpleNamespace(
                name="Research header",
                description="",
                direction="request",
                priority=100,
                disabled=False,
                scope=None,
                match_host=[],
                match_path=[],
                match_path_prefix=[],
                match_method=[],
                match_status=[],
                match_content_type=[],
                match_header_exists=[],
                match_endpoint_id=[],
                actions=["header.replace:X-Research=tester"],
                global_scope=False,
            ),
        )
        yaml_path = project_dir / "project.yaml"
        data = yaml.safe_load(yaml_path.read_text())
        assert len(data["http"]["rules"]) == 1
        assert data["http"]["rules"][0]["actions"][0]["op"] == "header.replace"

        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_list(
                manager,
                SimpleNamespace(
                    format="table",
                    direction=None,
                    layer=None,
                    enabled_only=False,
                ),
            )
        assert "Research header" in buf.getvalue()

    def test_cli_actions_help(
        self, data_dir: Path, project_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TALOS_DATA_DIR", str(data_dir))
        manager = _manager_with_project(data_dir, project_dir)
        buf = io.StringIO()
        with redirect_stdout(buf):
            run_http_cli(manager, ["actions"])
        assert "header.replace" in buf.getvalue()
