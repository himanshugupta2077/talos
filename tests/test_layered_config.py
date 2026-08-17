"""
Tests for CLI-022 — Layered configuration system.

Covers:
    - Precedence: defaults → global → project → CLI
    - Source attribution (get / effective)
    - set / unset inheritance
    - Dual-write: config set mirrors to SQLite; legacy set writes project.yaml
    - talos config CLI show/get/set/unset/effective
    - Proxy / scheduler / attack helpers read layered values
    - HTTP section present with empty rules by default
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import yaml

from talos.configuration.defaults import BUILTIN_DEFAULTS
from talos.configuration.manager import ConfigurationManager
from talos.configuration.merge import deep_merge, parse_cli_value
from talos.configuration.model import ValueSource
from talos.configuration.cli import (
    cmd_effective,
    cmd_get,
    cmd_set,
    cmd_show,
    cmd_unset,
    run_config_cli,
)
from talos.projects.attack_config import get_unauth_auto_run, set_unauth_auto_run
from talos.projects.db import init_project_db
from talos.projects.proxy_config import (
    get_upstream_url,
    resolve_upstream_url,
    set_upstream_url,
)
from talos.scheduler.db import get_scheduler_config, set_scheduler_config


# ------------------------------------------------------------------ #
# Fixtures                                                             #
# ------------------------------------------------------------------ #


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "talos-data"
    d.mkdir()
    (d / "projects").mkdir()
    return d


@pytest.fixture
def mgr(data_dir: Path) -> ConfigurationManager:
    return ConfigurationManager(data_dir)


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
# Merge / engine                                                       #
# ================================================================== #


class TestMergeAndEngine:
    def test_deep_merge_nested(self) -> None:
        base = {"a": {"x": 1, "y": 2}, "b": 3}
        over = {"a": {"y": 9}, "c": 4}
        assert deep_merge(base, over) == {"a": {"x": 1, "y": 9}, "b": 3, "c": 4}

    def test_parse_cli_value(self) -> None:
        assert parse_cli_value("true") is True
        assert parse_cli_value("off") is False
        assert parse_cli_value("null") is None
        assert parse_cli_value("15") == 15
        assert parse_cli_value("2.5") == 2.5
        assert parse_cli_value('["A","B"]') == ["A", "B"]
        assert parse_cli_value("hello") == "hello"

    def test_default_http_section_unmodified(self, mgr: ConfigurationManager) -> None:
        """By default the HTTP engine is on but carries no rules."""
        eff = mgr.load()
        assert eff.http.enabled is True
        assert list(eff.http.rules) == []
        assert "http" in BUILTIN_DEFAULTS
        assert BUILTIN_DEFAULTS["http"]["rules"] == []


# ================================================================== #
# ConfigurationManager precedence                                      #
# ================================================================== #


class TestConfigurationManager:
    def test_defaults_only(self, mgr: ConfigurationManager) -> None:
        eff = mgr.load()
        assert eff.upstream_url() is None
        assert eff.scheduler.min_delay == BUILTIN_DEFAULTS["scheduler"]["min_delay"]
        assert eff.attack.unauth_auto_run is False
        assert eff.source_of("scheduler.min_delay") == ValueSource.DEFAULT

    def test_global_overrides_defaults(
        self, mgr: ConfigurationManager, data_dir: Path
    ) -> None:
        mgr.set_value("scheduler.min_delay", 3.0, global_scope=True)
        eff = mgr.load()
        assert eff.scheduler.min_delay == 3.0
        assert eff.source_of("scheduler.min_delay") == ValueSource.GLOBAL
        assert (data_dir / "config.yaml").exists()

    def test_project_overrides_global(
        self, mgr: ConfigurationManager, project_dir: Path
    ) -> None:
        mgr.set_value("scheduler.min_delay", 3.0, global_scope=True)
        mgr.set_value(
            "scheduler.min_delay",
            15.0,
            global_scope=False,
            project_data_dir=project_dir,
            project_db_path=project_dir / "talos.db",
        )
        eff = mgr.load(project_data_dir=project_dir)
        assert eff.scheduler.min_delay == 15.0
        assert eff.source_of("scheduler.min_delay") == ValueSource.PROJECT

    def test_cli_overrides_project(
        self, mgr: ConfigurationManager, project_dir: Path
    ) -> None:
        mgr.set_value(
            "scheduler.min_delay",
            15.0,
            project_data_dir=project_dir,
            project_db_path=project_dir / "talos.db",
        )
        eff = mgr.load(
            project_data_dir=project_dir,
            cli_overrides={"scheduler": {"min_delay": 1.0}},
        )
        assert eff.scheduler.min_delay == 1.0
        assert eff.source_of("scheduler.min_delay") == ValueSource.CLI

    def test_unset_restores_inheritance(
        self, mgr: ConfigurationManager, project_dir: Path
    ) -> None:
        mgr.set_value("scheduler.max_delay", 8.0, global_scope=True)
        mgr.set_value(
            "scheduler.max_delay",
            20.0,
            project_data_dir=project_dir,
            project_db_path=project_dir / "talos.db",
        )
        mgr.unset_value(
            "scheduler.max_delay",
            project_data_dir=project_dir,
            project_db_path=project_dir / "talos.db",
        )
        eff = mgr.load(project_data_dir=project_dir)
        assert eff.scheduler.max_delay == 8.0
        assert eff.source_of("scheduler.max_delay") == ValueSource.GLOBAL

    def test_proxy_upstream_via_config(
        self, mgr: ConfigurationManager, project_dir: Path
    ) -> None:
        mgr.set_value(
            "proxy.upstream.url",
            "http://127.0.0.1:8081",
            project_data_dir=project_dir,
            project_db_path=project_dir / "talos.db",
        )
        mgr.set_value(
            "proxy.upstream.enabled",
            True,
            project_data_dir=project_dir,
            project_db_path=project_dir / "talos.db",
        )
        eff = mgr.load(project_data_dir=project_dir)
        assert eff.upstream_url() == "http://127.0.0.1:8081"
        # Dual-write into SQLite
        assert get_upstream_url(project_dir / "talos.db") == "http://127.0.0.1:8081"

    def test_legacy_sqlite_bridge(
        self, mgr: ConfigurationManager, project_dir: Path
    ) -> None:
        set_upstream_url(project_dir / "talos.db", "http://legacy:9")
        eff = mgr.load(project_data_dir=project_dir)
        assert eff.upstream_url() == "http://legacy:9"

    def test_isolated_project_skips_global(
        self, mgr: ConfigurationManager, tmp_path: Path
    ) -> None:
        """Projects outside data_dir/projects do not inherit global config."""
        mgr.set_value("scheduler.min_delay", 99.0, global_scope=True)
        orphan = tmp_path / "orphan"
        orphan.mkdir()
        init_project_db(orphan / "talos.db")
        eff = mgr.load(project_data_dir=orphan)
        assert eff.scheduler.min_delay == BUILTIN_DEFAULTS["scheduler"]["min_delay"]


# ================================================================== #
# Helper dual-read                                                     #
# ================================================================== #


class TestSubsystemHelpers:
    def test_scheduler_helpers_roundtrip(self, project_dir: Path, monkeypatch: pytest.MonkeyPatch, data_dir: Path) -> None:
        monkeypatch.setenv("TALOS_DATA_DIR", str(data_dir))
        set_scheduler_config(project_dir / "talos.db", 4.0, 10.0, 50)
        cfg = get_scheduler_config(project_dir / "talos.db")
        assert cfg["min_delay"] == 4.0
        assert cfg["max_delay"] == 10.0
        assert cfg["max_queue_size"] == 50
        assert cfg["testing_windows_enabled"] is False
        assert cfg["testing_windows"] == []
        yaml_path = project_dir / "project.yaml"
        assert yaml_path.exists()
        data = yaml.safe_load(yaml_path.read_text())
        assert data["scheduler"]["min_delay"] == 4.0

    def test_testing_windows_via_config_set(
        self, project_dir: Path, monkeypatch: pytest.MonkeyPatch, data_dir: Path
    ) -> None:
        monkeypatch.setenv("TALOS_DATA_DIR", str(data_dir))
        mgr = ConfigurationManager(data_dir)
        mgr.set_value(
            "scheduler.testing_windows.enabled",
            True,
            project_data_dir=project_dir,
        )
        mgr.set_value(
            "scheduler.testing_windows.windows",
            ["09:00-18:00"],
            project_data_dir=project_dir,
        )
        cfg = get_scheduler_config(project_dir / "talos.db")
        assert cfg["testing_windows_enabled"] is True
        assert cfg["testing_windows"] == ["09:00-18:00"]

    def test_attack_helpers_roundtrip(self, project_dir: Path, monkeypatch: pytest.MonkeyPatch, data_dir: Path) -> None:
        monkeypatch.setenv("TALOS_DATA_DIR", str(data_dir))
        assert get_unauth_auto_run(project_dir / "talos.db") is False
        set_unauth_auto_run(project_dir / "talos.db", True)
        assert get_unauth_auto_run(project_dir / "talos.db") is True

    def test_resolve_upstream_cli_override(
        self, project_dir: Path, monkeypatch: pytest.MonkeyPatch, data_dir: Path
    ) -> None:
        monkeypatch.setenv("TALOS_DATA_DIR", str(data_dir))
        set_upstream_url(project_dir / "talos.db", "http://from-config:1")
        assert (
            resolve_upstream_url(
                project_dir / "talos.db", cli_upstream="http://cli:2"
            )
            == "http://cli:2"
        )
        assert (
            resolve_upstream_url(project_dir / "talos.db", cli_no_upstream=True)
            is None
        )
        # Project store unchanged
        assert get_upstream_url(project_dir / "talos.db") == "http://from-config:1"


# ================================================================== #
# CLI                                                                  #
# ================================================================== #


class TestConfigCli:
    def test_show(self, data_dir: Path, project_dir: Path) -> None:
        manager = _manager_with_project(data_dir, project_dir)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_show(manager, SimpleNamespace(format="table"))
        text = buf.getvalue()
        assert "Global:" in text
        assert "Effective:" in text
        assert "project.yaml" in text or str(project_dir) in text

    def test_get_inherited(
        self, data_dir: Path, project_dir: Path, mgr: ConfigurationManager
    ) -> None:
        mgr.set_value("scheduler.max_delay", 12.0, global_scope=True)
        manager = _manager_with_project(data_dir, project_dir)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_get(
                manager,
                SimpleNamespace(key="scheduler.max_delay", format="table"),
            )
        text = buf.getvalue()
        assert "Global" in text
        assert "12" in text

    def test_set_and_unset(
        self, data_dir: Path, project_dir: Path
    ) -> None:
        manager = _manager_with_project(data_dir, project_dir)
        cmd_set(
            manager,
            SimpleNamespace(
                key="attack.unauth_auto_run",
                value="true",
                global_scope=False,
            ),
        )
        assert get_unauth_auto_run(project_dir / "talos.db") is True
        cmd_unset(
            manager,
            SimpleNamespace(key="attack.unauth_auto_run", global_scope=False),
        )
        # After unset, default (false) is inherited
        assert get_unauth_auto_run(project_dir / "talos.db") is False

    def test_effective_json(
        self, data_dir: Path, project_dir: Path
    ) -> None:
        manager = _manager_with_project(data_dir, project_dir)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_effective(
                manager,
                SimpleNamespace(output_format="json", section="scheduler"),
            )
        import json

        payload = json.loads(buf.getvalue())
        assert "values" in payload
        assert "sources" in payload

    def test_schema_json(self, data_dir: Path, project_dir: Path) -> None:
        manager = _manager_with_project(data_dir, project_dir)
        buf = io.StringIO()
        with redirect_stdout(buf):
            run_config_cli(manager, ["schema", "--format", "json"])
        import json

        payload = json.loads(buf.getvalue())
        assert "sections" in payload
        assert "known_keys" in payload
        assert "scheduler.max_delay" in payload["known_keys"]
        sched = next(s for s in payload["sections"] if s["id"] == "scheduler")
        keys = {s["key"] for s in sched["settings"]}
        assert "scheduler.min_delay" in keys
        assert "scheduler.testing_windows.enabled" in keys
        assert "scheduler.testing_windows.windows" in payload["known_keys"]

    def test_section_resource(
        self, data_dir: Path, project_dir: Path
    ) -> None:
        manager = _manager_with_project(data_dir, project_dir)
        buf = io.StringIO()
        with redirect_stdout(buf):
            run_config_cli(manager, ["proxy"])
        assert "Proxy" in buf.getvalue() or "proxy" in buf.getvalue().lower()

    def test_set_proxy_url_enables_upstream(
        self, data_dir: Path, project_dir: Path
    ) -> None:
        manager = _manager_with_project(data_dir, project_dir)
        cmd_set(
            manager,
            SimpleNamespace(
                key="proxy.upstream.url",
                value="http://127.0.0.1:8081",
                global_scope=False,
            ),
        )
        assert get_upstream_url(project_dir / "talos.db") == "http://127.0.0.1:8081"
