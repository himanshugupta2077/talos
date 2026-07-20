"""
Tests for dynamic upstream proxy configuration.

Covers:
  - No upstream configured → Direct mode (None; no --mode upstream on mitmdump)
  - Upstream configured via project configuration (proxy_config table)
  - Upstream supplied via CLI one-shot on `proxy start`
  - CLI overriding project configuration (--upstream and --no-upstream)
  - Invalid upstream configuration (empty, bad scheme, missing host)
  - build_mitmdump_command never hardcodes an upstream host/port
  - Replay / BAC / unauth HTTP clients use get_upstream_url (no hardcoded proxy)
  - Config changes are read on the next resolve (restart reflects config)
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from talos.projects.db import init_project_db
from talos.projects.manager import ProjectManager
from talos.projects.proxy_config import (
    InvalidUpstreamUrl,
    clear_upstream_url,
    get_upstream_url,
    resolve_upstream_url,
    set_upstream_url,
    validate_upstream_url,
)
from talos.proxy.cli import build_parser, run_proxy_cli
from talos.proxy.launcher import build_mitmdump_command


# ------------------------------------------------------------------ #
# Fixtures                                                             #
# ------------------------------------------------------------------ #


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


@pytest.fixture
def manager_with_project(tmp_path: Path) -> tuple[ProjectManager, MagicMock]:
    """Mock ProjectManager with an active project backed by a real DB."""
    db = tmp_path / "talos.db"
    init_project_db(db)

    project = MagicMock()
    project.id = "proj-upstream"
    project.db_path = db
    project.scope = ["example.com"]
    project.constraints.store_bodies = True
    project.constraints.max_body_size = 1024

    manager = MagicMock(spec=ProjectManager)
    manager.active.return_value = project
    return manager, project


# ------------------------------------------------------------------ #
# validate_upstream_url                                                #
# ------------------------------------------------------------------ #


class TestValidateUpstreamUrl:
    def test_accepts_http_with_port(self) -> None:
        assert validate_upstream_url("http://127.0.0.1:8081") == (
            "http://127.0.0.1:8081"
        )

    def test_accepts_https_and_strips(self) -> None:
        assert validate_upstream_url("  https://proxy.corp.example:8443  ") == (
            "https://proxy.corp.example:8443"
        )

    def test_accepts_userinfo(self) -> None:
        # Credentials may appear in the URL when the user supplies them;
        # Talos never hardcodes them — only validates structure.
        url = "http://user:pass@proxy.example:3128"
        assert validate_upstream_url(url) == url

    def test_rejects_empty(self) -> None:
        with pytest.raises(InvalidUpstreamUrl, match="empty"):
            validate_upstream_url("")
        with pytest.raises(InvalidUpstreamUrl, match="empty"):
            validate_upstream_url("   ")

    def test_rejects_missing_scheme(self) -> None:
        with pytest.raises(InvalidUpstreamUrl, match="http:// or https://"):
            validate_upstream_url("127.0.0.1:8081")

    def test_rejects_bad_scheme(self) -> None:
        with pytest.raises(InvalidUpstreamUrl, match="http:// or https://"):
            validate_upstream_url("socks5://127.0.0.1:1080")

    def test_rejects_missing_host(self) -> None:
        with pytest.raises(InvalidUpstreamUrl, match="host"):
            validate_upstream_url("http://")


# ------------------------------------------------------------------ #
# proxy_config table CRUD                                              #
# ------------------------------------------------------------------ #


class TestProxyConfigCrud:
    def test_no_upstream_by_default(self, db_path: Path) -> None:
        assert get_upstream_url(db_path) is None

    def test_set_and_get(self, db_path: Path) -> None:
        stored = set_upstream_url(db_path, "http://127.0.0.1:8081")
        assert stored == "http://127.0.0.1:8081"
        assert get_upstream_url(db_path) == "http://127.0.0.1:8081"

    def test_clear_returns_to_direct(self, db_path: Path) -> None:
        set_upstream_url(db_path, "http://proxy.example:8080")
        clear_upstream_url(db_path)
        assert get_upstream_url(db_path) is None

    def test_set_rejects_invalid(self, db_path: Path) -> None:
        with pytest.raises(InvalidUpstreamUrl):
            set_upstream_url(db_path, "not-a-url")
        assert get_upstream_url(db_path) is None

    def test_missing_db_is_direct(self, tmp_path: Path) -> None:
        assert get_upstream_url(tmp_path / "missing.db") is None

    def test_config_change_reflected_immediately(self, db_path: Path) -> None:
        """Next resolve after set/clear sees the new value (restart semantics)."""
        assert resolve_upstream_url(db_path) is None
        set_upstream_url(db_path, "http://burp.local:8081")
        assert resolve_upstream_url(db_path) == "http://burp.local:8081"
        clear_upstream_url(db_path)
        assert resolve_upstream_url(db_path) is None


# ------------------------------------------------------------------ #
# resolve_upstream_url (shared resolution)                             #
# ------------------------------------------------------------------ #


class TestResolveUpstreamUrl:
    def test_no_config_no_cli_is_direct(self, db_path: Path) -> None:
        assert resolve_upstream_url(db_path) is None

    def test_project_config_used(self, db_path: Path) -> None:
        set_upstream_url(db_path, "http://config.example:9000")
        assert resolve_upstream_url(db_path) == "http://config.example:9000"

    def test_cli_upstream_overrides_config(self, db_path: Path) -> None:
        set_upstream_url(db_path, "http://config.example:9000")
        assert resolve_upstream_url(
            db_path, cli_upstream="http://cli.example:8081"
        ) == "http://cli.example:8081"
        # Project config unchanged.
        assert get_upstream_url(db_path) == "http://config.example:9000"

    def test_cli_no_upstream_overrides_config(self, db_path: Path) -> None:
        set_upstream_url(db_path, "http://config.example:9000")
        assert resolve_upstream_url(db_path, cli_no_upstream=True) is None
        assert get_upstream_url(db_path) == "http://config.example:9000"

    def test_cli_upstream_without_config(self, db_path: Path) -> None:
        assert resolve_upstream_url(
            db_path, cli_upstream="http://oneshot:3128"
        ) == "http://oneshot:3128"
        assert get_upstream_url(db_path) is None

    def test_cli_invalid_upstream_raises(self, db_path: Path) -> None:
        with pytest.raises(InvalidUpstreamUrl):
            resolve_upstream_url(db_path, cli_upstream="ftp://bad")


# ------------------------------------------------------------------ #
# build_mitmdump_command (launcher)                                    #
# ------------------------------------------------------------------ #


class TestBuildMitmdumpCommand:
    def test_direct_mode_omits_upstream_flag(self, tmp_path: Path) -> None:
        addon = tmp_path / "addon.py"
        addon.write_text("# stub\n")
        cmd = build_mitmdump_command(
            listen_host="127.0.0.1",
            port=8080,
            addon_path=addon,
            upstream_url=None,
        )
        assert cmd[0] == "mitmdump"
        assert "--mode" not in cmd
        assert not any("upstream:" in part for part in cmd)
        assert "127.0.0.1:8081" not in " ".join(cmd)

    def test_empty_string_is_direct(self, tmp_path: Path) -> None:
        addon = tmp_path / "addon.py"
        addon.write_text("# stub\n")
        cmd = build_mitmdump_command(
            listen_host="0.0.0.0",
            port=9090,
            addon_path=addon,
            upstream_url="",
        )
        assert "--mode" not in cmd

    def test_upstream_mode_uses_supplied_url(self, tmp_path: Path) -> None:
        addon = tmp_path / "addon.py"
        addon.write_text("# stub\n")
        url = "http://corp-proxy.example:3128"
        cmd = build_mitmdump_command(
            listen_host="127.0.0.1",
            port=8080,
            addon_path=addon,
            upstream_url=url,
        )
        assert "--mode" in cmd
        mode_idx = cmd.index("--mode")
        assert cmd[mode_idx + 1] == f"upstream:{url}"
        # Must not inject any hardcoded fallback host/port.
        assert "127.0.0.1:8081" not in " ".join(cmd)

    def test_upstream_url_varies_with_input(self, tmp_path: Path) -> None:
        addon = tmp_path / "addon.py"
        addon.write_text("# stub\n")
        a = build_mitmdump_command(
            listen_host="127.0.0.1", port=8080, addon_path=addon,
            upstream_url="http://a:1",
        )
        b = build_mitmdump_command(
            listen_host="127.0.0.1", port=8080, addon_path=addon,
            upstream_url="http://b:2",
        )
        assert "upstream:http://a:1" in a
        assert "upstream:http://b:2" in b
        assert a != b


# ------------------------------------------------------------------ #
# CLI: proxy config                                                    #
# ------------------------------------------------------------------ #


class TestProxyConfigCli:
    def test_show_direct_by_default(
        self,
        manager_with_project: tuple[ProjectManager, MagicMock],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        manager, _ = manager_with_project
        run_proxy_cli(manager, ["config"])
        out = capsys.readouterr().out
        assert "Direct" in out

    def test_set_upstream(
        self,
        manager_with_project: tuple[ProjectManager, MagicMock],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        manager, project = manager_with_project
        run_proxy_cli(
            manager, ["config", "--upstream", "http://127.0.0.1:8081"]
        )
        out = capsys.readouterr().out
        assert "Upstream Proxy" in out
        assert "http://127.0.0.1:8081" in out
        assert get_upstream_url(project.db_path) == "http://127.0.0.1:8081"

    def test_clear_upstream(
        self,
        manager_with_project: tuple[ProjectManager, MagicMock],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        manager, project = manager_with_project
        set_upstream_url(project.db_path, "http://127.0.0.1:8081")
        run_proxy_cli(manager, ["config", "--no-upstream"])
        out = capsys.readouterr().out
        assert "Direct" in out
        assert get_upstream_url(project.db_path) is None

    def test_invalid_upstream_exits_usage(
        self,
        manager_with_project: tuple[ProjectManager, MagicMock],
    ) -> None:
        manager, project = manager_with_project
        with pytest.raises(SystemExit) as exc:
            run_proxy_cli(manager, ["config", "--upstream", "not-valid"])
        assert exc.value.code == 2
        assert get_upstream_url(project.db_path) is None

    def test_mutual_exclusion(
        self,
        manager_with_project: tuple[ProjectManager, MagicMock],
    ) -> None:
        manager, _ = manager_with_project
        with pytest.raises(SystemExit) as exc:
            run_proxy_cli(
                manager,
                [
                    "config",
                    "--upstream", "http://127.0.0.1:8081",
                    "--no-upstream",
                ],
            )
        assert exc.value.code == 2


# ------------------------------------------------------------------ #
# CLI: proxy start resolution (mocked process spawn)                   #
# ------------------------------------------------------------------ #


class TestProxyStartResolution:
    def _run_start(
        self,
        manager: ProjectManager,
        argv: list[str],
    ) -> dict:
        """
        Run start with ProxyRuntimeManager.start mocked.
        Returns kwargs passed to start() (includes resolved upstream_url).
        """
        from talos.proxy.runtime.manager import ProxyRuntimeInfo
        from talos.proxy.runtime.state import ProxyState

        captured: dict = {}

        def _fake_start(**kwargs):  # type: ignore[no-untyped-def]
            captured.update(kwargs)
            return ProxyRuntimeInfo(
                state=ProxyState.RUNNING,
                pid=4242,
                create_time=1.0,
                project_id=kwargs["project"].id,
                role_id=None,
                module_id=None,
                listen_host=kwargs.get("listen_host"),
                listen_port=kwargs.get("port"),
                upstream_url=kwargs.get("upstream_url"),
                startup_time="2026-01-01T00:00:00+00:00",
                applied_project_id=kwargs["project"].id,
                applied_generation=0,
                restart_pending=False,
                runtime_version=1,
                last_error=None,
                log_path="/tmp/proxy.log",
            )

        with (
            patch("talos.proxy.cli.ProxyRuntimeManager") as mgr_cls,
            patch("talos.proxy.cli.logging.getLogger"),
        ):
            instance = mgr_cls.return_value
            instance.start.side_effect = _fake_start
            try:
                run_proxy_cli(manager, argv)
            except SystemExit as exc:
                if exc.code not in (0, None):
                    raise
        assert captured, "ProxyRuntimeManager.start was not called"
        return captured

    def test_start_direct_when_unconfigured(
        self,
        manager_with_project: tuple[ProjectManager, MagicMock],
    ) -> None:
        manager, _ = manager_with_project
        kwargs = self._run_start(manager, ["start", "--port", "8080"])
        assert kwargs["upstream_url"] is None
        assert kwargs["port"] == 8080

    def test_start_uses_project_config(
        self,
        manager_with_project: tuple[ProjectManager, MagicMock],
    ) -> None:
        manager, project = manager_with_project
        set_upstream_url(project.db_path, "http://burp.local:8081")
        kwargs = self._run_start(manager, ["start"])
        assert kwargs["upstream_url"] == "http://burp.local:8081"

    def test_start_cli_upstream_overrides_config(
        self,
        manager_with_project: tuple[ProjectManager, MagicMock],
    ) -> None:
        manager, project = manager_with_project
        set_upstream_url(project.db_path, "http://from-config:1")
        kwargs = self._run_start(
            manager, ["start", "--upstream", "http://from-cli:2"]
        )
        assert kwargs["upstream_url"] == "http://from-cli:2"
        # One-shot: project config not rewritten.
        assert get_upstream_url(project.db_path) == "http://from-config:1"

    def test_start_cli_no_upstream_overrides_config(
        self,
        manager_with_project: tuple[ProjectManager, MagicMock],
    ) -> None:
        manager, project = manager_with_project
        set_upstream_url(project.db_path, "http://from-config:1")
        kwargs = self._run_start(manager, ["start", "--no-upstream"])
        assert kwargs["upstream_url"] is None
        assert get_upstream_url(project.db_path) == "http://from-config:1"

    def test_start_invalid_cli_upstream_exits_usage(
        self,
        manager_with_project: tuple[ProjectManager, MagicMock],
    ) -> None:
        manager, _ = manager_with_project
        with pytest.raises(SystemExit) as exc:
            run_proxy_cli(manager, ["start", "--upstream", "bad"])
        assert exc.value.code == 2

    def test_start_after_config_change_uses_new_value(
        self,
        manager_with_project: tuple[ProjectManager, MagicMock],
    ) -> None:
        """Simulates restart: config write then start reads the new URL."""
        manager, project = manager_with_project
        set_upstream_url(project.db_path, "http://first:1")
        kwargs1 = self._run_start(manager, ["start"])
        assert kwargs1["upstream_url"] == "http://first:1"

        set_upstream_url(project.db_path, "http://second:2")
        kwargs2 = self._run_start(manager, ["start"])
        assert kwargs2["upstream_url"] == "http://second:2"

        clear_upstream_url(project.db_path)
        kwargs3 = self._run_start(manager, ["start"])
        assert kwargs3["upstream_url"] is None


# ------------------------------------------------------------------ #
# Parser help documents dynamic upstream flags                         #
# ------------------------------------------------------------------ #


def test_start_parser_documents_upstream_override() -> None:
    parser = build_parser()
    # Parse help for start subcommand.
    start = None
    for action in parser._subparsers._group_actions:  # type: ignore[attr-defined]
        if action.dest == "command":
            start = action.choices["start"]
            break
    assert start is not None
    help_text = start.format_help()
    assert "--upstream" in help_text
    assert "--no-upstream" in help_text


# ------------------------------------------------------------------ #
# Source-level: engines must not hardcode 127.0.0.1:8081              #
# ------------------------------------------------------------------ #


class TestNoHardcodedUpstreamInSource:
    """
    Guard against regressions that reintroduce a hardcoded upstream.
    Runtime paths already tested above; this catches copy-paste leftovers.
    """

    _ENGINE_FILES = (
        "talos/proxy/launcher.py",
        "talos/replay/engine.py",
        "talos/replay/auth_strip.py",
        "talos/projects/bac/engine.py",
        "talos/projects/unauth/engine.py",
    )

    def test_engines_do_not_hardcode_8081(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for rel in self._ENGINE_FILES:
            text = (root / rel).read_text(encoding="utf-8")
            # Docstring examples may mention the URL as illustration only in
            # launcher; engines must not pass it as a proxy= default.
            if rel.endswith("launcher.py"):
                # Runtime path uses f"upstream:{upstream_url}" only.
                assert "upstream:http://127.0.0.1:8081" not in text
                assert 'f"upstream:{upstream_url}"' in text
            else:
                assert "127.0.0.1:8081" not in text
                assert "get_upstream_url" in text
