"""
Control Panel open-directory tests.

Security boundary: project identity + server-side registry resolution.
The browser must never supply an arbitrary filesystem path as the open target.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


@pytest.fixture()
def home(tmp_path, monkeypatch):
    """
    Purpose:
        Isolated TALOS_HOME with one conventional project and one override.
    """
    talos_home = tmp_path / "talos-home"
    projects = talos_home / "projects"
    projects.mkdir(parents=True)

    # Conventional layout: ~/.talos/projects/demo
    demo_dir = projects / "demo"
    demo_dir.mkdir()
    (demo_dir / "talos.db").write_bytes(b"")

    # Registry data_dir override outside projects root
    override_dir = tmp_path / "custom-location" / "override-proj"
    override_dir.mkdir(parents=True)

    registry = {
        "demo": {
            "name": "Demo",
            "status": "inactive",
            "scope": [],
            "created_at": "2026-01-01T00:00:00",
        },
        "override": {
            "name": "Override",
            "status": "inactive",
            "scope": [],
            "data_dir": str(override_dir),
            "created_at": "2026-01-02T00:00:00",
        },
        "missing-dir": {
            "name": "Missing",
            "status": "inactive",
            "scope": [],
            # Intentionally no data_dir and no on-disk folder under projects/
            "created_at": "2026-01-03T00:00:00",
        },
    }
    (projects / "registry.json").write_text(json.dumps(registry), encoding="utf-8")

    monkeypatch.setenv("TALOS_HOME", str(talos_home))
    # Reload config paths bound at import time.
    import talos_ui.config as config

    monkeypatch.setattr(config, "TALOS_HOME", talos_home)
    monkeypatch.setattr(config, "PROJECTS_ROOT", projects)
    monkeypatch.setattr(config, "REGISTRY_PATH", projects / "registry.json")

    return {
        "talos_home": talos_home,
        "projects": projects,
        "demo_dir": demo_dir,
        "override_dir": override_dir,
    }


@pytest.fixture()
def client(home):
    from talos_ui.main import app

    return TestClient(app)


def test_data_dir_resolves_through_project_data_dir(client, home):
    with patch("talos_ui.routers.projects.open_directory") as opener:
        res = client.post(
            "/api/projects/demo/open-directory",
            json={"target": "data_dir"},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True
        assert body["target"] == "data_dir"
        assert body["project_id"] == "demo"
        assert Path(body["path"]) == home["demo_dir"]
        opener.assert_called_once()
        called_path = opener.call_args[0][0]
        assert Path(called_path) == home["demo_dir"]


def test_registry_data_dir_override_respected(client, home):
    with patch("talos_ui.routers.projects.open_directory") as opener:
        res = client.post(
            "/api/projects/override/open-directory",
            json={"target": "data_dir"},
        )
        assert res.status_code == 200
        body = res.json()
        assert Path(body["path"]) == home["override_dir"]
        # Must not reject merely because path is outside PROJECTS_ROOT.
        assert str(home["projects"]) not in str(home["override_dir"])
        opener.assert_called_once_with(home["override_dir"])


def test_database_dir_is_parent_of_project_db_path(client, home):
    with patch("talos_ui.routers.projects.open_directory") as opener:
        res = client.post(
            "/api/projects/demo/open-directory",
            json={"target": "database_dir"},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["target"] == "database_dir"
        # Parent of talos.db — same as data_dir in conventional layout.
        assert Path(body["path"]) == home["demo_dir"]
        assert not str(body["path"]).endswith("talos.db")
        opener.assert_called_once()


def test_database_dir_openable_before_talos_db_exists(client, home, monkeypatch):
    """Open database_dir when parent exists even if talos.db is missing."""
    # Project with data dir but no talos.db yet
    bare = home["projects"] / "bare"
    bare.mkdir()
    registry_path = home["projects"] / "registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry["bare"] = {
        "name": "Bare",
        "status": "inactive",
        "scope": [],
        "created_at": "2026-01-04T00:00:00",
    }
    registry_path.write_text(json.dumps(registry), encoding="utf-8")

    with patch("talos_ui.routers.projects.open_directory") as opener:
        res = client.post(
            "/api/projects/bare/open-directory",
            json={"target": "database_dir"},
        )
        assert res.status_code == 200
        assert Path(res.json()["path"]) == bare
        opener.assert_called_once()


def test_project_not_found_rejected(client):
    res = client.post(
        "/api/projects/does-not-exist/open-directory",
        json={"target": "data_dir"},
    )
    assert res.status_code == 404
    assert "project not found" in res.json()["detail"].lower()


def test_invalid_target_rejected(client):
    res = client.post(
        "/api/projects/demo/open-directory",
        json={"target": "not_a_real_target"},
    )
    assert res.status_code == 422


def test_arbitrary_path_cannot_be_supplied_as_target(client, home):
    """
    Path-like strings must not be accepted as targets.
    There is no path/query field for filesystem paths.
    """
    res = client.post(
        "/api/projects/demo/open-directory",
        json={"target": "/etc/passwd"},
    )
    assert res.status_code == 422

    # Extra body fields must not change resolution; only target enum is used.
    with patch("talos_ui.routers.projects.open_directory") as opener:
        res2 = client.post(
            "/api/projects/demo/open-directory",
            json={"path": "/etc/passwd", "target": "data_dir"},
        )
        assert res2.status_code == 200
        called = opener.call_args[0][0]
        assert Path(called) == home["demo_dir"]
        assert "/etc/passwd" not in str(called)
        assert Path(called).name == "demo"


def test_missing_directory_returns_actionable_failure(client, home):
    """Real open_directory rejects a missing resolved data dir with 400."""
    res = client.post(
        "/api/projects/missing-dir/open-directory",
        json={"target": "data_dir"},
    )
    assert res.status_code == 400
    detail = res.json()["detail"]
    assert "does not exist" in detail.lower()


def test_linux_invokes_xdg_open_argument_list(home, monkeypatch):
    from talos_ui.platform_open import open_directory

    monkeypatch.setattr(sys, "platform", "linux")
    with patch("talos_ui.platform_open.subprocess.Popen") as popen:
        popen.return_value = MagicMock()
        open_directory(home["demo_dir"])
        popen.assert_called_once()
        args, kwargs = popen.call_args
        argv = args[0]
        assert argv[0] == "xdg-open"
        assert Path(argv[1]) == home["demo_dir"].resolve()
        assert kwargs.get("shell") is False
        assert "shell" in kwargs or kwargs.get("shell", False) is False


def test_linux_no_shell_true(home, monkeypatch):
    from talos_ui.platform_open import open_directory

    monkeypatch.setattr(sys, "platform", "linux")
    with patch("talos_ui.platform_open.subprocess.Popen") as popen:
        popen.return_value = MagicMock()
        open_directory(home["demo_dir"])
        assert popen.call_args.kwargs.get("shell", False) is False


def test_windows_invokes_startfile(home, monkeypatch):
    from talos_ui.platform_open import open_directory

    monkeypatch.setattr(sys, "platform", "win32")
    # create=True: os.startfile exists only on Windows Python builds.
    with patch("talos_ui.platform_open.os.startfile", create=True) as startfile:
        open_directory(home["demo_dir"])
        startfile.assert_called_once()
        opened = startfile.call_args[0][0]
        assert Path(opened) == home["demo_dir"].resolve()


def test_process_launch_failure_surfaced(home, monkeypatch):
    from talos_ui.platform_open import OpenDirectoryError, open_directory

    monkeypatch.setattr(sys, "platform", "linux")
    with patch(
        "talos_ui.platform_open.subprocess.Popen",
        side_effect=OSError("spawn failed"),
    ):
        with pytest.raises(OpenDirectoryError) as exc:
            open_directory(home["demo_dir"])
        assert "failed to launch" in str(exc.value).lower()


def test_xdg_open_missing_surfaced(home, monkeypatch):
    from talos_ui.platform_open import OpenDirectoryError, open_directory

    monkeypatch.setattr(sys, "platform", "linux")
    with patch(
        "talos_ui.platform_open.subprocess.Popen",
        side_effect=FileNotFoundError("xdg-open"),
    ):
        with pytest.raises(OpenDirectoryError) as exc:
            open_directory(home["demo_dir"])
        assert "xdg-open" in str(exc.value).lower()


def test_unsupported_platform(home, monkeypatch):
    from talos_ui.platform_open import OpenDirectoryError, open_directory

    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(OpenDirectoryError) as exc:
        open_directory(home["demo_dir"])
    assert "unsupported operating system" in str(exc.value).lower()


def test_open_directory_endpoint_surfaces_launch_failure(client, home):
    from talos_ui.platform_open import OpenDirectoryError

    with patch(
        "talos_ui.routers.projects.open_directory",
        side_effect=OpenDirectoryError("Failed to launch directory opener: boom"),
    ):
        res = client.post(
            "/api/projects/demo/open-directory",
            json={"target": "data_dir"},
        )
    assert res.status_code == 400
    assert "failed to launch" in res.json()["detail"].lower()


def test_no_cli_and_no_db_write_on_open(client, home):
    """Open directory must not route through Talos CLI or write SQLite."""
    with (
        patch("talos_ui.routers.projects.open_directory") as opener,
        patch("talos_ui.routers.projects.cli.run") as cli_run,
        patch("talos_ui.routers.projects.cli.run_scoped") as cli_scoped,
    ):
        res = client.post(
            "/api/projects/demo/open-directory",
            json={"target": "data_dir"},
        )
        assert res.status_code == 200
        opener.assert_called_once()
        cli_run.assert_not_called()
        cli_scoped.assert_not_called()
