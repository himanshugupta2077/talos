"""
Tests for ProxyRuntimeManager lifecycle using a fake ProcessOps child
(graceful_child fixture) instead of mitmdump.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from talos.projects.manager import ProjectManager
from talos.proxy.runtime.lock import RuntimeLock
from talos.proxy.runtime.manager import (
    ProxyAlreadyRunning,
    ProxyRuntimeManager,
)
from talos.proxy.runtime.process_ops import ProcessOps
from talos.proxy.runtime.state import ProxyState, load_state, proxy_state_path

FIXTURE = Path(__file__).parent / "fixtures" / "graceful_child.py"


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "talos-data"
    d.mkdir()
    return d


@pytest.fixture
def project(data_dir: Path) -> MagicMock:
    """Minimal project-like object for manager.start."""
    # Create a real project via ProjectManager so seed/role APIs work.
    root = data_dir / "projects"
    root.mkdir()
    mgr = ProjectManager(projects_root=root)
    proj = mgr.create("runtime-test", scope=["example.com"])
    mgr.open("runtime-test")
    return proj


class FakeMitmOps(ProcessOps):
    """
    ProcessOps that spawns graceful_child instead of the real argv.
    Captures the original argv for assertions.
    """

    def __init__(self, ready_dir: Path) -> None:
        self.last_argv: list[str] | None = None
        self._ready_dir = ready_dir
        self._counter = 0

    def spawn_managed(self, argv, *, env=None, log_path=None, cwd=None):  # type: ignore[no-untyped-def]
        self.last_argv = list(argv)
        self._counter += 1
        ready = self._ready_dir / f"ready-{self._counter}"
        graceful = self._ready_dir / f"graceful-{self._counter}"
        # Also open a TCP port so manager readiness checks pass.
        port = "0"
        if "--listen-port" in argv:
            port = argv[argv.index("--listen-port") + 1]
        child_argv = [
            sys.executable,
            str(FIXTURE),
            "--ready",
            str(ready),
            "--graceful",
            str(graceful),
            "--hold-seconds",
            "30",
            "--listen-port",
            port,
        ]
        identity = super().spawn_managed(child_argv, env=env, log_path=log_path, cwd=cwd)
        # Wait for READY so settle checks pass.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if ready.exists():
                break
            time.sleep(0.05)
        return identity


def test_start_status_stop(data_dir: Path, project: MagicMock, tmp_path: Path) -> None:
    ops = FakeMitmOps(tmp_path / "child")
    (tmp_path / "child").mkdir()
    mgr = ProxyRuntimeManager(data_dir=data_dir, process_ops=ops)

    info = mgr.start(
        project=project,
        listen_host="127.0.0.1",
        port=18080,
        upstream_url=None,
    )
    assert info.state == ProxyState.RUNNING
    assert info.pid is not None
    assert info.project_id == project.id
    assert ops.last_argv is not None
    assert ops.last_argv[0] == "mitmdump"
    assert "--listen-port" in ops.last_argv

    status = mgr.status()
    assert status.state == ProxyState.RUNNING
    assert status.pid == info.pid
    assert status.validation_deferred is False

    stopped = mgr.stop()
    assert stopped.state == ProxyState.STOPPED
    assert stopped.pid is None

    status2 = mgr.status()
    assert status2.state == ProxyState.STOPPED


def test_double_start_refused(data_dir: Path, project: MagicMock, tmp_path: Path) -> None:
    ops = FakeMitmOps(tmp_path / "child")
    (tmp_path / "child").mkdir()
    mgr = ProxyRuntimeManager(data_dir=data_dir, process_ops=ops)
    mgr.start(project=project, port=18081)
    with pytest.raises(ProxyAlreadyRunning):
        mgr.start(project=project, port=18082)
    mgr.stop()


def test_stale_pid_cleared_on_status(
    data_dir: Path, project: MagicMock, tmp_path: Path
) -> None:
    ops = FakeMitmOps(tmp_path / "child")
    (tmp_path / "child").mkdir()
    mgr = ProxyRuntimeManager(data_dir=data_dir, process_ops=ops)
    info = mgr.start(project=project, port=18083)
    # Corrupt create_time to simulate PID reuse / stale state.
    state = load_state(data_dir)
    state.create_time = (state.create_time or 0.0) + 999999.0
    from talos.proxy.runtime.state import save_state

    save_state(data_dir, state)

    status = mgr.status()
    assert status.state == ProxyState.STOPPED
    assert status.pid is None
    # Ensure we did not leave a live orphan untracked — kill original.
    if info.pid is not None and info.create_time is not None:
        from talos.proxy.runtime.process_ops import ProcessIdentity

        ops.force_kill(ProcessIdentity(pid=info.pid, create_time=info.create_time))


def test_zero_create_time_rebound_on_status(
    data_dir: Path, project: MagicMock, tmp_path: Path
) -> None:
    """
    Spawn-time create_time read can fail on Windows (recorded as 0.0). Status
    must rebind create_time and keep RUNNING instead of clearing to stopped.
    """
    ops = FakeMitmOps(tmp_path / "child")
    (tmp_path / "child").mkdir()
    mgr = ProxyRuntimeManager(data_dir=data_dir, process_ops=ops)
    info = mgr.start(project=project, port=18085)
    assert info.pid is not None

    from talos.proxy.runtime.state import save_state

    state = load_state(data_dir)
    state.create_time = 0.0
    save_state(data_dir, state)

    status = mgr.status()
    assert status.state == ProxyState.RUNNING
    assert status.pid == info.pid
    assert status.create_time is not None
    assert status.create_time != 0.0

    rebound = load_state(data_dir)
    assert rebound.create_time not in (None, 0.0)
    assert rebound.pid == info.pid

    mgr.stop()


def test_status_deferred_when_lock_held(
    data_dir: Path, project: MagicMock, tmp_path: Path
) -> None:
    ops = FakeMitmOps(tmp_path / "child")
    (tmp_path / "child").mkdir()
    mgr = ProxyRuntimeManager(data_dir=data_dir, process_ops=ops)
    info = mgr.start(project=project, port=18084)

    from talos.proxy.runtime.state import proxy_lock_path

    lock = RuntimeLock(proxy_lock_path(data_dir))
    lock.acquire()
    try:
        status = mgr.status()
        assert status.validation_deferred is True
        # Snapshot should still show running from atomic json.
        assert status.state == ProxyState.RUNNING
        assert status.pid == info.pid
    finally:
        lock.release()
        mgr.stop()


def test_restart_new_identity(
    data_dir: Path, project: MagicMock, tmp_path: Path
) -> None:
    ops = FakeMitmOps(tmp_path / "child")
    (tmp_path / "child").mkdir()
    mgr = ProxyRuntimeManager(data_dir=data_dir, process_ops=ops)
    first = mgr.start(project=project, port=18085)
    second = mgr.restart(project=project)
    assert second.state == ProxyState.RUNNING
    assert second.pid != first.pid
    mgr.stop()


def test_atomic_state_file_is_valid_json(
    data_dir: Path, project: MagicMock, tmp_path: Path
) -> None:
    ops = FakeMitmOps(tmp_path / "child")
    (tmp_path / "child").mkdir()
    mgr = ProxyRuntimeManager(data_dir=data_dir, process_ops=ops)
    mgr.start(project=project, port=18086)
    raw = json.loads(proxy_state_path(data_dir).read_text(encoding="utf-8"))
    assert raw["state"] == "running"
    assert raw["project_id"] == project.id
    mgr.stop()


def test_start_refuses_when_port_busy(
    data_dir: Path, project: MagicMock, tmp_path: Path
) -> None:
    import socket

    from talos.proxy.runtime.manager import ProxyStartError

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(1)
    try:
        ops = FakeMitmOps(tmp_path / "child")
        (tmp_path / "child").mkdir(exist_ok=True)
        mgr = ProxyRuntimeManager(data_dir=data_dir, process_ops=ops)
        with pytest.raises(ProxyStartError) as exc:
            mgr.start(project=project, port=port)
        assert "already in use" in str(exc.value).lower()
        assert "proxy kill" in str(exc.value).lower()
    finally:
        sock.close()
