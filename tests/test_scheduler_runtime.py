"""Tests for SchedulerRuntimeManager process lifecycle and project rebind."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from talos.projects.manager import ProjectManager
from talos.proxy.runtime.process_ops import ProcessOps
from talos.proxy.runtime.state import ProxyState
from talos.scheduler.runtime import (
    SchedulerAlreadyRunning,
    SchedulerRuntimeManager,
)

FIXTURE = Path(__file__).parent / "fixtures" / "graceful_child.py"


class FakeSchedulerOps(ProcessOps):
    """Spawn graceful_child instead of talos.scheduler.runner."""

    def __init__(self, ready_dir: Path) -> None:
        self._ready_dir = ready_dir
        self._counter = 0
        self.spawn_count = 0
        self.last_argv: list[str] | None = None

    def spawn_managed(self, argv, *, env=None, log_path=None, cwd=None):  # type: ignore[no-untyped-def]
        self.last_argv = list(argv)
        self.spawn_count += 1
        self._counter += 1
        ready = self._ready_dir / f"ready-{self._counter}"
        graceful = self._ready_dir / f"graceful-{self._counter}"
        child_argv = [
            sys.executable,
            str(FIXTURE),
            "--ready",
            str(ready),
            "--graceful",
            str(graceful),
            "--hold-seconds",
            "30",
        ]
        identity = super().spawn_managed(child_argv, env=env, log_path=log_path, cwd=cwd)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if ready.exists():
                break
            time.sleep(0.05)
        return identity


@pytest.fixture
def env(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    projects = data_dir / "projects"
    projects.mkdir()
    mgr = ProjectManager(projects_root=projects)
    a = mgr.create("proj-a", scope=["a.example.com"])
    b = mgr.create("proj-b", scope=["b.example.com"])
    mgr.open("proj-a")
    child = tmp_path / "child"
    child.mkdir()
    ops = FakeSchedulerOps(child)
    runtime = SchedulerRuntimeManager(data_dir=data_dir, process_ops=ops)
    return mgr, a, b, runtime, ops


def test_start_stop_status(env) -> None:
    mgr, project_a, _b, runtime, ops = env
    info = runtime.start(project=project_a)
    assert info.state == ProxyState.RUNNING
    assert info.project_id == project_a.id
    assert ops.last_argv is not None
    assert "talos.scheduler.runner" in ops.last_argv

    status = runtime.status()
    assert status.pid == info.pid
    assert status.validation_deferred is False

    with pytest.raises(SchedulerAlreadyRunning):
        runtime.start(project=project_a)

    stopped = runtime.stop()
    assert stopped.state == ProxyState.STOPPED
    assert stopped.pid is None


def test_rebind_on_project_switch(env) -> None:
    mgr, project_a, project_b, runtime, ops = env
    first = runtime.start(project=project_a)
    assert first.project_id == "proj-a"
    first_pid = first.pid

    rebound = runtime.reconcile_active_project(active_project=project_b)
    assert rebound.state == ProxyState.RUNNING
    assert rebound.project_id == "proj-b"
    assert rebound.pid != first_pid
    assert ops.spawn_count == 2

    stopped = runtime.reconcile_active_project(active_project=None)
    assert stopped.state == ProxyState.STOPPED
