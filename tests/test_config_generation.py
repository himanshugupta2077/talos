"""Tests for proxy config generation, transactions, and reconcile honesty."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from talos.projects.manager import ProjectManager
from talos.proxy.runtime.generation import (
    bump_generation,
    get_generation,
    proxy_config_transaction,
)
from talos.proxy.runtime.manager import ProxyRuntimeManager
from talos.proxy.runtime.process_ops import ProcessOps
from talos.proxy.runtime.state import ProxyState

FIXTURE = Path(__file__).parent / "fixtures" / "graceful_child.py"


class FakeMitmOps(ProcessOps):
    def __init__(self, ready_dir: Path) -> None:
        self._ready_dir = ready_dir
        self._counter = 0
        self.spawn_count = 0

    def spawn_managed(self, argv, *, env=None, log_path=None, cwd=None):  # type: ignore[no-untyped-def]
        self.spawn_count += 1
        self._counter += 1
        ready = self._ready_dir / f"ready-{self._counter}"
        graceful = self._ready_dir / f"graceful-{self._counter}"
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
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if ready.exists():
                break
            time.sleep(0.05)
        return identity


@pytest.fixture
def projects_root(tmp_path: Path) -> Path:
    root = tmp_path / "projects"
    root.mkdir()
    return root


def test_bump_and_get(projects_root: Path) -> None:
    assert get_generation(projects_root, "p1") == 0
    assert bump_generation(projects_root, "p1", reason="test") == 1
    assert bump_generation(projects_root, "p1", reason="test2") == 2
    assert get_generation(projects_root, "p1") == 2
    assert get_generation(projects_root, "other") == 0


def test_transaction_single_bump(projects_root: Path) -> None:
    with proxy_config_transaction(projects_root, "p1"):
        bump_generation(projects_root, "p1", reason="a")
        bump_generation(projects_root, "p1", reason="b")
        bump_generation(projects_root, "p1", reason="c")
        assert get_generation(projects_root, "p1") == 0  # not committed yet
    assert get_generation(projects_root, "p1") == 1


def test_transaction_rollback_on_error(projects_root: Path) -> None:
    try:
        with proxy_config_transaction(projects_root, "p1"):
            bump_generation(projects_root, "p1", reason="a")
            raise RuntimeError("fail")
    except RuntimeError:
        pass
    assert get_generation(projects_root, "p1") == 0


def test_reconcile_restarts_on_generation(
    tmp_path: Path, projects_root: Path
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    # Point projects under data_dir/projects for ProjectManager consistency.
    proj_root = data_dir / "projects"
    proj_root.mkdir()
    mgr = ProjectManager(projects_root=proj_root)
    project = mgr.create("gen-test", scope=["example.com"])
    mgr.open("gen-test")

    child_dir = tmp_path / "child"
    child_dir.mkdir()
    ops = FakeMitmOps(child_dir)
    runtime = ProxyRuntimeManager(data_dir=data_dir, process_ops=ops)

    info = runtime.start(project=project, port=19001, spawn_generation=0)
    assert info.applied_generation == 0
    first_pid = info.pid
    assert ops.spawn_count == 1

    # Bump generation and reconcile.
    gen = bump_generation(proj_root, project.id, reason="mutation")
    assert gen == 1
    info2 = runtime.reconcile(
        active_project=project,
        spawn_generation=gen,
        generation_reader=lambda pid: get_generation(proj_root, pid),
    )
    assert info2.state == ProxyState.RUNNING
    assert info2.applied_generation == 1
    assert info2.pid != first_pid
    assert ops.spawn_count == 2
    runtime.stop()


def test_reconcile_no_op_same_generation(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    proj_root = data_dir / "projects"
    proj_root.mkdir()
    mgr = ProjectManager(projects_root=proj_root)
    project = mgr.create("gen-noop", scope=["example.com"])
    mgr.open("gen-noop")

    child_dir = tmp_path / "child"
    child_dir.mkdir()
    ops = FakeMitmOps(child_dir)
    runtime = ProxyRuntimeManager(data_dir=data_dir, process_ops=ops)
    runtime.start(project=project, port=19002, spawn_generation=0)
    spawns = ops.spawn_count
    info = runtime.reconcile(
        active_project=project,
        spawn_generation=0,
        generation_reader=lambda pid: get_generation(proj_root, pid),
    )
    assert info.state == ProxyState.RUNNING
    assert ops.spawn_count == spawns  # no restart
    runtime.stop()


def test_reconcile_stop_when_no_active(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    proj_root = data_dir / "projects"
    proj_root.mkdir()
    mgr = ProjectManager(projects_root=proj_root)
    project = mgr.create("gen-close", scope=["example.com"])
    mgr.open("gen-close")

    child_dir = tmp_path / "child"
    child_dir.mkdir()
    ops = FakeMitmOps(child_dir)
    runtime = ProxyRuntimeManager(data_dir=data_dir, process_ops=ops)
    runtime.start(project=project, port=19003)
    info = runtime.reconcile(active_project=None)
    assert info.state == ProxyState.STOPPED
    assert info.pid is None
