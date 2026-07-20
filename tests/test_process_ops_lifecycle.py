"""
Real subprocess lifecycle tests for ProcessOps.

Runs on Linux and Windows with the graceful_child fixture — does not mock
process_ops. Validates spawn, identity, graceful stop, force kill, and
double-identity matching.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from talos.proxy.runtime.process_ops import ProcessIdentity, ProcessOps

FIXTURE = Path(__file__).parent / "fixtures" / "graceful_child.py"


def _wait_file(path: Path, timeout_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise AssertionError(f"Timed out waiting for {path}")


@pytest.fixture
def ops() -> ProcessOps:
    return ProcessOps()


@pytest.fixture
def child_paths(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "ready", tmp_path / "graceful"


def _spawn_child(
    ops: ProcessOps,
    ready: Path,
    graceful: Path,
    *,
    ignore_graceful: int = 0,
    hold_seconds: float = 30.0,
    log_path: Path | None = None,
) -> ProcessIdentity:
    argv = [
        sys.executable,
        str(FIXTURE),
        "--ready",
        str(ready),
        "--graceful",
        str(graceful),
        "--ignore-graceful",
        str(ignore_graceful),
        "--hold-seconds",
        str(hold_seconds),
    ]
    identity = ops.spawn_managed(argv, log_path=log_path)
    _wait_file(ready)
    return identity


def test_spawn_and_identity(ops: ProcessOps, child_paths: tuple[Path, Path]) -> None:
    ready, graceful = child_paths
    identity = _spawn_child(ops, ready, graceful)
    try:
        assert ops.is_alive(identity)
        assert ops.identity_matches(identity)
        # Wrong create_time must not match (PID reuse defence).
        fake = ProcessIdentity(pid=identity.pid, create_time=identity.create_time + 99999)
        assert not ops.identity_matches(fake)
    finally:
        ops.request_graceful_shutdown(identity)
        ops.wait(identity, timeout_s=5.0)


def test_graceful_stop_writes_marker(
    ops: ProcessOps, child_paths: tuple[Path, Path]
) -> None:
    ready, graceful = child_paths
    identity = _spawn_child(ops, ready, graceful)
    assert not graceful.exists()
    ops.request_graceful_shutdown(identity)
    exited = ops.wait(identity, timeout_s=5.0)
    assert not ops.is_alive(identity)
    _wait_file(graceful, timeout_s=2.0)
    assert graceful.read_text(encoding="utf-8").strip() == "ok"
    # Exit code may be None when process is not a direct waitable child
    # of this Python across platforms; liveness is the contract.
    del exited


def test_force_kill_after_ignored_graceful(
    ops: ProcessOps, child_paths: tuple[Path, Path]
) -> None:
    ready, graceful = child_paths
    identity = _spawn_child(ops, ready, graceful, ignore_graceful=99)
    ops.request_graceful_shutdown(identity)
    time.sleep(0.3)
    assert ops.is_alive(identity)
    assert not graceful.exists()
    ops.force_kill(identity)
    ops.wait(identity, timeout_s=5.0)
    assert not ops.is_alive(identity)


def test_double_start_exclusion_via_alive(
    ops: ProcessOps, child_paths: tuple[Path, Path], tmp_path: Path
) -> None:
    ready, graceful = child_paths
    first = _spawn_child(ops, ready, graceful)
    try:
        assert ops.is_alive(first)
        # Second independent child is allowed at ProcessOps layer; exclusion
        # is enforced by ProxyRuntimeManager. Just prove two identities differ.
        ready2 = tmp_path / "ready2"
        graceful2 = tmp_path / "graceful2"
        second = _spawn_child(ops, ready2, graceful2)
        try:
            assert first.pid != second.pid
            assert ops.is_alive(second)
        finally:
            ops.request_graceful_shutdown(second)
            ops.wait(second, timeout_s=5.0)
    finally:
        ops.request_graceful_shutdown(first)
        ops.wait(first, timeout_s=5.0)
