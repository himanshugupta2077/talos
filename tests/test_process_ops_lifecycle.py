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


def test_wait_after_exit_does_not_raise_on_platform_apis(
    ops: ProcessOps, child_paths: tuple[Path, Path]
) -> None:
    """
    Regression: wait() must not call POSIX-only os.WNOHANG on Windows.

    Proxy start failure paths call request_graceful_shutdown + wait; on
    Windows that used to crash with AttributeError: os has no attribute WNOHANG.
    """
    ready, graceful = child_paths
    identity = _spawn_child(ops, ready, graceful, hold_seconds=2.0)
    ops.request_graceful_shutdown(identity)
    # Must return (exit code or None) without raising on any platform.
    exit_code = ops.wait(identity, timeout_s=5.0)
    assert not ops.is_alive(identity)
    assert exit_code is None or isinstance(exit_code, int)
    # Calling _try_exit_code again on a dead pid must also be safe.
    again = ops._try_exit_code(identity.pid)
    assert again is None or isinstance(again, int)


def test_try_exit_code_win32_branch_avoids_posix_waitpid(
    ops: ProcessOps, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Force the win32 branch even on Linux CI so a regression reintroducing
    os.WNOHANG in _try_exit_code is caught without a Windows runner.
    """
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(ops, "_windows_exit_code", lambda pid: 0 if pid == 42 else None)

    def _forbid_waitpid(*_a, **_k):  # type: ignore[no-untyped-def]
        raise AssertionError("os.waitpid must not be called on win32")

    monkeypatch.setattr("os.waitpid", _forbid_waitpid)
    assert ops._try_exit_code(42) == 0
    assert ops._try_exit_code(99) is None


def test_try_exit_code_never_raises_without_wnohang(
    ops: ProcessOps, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Regression: AttributeError: module 'os' has no attribute 'WNOHANG'.

    Even if platform detection is wrong or WNOHANG is missing, wait/exit-code
    probing must return None — not crash proxy start cleanup.
    """
    import os as os_mod

    # Simulate a Windows-like environment where WNOHANG does not exist.
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delattr(os_mod, "WNOHANG", raising=False)
    monkeypatch.setattr(ops, "_windows_exit_code", lambda pid: None)
    assert ops._try_exit_code(1) is None

    # POSIX path without WNOHANG must also be safe (stripped / exotic builds).
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delattr(os_mod, "WNOHANG", raising=False)
    assert ops._try_exit_code(1) is None


def test_wait_on_win32_platform_never_calls_waitpid(
    ops: ProcessOps, child_paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Full wait() path with platform forced to win32 (Linux CI).

    Mirrors proxy start readiness-timeout cleanup:
    request_graceful_shutdown → wait → _try_exit_code.
    """
    ready, graceful = child_paths
    identity = _spawn_child(ops, ready, graceful, hold_seconds=2.0)

    def _forbid_waitpid(*_a, **_k):  # type: ignore[no-untyped-def]
        raise AssertionError("os.waitpid must not be called when platform is win32")

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr("os.waitpid", _forbid_waitpid)
    monkeypatch.setattr(ops, "_windows_exit_code", lambda pid: None)
    monkeypatch.setattr(ops, "_windows_ctrl_break", lambda pid: None)
    monkeypatch.setattr(ops, "_windows_terminate", lambda pid: None)
    # Pretend process already exited so wait() probes exit code immediately.
    monkeypatch.setattr(ops, "_read_create_time", lambda pid: None)

    ops.request_graceful_shutdown(identity)
    exit_code = ops.wait(identity, timeout_s=2.0)
    assert exit_code is None
    # Reap the real child so the suite does not leak processes.
    monkeypatch.undo()
    if ops.is_alive(identity):
        ops.force_kill(identity)
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
