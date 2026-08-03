"""
Module: talos.proxy.runtime.process_ops

Purpose:
    Platform-specific process control for managed Talos children
    (mitmdump, scheduler). Callers use semantic methods only:

        spawn_managed / request_graceful_shutdown / force_kill /
        wait / is_alive / identity_matches

    Managers never import SIGTERM, CTRL_BREAK_EVENT, or TerminateProcess.

Platform contracts:
    POSIX:
        spawn: start_new_session=True
        graceful: SIGTERM
        force: SIGKILL
        identity: /proc/<pid>/stat starttime (clock ticks)

    Windows:
        spawn: CREATE_NEW_PROCESS_GROUP (required for CTRL_BREAK)
        graceful: CTRL_BREAK_EVENT  (NOT Popen.terminate)
        force: TerminateProcess via Popen.kill
        identity: GetProcessTimes creation FILETIME

Dependencies: os, signal, subprocess, sys, time, dataclasses, pathlib
Data flow:
    ProxyRuntimeManager / SchedulerRuntimeManager → ProcessOps → OS
Side effects:
    Spawns processes; opens log files; sends signals; may kill processes.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcessIdentity:
    """
    Purpose:
        Durable process identity that survives PID reuse.
    Fields:
        pid         — OS process id.
        create_time — platform-normalized creation stamp (comparable equality).
    """

    pid: int
    create_time: float


class ProcessOps:
    """
    Purpose:
        Semantic process control for managed Talos children.
        One implementation class with platform branches inside methods.
    """

    def spawn_managed(
        self,
        argv: list[str],
        *,
        env: Optional[dict[str, str]] = None,
        log_path: Optional[Path] = None,
        cwd: Optional[Path] = None,
    ) -> ProcessIdentity:
        """
        Purpose:
            Start a long-lived child process and return its identity.
        Input:
            argv     — full argv including executable as argv[0].
            env      — environment mapping (None → inherit with copy).
            log_path — if set, redirect stdout/stderr to this file (append).
            cwd      — optional working directory.
        Output:
            ProcessIdentity for the new child.
        Side effects:
            Spawns a process; may create/append log_path.
        """
        child_env = os.environ.copy() if env is None else dict(env)

        # log_path set  → append child output to file (background daemon).
        # log_path None → inherit parent stdio (foreground) so operator sees
        # mitmdump output; stdin still closed to avoid accidental grabs.
        log_handle = None
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_handle = open(log_path, "ab", buffering=0)  # noqa: SIM115
            stdout_target = log_handle
            stderr_target = log_handle
        else:
            stdout_target = None
            stderr_target = None

        popen_kwargs: dict = {
            "args": argv,
            "env": child_env,
            "stdout": stdout_target,
            "stderr": stderr_target,
            "stdin": subprocess.DEVNULL,
        }
        if cwd is not None:
            popen_kwargs["cwd"] = str(cwd)

        if sys.platform == "win32":
            # CREATE_NEW_PROCESS_GROUP enables CTRL_BREAK_EVENT delivery.
            # Do not combine with DETACHED_PROCESS — that can strip console
            # attachment and break graceful control-event delivery.
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            # New session so SIGTERM can target the process group cleanly.
            popen_kwargs["start_new_session"] = True

        try:
            proc = subprocess.Popen(**popen_kwargs)
        except Exception:
            if log_handle is not None:
                log_handle.close()
            raise

        # Parent keeps the log handle open for the child's lifetime only if
        # we retained a reference; on POSIX the child inherits the fd and we
        # can close our copy. Closing is safe: child still has the fd.
        if log_handle is not None:
            log_handle.close()

        # Brief settle so /proc or Win32 handles exist before identity read.
        time.sleep(0.05)
        create_time = self._read_create_time(proc.pid)
        if create_time is None:
            # Process may have exited immediately; still record best-effort.
            create_time = 0.0
            logger.warning(
                "Could not read create_time for pid=%s immediately after spawn",
                proc.pid,
            )

        identity = ProcessIdentity(pid=proc.pid, create_time=create_time)
        logger.info(
            "Spawned managed process pid=%s create_time=%s argv0=%s",
            identity.pid,
            identity.create_time,
            argv[0] if argv else "?",
        )
        # Retain no Popen reference — lifecycle uses pid + signals only so
        # managers survive across CLI process boundaries.
        return identity

    def request_graceful_shutdown(self, identity: ProcessIdentity) -> None:
        """
        Purpose:
            Ask the child to shut down cleanly so addon done()/drain can run.
        Input:
            identity — process to signal.
        Side effects:
            Sends SIGTERM (POSIX) or CTRL_BREAK_EVENT (Windows).
        """
        if not self.is_alive(identity):
            return

        if sys.platform == "win32":
            self._windows_ctrl_break(identity.pid)
            logger.info("Requested graceful shutdown (CTRL_BREAK) pid=%s", identity.pid)
            return

        try:
            os.kill(identity.pid, signal.SIGTERM)
            logger.info("Requested graceful shutdown (SIGTERM) pid=%s", identity.pid)
        except ProcessLookupError:
            pass
        except PermissionError:
            logger.warning("Permission denied sending SIGTERM to pid=%s", identity.pid)

    def force_kill(self, identity: ProcessIdentity) -> None:
        """
        Purpose:
            Forcefully terminate a child that ignored graceful shutdown.
            Escalation only — never the first stop mechanism.
        Input:
            identity — process to kill.
        Side effects:
            SIGKILL (POSIX) or TerminateProcess (Windows).
        """
        if not self.is_alive(identity):
            return
        self.force_kill_pid(identity.pid)

    def force_kill_pid(self, pid: int) -> None:
        """
        Purpose:
            Force-kill by PID without create_time validation.
            Used for orphan mitmdump / port reclamation.
        """
        if pid <= 0:
            return
        if sys.platform == "win32":
            self._windows_terminate(pid)
            logger.warning("Force-killed process (TerminateProcess) pid=%s", pid)
            return
        try:
            os.kill(pid, signal.SIGKILL)
            logger.warning("Force-killed process (SIGKILL) pid=%s", pid)
        except ProcessLookupError:
            pass
        except PermissionError:
            logger.warning("Permission denied sending SIGKILL to pid=%s", pid)

    def request_graceful_shutdown_pid(self, pid: int) -> None:
        """Graceful stop by PID without create_time validation (orphans)."""
        if pid <= 0:
            return
        if sys.platform == "win32":
            self._windows_ctrl_break(pid)
            logger.info("Requested graceful shutdown (CTRL_BREAK) pid=%s", pid)
            return
        try:
            os.kill(pid, signal.SIGTERM)
            logger.info("Requested graceful shutdown (SIGTERM) pid=%s", pid)
        except ProcessLookupError:
            pass
        except PermissionError:
            logger.warning("Permission denied sending SIGTERM to pid=%s", pid)

    def wait(
        self,
        identity: ProcessIdentity,
        timeout_s: Optional[float] = None,
    ) -> Optional[int]:
        """
        Purpose:
            Wait until the process exits or timeout elapses.
        Input:
            identity  — process to wait for.
            timeout_s — seconds to wait; None waits indefinitely.
        Output:
            Exit code if known and process has exited; None if still alive
            after timeout or exit code unavailable.
        Side effects: None (polls OS).
        """
        deadline = None if timeout_s is None else time.monotonic() + timeout_s
        while True:
            if not self.is_alive(identity):
                return self._try_exit_code(identity.pid)
            if deadline is not None and time.monotonic() >= deadline:
                return None
            time.sleep(0.1)

    def is_alive(self, identity: ProcessIdentity) -> bool:
        """
        Purpose:
            True only if a process with this pid exists AND create_time matches.
        Input:
            identity — recorded identity.
        Output:
            bool.
        Side effects: None.
        """
        return self.identity_matches(identity)

    def identity_matches(self, recorded: ProcessIdentity) -> bool:
        """
        Purpose:
            Validate that recorded.pid still refers to the same process
            instance (create_time match). Defends against PID reuse.
        Input:
            recorded — identity from spawn / runtime state.
        Output:
            True if the process is alive and create_time matches.
        Side effects: None.
        """
        if recorded.pid <= 0:
            return False
        current = self._read_create_time(recorded.pid)
        if current is None:
            return False
        # Allow tiny float noise; create_time values are coarse OS units.
        return abs(current - recorded.create_time) < 0.5

    def read_identity(self, pid: int) -> Optional[ProcessIdentity]:
        """
        Purpose:
            Build identity for an existing pid, or None if not running.
        """
        create_time = self._read_create_time(pid)
        if create_time is None:
            return None
        return ProcessIdentity(pid=pid, create_time=create_time)

    # ------------------------------------------------------------------ #
    # Platform helpers                                                     #
    # ------------------------------------------------------------------ #

    def _read_create_time(self, pid: int) -> Optional[float]:
        if sys.platform == "win32":
            return self._windows_create_time(pid)
        return self._posix_create_time(pid)

    def _posix_create_time(self, pid: int) -> Optional[float]:
        """
        Read starttime (field 22) from /proc/<pid>/stat as float clock ticks.
        Returns None if the process does not exist or is a zombie (already dead).
        """
        # Reap our own children so zombies do not linger as "alive".
        try:
            os.waitpid(pid, os.WNOHANG)
        except (ChildProcessError, OSError):
            pass

        try:
            with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as handle:
                data = handle.read()
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            return None
        # comm may contain spaces/parentheses; find closing paren of comm.
        close = data.rfind(")")
        if close < 0:
            return None
        rest = data[close + 2 :].split()
        # After comm: state(0) … starttime is index 19 in the remaining fields
        # (man proc: field 22 overall = starttime; fields 1-2 are pid+comm).
        try:
            state = rest[0]
            if state == "Z":
                # Zombie — process has exited; treat as not alive.
                return None
            starttime = float(rest[19])
        except (IndexError, ValueError):
            return None
        return starttime

    def _try_exit_code(self, pid: int) -> Optional[int]:
        """
        Best-effort exit status for a reaped/exited process.

        POSIX: non-blocking waitpid on our own children (WNOHANG).
        Windows: WNOHANG / WIF* are not available; we do not retain a Popen
        handle across CLI invocations, so exit codes are usually unavailable.
        Callers treat None as "unknown" and rely on is_alive for liveness.
        """
        if sys.platform == "win32":
            return self._windows_exit_code(pid)
        try:
            finished_pid, status = os.waitpid(pid, os.WNOHANG)
            if finished_pid == 0:
                return None
            if os.WIFEXITED(status):
                return os.WEXITSTATUS(status)
            if os.WIFSIGNALED(status):
                return -os.WTERMSIG(status)
        except (ChildProcessError, OSError):
            pass
        return None

    def _windows_exit_code(self, pid: int) -> Optional[int]:
        """
        Query exit code via GetExitCodeProcess when the process handle is
        still openable. Returns None if still running, already reaped, or
        inaccessible (common once the process has fully exited).
        """
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            PROCESS_QUERY_INFORMATION = 0x0400
            handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            return None
        try:
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return None
            if code.value == STILL_ACTIVE:
                return None
            return int(code.value)
        finally:
            kernel32.CloseHandle(handle)

    def _windows_ctrl_break(self, pid: int) -> None:
        """Send CTRL_BREAK_EVENT to the process group identified by pid."""
        import ctypes

        # CTRL_BREAK_EVENT = 1
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        # Process group id equals the pid of the group leader when spawned
        # with CREATE_NEW_PROCESS_GROUP.
        if kernel32.GenerateConsoleCtrlEvent(1, pid) == 0:
            err = ctypes.get_last_error()
            logger.warning(
                "GenerateConsoleCtrlEvent(CTRL_BREAK) failed for pid=%s last_error=%s",
                pid,
                err,
            )

    def _windows_terminate(self, pid: int) -> None:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        PROCESS_TERMINATE = 0x0001
        handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if not handle:
            return
        try:
            kernel32.TerminateProcess(handle, 1)
        finally:
            kernel32.CloseHandle(handle)

    def _windows_create_time(self, pid: int) -> Optional[float]:
        """Return process creation time as float FILETIME (100ns units)."""
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            # Fallback older mask.
            PROCESS_QUERY_INFORMATION = 0x0400
            handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            return None

        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", wintypes.DWORD),
                        ("dwHighDateTime", wintypes.DWORD)]

        creation = FILETIME()
        exit_t = FILETIME()
        kernel_t = FILETIME()
        user_t = FILETIME()
        try:
            ok = kernel32.GetProcessTimes(
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_t),
                ctypes.byref(kernel_t),
                ctypes.byref(user_t),
            )
            if not ok:
                return None
            # Combine to 64-bit integer then float for comparison.
            value = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
            return float(value)
        finally:
            kernel32.CloseHandle(handle)
