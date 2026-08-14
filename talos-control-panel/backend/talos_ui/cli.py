"""
CLI execution layer.

This is the *only* place in the backend that mutates Talos state. Every write
action in the control panel is expressed as a `talos ...` argv list and run
here via subprocess — never as a direct SQL write. This keeps the CLI as the
single source of truth, per the project's architectural rule.

Two execution modes:
  run()              — short-lived command, waits for completion, captures
                        stdout/stderr/exit code. Proxy lifecycle (start/stop/
                        restart/status) uses this path; Talos core owns the
                        managed mitmdump process and runtime state.
  ProcessManager      — optional long-running background processes for Console
                        one-shots that must keep a CLI process alive for live
                        log streaming. Not used for proxy lifecycle.
"""

from __future__ import annotations
import shlex
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import os
import signal
import socket

from . import config

def _talos_env() -> dict[str, str]:
    env = os.environ.copy()

    venv_bin = str(Path(config.TALOS_PYTHON).parent)
    env["PATH"] = venv_bin + os.pathsep + env.get("PATH", "")
    # Child Python must use UTF-8 stdio. Windows locale encoding (cp1252)
    # cannot encode schema arrows or captured target text.
    env["PYTHONIOENCODING"] = "utf-8"

    return env


# Decode Talos CLI pipes as UTF-8 so Windows cp1252 locale does not raise
# UnicodeDecodeError on arrows / box drawing / target Unicode.
_CLI_TEXT = {"text": True, "encoding": "utf-8", "errors": "replace"}

@dataclass
class CommandResult:
    cmd: list[str]
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    ok: bool
    timed_out: bool = False

    def to_dict(self) -> dict:
        return {
            "cmd": self.cmd,
            "cmd_str": " ".join(shlex.quote(c) for c in self.cmd),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "ok": self.ok,
            "timed_out": self.timed_out,
        }


def _talos_argv(args: list[str]) -> list[str]:
    return [
        config.TALOS_PYTHON,
        "-m",
        "talos",
        *args,
    ]

def run(
    args: list[str],
    timeout: Optional[int] = None,
    stdin_text: Optional[str] = None,
) -> CommandResult:
    """Run a single talos CLI invocation and capture its result.

    When ``stdin_text`` is set, it is piped to the process stdin (used for
    commands that read free-form content from stdin, e.g. ``finding note set``).
    """
    argv = _talos_argv(args)
    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=config.TALOS_ROOT,
            env=_talos_env(),
            capture_output=True,
            input=stdin_text,
            timeout=timeout or config.CLI_TIMEOUT,
            **_CLI_TEXT,
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        return CommandResult(
            cmd=argv,
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            duration_ms=duration_ms,
            ok=proc.returncode == 0,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        return CommandResult(
            cmd=argv,
            stdout=(exc.stdout or ""),
            stderr=(exc.stderr or "") + "\n[control panel] command timed out",
            exit_code=-1,
            duration_ms=duration_ms,
            ok=False,
            timed_out=True,
        )
    except FileNotFoundError:
        return CommandResult(
            cmd=argv,
            stdout="",
            stderr=(
                f"[control panel] could not find Python at '{config.TALOS_PYTHON}'. "
                "Run scripts/run-control-panel.sh (Linux/macOS) or "
                "scripts/run-control-panel.ps1 (Windows) to create the Talos "
                "venv, or set TALOS_PYTHON to the interpreter that has talos "
                "installed (python -m talos)."
            ),
            exit_code=-1,
            duration_ms=0,
            ok=False,
        )


def run_sequence(steps: list[list[str]], timeout: Optional[int] = None) -> list[CommandResult]:
    """Run several commands in order, stopping early if one fails."""
    results: list[CommandResult] = []
    for step in steps:
        result = run(step, timeout=timeout)
        results.append(result)
        if not result.ok:
            break
    return results


def run_with_editor_content(
    args: list[str], content: str, timeout: Optional[int] = None
) -> CommandResult:
    """
    Run a command that normally opens $EDITOR for the operator to paste content
    (e.g. `talos auth-config set-session <role>`), without a human at a
    terminal. We point EDITOR/VISUAL at a tiny shim script that ignores its
    argument and simply writes our pre-supplied content into whatever file the
    CLI asked the editor to open. This is a standard technique for driving
    editor-invoking CLIs non-interactively and does not require any special
    support from Talos itself.
    """
    import os
    import stat
    import tempfile

    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="talos-cp-editor-") as tmp:
        content_path = Path(tmp) / "content.txt"
        content_path.write_text(content, encoding="utf-8")

        shim_path = Path(tmp) / "editor-shim.sh"
        shim_path.write_text(
            "#!/bin/sh\n"
            f'cat "{content_path}" > "$1"\n',
            encoding="utf-8",
        )
        shim_path.chmod(shim_path.stat().st_mode | stat.S_IEXEC)

        env = {**os.environ, "EDITOR": str(shim_path), "VISUAL": str(shim_path)}
        argv = _talos_argv(args)
        try:
            proc = subprocess.run(
                argv,
                cwd=config.TALOS_ROOT,
                capture_output=True,
                timeout=timeout or config.CLI_TIMEOUT,
                env={**_talos_env(), **env},
                **_CLI_TEXT,
            )
            duration_ms = int((time.monotonic() - start) * 1000)
            return CommandResult(
                cmd=argv, stdout=proc.stdout, stderr=proc.stderr,
                exit_code=proc.returncode, duration_ms=duration_ms,
                ok=proc.returncode == 0,
            )
        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            return CommandResult(
                cmd=argv, stdout=(exc.stdout or ""),
                stderr=(exc.stderr or "") + "\n[control panel] command timed out",
                exit_code=-1, duration_ms=duration_ms, ok=False, timed_out=True,
            )


def run_scoped(project_id: str, args: list[str], timeout: Optional[int] = None) -> list[CommandResult]:
    """
    Run a project-scoped command, first ensuring that project is the active one.
    Talos's CLI keeps "active project" as persistent state (see `talos project
    open <id>`), so every scoped action opens the right project immediately
    beforehand. Both steps are returned so the UI can show exactly what ran.
    """
    return run_sequence([["project", "open", project_id], args], timeout=timeout)


def run_scoped_with_stdin(
    project_id: str,
    args: list[str],
    stdin_text: str,
    timeout: Optional[int] = None,
) -> list[CommandResult]:
    """
    Project-scoped command that feeds ``stdin_text`` to the CLI process
    (e.g. ``finding note set <uuid>``).
    """
    open_result = run(["project", "open", project_id], timeout=timeout)
    if not open_result.ok:
        return [open_result]
    return [open_result, run(args, timeout=timeout, stdin_text=stdin_text)]


def run_scoped_with_editor_content(
    project_id: str, args: list[str], content: str, timeout: Optional[int] = None
) -> list[CommandResult]:
    open_result = run(["project", "open", project_id], timeout=timeout)
    if not open_result.ok:
        return [open_result]
    return [open_result, run_with_editor_content(args, content, timeout=timeout)]


def run_scoped_with_temp_file(
    project_id: str,
    args_before_file: list[str],
    content: str,
    suffix: str = ".py",
    timeout: Optional[int] = None,
) -> list[CommandResult]:
    """
    For commands that take a literal filename argument (e.g.
    `talos auth-config set-extractor <role> <flow_id> extractor.py`), write
    the operator-supplied content to a temp file and pass its path.
    """
    import tempfile

    open_result = run(["project", "open", project_id], timeout=timeout)
    if not open_result.ok:
        return [open_result]
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, prefix="talos-cp-", delete=False, encoding="utf-8"
    ) as fh:
        fh.write(content)
        tmp_path = fh.name
    try:
        result = run([*args_before_file, tmp_path], timeout=timeout)
    finally:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except OSError:
            pass
    return [open_result, result]


# ------------------------------------------------------------------ #
# Background processes (proxy, ui)                                    #
# ------------------------------------------------------------------ #

@dataclass
class ManagedProcess:
    name: str
    argv: list[str]
    proc: subprocess.Popen
    started_at: float
    log: deque = field(default_factory=lambda: deque(maxlen=2000))
    _thread: Optional[threading.Thread] = None

    def _pump(self):
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.log.append(line.rstrip("\n"))

    def start_pump(self):
        self._thread = threading.Thread(target=self._pump, daemon=True)
        self._thread.start()

    def is_running(self) -> bool:
        return self.proc.poll() is None

    def status(self) -> dict:
        return {
            "name": self.name,
            "argv": self.argv,
            "cmd_str": " ".join(shlex.quote(c) for c in self.argv),
            "running": self.is_running(),
            "pid": self.proc.pid,
            "started_at": self.started_at,
            "exit_code": self.proc.poll(),
        }


def wait_for_port_release(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> bool:
    """
    Wait until a TCP listen port can be bound again.

    Used after terminating the proxy process tree to make sure mitmdump has
    actually released the listener before a new proxy process is started.
    """
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            sock.bind((host, port))
            return True
        except OSError:
            time.sleep(0.1)
        finally:
            sock.close()

    return False

def wait_for_port_listener(
    host: str,
    port: int,
    timeout: float = 10.0,
) -> bool:
    """
    Wait until a TCP listener accepts connections on host:port.

    Used after starting the Talos proxy to verify that mitmdump actually
    started and successfully bound the configured listener.
    """
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)

    return False


class ProcessManager:
    """In-memory registry of long-running Talos processes."""

    def __init__(self):
        self._procs: dict[str, ManagedProcess] = {}
        self._lock = threading.RLock()
        self._lifecycle_locks: dict[str, threading.Lock] = {}

    def _get_lifecycle_lock(self, name: str) -> threading.Lock:
        with self._lock:
            return self._lifecycle_locks.setdefault(
                name,
                threading.Lock(),
            )

    def _kill_process_tree(
        self,
        managed: ManagedProcess,
        force: bool = False,
    ) -> None:
        proc = managed.proc

        if proc.poll() is not None:
            return

        if os.name == "nt":
            subprocess.run(
                [
                    "taskkill",
                    "/PID",
                    str(proc.pid),
                    "/T",
                    "/F",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return

        try:
            pgid = os.getpgid(proc.pid)
            sig = signal.SIGKILL if force else signal.SIGTERM
            os.killpg(pgid, sig)
        except ProcessLookupError:
            pass
        except (PermissionError, OSError):
            try:
                if force:
                    proc.kill()
                else:
                    proc.terminate()
            except ProcessLookupError:
                pass

    def _start_unlocked(
        self,
        name: str,
        args: list[str],
    ) -> dict:
        existing = self._procs.get(name)

        if existing and existing.is_running():
            return {
                "already_running": True,
                **existing.status(),
            }

        argv = _talos_argv(args)

        popen_kwargs = {
            "cwd": config.TALOS_ROOT,
            "env": _talos_env(),
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "bufsize": 1,
            **_CLI_TEXT,
        }

        if os.name == "nt":
            popen_kwargs["creationflags"] = (
                subprocess.CREATE_NEW_PROCESS_GROUP
            )
        else:
            popen_kwargs["start_new_session"] = True

        try:
            proc = subprocess.Popen(
                argv,
                **popen_kwargs,
            )
        except FileNotFoundError:
            return {
                "already_running": False,
                "running": False,
                "error": (
                    f"could not find Talos Python executable "
                    f"'{config.TALOS_PYTHON}'"
                ),
            }

        managed = ManagedProcess(
            name=name,
            argv=argv,
            proc=proc,
            started_at=time.time(),
        )

        managed.start_pump()
        self._procs[name] = managed

        return {
            "already_running": False,
            **managed.status(),
        }

    def _stop_unlocked(
        self,
        name: str,
        force: bool = False,
    ) -> dict:
        managed = self._procs.get(name)

        if not managed:
            return {
                "was_running": False,
                "running": False,
            }

        was_running = managed.is_running()

        if was_running:
            self._kill_process_tree(
                managed,
                force=force,
            )

            try:
                managed.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._kill_process_tree(
                    managed,
                    force=True,
                )

                try:
                    managed.proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass

        return {
            "was_running": was_running,
            **managed.status(),
        }

    def start(
        self,
        name: str,
        args: list[str],
    ) -> dict:
        lifecycle_lock = self._get_lifecycle_lock(name)

        with lifecycle_lock:
            with self._lock:
                return self._start_unlocked(
                    name,
                    args,
                )

    def stop(
        self,
        name: str,
        force: bool = False,
    ) -> dict:
        lifecycle_lock = self._get_lifecycle_lock(name)

        with lifecycle_lock:
            with self._lock:
                return self._stop_unlocked(
                    name,
                    force=force,
                )

    def restart(
        self,
        name: str,
        args: list[str],
        host: str,
        port: int,
        force: bool = False,
    ) -> dict:
        lifecycle_lock = self._get_lifecycle_lock(name)

        with lifecycle_lock:
            with self._lock:
                stop_result = self._stop_unlocked(
                    name,
                    force=force,
                )

            if not wait_for_port_release(
                host,
                port,
                timeout=5.0,
            ):
                return {
                    "restarted": False,
                    "running": False,
                    "error": (
                        f"port {host}:{port} is still in use "
                        f"after stopping the managed proxy"
                    ),
                    "stop_result": stop_result,
                }

            with self._lock:
                started = self._start_unlocked(
                    name,
                    args,
                )

            if started.get("error"):
                return {
                    "restarted": False,
                    "running": False,
                    "error": started["error"],
                    "start_result": started,
                }

            deadline = time.monotonic() + 5.0

            while time.monotonic() < deadline:
                current = self.status(name)

                if not current or not current.get("running"):
                    return {
                        "restarted": False,
                        "running": False,
                        "error": (
                            "proxy process exited during startup"
                        ),
                        "start_result": started,
                        "logs": self.logs(
                            name,
                            tail=50,
                        ),
                    }

                if wait_for_port_listener(
                    host,
                    port,
                    timeout=0.25,
                ):
                    return {
                        "restarted": True,
                        **current,
                    }

                time.sleep(0.1)

            current = self.status(name)

            return {
                "restarted": False,
                "running": bool(
                    current and current.get("running")
                ),
                "error": (
                    f"proxy process started but no listener "
                    f"appeared on {host}:{port}"
                ),
                "start_result": started,
                "logs": self.logs(
                    name,
                    tail=50,
                ),
            }

    def status(
        self,
        name: str,
    ) -> Optional[dict]:
        with self._lock:
            managed = self._procs.get(name)

            return (
                managed.status()
                if managed
                else None
            )

    def logs(
        self,
        name: str,
        tail: int = 300,
    ) -> list[str]:
        with self._lock:
            managed = self._procs.get(name)

            if not managed:
                return []

            return list(managed.log)[-tail:]

process_manager = ProcessManager()
