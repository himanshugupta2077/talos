"""
Module: talos.ui.proxy_manager

Purpose:
    Singleton process manager for the Talos capture proxy.
    Spawns mitmdump as an async subprocess attached to the currently active
    project, captures stdout and stderr as a merged stream, and broadcasts
    each log line to registered SSE subscriber queues.

    Attach one instance to app.state.proxy_manager at startup.

Dependencies: asyncio, logging, collections, pathlib, talos.projects.manager
Data flow:
    start()
        → ProjectManager.active() → validate project
        → asyncio.create_subprocess_exec(mitmdump …)
        → _read_output() task loops readline()
            → append to _log_buffer
            → _log() broadcasts to all _subscribers
    stop()
        → process.terminate() → await wait()
        → cancel _reader_task
        → _broadcast_status("stopped")

Side effects:
    - Spawns a mitmdump child process on start().
    - Terminates the child process on stop().
    - Maintains up to _LOG_BUFFER_SIZE recent log lines in memory.
    - Holds an asyncio.Task for the duration the process is running.
"""

import asyncio
import logging
from collections import deque
from pathlib import Path
from typing import Optional

from talos.projects.manager import ProjectManager

logger = logging.getLogger(__name__)

# Rolling window of retained log lines (per-manager lifetime, not per-run).
_LOG_BUFFER_SIZE: int = 500

# Max items queued per subscriber before lines are silently dropped.
# Prevents a slow SSE consumer from accumulating unbounded memory.
_SUBSCRIBER_QUEUE_MAX: int = 200

# Path to the mitmproxy capture addon, resolved relative to this file.
_ADDON_PATH: Path = Path(__file__).parent.parent / "proxy" / "addon.py"


class ProxyManager:
    """
    Purpose:
        Manage the lifecycle of a single mitmdump subprocess.
        Provides start/stop control, a rolling log buffer, and a
        pub/sub mechanism so SSE streams receive log lines in real time.

    Attributes:
        _projects_root — Path to the Talos projects directory.
        _process       — Running asyncio subprocess, or None.
        _reader_task   — asyncio.Task reading process output, or None.
        _subscribers   — List of per-SSE-client asyncio.Queue instances.
        _log_buffer    — Rolling deque of the last _LOG_BUFFER_SIZE lines.
        _status        — "running" or "stopped".
        _pid           — OS PID of the running process, or None.
    """

    def __init__(self, projects_root: Path) -> None:
        self._projects_root: Path = projects_root
        self._process: Optional[asyncio.subprocess.Process] = None
        self._reader_task: Optional[asyncio.Task] = None
        self._subscribers: list[asyncio.Queue] = []
        self._log_buffer: deque[str] = deque(maxlen=_LOG_BUFFER_SIZE)
        self._status: str = "stopped"
        self._pid: Optional[int] = None

    # ------------------------------------------------------------------ #
    # Public properties                                                    #
    # ------------------------------------------------------------------ #

    @property
    def status(self) -> str:
        """
        Purpose:
            Return "running" or "stopped", polling process returncode so the
            state stays accurate even if the process exits without an explicit
            stop() call (e.g. mitmdump crash).
        Side effects: May clear internal process references if process is dead.
        """
        if self._process is not None and self._process.returncode is not None:
            # Process already exited; reconcile internal state without blocking.
            self._status = "stopped"
            self._pid = None
            self._process = None
        return self._status

    @property
    def pid(self) -> Optional[int]:
        """Return the OS PID of the running proxy process, or None."""
        return self._pid if self.status == "running" else None

    @property
    def log_buffer(self) -> list[str]:
        """Return a snapshot of recent log lines, oldest first."""
        return list(self._log_buffer)

    # ------------------------------------------------------------------ #
    # Lifecycle control                                                    #
    # ------------------------------------------------------------------ #

    async def start(self, port: int = 8080, listen_host: str = "127.0.0.1") -> dict:
        """
        Purpose:
            Start the mitmdump proxy subprocess for the active project.
        Input:
            port        — Port mitmdump should listen on.
            listen_host — Interface address to bind.
        Output:
            {"ok": bool, "detail": str}
        Side effects:
            Spawns mitmdump subprocess; starts log reader task.
            Broadcasts status "running" and a startup log line to subscribers.
        """
        if self.status == "running":
            return {"ok": False, "detail": "Proxy is already running."}

        project = ProjectManager(self._projects_root).active()
        if project is None:
            return {"ok": False, "detail": "No active project. Open a project first."}

        cmd = [
            "mitmdump",
            "--listen-host", listen_host,
            "--listen-port", str(port),
            # Skip upstream TLS verification — required for pentest interception.
            "--ssl-insecure",
            "-s", str(_ADDON_PATH),
        ]

        try:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                # Merge stderr into stdout so a single reader captures everything.
                stderr=asyncio.subprocess.STDOUT,
            )
        except FileNotFoundError:
            return {"ok": False, "detail": "mitmdump not found. Is mitmproxy installed?"}
        except OSError as exc:
            logger.error("proxy_manager: failed to start mitmdump: %s", exc)
            return {"ok": False, "detail": str(exc)}

        self._status = "running"
        self._pid = self._process.pid
        self._reader_task = asyncio.create_task(self._read_output())
        self._broadcast_status()
        self._append_log(
            f"[talos] proxy started  pid={self._pid}  {listen_host}:{port}  project={project.id}"
        )
        return {"ok": True, "detail": f"Proxy started (pid={self._pid})"}

    async def stop(self) -> dict:
        """
        Purpose:
            Terminate the running proxy subprocess gracefully, then forcibly.
        Output:
            {"ok": bool, "detail": str}
        Side effects:
            Sends SIGTERM; if process does not exit within 5 s, sends SIGKILL.
            Cancels and awaits the log reader task.
            Broadcasts status "stopped" and a stop log line to subscribers.
        """
        if self.status != "running" or self._process is None:
            return {"ok": False, "detail": "Proxy is not running."}

        try:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
        except Exception as exc:
            logger.warning("proxy_manager: error during stop: %s", exc)

        if self._reader_task is not None:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None

        self._status = "stopped"
        self._pid = None
        self._process = None
        self._broadcast_status()
        self._append_log("[talos] proxy stopped")
        return {"ok": True, "detail": "Proxy stopped."}

    async def cleanup(self) -> None:
        """
        Purpose:
            Stop the proxy if running; used by the app lifespan shutdown hook.
        Side effects:
            Calls stop() if status is "running".
        """
        if self.status == "running":
            await self.stop()

    # ------------------------------------------------------------------ #
    # SSE subscription                                                     #
    # ------------------------------------------------------------------ #

    def subscribe(self) -> asyncio.Queue:
        """
        Purpose:
            Register a new SSE client.  Returns a queue pre-seeded with
            recent log history and current status so the client renders
            correct state immediately on connect.
        Output:
            asyncio.Queue[tuple[str, str]] — items are ("log", line) or
            ("status", status_str).
        Side effects:
            Adds the new queue to _subscribers.
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=_SUBSCRIBER_QUEUE_MAX)

        # Replay buffered history so new clients see context.
        for line in self._log_buffer:
            try:
                q.put_nowait(("log", line))
            except asyncio.QueueFull:
                break

        # Current status delivered after history so the client state is final.
        try:
            q.put_nowait(("status", self.status))
        except asyncio.QueueFull:
            pass

        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """
        Purpose:
            Remove an SSE subscriber queue.
        Side effects:
            Removes queue from _subscribers; no-op if already removed.
        """
        try:
            self._subscribers.remove(q)
        except ValueError:
            pass

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    async def _read_output(self) -> None:
        """
        Purpose:
            Async task that reads the merged stdout/stderr stream line-by-line
            until the process exits or the task is cancelled.
        Side effects:
            Calls _append_log() for each line received.
            Updates _status to "stopped" and broadcasts when the process exits.
        """
        assert self._process is not None and self._process.stdout is not None
        try:
            async for raw in self._process.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if line:
                    self._append_log(line)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("proxy_manager: stdout reader error: %s", exc)
        finally:
            # Process has exited naturally; reconcile state if stop() hasn't run yet.
            if self._status == "running":
                self._status = "stopped"
                self._pid = None
                self._broadcast_status()
                self._append_log("[talos] proxy process exited")

    def _append_log(self, line: str) -> None:
        """
        Purpose:
            Append a line to the rolling buffer and push it to all subscribers.
        Side effects:
            Modifies _log_buffer.
            Calls put_nowait() on each subscriber queue; drops line silently for
            any queue that is full (prevents blocking on a slow consumer).
        """
        self._log_buffer.append(line)
        for q in list(self._subscribers):
            try:
                q.put_nowait(("log", line))
            except asyncio.QueueFull:
                pass

    def _broadcast_status(self) -> None:
        """
        Purpose:
            Push the current status string to all subscriber queues.
        Side effects:
            Calls put_nowait() on each subscriber queue.
        """
        for q in list(self._subscribers):
            try:
                q.put_nowait(("status", self._status))
            except asyncio.QueueFull:
                pass
