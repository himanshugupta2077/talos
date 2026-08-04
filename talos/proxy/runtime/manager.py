"""
Module: talos.proxy.runtime.manager

Purpose:
    ProxyRuntimeManager — sole owner of mitmdump lifecycle for Talos.

    Responsibilities:
        start / stop / restart / status
        runtime validation (PID + create_time)
        exclusive lifecycle locking
        graceful drain coordination via ProcessOps

    Generation-based reconcile and auto-restart hooks land in a later phase;
    reconcile() currently applies project-identity / stop-when-no-project rules
    for running processes using last start params.

Dependencies:
    talos.proxy.runtime.{lock,state,process_ops},
    talos.proxy.launcher, talos.projects.model, talos.projects.access
Data flow:
    CLI → ProxyRuntimeManager → ProcessOps → mitmdump
    status → try-lock or atomic snapshot
Side effects:
    Spawns/signals mitmdump; writes proxy.json; holds proxy.lock on mutations.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from talos.projects.access import get_active_module_id, get_active_role_id
from talos.projects.db import seed_default_context
from talos.projects.model import Project
from talos.proxy.launcher import build_mitmdump_command
from talos.proxy.runtime.lock import RuntimeLock
from talos.proxy.runtime.port_ops import (
    describe_listeners,
    find_listening_pids,
    is_port_free,
    is_port_listening,
    looks_like_mitmdump,
)
from talos.proxy.runtime.process_ops import ProcessIdentity, ProcessOps
from talos.proxy.runtime.state import (
    ProxyRuntimeState,
    ProxyState,
    load_state,
    proxy_lock_path,
    proxy_log_path,
    save_state,
    utc_now_iso,
)

logger = logging.getLogger(__name__)

# Default settle / drain timeouts.
_START_SETTLE_S: float = 0.4
# Linux is typically ready in ~1–2s. Windows (esp. VDI + AV) can take longer
# for mitmdump to import the addon and bind the listen port.
_START_READY_TIMEOUT_S: float = 20.0 if sys.platform == "win32" else 5.0
_DEFAULT_STOP_TIMEOUT_S: float = 30.0
_STATUS_LOCK_TIMEOUT_S: float = 0.2
_FORCE_KILL_WAIT_S: float = 5.0
_ORPHAN_GRACE_S: float = 2.0

# Addon path relative to this package's parent (talos/proxy/addon.py).
_ADDON_PATH = Path(__file__).resolve().parent.parent / "addon.py"


@dataclass(frozen=True)
class ProxyRuntimeInfo:
    """
    Purpose:
        Immutable public status snapshot returned by manager methods.
    """

    state: ProxyState
    pid: Optional[int]
    create_time: Optional[float]
    project_id: Optional[str]
    role_id: Optional[str]
    module_id: Optional[str]
    listen_host: Optional[str]
    listen_port: Optional[int]
    upstream_url: Optional[str]
    startup_time: Optional[str]
    applied_project_id: Optional[str]
    applied_generation: Optional[int]
    restart_pending: bool
    runtime_version: int
    last_error: Optional[str]
    validation_deferred: bool = False
    transitional: bool = False
    log_path: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "state": self.state.value,
            "pid": self.pid,
            "create_time": self.create_time,
            "project_id": self.project_id,
            "role_id": self.role_id,
            "module_id": self.module_id,
            "listen_host": self.listen_host,
            "listen_port": self.listen_port,
            "upstream_url": self.upstream_url,
            "startup_time": self.startup_time,
            "applied_project_id": self.applied_project_id,
            "applied_generation": self.applied_generation,
            "restart_pending": self.restart_pending,
            "runtime_version": self.runtime_version,
            "last_error": self.last_error,
            "validation_deferred": self.validation_deferred,
            "transitional": self.transitional,
            "log_path": self.log_path,
        }


class ProxyAlreadyRunning(Exception):
    """Raised when start is refused because a validated proxy is RUNNING."""


class ProxyStartError(Exception):
    """Raised when the child exits or cannot be started."""


class ProxyRuntimeManager:
    """
    Purpose:
        Own the managed mitmdump process end-to-end.
    """

    def __init__(
        self,
        data_dir: Path,
        process_ops: Optional[ProcessOps] = None,
    ) -> None:
        self._data_dir = Path(data_dir)
        self._ops = process_ops or ProcessOps()

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def start(
        self,
        *,
        project: Project,
        listen_host: str = "127.0.0.1",
        port: int = 8080,
        upstream_url: Optional[str] = None,
        quiet: bool = False,
        foreground: bool = False,
        spawn_generation: int = 0,
    ) -> ProxyRuntimeInfo:
        """
        Purpose:
            Start mitmdump for the given project if not already running.
        Input:
            project / listen / upstream / quiet / foreground.
            spawn_generation — generation snapshotted before spawn (PR3);
                               recorded as applied_generation.
        Side effects:
            Acquires lifecycle lock; may spawn mitmdump; writes proxy.json.
            Foreground mode records RUNNING then releases the lock before
            blocking so concurrent status/stop remain possible.
        Raises:
            ProxyAlreadyRunning, ProxyStartError.
        """
        lock = RuntimeLock(proxy_lock_path(self._data_dir))
        with lock.acquire():
            state = self._load_and_validate_locked()
            if self._is_live_running(state):
                raise ProxyAlreadyRunning(
                    f"Proxy already running (pid={state.pid}, project={state.project_id})."
                )

            if foreground:
                identity = self._spawn_into(
                    state,
                    project=project,
                    listen_host=listen_host,
                    port=port,
                    upstream_url=upstream_url,
                    quiet=quiet,
                    foreground=False,
                    spawn_generation=spawn_generation,
                    redirect_logs=False,
                )
                # identity is ProxyRuntimeInfo; re-read process for wait.
                fg_pid = identity.pid
                fg_ct = identity.create_time
            else:
                return self._spawn_into(
                    state,
                    project=project,
                    listen_host=listen_host,
                    port=port,
                    upstream_url=upstream_url,
                    quiet=quiet,
                    foreground=False,
                    spawn_generation=spawn_generation,
                    redirect_logs=True,
                )

        # Foreground wait outside the lifecycle lock.
        if foreground and fg_pid is not None and fg_ct is not None:
            return self._wait_foreground(
                ProcessIdentity(pid=fg_pid, create_time=fg_ct)
            )
        return identity

    def stop(self, *, timeout_s: float = _DEFAULT_STOP_TIMEOUT_S) -> ProxyRuntimeInfo:
        """
        Purpose:
            Gracefully stop the managed proxy if running.
        Side effects:
            Lifecycle lock; signals child; updates proxy.json.
        """
        lock = RuntimeLock(proxy_lock_path(self._data_dir))
        with lock.acquire():
            state = self._load_and_validate_locked()
            if not self._is_live_running(state) and state.state == ProxyState.STOPPED:
                logger.info("Proxy stop requested but already STOPPED")
                return self._info_from_state(state)

            self._stop_locked(state, timeout_s=timeout_s)
            state.last_error = None
            save_state(self._data_dir, state)
            logger.info("Proxy stopped")
            return self._info_from_state(state)

    def kill(
        self,
        *,
        listen_host: Optional[str] = None,
        port: Optional[int] = None,
        force_any_owner: bool = False,
        timeout_s: float = _DEFAULT_STOP_TIMEOUT_S,
    ) -> dict:
        """
        Purpose:
            Hard recovery for stuck proxies:
              1. Stop the managed runtime process if present.
              2. Free listen host:port by stopping orphan listeners
                 (mitmdump by default; any owner when force_any_owner=True).

        Input:
            listen_host / port — target address; default from runtime state
                                 or 127.0.0.1:8080.
            force_any_owner — if True, kill any PID on the port (not only mitmdump).
        Output:
            Summary dict for CLI/JSON.
        Side effects:
            Signals/kills processes; clears proxy.json process fields.
        """
        lock = RuntimeLock(proxy_lock_path(self._data_dir))
        with lock.acquire():
            state = self._load_and_validate_locked()
            host = listen_host or state.listen_host or "127.0.0.1"
            listen_port = port if port is not None else (
                state.listen_port if state.listen_port is not None else 8080
            )

            managed_stopped = False
            if self._is_live_running(state) or state.pid is not None:
                if self._is_live_running(state):
                    self._stop_locked(state, timeout_s=timeout_s)
                    managed_stopped = True
                else:
                    state.clear_process()

            orphan_pids = find_listening_pids(host, listen_port)
            killed: list[int] = []
            skipped: list[int] = []
            for pid in orphan_pids:
                if not force_any_owner and not looks_like_mitmdump(pid):
                    skipped.append(pid)
                    logger.warning(
                        "Port reclaim: skipping non-mitmdump pid=%s on %s:%s "
                        "(use --force to kill any owner)",
                        pid,
                        host,
                        listen_port,
                    )
                    continue
                logger.info(
                    "Port reclaim: stopping listener pid=%s on %s:%s",
                    pid,
                    host,
                    listen_port,
                )
                self._ops.request_graceful_shutdown_pid(pid)
                deadline = time.monotonic() + _ORPHAN_GRACE_S
                while time.monotonic() < deadline:
                    if self._ops.read_identity(pid) is None:
                        break
                    time.sleep(0.1)
                if self._ops.read_identity(pid) is not None:
                    self._ops.force_kill_pid(pid)
                killed.append(pid)

            # Drop process fields; keep last listen hints for the operator.
            state.clear_process()
            state.listen_host = host
            state.listen_port = listen_port
            state.last_error = None
            save_state(self._data_dir, state)

            free_now = is_port_free(host, listen_port)
            summary = {
                "listen_host": host,
                "listen_port": listen_port,
                "managed_stopped": managed_stopped,
                "killed_pids": killed,
                "skipped_pids": skipped,
                "port_free": free_now,
            }
            logger.info("Proxy kill complete: %s", summary)
            return summary

    def restart(
        self,
        *,
        project: Optional[Project] = None,
        listen_host: Optional[str] = None,
        port: Optional[int] = None,
        upstream_url: Optional[str] = None,
        quiet: Optional[bool] = None,
        timeout_s: float = _DEFAULT_STOP_TIMEOUT_S,
        spawn_generation: int = 0,
    ) -> ProxyRuntimeInfo:
        """
        Purpose:
            Stop if running, then start with provided or last-known params.
        Input:
            project required if no prior runtime project / override missing.
            listen/port/upstream/quiet optional overrides of last start.
        """
        lock = RuntimeLock(proxy_lock_path(self._data_dir))
        with lock.acquire():
            state = self._load_and_validate_locked()

            # Capture last params before stop clears process fields.
            last_host = state.listen_host or "127.0.0.1"
            last_port = state.listen_port if state.listen_port is not None else 8080
            last_upstream = state.upstream_url
            last_quiet = state.quiet
            last_project_id = state.project_id

            if self._is_live_running(state) or state.state not in (
                ProxyState.STOPPED,
            ):
                self._stop_locked(state, timeout_s=timeout_s)

            target_project = project
            if target_project is None:
                raise ProxyStartError(
                    "restart requires a project (pass project= or ensure one is active)."
                )

            return self._spawn_into(
                state,
                project=target_project,
                listen_host=listen_host if listen_host is not None else last_host,
                port=port if port is not None else last_port,
                upstream_url=upstream_url if upstream_url is not None else last_upstream,
                quiet=quiet if quiet is not None else last_quiet,
                foreground=False,
                spawn_generation=spawn_generation,
            )

    def status(self) -> ProxyRuntimeInfo:
        """
        Purpose:
            Non-blocking observational status.
            Tries lifecycle lock briefly; on contention returns atomic snapshot
            with validation_deferred=True.
        """
        lock = RuntimeLock(proxy_lock_path(self._data_dir))
        acquired = lock.try_acquire(timeout_s=_STATUS_LOCK_TIMEOUT_S)
        if not acquired:
            state = load_state(self._data_dir)
            transitional = state.state in (
                ProxyState.STARTING,
                ProxyState.DRAINING,
                ProxyState.STOPPING,
            )
            logger.debug("Proxy status: lock busy; deferred validation")
            return self._info_from_state(
                state,
                validation_deferred=True,
                transitional=transitional,
            )

        try:
            state = self._load_and_validate_locked()
            save_state(self._data_dir, state)
            transitional = state.state in (
                ProxyState.STARTING,
                ProxyState.DRAINING,
                ProxyState.STOPPING,
            )
            return self._info_from_state(
                state,
                validation_deferred=False,
                transitional=transitional,
            )
        finally:
            lock.release()

    def reconcile(
        self,
        *,
        active_project: Optional[Project],
        spawn_generation: int = 0,
        generation_reader: Optional[Callable[[str], int]] = None,
        timeout_s: float = _DEFAULT_STOP_TIMEOUT_S,
        max_start_retries: int = 3,
    ) -> ProxyRuntimeInfo:
        """
        Purpose:
            Align running proxy with active project identity and generation.

            Generation honesty: applied_generation is always the generation
            captured immediately before spawn (spawn_generation). If desired
            advances during start, bounded follow-up restart or restart_pending.

        Input:
            active_project    — current ACTIVE project or None after close.
            spawn_generation  — initial desired gen hint (re-read under lock
                                when generation_reader is provided).
            generation_reader — optional callable(project_id) -> int to re-read
                                desired generation under the lifecycle lock.
            max_start_retries — bounded follow-up restarts when gen advances.
        """
        lock = RuntimeLock(proxy_lock_path(self._data_dir))
        with lock.acquire():
            state = self._load_and_validate_locked()

            if not self._is_live_running(state):
                return self._info_from_state(state)

            if active_project is None:
                logger.info("Reconcile: no active project — stopping proxy")
                self._stop_locked(state, timeout_s=timeout_s)
                save_state(self._data_dir, state)
                return self._info_from_state(state)

            def _desired() -> int:
                if generation_reader is not None:
                    return int(generation_reader(active_project.id))
                return spawn_generation

            desired = _desired()
            same_project = state.project_id == active_project.id
            applied = state.applied_generation
            if (
                same_project
                and not state.restart_pending
                and applied is not None
                and applied == desired
            ):
                return self._info_from_state(state)
            if (
                same_project
                and not state.restart_pending
                and applied is None
                and desired == 0
            ):
                return self._info_from_state(state)

            last_host = state.listen_host or "127.0.0.1"
            last_port = state.listen_port if state.listen_port is not None else 8080
            last_upstream = state.upstream_url
            last_quiet = state.quiet
            logger.info(
                "Reconcile: restarting proxy project=%s → %s desired_gen=%s",
                state.project_id,
                active_project.id,
                desired,
            )
            self._stop_locked(state, timeout_s=timeout_s)

            retries = 0
            while True:
                # Capture generation BEFORE resolve/spawn (honesty invariant).
                gen_at_spawn = _desired()
                info = self._spawn_into(
                    state,
                    project=active_project,
                    listen_host=last_host,
                    port=last_port,
                    upstream_url=last_upstream,
                    quiet=last_quiet,
                    foreground=False,
                    spawn_generation=gen_at_spawn,
                )
                # Re-read after spawn — concurrent writers may have advanced.
                latest = _desired()
                if latest == gen_at_spawn:
                    return info
                retries += 1
                logger.info(
                    "Reconcile: generation advanced during spawn "
                    "(%s → %s); retry=%s",
                    gen_at_spawn,
                    latest,
                    retries,
                )
                if retries >= max_start_retries:
                    state = load_state(self._data_dir)
                    state.restart_pending = True
                    save_state(self._data_dir, state)
                    logger.warning(
                        "Reconcile: max start retries exceeded; "
                        "restart_pending=true applied_generation=%s",
                        gen_at_spawn,
                    )
                    return self._info_from_state(state)
                # Stop the just-spawned child and loop with new gen.
                state = self._load_and_validate_locked()
                if self._is_live_running(state):
                    self._stop_locked(state, timeout_s=timeout_s)

    # ------------------------------------------------------------------ #
    # Internals                                                            #
    # ------------------------------------------------------------------ #

    def _load_and_validate_locked(self) -> ProxyRuntimeState:
        state = load_state(self._data_dir)
        if state.pid is None:
            if state.state != ProxyState.STOPPED:
                logger.info(
                    "Runtime validation: no pid but state=%s — clearing to STOPPED",
                    state.state.value,
                )
                state.clear_process()
                state.last_error = None
                save_state(self._data_dir, state)
            return state

        identity = ProcessIdentity(pid=state.pid, create_time=state.create_time or 0.0)
        if state.create_time is None or not self._ops.identity_matches(identity):
            logger.warning(
                "Stale runtime removed pid=%s create_time=%s",
                state.pid,
                state.create_time,
            )
            state.clear_process()
            state.last_error = None
            save_state(self._data_dir, state)
        return state

    def _is_live_running(self, state: ProxyRuntimeState) -> bool:
        if state.pid is None or state.create_time is None:
            return False
        identity = ProcessIdentity(pid=state.pid, create_time=state.create_time)
        return self._ops.identity_matches(identity) and state.state in (
            ProxyState.RUNNING,
            ProxyState.STARTING,
            ProxyState.DRAINING,
            ProxyState.STOPPING,
        )

    def _stop_locked(
        self,
        state: ProxyRuntimeState,
        *,
        timeout_s: float,
    ) -> None:
        if state.pid is None:
            state.clear_process()
            return

        identity = ProcessIdentity(
            pid=state.pid,
            create_time=state.create_time if state.create_time is not None else 0.0,
        )
        if not self._ops.identity_matches(identity):
            logger.info("Stop: process already gone; clearing state")
            state.clear_process()
            return

        state.state = ProxyState.DRAINING
        save_state(self._data_dir, state)
        logger.info("Drain started pid=%s", identity.pid)

        self._ops.request_graceful_shutdown(identity)
        state.state = ProxyState.STOPPING
        save_state(self._data_dir, state)

        exited = self._ops.wait(identity, timeout_s=timeout_s)
        if self._ops.is_alive(identity):
            logger.warning(
                "Graceful stop timed out after %.1fs; force killing pid=%s",
                timeout_s,
                identity.pid,
            )
            self._ops.force_kill(identity)
            self._ops.wait(identity, timeout_s=_FORCE_KILL_WAIT_S)

        logger.info("Drain complete pid=%s exit=%s", identity.pid, exited)
        state.clear_process()

    def _spawn_into(
        self,
        state: ProxyRuntimeState,
        *,
        project: Project,
        listen_host: str,
        port: int,
        upstream_url: Optional[str],
        quiet: bool,
        foreground: bool,
        spawn_generation: int,
        redirect_logs: bool = True,
    ) -> ProxyRuntimeInfo:
        """
        Spawn mitmdump and record RUNNING. Must be called while holding the
        lifecycle lock. Does not block for the child lifetime.
        """
        del foreground  # start() handles foreground wait outside the lock.
        state.state = ProxyState.STARTING
        state.project_id = project.id
        state.listen_host = listen_host
        state.listen_port = port
        state.upstream_url = upstream_url
        state.quiet = quiet
        state.last_error = None
        state.pid = None
        state.create_time = None
        save_state(self._data_dir, state)
        logger.info(
            "Proxy starting project=%s listen=%s:%s generation=%s",
            project.id,
            listen_host,
            port,
            spawn_generation,
        )

        seed_default_context(project.db_path)
        try:
            role_id = get_active_role_id(project.db_path)
            module_id = get_active_module_id(project.db_path)
        except Exception as exc:  # noqa: BLE001
            role_id = None
            module_id = None
            logger.warning("Could not resolve role/module at start: %s", exc)

        # Fail fast if something already owns the listen address (orphan
        # mitmdump from an old launch is the common case).
        if not is_port_free(listen_host, port):
            detail = describe_listeners(listen_host, port)
            state.clear_process()
            state.listen_host = listen_host
            state.listen_port = port
            state.project_id = project.id
            state.last_error = (
                f"Port {listen_host}:{port} is already in use. {detail}. "
                f"Run 'talos proxy kill --port {port}' to reclaim it, "
                f"or start with a different --port."
            )
            save_state(self._data_dir, state)
            logger.error("Proxy start refused: %s", state.last_error)
            raise ProxyStartError(state.last_error)

        argv = build_mitmdump_command(
            listen_host=listen_host,
            port=port,
            addon_path=_ADDON_PATH,
            upstream_url=upstream_url,
        )
        env = os.environ.copy()
        env["TALOS_PROJECT"] = project.id
        if quiet:
            env["TALOS_PROXY_QUIET"] = "1"

        log_path = proxy_log_path(self._data_dir) if redirect_logs else None

        try:
            identity = self._ops.spawn_managed(argv, env=env, log_path=log_path)
        except FileNotFoundError as exc:
            state.clear_process()
            state.last_error = f"Failed to spawn mitmdump: {exc}"
            save_state(self._data_dir, state)
            raise ProxyStartError(state.last_error) from exc
        except OSError as exc:
            state.clear_process()
            state.last_error = f"Failed to spawn mitmdump: {exc}"
            save_state(self._data_dir, state)
            raise ProxyStartError(state.last_error) from exc

        # Wait until the proxy is actually listening, or the child dies.
        # A short is_alive-only settle is insufficient: mitmdump can load the
        # addon then exit on EADDRINUSE after our old 0.4s check passed.
        ready_deadline = time.monotonic() + _START_READY_TIMEOUT_S
        time.sleep(_START_SETTLE_S)
        while time.monotonic() < ready_deadline:
            if not self._ops.is_alive(identity):
                state.clear_process()
                state.listen_host = listen_host
                state.listen_port = port
                state.project_id = project.id
                log_hint = f" See log: {log_path}" if log_path else ""
                tail = _tail_log(log_path) if log_path else ""
                detail = f"{log_hint}"
                if tail:
                    detail = f"{detail}\nLast log lines:\n{tail}"
                if not is_port_free(listen_host, port):
                    detail = (
                        f" {describe_listeners(listen_host, port)}."
                        f" Try: talos proxy kill --port {port}"
                        f"{detail}"
                    )
                state.last_error = (
                    f"mitmdump exited before becoming ready on "
                    f"{listen_host}:{port}.{detail}"
                )
                save_state(self._data_dir, state)
                logger.error("Proxy start failed: child died during readiness")
                raise ProxyStartError(state.last_error)

            if is_port_listening(listen_host, port):
                break
            time.sleep(0.15)
        else:
            # Timeout still alive but not listening — treat as failure.
            self._ops.request_graceful_shutdown(identity)
            self._ops.wait(identity, timeout_s=3.0)
            if self._ops.is_alive(identity):
                self._ops.force_kill(identity)
            state.clear_process()
            state.listen_host = listen_host
            state.listen_port = port
            state.project_id = project.id
            log_hint = f" See log: {log_path}" if log_path else ""
            state.last_error = (
                f"mitmdump did not listen on {listen_host}:{port} within "
                f"{_START_READY_TIMEOUT_S:.0f}s.{log_hint}"
            )
            save_state(self._data_dir, state)
            raise ProxyStartError(state.last_error)

        state.state = ProxyState.RUNNING
        state.pid = identity.pid
        state.create_time = identity.create_time
        state.project_id = project.id
        state.role_id = role_id
        state.module_id = module_id
        state.listen_host = listen_host
        state.listen_port = port
        state.upstream_url = upstream_url
        state.startup_time = utc_now_iso()
        state.applied_project_id = project.id
        state.applied_generation = spawn_generation
        state.restart_pending = False
        state.last_error = None
        save_state(self._data_dir, state)
        logger.info(
            "Proxy started pid=%s project=%s applied_generation=%s listen=%s:%s",
            identity.pid,
            project.id,
            spawn_generation,
            listen_host,
            port,
        )
        return self._info_from_state(state)

    def _wait_foreground(self, identity: ProcessIdentity) -> ProxyRuntimeInfo:
        """
        Purpose:
            Block until the foreground child exits (or Ctrl+C), outside the
            lifecycle lock so concurrent status/stop can run.
        """
        logger.info("Proxy foreground wait pid=%s", identity.pid)
        try:
            while self._ops.is_alive(identity):
                time.sleep(0.2)
        except KeyboardInterrupt:
            logger.info("Foreground interrupted — graceful stop pid=%s", identity.pid)
            lock = RuntimeLock(proxy_lock_path(self._data_dir))
            with lock.acquire():
                state = self._load_and_validate_locked()
                if (
                    state.pid == identity.pid
                    and state.create_time == identity.create_time
                ):
                    self._stop_locked(state, timeout_s=_DEFAULT_STOP_TIMEOUT_S)
                    save_state(self._data_dir, state)
                    return self._info_from_state(state)

        lock = RuntimeLock(proxy_lock_path(self._data_dir))
        with lock.acquire():
            state = self._load_and_validate_locked()
            if state.pid == identity.pid:
                state.clear_process()
                save_state(self._data_dir, state)
            logger.info("Proxy foreground session ended")
            return self._info_from_state(state)

    def _info_from_state(
        self,
        state: ProxyRuntimeState,
        *,
        validation_deferred: bool = False,
        transitional: bool = False,
    ) -> ProxyRuntimeInfo:
        return ProxyRuntimeInfo(
            state=state.state,
            pid=state.pid,
            create_time=state.create_time,
            project_id=state.project_id,
            role_id=state.role_id,
            module_id=state.module_id,
            listen_host=state.listen_host,
            listen_port=state.listen_port,
            upstream_url=state.upstream_url,
            startup_time=state.startup_time,
            applied_project_id=state.applied_project_id,
            applied_generation=state.applied_generation,
            restart_pending=state.restart_pending,
            runtime_version=state.runtime_version,
            last_error=state.last_error,
            validation_deferred=validation_deferred,
            transitional=transitional,
            log_path=str(proxy_log_path(self._data_dir)),
        )


def _tail_log(path: Optional[Path], *, max_lines: int = 12) -> str:
    """Return the last few lines of a log file for error messages."""
    if path is None or not path.exists():
        return ""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if not lines:
        return ""
    return "\n".join(lines[-max_lines:])
