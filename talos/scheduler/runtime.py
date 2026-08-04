"""
Module: talos.scheduler.runtime

Purpose:
    SchedulerRuntimeManager — owns the standalone ReplayScheduler process.
    Independent of proxy lifecycle except on active-project transitions.

Dependencies: json, logging, os, sys, pathlib, dataclasses
              talos.proxy.runtime.{lock,process_ops,atomic_io}, talos.projects.model
Data flow:
    CLI / project open-close → SchedulerRuntimeManager → ProcessOps → runner
Side effects:
    Spawns/signals scheduler child; writes ~/.talos/runtime/scheduler.json.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from talos.projects.model import Project
from talos.proxy.runtime.atomic_io import atomic_write_text
from talos.proxy.runtime.lock import RuntimeLock
from talos.proxy.runtime.process_ops import ProcessIdentity, ProcessOps
from talos.proxy.runtime.state import ProxyState

logger = logging.getLogger(__name__)

RUNTIME_VERSION = 1
_STATUS_LOCK_TIMEOUT_S = 0.2
_DEFAULT_STOP_TIMEOUT_S = 30.0
_FORCE_KILL_WAIT_S = 5.0
_START_SETTLE_S = 0.4


def _runtime_dir(data_dir: Path) -> Path:
    return data_dir / "runtime"


def scheduler_state_path(data_dir: Path) -> Path:
    return _runtime_dir(data_dir) / "scheduler.json"


def scheduler_lock_path(data_dir: Path) -> Path:
    return _runtime_dir(data_dir) / "scheduler.lock"


def scheduler_log_path(data_dir: Path) -> Path:
    return _runtime_dir(data_dir) / "scheduler.log"


@dataclass
class SchedulerRuntimeState:
    runtime_version: int = RUNTIME_VERSION
    state: ProxyState = ProxyState.STOPPED
    pid: Optional[int] = None
    create_time: Optional[float] = None
    project_id: Optional[str] = None
    startup_time: Optional[str] = None
    last_error: Optional[str] = None

    def clear_process(self) -> None:
        self.state = ProxyState.STOPPED
        self.pid = None
        self.create_time = None
        self.startup_time = None
        # Keep last project_id for operator context after stop? Clear it.
        self.project_id = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["state"] = self.state.value
        return data

    @classmethod
    def from_dict(cls, raw: dict) -> "SchedulerRuntimeState":
        try:
            state = ProxyState(raw.get("state", "stopped"))
        except ValueError:
            state = ProxyState.STOPPED
        return cls(
            runtime_version=int(raw.get("runtime_version", RUNTIME_VERSION)),
            state=state,
            pid=raw.get("pid"),
            create_time=raw.get("create_time"),
            project_id=raw.get("project_id"),
            startup_time=raw.get("startup_time"),
            last_error=raw.get("last_error"),
        )


@dataclass(frozen=True)
class SchedulerRuntimeInfo:
    state: ProxyState
    pid: Optional[int]
    create_time: Optional[float]
    project_id: Optional[str]
    startup_time: Optional[str]
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
            "startup_time": self.startup_time,
            "runtime_version": self.runtime_version,
            "last_error": self.last_error,
            "validation_deferred": self.validation_deferred,
            "transitional": self.transitional,
            "log_path": self.log_path,
        }


class SchedulerAlreadyRunning(Exception):
    pass


class SchedulerStartError(Exception):
    pass


def load_scheduler_state(data_dir: Path) -> SchedulerRuntimeState:
    path = scheduler_state_path(data_dir)
    if not path.exists():
        return SchedulerRuntimeState()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return SchedulerRuntimeState()
        return SchedulerRuntimeState.from_dict(raw)
    except (OSError, json.JSONDecodeError):
        return SchedulerRuntimeState()


def save_scheduler_state(data_dir: Path, state: SchedulerRuntimeState) -> None:
    path = scheduler_state_path(data_dir)
    payload = json.dumps(state.to_dict(), indent=2, sort_keys=True) + "\n"
    atomic_write_text(path, payload, prefix=".scheduler.json.", suffix=".tmp")


class SchedulerRuntimeManager:
    """Sole owner of the standalone scheduler process."""

    def __init__(
        self,
        data_dir: Path,
        process_ops: Optional[ProcessOps] = None,
    ) -> None:
        self._data_dir = Path(data_dir)
        self._ops = process_ops or ProcessOps()

    def start(self, *, project: Project) -> SchedulerRuntimeInfo:
        lock = RuntimeLock(scheduler_lock_path(self._data_dir))
        with lock.acquire():
            state = self._load_and_validate_locked()
            if self._is_live(state):
                raise SchedulerAlreadyRunning(
                    f"Scheduler already running (pid={state.pid}, "
                    f"project={state.project_id})."
                )
            return self._spawn(state, project=project)

    def stop(self, *, timeout_s: float = _DEFAULT_STOP_TIMEOUT_S) -> SchedulerRuntimeInfo:
        lock = RuntimeLock(scheduler_lock_path(self._data_dir))
        with lock.acquire():
            state = self._load_and_validate_locked()
            if not self._is_live(state):
                state.clear_process()
                save_scheduler_state(self._data_dir, state)
                return self._info(state)
            self._stop_locked(state, timeout_s=timeout_s)
            state.last_error = None
            save_scheduler_state(self._data_dir, state)
            logger.info("Scheduler stopped")
            return self._info(state)

    def status(self) -> SchedulerRuntimeInfo:
        lock = RuntimeLock(scheduler_lock_path(self._data_dir))
        if not lock.try_acquire(timeout_s=_STATUS_LOCK_TIMEOUT_S):
            state = load_scheduler_state(self._data_dir)
            transitional = state.state in (
                ProxyState.STARTING,
                ProxyState.DRAINING,
                ProxyState.STOPPING,
            )
            return self._info(
                state, validation_deferred=True, transitional=transitional
            )
        try:
            state = self._load_and_validate_locked()
            save_scheduler_state(self._data_dir, state)
            transitional = state.state in (
                ProxyState.STARTING,
                ProxyState.DRAINING,
                ProxyState.STOPPING,
            )
            return self._info(state, transitional=transitional)
        finally:
            lock.release()

    def reconcile_active_project(
        self,
        *,
        active_project: Optional[Project],
        timeout_s: float = _DEFAULT_STOP_TIMEOUT_S,
    ) -> SchedulerRuntimeInfo:
        """
        Project ownership only. Never auto-starts when STOPPED.
        running A + active B → stop A, start B
        running A + none → stop
        running A + A → no-op
        """
        lock = RuntimeLock(scheduler_lock_path(self._data_dir))
        with lock.acquire():
            state = self._load_and_validate_locked()
            if not self._is_live(state):
                return self._info(state)

            if active_project is None:
                logger.info("Scheduler reconcile: no active project — stopping")
                self._stop_locked(state, timeout_s=timeout_s)
                save_scheduler_state(self._data_dir, state)
                return self._info(state)

            if state.project_id == active_project.id:
                return self._info(state)

            logger.info(
                "Scheduler reconcile: rebind %s → %s",
                state.project_id,
                active_project.id,
            )
            self._stop_locked(state, timeout_s=timeout_s)
            return self._spawn(state, project=active_project)

    # ------------------------------------------------------------------ #

    def _load_and_validate_locked(self) -> SchedulerRuntimeState:
        state = load_scheduler_state(self._data_dir)
        if state.pid is None:
            if state.state != ProxyState.STOPPED:
                state.clear_process()
                save_scheduler_state(self._data_dir, state)
            return state
        identity = ProcessIdentity(
            pid=state.pid, create_time=state.create_time or 0.0
        )
        if state.create_time is None or not self._ops.identity_matches(identity):
            logger.warning(
                "Stale scheduler runtime removed pid=%s", state.pid
            )
            state.clear_process()
            save_scheduler_state(self._data_dir, state)
        return state

    def _is_live(self, state: SchedulerRuntimeState) -> bool:
        if state.pid is None or state.create_time is None:
            return False
        identity = ProcessIdentity(pid=state.pid, create_time=state.create_time)
        return self._ops.identity_matches(identity)

    def _stop_locked(
        self, state: SchedulerRuntimeState, *, timeout_s: float
    ) -> None:
        if state.pid is None:
            state.clear_process()
            return
        identity = ProcessIdentity(
            pid=state.pid,
            create_time=state.create_time if state.create_time is not None else 0.0,
        )
        if not self._ops.identity_matches(identity):
            state.clear_process()
            return
        state.state = ProxyState.DRAINING
        save_scheduler_state(self._data_dir, state)
        self._ops.request_graceful_shutdown(identity)
        state.state = ProxyState.STOPPING
        save_scheduler_state(self._data_dir, state)
        self._ops.wait(identity, timeout_s=timeout_s)
        if self._ops.is_alive(identity):
            self._ops.force_kill(identity)
            self._ops.wait(identity, timeout_s=_FORCE_KILL_WAIT_S)
        state.clear_process()

    def _spawn(
        self, state: SchedulerRuntimeState, *, project: Project
    ) -> SchedulerRuntimeInfo:
        state.state = ProxyState.STARTING
        state.project_id = project.id
        state.last_error = None
        state.pid = None
        state.create_time = None
        save_scheduler_state(self._data_dir, state)

        argv = [
            sys.executable,
            "-m",
            "talos.scheduler.runner",
            "--project",
            project.id,
        ]
        env = os.environ.copy()
        env["TALOS_PROJECT"] = project.id
        log_path = scheduler_log_path(self._data_dir)

        try:
            identity = self._ops.spawn_managed(argv, env=env, log_path=log_path)
        except OSError as exc:
            state.clear_process()
            state.last_error = f"Failed to spawn scheduler: {exc}"
            save_scheduler_state(self._data_dir, state)
            raise SchedulerStartError(state.last_error) from exc

        time.sleep(_START_SETTLE_S)
        if not self._ops.is_alive(identity):
            state.clear_process()
            state.last_error = (
                f"Scheduler exited immediately after start. See log: {log_path}"
            )
            save_scheduler_state(self._data_dir, state)
            raise SchedulerStartError(state.last_error)

        state.state = ProxyState.RUNNING
        state.pid = identity.pid
        state.create_time = identity.create_time
        state.project_id = project.id
        state.startup_time = (
            datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        )
        state.last_error = None
        save_scheduler_state(self._data_dir, state)
        logger.info(
            "Scheduler started pid=%s project=%s", identity.pid, project.id
        )
        return self._info(state)

    def _info(
        self,
        state: SchedulerRuntimeState,
        *,
        validation_deferred: bool = False,
        transitional: bool = False,
    ) -> SchedulerRuntimeInfo:
        return SchedulerRuntimeInfo(
            state=state.state,
            pid=state.pid,
            create_time=state.create_time,
            project_id=state.project_id,
            startup_time=state.startup_time,
            runtime_version=state.runtime_version,
            last_error=state.last_error,
            validation_deferred=validation_deferred,
            transitional=transitional,
            log_path=str(scheduler_log_path(self._data_dir)),
        )
