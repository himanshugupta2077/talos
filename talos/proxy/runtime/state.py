"""
Module: talos.proxy.runtime.state

Purpose:
    Atomic persistence of proxy runtime state under ~/.talos/runtime/proxy.json.
    Writers use atomic_write_text (temp + replace, with Windows lock retries)
    so concurrent status readers almost always see a complete JSON document.

Dependencies: json, pathlib, dataclasses, enum, datetime, atomic_io
Data flow:
    ProxyRuntimeManager → load_state / save_state → proxy.json
Side effects:
    Creates runtime directory; writes/replaces proxy.json.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from talos.proxy.runtime.atomic_io import atomic_write_text

logger = logging.getLogger(__name__)

# Brief retries when status readers / AV hold proxy.json open on Windows.
_LOAD_ATTEMPTS: int = 5
_LOAD_DELAY_S: float = 0.05

RUNTIME_VERSION: int = 1


class ProxyState(str, Enum):
    """Explicit proxy lifecycle states."""

    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    DRAINING = "draining"
    STOPPING = "stopping"


@dataclass
class ProxyRuntimeState:
    """
    Purpose:
        Mutable on-disk representation of proxy runtime.
    Fields mirror the plan's proxy.json schema.
    """

    runtime_version: int = RUNTIME_VERSION
    state: ProxyState = ProxyState.STOPPED
    pid: Optional[int] = None
    create_time: Optional[float] = None
    project_id: Optional[str] = None
    role_id: Optional[str] = None
    module_id: Optional[str] = None
    listen_host: Optional[str] = None
    listen_port: Optional[int] = None
    upstream_url: Optional[str] = None
    startup_time: Optional[str] = None
    applied_project_id: Optional[str] = None
    applied_generation: Optional[int] = None
    restart_pending: bool = False
    last_error: Optional[str] = None
    # Last successful start params (for restart reuse).
    quiet: bool = False

    def clear_process(self) -> None:
        """Reset process-linked fields after stop or stale validation."""
        self.state = ProxyState.STOPPED
        self.pid = None
        self.create_time = None
        self.startup_time = None
        # Keep listen/project hints for operator context; clear applied process
        # ownership that is no longer live.
        self.role_id = None
        self.module_id = None
        self.applied_project_id = None
        self.applied_generation = None
        self.restart_pending = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        return data

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ProxyRuntimeState":
        state_raw = raw.get("state", "stopped")
        try:
            state = ProxyState(state_raw)
        except ValueError:
            state = ProxyState.STOPPED
        return cls(
            runtime_version=int(raw.get("runtime_version", RUNTIME_VERSION)),
            state=state,
            pid=raw.get("pid"),
            create_time=raw.get("create_time"),
            project_id=raw.get("project_id"),
            role_id=raw.get("role_id"),
            module_id=raw.get("module_id"),
            listen_host=raw.get("listen_host"),
            listen_port=raw.get("listen_port"),
            upstream_url=raw.get("upstream_url"),
            startup_time=raw.get("startup_time"),
            applied_project_id=raw.get("applied_project_id"),
            applied_generation=raw.get("applied_generation"),
            restart_pending=bool(raw.get("restart_pending", False)),
            last_error=raw.get("last_error"),
            quiet=bool(raw.get("quiet", False)),
        )


def runtime_dir(data_dir: Path) -> Path:
    return data_dir / "runtime"


def proxy_state_path(data_dir: Path) -> Path:
    return runtime_dir(data_dir) / "proxy.json"


def proxy_lock_path(data_dir: Path) -> Path:
    return runtime_dir(data_dir) / "proxy.lock"


def proxy_log_path(data_dir: Path) -> Path:
    return runtime_dir(data_dir) / "proxy.log"


def load_state(data_dir: Path) -> ProxyRuntimeState:
    """
    Purpose:
        Load proxy.json or return a fresh STOPPED state if missing/corrupt.
        Retries briefly on transient Windows sharing / access errors.
    """
    path = proxy_state_path(data_dir)
    if not path.exists():
        return ProxyRuntimeState()
    last_exc: Optional[BaseException] = None
    for attempt in range(_LOAD_ATTEMPTS):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                logger.warning("proxy.json is not an object; treating as STOPPED")
                return ProxyRuntimeState()
            return ProxyRuntimeState.from_dict(raw)
        except (OSError, json.JSONDecodeError) as exc:
            last_exc = exc
            if attempt + 1 < _LOAD_ATTEMPTS:
                time.sleep(_LOAD_DELAY_S * (attempt + 1))
                continue
            logger.warning(
                "Failed to read proxy.json (%s); treating as STOPPED",
                exc,
            )
            return ProxyRuntimeState()
    logger.warning(
        "Failed to read proxy.json (%s); treating as STOPPED",
        last_exc,
    )
    return ProxyRuntimeState()


def save_state(data_dir: Path, state: ProxyRuntimeState) -> None:
    """
    Purpose:
        Atomically write proxy.json (Windows-safe replace with retries).
    """
    path = proxy_state_path(data_dir)
    payload = json.dumps(state.to_dict(), indent=2, sort_keys=True) + "\n"
    atomic_write_text(path, payload, prefix=".proxy.json.", suffix=".tmp")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
